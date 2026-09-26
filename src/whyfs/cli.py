from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .daemon import capability_report, run_foreground, start_background, status as daemon_status, stop_background
from .query import history as qhistory
from .query import impact as qimpact
from .query import raw_process_events
from .query import why as qwhy
from .store import connect, import_log, normalize

ROOT_MARKER = ".whyfs"
VERSION = "0.2.0a1"


def project_root(start: Path | None = None) -> Path:
    p = (start or Path.cwd()).resolve()
    for q in [p, *p.parents]:
        if (q / ROOT_MARKER).exists():
            return q
    return p


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def native_lib(root: Path) -> Path:
    out = root / ROOT_MARKER / "libwhyfs.so"
    src = package_root() / "native" / "libwhyfs.c"
    if not src.exists():
        src = Path(__file__).resolve().parent / "libwhyfs.c"
    if not out.exists() or (src.exists() and src.stat().st_mtime_ns > out.stat().st_mtime_ns):
        cc = shutil.which("cc") or shutil.which("gcc")
        if not cc:
            raise SystemExit("whyfs trace needs a C compiler for the LD_PRELOAD fallback (install gcc/clang).")
        if not src.exists():
            raise SystemExit("native collector source not found")
        out.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([cc, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", str(out), str(src), "-ldl"], check=True)
    return out


def redact_argv(argv: list[str]) -> str:
    out = []
    secret_next = False
    sensitive = ("password", "passwd", "token", "secret", "api-key", "apikey", "api_key", "access-key", "access_key", "private-key", "private_key", "credential", "authorization")
    for a in argv:
        low = a.lower()
        if secret_next:
            out.append("<redacted>")
            secret_next = False
            continue
        if any(low == "--" + s or low == s for s in sensitive):
            out.append(a)
            secret_next = True
            continue
        if "=" in a and any(s in low.split("=", 1)[0] for s in sensitive):
            out.append(a.split("=", 1)[0] + "=<redacted>")
        else:
            out.append(a)
    return shlex.join(out)


def cmd_init(a):
    root = Path(a.path).resolve()
    d = root / ROOT_MARKER
    d.mkdir(parents=True, exist_ok=True)
    connect(root).close()
    gi = root / ".gitignore"
    if gi.exists():
        text = gi.read_text(errors="ignore")
        if ".whyfs/" not in text:
            gi.write_text(text + ("\n" if text and not text.endswith("\n") else "") + ".whyfs/\n")
    print(f"Initialized whyfs in {root}")


def cmd_trace(a):
    """v0.1-compatible explicit tracing fallback."""
    command = list(a.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("usage: whyfs trace -- COMMAND [ARGS...]")
    root = Path(a.workspace or project_root()).resolve()
    (root / ROOT_MARKER).mkdir(parents=True, exist_ok=True)
    con = connect(root)
    lib = native_lib(root)
    run_id = uuid.uuid4().hex
    log = root / ROOT_MARKER / f"events-{run_id}.jsonl"
    started = time.time_ns()
    command_text = redact_argv(command)
    con.execute(
        "INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
        (run_id, started, str(Path.cwd()), command_text, str(root), "preload"),
    )
    con.commit()
    env = os.environ.copy()
    old = env.get("LD_PRELOAD", "")
    env["LD_PRELOAD"] = str(lib) + (":" + old if old else "")
    env["WHYFS_LOG"] = str(log)
    env["WHYFS_RUN_ID"] = run_id
    env["WHYFS_ROOT"] = str(root)
    env["WHYFS_CAPTURE_ALL"] = "1" if a.all_files else "0"
    proc = subprocess.run(command, env=env)
    n = import_log(con, log)
    ended = time.time_ns()
    con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (ended, proc.returncode, run_id))
    con.commit()
    con.close()
    if not a.keep_raw:
        try:
            log.unlink()
        except OSError:
            pass
    print(f"whyfs: captured {n} events · run {run_id[:8]} · exit {proc.returncode}", file=sys.stderr)
    return proc.returncode


def _root_and_con(path=None):
    root = project_root(Path(path).resolve().parent if path else None)
    return root, connect(root)


def cmd_why(a):
    _root, con = _root_and_con(a.file)
    show_all = a.all or a.raw
    result = qwhy(con, a.file, show_all)
    if result and a.raw and result.get("run_id"):
        result["raw_events"] = [dict(r) for r in raw_process_events(con, result["run_id"], result["process_key"])]
    con.close()
    if a.json:
        print(json.dumps(result, indent=2))
        return 0 if result else 1
    if not result:
        print(f"No recorded origin for {normalize(a.file)}")
        return 1
    print(result["path"])
    for mv in result.get("renamed_from") or []:
        print(f"├── moved from {mv['from']}  (by {mv['exe'] or '?'}, pid {mv['pid']})")
    if result.get("run_id") is None:
        print("└── original writer not observed")
        return 0
    print(f"└── created by {result['exe']}  (pid {result['pid']})")
    print(f"    run: {result['command']}")
    par = result.get("parent")
    if par and par.get("exe"):
        cmd = par.get("command") or ""
        cmd = cmd if len(cmd) <= 100 else cmd[:97] + "..."
        print(f"    parent: {par['exe'] or '(image unknown)'}  (pid {par['pid']})" + (f"  · {cmd}" if cmd else ""))
    print(f"    evidence: {result['collector']}")
    if result["inputs"]:
        print("    inputs:")
        for p in result["inputs"][: a.limit]:
            print(f"      ├── {p}")
        if len(result["inputs"]) > a.limit:
            print(f"      └── +{len(result['inputs']) - a.limit} more")
    else:
        print("    inputs: none recorded")
    for t in result.get("temporaries") or []:
        print(f"    via temporary {t['temporary']}  (written by {t['written_by'] or '?'}, pid {t['pid']})")
    if result.get("inputs_via_temporaries"):
        print("    inputs through temporaries:")
        for p in result["inputs_via_temporaries"][: a.limit]:
            print(f"      ├── {p}")
    if result.get("hidden_input_count") and not show_all:
        print(f"    ({result['hidden_input_count']} system/runtime/dependency reads hidden; use --raw)")
    if a.raw:
        print("    raw evidence (creator process, unfiltered):")
        for r in result.get("raw_events", []):
            flag = "r" if r["is_read"] else ("w" if r["is_write"] else "-")
            tail = f" -> {r['path2']}" if r["path2"] else ""
            print(f"      {r['ts_ns']}  {r['kind']:<7} {flag}  {r['path']}{tail}  [{r['api']}]")
    return 0


def cmd_history(a):
    _root, con = _root_and_con(a.file)
    rows = qhistory(con, a.file, a.limit)
    con.close()
    if a.json:
        print(json.dumps([dict(r) for r in rows], indent=2))
        return 0
    if not rows:
        print(f"No recorded writes for {normalize(a.file)}")
        return 1
    print(normalize(a.file))
    for r in rows:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts_ns"] / 1e9))
        print(f"{stamp}  {r['kind']:<7}  {(r['exe'] or '?')}  · {r['command']}")
    return 0


def cmd_impact(a):
    _root, con = _root_and_con(a.file)
    edges = qimpact(con, a.file, a.depth, a.all)
    con.close()
    if a.json:
        print(json.dumps([{"from": x, "to": y, "exe": e, "run_id": r} for x, y, e, r in edges], indent=2))
        return 0
    start = normalize(a.file)
    print(start)
    if not edges:
        print("└── no recorded downstream outputs")
        return 0
    for _src, dst, exe, run in edges:
        print(f"├── {dst}\n│   via {exe}  [{run[:8]}]")
    return 0


def cmd_stats(a):
    root = project_root()
    con = connect(root)
    counts = {}
    for table in ("runs", "processes", "events"):
        counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    for key, value in con.execute("SELECT key, COALESCE(SUM(value),0) FROM collector_stats GROUP BY key"):
        counts[key] = value
    counts.setdefault("kernel_drops", 0)
    counts.setdefault("queue_drops", 0)
    con.close()
    db = root / ROOT_MARKER / "whyfs.db"
    counts["bytes"] = db.stat().st_size if db.exists() else 0
    if a.json:
        print(json.dumps(counts, indent=2))
    else:
        print(
            f"runs {counts['runs']} · processes {counts['processes']} · events {counts['events']} "
            f"· kernel drops {counts['kernel_drops']} · queue drops {counts['queue_drops']} "
            f"· db {counts['bytes']/1024:.1f} KiB"
        )


def cmd_doctor(a):
    report = capability_report()
    if a.json:
        print(json.dumps(report, indent=2))
    elif report.get("platform") == "windows":
        print("whyfs Windows capability check")
        for key in ("architecture", "service", "binaries_installed", "install_dir", "ready"):
            print(f"  {key:18} {report.get(key)}")
        if not report["ready"]:
            print("\nInstall the collector service once, as administrator:  whyfs service install")
    else:
        print("whyfs eBPF capability check")
        for key in ("linux", "bcc_importable", "bpf_fs", "btf_vmlinux", "kernel_headers", "cap_bpf", "cap_perfmon", "euid", "native_collector", "ready"):
            print(f"  {key:16} {report.get(key)}")
        if not report["ready"]:
            print("\nAlways-on capture is not ready on this host. `whyfs trace` remains available as the explicit fallback.")
            if not report["bcc_importable"]:
                print("Install BCC (Ubuntu/Debian: bpfcc-tools python3-bpfcc) and Clang/kernel headers.")
            if not report.get("kernel_headers"):
                print("Kernel headers missing. On WSL2: `sudo modprobe kheaders` (provides /sys/kernel/kheaders.tar.xz).")
            if report["euid"] != 0 and not (report.get("cap_bpf") and report.get("cap_perfmon")):
                print("Run the daemon with sufficient BPF/perf capabilities (commonly via sudo during alpha testing).")
    return 0 if report["ready"] else 2


def cmd_daemon(a):
    root = Path(a.workspace or project_root()).resolve()
    if a.action == "run":
        return run_foreground(root, capture_all=a.all_files)
    if a.action == "start":
        s = start_background(root, capture_all=a.all_files)
        print(f"whyfs daemon running · pid {s['pid']} · workspace {s['workspace']}")
        return 0
    if a.action == "stop":
        stopped = stop_background(root)
        print("whyfs daemon stopped" if stopped else "whyfs daemon is not running")
        return 0
    if a.action == "status":
        s = daemon_status(root)
        if a.json:
            print(json.dumps(s, indent=2))
        elif s["running"]:
            print(f"running · pid {s['pid']} · {s['backend']} · workspace {s['workspace']}")
        else:
            print(f"not running · workspace {s['workspace']}")
        return 0 if s["running"] else 1
    raise SystemExit("unknown daemon action")


def cmd_service(a):
    if os.name != "nt":
        raise SystemExit("`whyfs service` manages the Windows collector service; on Linux use `sudo whyfs daemon start`")
    from . import winsvc
    if a.action == "install":
        return winsvc.service_install(Path(a.source) if a.source else None)
    if a.action == "uninstall":
        return winsvc.service_uninstall()
    print(json.dumps(winsvc.service_state(), indent=2))
    return 0


def cmd_daemon_worker(a):
    return run_foreground(Path(a.workspace), capture_all=a.all_files, quiet=True)


def parser():
    p = argparse.ArgumentParser(prog="whyfs", description="Ask your filesystem where files came from.")
    p.add_argument("--version", action="version", version=f"whyfs {VERSION}")
    sp = p.add_subparsers(dest="cmd", required=True)

    q = sp.add_parser("init")
    q.add_argument("path", nargs="?", default=".")
    q.set_defaults(func=cmd_init)

    q = sp.add_parser("trace", help="run one command with the portable LD_PRELOAD capture fallback")
    q.add_argument("--workspace")
    q.add_argument("--keep-raw", action="store_true")
    q.add_argument("--all-files", action="store_true", help="capture reads/writes outside the workspace too")
    q.add_argument("command", nargs=argparse.REMAINDER)
    q.set_defaults(func=cmd_trace)

    q = sp.add_parser("why", help="show the last observed creator and inputs of a file")
    q.add_argument("file")
    q.add_argument("--all", action="store_true", help="include system/library reads")
    q.add_argument("--raw", action="store_true", help="unfiltered inputs plus the creator's raw stored events")
    q.add_argument("--limit", type=int, default=20)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_why)

    q = sp.add_parser("history", help="show observed write history of a file")
    q.add_argument("file")
    q.add_argument("--limit", type=int, default=20)
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_history)

    q = sp.add_parser("impact", help="show downstream outputs that consumed this file")
    q.add_argument("file")
    q.add_argument("--depth", type=int, default=5)
    q.add_argument("--all", "--raw", dest="all", action="store_true", help="include system/runtime outputs")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_impact)

    q = sp.add_parser("stats")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_stats)

    q = sp.add_parser("doctor", help="check whether this host can run the always-on collector")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_doctor)

    q = sp.add_parser("daemon", help="always-on collector for this workspace (Linux eBPF / Windows ETW)")
    q.add_argument("action", choices=("run", "start", "stop", "status"))
    q.add_argument("--workspace")
    q.add_argument("--all-files", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_daemon)

    q = sp.add_parser("service", help="Windows: install/uninstall the collector service (once, as administrator)")
    q.add_argument("action", choices=("install", "uninstall", "status"))
    q.add_argument("--from", dest="source", help=argparse.SUPPRESS)
    q.set_defaults(func=cmd_service)

    # Internal worker launched by `daemon start`.
    q = sp.add_parser("_daemon-worker", help=argparse.SUPPRESS)
    q.add_argument("--workspace", required=True)
    q.add_argument("--all-files", action="store_true")
    q.set_defaults(func=cmd_daemon_worker)
    return p


def main():
    if os.name == "nt":
        # A pipe or a legacy-code-page console must never crash or mangle the output.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding=stream.encoding if stream.isatty() else "utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    a = parser().parse_args()
    rc = a.func(a)
    raise SystemExit(rc or 0)


if __name__ == "__main__":
    main()
