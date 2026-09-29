#!/usr/bin/env python3
"""Live secret-redaction gate: secrets passed on real command lines never reach whyfs output.

Linux:   sudo python3 scripts/secret_gate.py --user USER --out DIR   (eBPF daemon; workload as USER)
macOS:   sudo python3 scripts/secret_gate.py --installed --user USER --out DIR   (the launchd machine service:
         macOS has no per-workspace daemon; the store and logs scanned are the service's)
Windows: python scripts\\secret_gate.py --out DIR                    (whyfs service)
Add --installed to exercise the installed package instead of this source tree.

Runs, under the always-on collector, commands whose secrets sit where argv tokenization
cannot isolate them -- shell wrappers (sh -c / bash -c / cmd /c / PowerShell -Command) --
and plain argv secrets.  Every secret value contains the marker SECRETVAL.  Then:

* `why`, `history` and `impact` (human and --json output) of every output: no secret, the
  creator's command still shows its non-secret parts and <redacted>;
* every stored wrapper (parent) command line -- where env-assignment secrets live -- is redacted;
* every byte of the workspace state directory (SQLite db, -wal, -shm, daemon.json, logs)
  and the collector logs (Windows: %ProgramData%\\whyfs\\logs): no secret, in UTF-8 or UTF-16;
* the gate's own report and logs (written with secrets masked): no secret.

Exits 0 only if every check passes and the collector lost nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALLED = "--installed" in sys.argv  # the store is read with sqlite3: no whyfs import needed

LINUX = sys.platform.startswith("linux")
MAC = sys.platform == "darwin"
POSIX = LINUX or MAC
MAC_STORE = Path("/Library/Application Support/WhyFS/machine")
ENV = dict(os.environ) if INSTALLED else dict(os.environ, PYTHONPATH=str(REPO / "src"))
_INSTALLED_EXE = "/usr/local/bin/whyfs" if MAC else shutil.which("whyfs") or (os.path.join(os.environ.get("ProgramFiles", ""), "whyfs", "whyfs.exe")
                                           if os.name == "nt" else "whyfs")  # PATH of an older shell may predate the install
WHYFS = [_INSTALLED_EXE] if INSTALLED else [sys.executable, "-m", "whyfs"]
MARK = b"SECRETVAL"
PY = "python3" if POSIX else sys.executable
WRITE = "import sys; open(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('-') else 'o.txt','w').write(open('in.txt').read())"


def cases():
    """(name, output file, how to run it, non-secret text the stored command must still show)."""
    code = WRITE
    if POSIX:
        return [
            ("sh -c wrapper", "o1.txt", ["sh", "-c", f"{PY} -c \"{code}\" o1.txt --token SECRETVAL_1 API_KEY=SECRETVAL_2"],
             ["--token", "API_KEY="]),
            ("bash -c wrapper, quoted value", "o2.txt",
             ["bash", "-c", f"export ACCESS_TOKEN=SECRETVAL_3; {PY} -c \"{code}\" o2.txt --password 'SECRETVAL_4 two words'"],
             ["o2.txt", "--password"]),  # ACCESS_TOKEN is bash's (the parent's), not python's
            ("bash -lc env prefix", "o3.txt", ["bash", "-lc", f"PRIVATE_KEY=SECRETVAL_5 {PY} -c \"{code}\" o3.txt --token SECRETVAL_9"],
             ["o3.txt", "--token"]),  # PRIVATE_KEY is in bash's line (checked with the wrappers) and python's environment
            ("plain argv", "o4.txt", [PY, "-c", code, "o4.txt", "--auth-token", "SECRETVAL_6", "db_password=SECRETVAL_7", "--api-key=SECRETVAL_8"],
             ["--auth-token", "db_password=", "--api-key="]),
        ]
    q = f'"{PY}" -c "{code}"'
    ps_code = code.replace("'", "''")
    return [
        ("cmd /c wrapper", "o1.txt", f'{q} o1.txt --password SECRETVAL_1 API_KEY=SECRETVAL_2 /token:SECRETVAL_3', ["--password", "API_KEY=", "/token:"]),
        ("cmd /c set + &&", "o2.txt", f'set "ACCESS_TOKEN=SECRETVAL_4" && {q} o2.txt --api-key "SECRETVAL_5 two words"', ["--api-key"]),
        ("PowerShell -Command", "o3.txt",
         ["powershell", "-NoProfile", "-Command",
          f"$env:API_KEY='SECRETVAL_6'; & '{PY}' -c '{ps_code}' o3.txt -Token SECRETVAL_7 -Password:SECRETVAL_8"],
         ["-Token", "-Password:"]),
        ("plain argv", "o4.txt", [PY, "-c", code, "o4.txt", "--auth-token", "SECRETVAL_9", "PRIVATE_KEY=SECRETVAL_10"],
         ["--auth-token", "PRIVATE_KEY="]),
    ]


def mask(s: str) -> str:
    import re
    return re.sub(r"SECRETVAL[_0-9]*", "<LEAKED>", s)


def whyfs(*args, cwd, check=True):
    p = subprocess.run([*WHYFS, *args], cwd=cwd, env=ENV, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise SystemExit(f"whyfs {' '.join(args)} failed: {mask(p.stdout + p.stderr)}")
    return p


def leaks_in(path: Path) -> bool:
    try:
        b = path.read_bytes()
    except OSError:
        return False
    return MARK in b or MARK.decode().encode("utf-16-le") in b


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--installed", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if POSIX and os.geteuid() != 0:
        raise SystemExit("run as root (the collector and its store are root's); the workload runs as --user")
    home = f"/Users/{a.user}" if MAC and a.user else f"/home/{a.user}" if LINUX and a.user else None
    ws = Path(tempfile.mkdtemp(prefix="whyfs-secret-", dir=home)).resolve()
    (ws / "in.txt").write_text("payload\n")
    if POSIX:
        os.chmod(ws, 0o755)
        if a.user:
            subprocess.run(["chown", "-R", a.user if MAC else f"{a.user}:", str(ws)], check=True)
    if MAC:  # the machine service records everything in scope; nothing is initialized
        deadline = time.time() + 120
        while not (json.loads(whyfs("status", "--json", cwd=ws, check=False).stdout or "{}").get("collector_ready")):
            if time.time() > deadline:
                raise SystemExit("the machine collector is not ready after 120 s")
            time.sleep(1.0)
    else:
        whyfs("init", ".", cwd=ws)
        whyfs("daemon", "start", "--workspace", str(ws), cwd=ws)
        time.sleep(1.0)
    runs = []
    for name, output, cmd, _visible in cases():
        if POSIX:
            argv = (["sudo", "-u", a.user, "--"] if MAC else ["runuser", "-u", a.user, "--"]) + cmd if a.user else cmd
            p = subprocess.run(argv, cwd=ws, capture_output=True, text=True)
        elif isinstance(cmd, str):
            p = subprocess.run(cmd, cwd=ws, shell=True, capture_output=True, text=True)
        else:
            p = subprocess.run(cmd, cwd=ws, capture_output=True, text=True)
        runs.append({"case": name, "rc": p.returncode, "stderr": mask(p.stderr)[-400:]})
    if MAC:
        time.sleep(3.0)  # the collector's writer commits within a batch interval
    else:
        time.sleep(0.5)
        whyfs("daemon", "stop", "--workspace", str(ws), cwd=ws)

    checks = {}
    shown = {}
    parents = []
    for (name, output, _cmd, visible), r in zip(cases(), runs):
        checks[f"{name}: workload ran"] = r["rc"] == 0 and (ws / output).exists()
        texts = []
        for args in (("why", output), ("why", output, "--json"), ("history", output), ("history", output, "--json"),
                     ("impact", "in.txt"), ("impact", "in.txt", "--json")):
            texts.append(whyfs(*args, cwd=ws, check=False).stdout)
        wj = json.loads(texts[1] or "{}") or {}
        cmd = wj.get("command") or ""
        parents.append((wj.get("parent") or {}).get("command"))
        shown[name] = mask(cmd)
        checks[f"{name}: no secret in why/history/impact output"] = not any("SECRETVAL" in t for t in texts)
        checks[f"{name}: command stored and redacted"] = "<redacted>" in cmd
        checks[f"{name}: non-secret parts still shown"] = all(v in cmd for v in visible)
    state_dir = MAC_STORE / ".whyfs" if MAC else ws / ".whyfs"
    state_files = [p for p in state_dir.rglob("*") if p.is_file()]
    logs = []
    if MAC:
        logs = [p for p in Path("/Library/Logs/WhyFS").glob("*") if p.is_file()]
    elif not LINUX:
        logs = [p for p in (Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "whyfs" / "logs").glob("*") if p.is_file()]
    checks["state dir (db, wal, shm, daemon files, logs) free of secrets"] = bool(state_files) and not any(leaks_in(p) for p in state_files)
    checks["collector logs free of secrets"] = not any(leaks_in(p) for p in logs)
    import sqlite3
    con = sqlite3.connect(f"file:{state_dir / 'whyfs.db'}?mode=ro", uri=True)
    stats = {k: v for k, v in con.execute("SELECT key, SUM(value) FROM collector_stats GROUP BY key")}
    rows = con.execute("SELECT COUNT(*) FROM processes WHERE command LIKE '%<redacted>%'").fetchone()[0]
    all_cmds = sorted({mask(r[0]) for r in con.execute("SELECT command FROM processes WHERE command IS NOT NULL")})
    # the workload wrappers: parents of the creators (unrelated ancestors, e.g. the shell that started
    # this gate, are not the gate's business)
    wrappers = sorted({mask(p) for p in parents if p and any(w in p.lower() for w in ("cmd.exe", "powershell", "sh -c", "bash -c", "bash -lc"))})
    checks["wrapper (parent) command lines stored and redacted"] = bool(wrappers) and all("<redacted>" in c for c in wrappers)
    frags = (["export ACCESS_TOKEN=<redacted>;", "PRIVATE_KEY=<redacted> python3", "--token <redacted> API_KEY=<redacted>"] if POSIX
             else ['set "ACCESS_TOKEN=<redacted>" &&', "$env:API_KEY='<redacted>';", "--password <redacted> API_KEY=<redacted> /token:<redacted>"])
    checks["wrapper env assignments shown with values redacted"] = all(any(f in c for c in all_cmds) for f in frags)
    con.close()
    lost = sum(int(stats.get(k, 0) or 0) for k in ("kernel_drops", "queue_drops", "user_unresolved", "late_records"))
    checks["zero loss"] = lost == 0
    report = {"platform": platform.platform(), "machine": platform.machine(), "installed": INSTALLED, "runs": runs,
              "stored_commands": shown, "all_stored_commands": all_cmds, "workload_wrappers": wrappers, "redacted_process_rows": rows, "state_files_scanned": len(state_files),
              "log_files_scanned": len(logs), "lost": lost, "checks": checks, "workspace": str(ws),
              "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    rp = out / "secret_gate.json"
    rp.write_text(json.dumps(report, indent=1))
    checks["gate report free of secrets"] = not leaks_in(rp)
    report["checks"] = checks
    rp.write_text(json.dumps(report, indent=1))
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'} {k}")
    for k, v in shown.items():
        print(f"  stored [{k}]: {v}")
    ok = all(checks.values())
    print(f"secret gate on {platform.system()} {platform.machine()}: {sum(checks.values())}/{len(checks)} checks, "
          f"{len(state_files)} state files + {len(logs)} logs scanned, lost {lost}")
    if ok:
        shutil.rmtree(ws, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
