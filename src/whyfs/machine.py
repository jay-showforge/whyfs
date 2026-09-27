"""The machine-wide provenance service (docs/MACHINE_MODE.md).

Linux:   `whyfs machine run` (systemd whyfs.service, root): eBPF programs + native collector
         in machine mode, the local API socket, live loss counters, retention.
Windows: `whyfs machine serve` (started by the whyfs service, SYSTEM): supervises the ETW
         collector in machine mode, serves the local API pipe, retention.
Both write one machine store that only the service (and administrators) can read.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import retention
from .scope import defaults_text

NT = os.name == "nt"


def paths() -> dict:
    if NT:
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "whyfs"
        inst = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "whyfs"
        return {"base": base, "root": base / "machine", "config": base / "config.json", "scope": base / "scope.conf",
                "default_scope": inst / "scope-default.conf", "generated_scope": base / "scope-default.conf",
                "log": base / "logs" / "machine.log"}
    return {"base": Path("/var/lib/whyfs"), "root": Path("/var/lib/whyfs/machine"), "config": Path("/etc/whyfs/config.json"),
            "scope": Path("/etc/whyfs/scope.conf"), "default_scope": Path("/usr/lib/whyfs/scope-default.conf"),
            "generated_scope": Path("/run/whyfs/scope-default.conf"), "log": None}


DEFAULT_CONFIG = {**retention.DEFAULTS, "prune_every_s": 3600}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        cfg.update(json.loads(paths()["config"].read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return cfg


def scope_files() -> list[str]:
    """Rule files for the collector: the shipped defaults (or generated ones in a source
    checkout), then the administrator's additions."""
    p = paths()
    files = []
    if p["default_scope"].exists():
        files.append(str(p["default_scope"]))
    else:
        p["generated_scope"].parent.mkdir(parents=True, exist_ok=True)
        p["generated_scope"].write_text(defaults_text(NT), encoding="utf-8")
        files.append(str(p["generated_scope"]))
    if p["scope"].exists():
        files.append(str(p["scope"]))
    return files


def effective_scope_text() -> str:
    out = []
    for f in scope_files():
        try:
            out.append(f"# --- {f}\n" + Path(f).read_text(encoding="utf-8"))
        except OSError:
            pass
    return "\n".join(out)


READY_NAME = "machine-ready.json"


def collector_ready() -> bool:
    """True once the machine collector is attached and recording (not merely started):
    Linux: the daemon state file, written after the BPF programs load; Windows: written by
    serve_windows when the collector reports ready."""
    d = paths()["root"] / ".whyfs"
    f = d / (READY_NAME if NT else "daemon.json")
    try:
        st = json.loads(f.read_text())
    except (OSError, ValueError):
        return False
    pid = int(st.get("collector_pid") or st.get("pid") or 0)
    if NT:
        from .winsecurity import process_image
        return bool(pid) and process_image(pid) is not None
    return bool(pid) and os.path.exists(f"/proc/{pid}")


def _prune_tick(root: Path, state: dict) -> None:
    cfg = load_config()
    if time.monotonic() < state.get("next_prune", 0):
        return
    state["next_prune"] = time.monotonic() + float(cfg.get("prune_every_s", 3600))
    from .store import connect
    con = connect(root)
    try:
        state["last_prune"] = retention.prune(con, cfg)
    finally:
        con.close()


# ---------------------------------------------------------------- Linux
def run_linux() -> int:
    from .api import serve_unix
    from .daemon import run_foreground
    if os.geteuid() != 0:
        raise SystemExit("the machine service runs as root (systemd: whyfs.service)")
    root = paths()["root"]
    root.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(root.parent, 0o755)
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    from .observation import HEARTBEAT_EVERY_S, close_unclean_runs
    from .store import connect
    con = connect(root)  # the store exists before the API and the writer open it
    try:
        closed = close_unclean_runs(con)  # a crashed predecessor ends at its last heartbeat: a recorded gap
    finally:
        con.close()
    if closed:
        print(f"whyfs machine: closed {len(closed)} run(s) that ended unexpectedly", file=sys.stderr)
    stop = threading.Event()
    serve_unix(root, stop=stop)
    state: dict = {"next_prune": time.monotonic() + 300}
    try:
        return run_foreground(root, machine=True, scope_files=tuple(scope_files()),
                              tick=lambda ctx: _prune_tick(root, state), tick_every=float(HEARTBEAT_EVERY_S))
    finally:
        stop.set()


# ---------------------------------------------------------------- Windows
def _win_collector() -> Path:
    here = Path(__file__).resolve()
    inst = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "whyfs" / "whyfs-collect-win.exe"
    if inst.exists():
        return inst
    from .winsvc import bundled_binaries
    return bundled_binaries() / "whyfs-collect-win.exe"


def _log(msg: str) -> None:
    p = paths()["log"]
    if p is None:
        print(msg, file=sys.stderr)
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")


def serve_windows() -> int:
    """Run by the whyfs service as SYSTEM.  Reads `stop` on stdin (sent by the service)."""
    from . import winsecurity as ws
    from .api import serve_pipe
    from .store import connect
    from .winsvc import _temp_roots

    root = paths()["root"]
    root.mkdir(parents=True, exist_ok=True)
    ws.protect_dir(str(root))  # SYSTEM + Administrators only: the store is read through the API
    connect(root).close()
    stop = threading.Event()
    serve_pipe(root, stop=stop)
    threading.Thread(target=lambda: (sys.stdin.readline(), stop.set()), daemon=True).start()
    state: dict = {"next_prune": time.monotonic() + 300}
    backoff = 1.0
    from .observation import HEARTBEAT_EVERY_S, close_unclean_runs, heartbeat
    while not stop.is_set():
        run_id = "machine-" + uuid.uuid4().hex
        con = connect(root)
        closed = close_unclean_runs(con)  # a crashed predecessor ends at its last heartbeat: a recorded gap
        if closed:
            _log(f"closed {len(closed)} run(s) that ended unexpectedly")
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                    (run_id, time.time_ns(), str(root), "whyfs machine", str(root), "etw-native"))
        con.commit()
        con.close()
        args = [str(_win_collector()), "--machine", "--root", str(root), "--run-id", run_id, "--session", "whyfs-machine"]
        for f in scope_files():
            args += ["--scope", f]
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                             creationflags=0x08000000)  # CREATE_NO_WINDOW
        _log(f"machine collector started: run {run_id} pid {p.pid}")
        lines: list[str] = []
        ready = root / ".whyfs" / READY_NAME

        def reader():
            for x in p.stdout:
                if not x.strip():
                    continue
                lines.append(x)
                if '"ready"' in x:
                    ready.write_text(json.dumps({"collector_pid": p.pid, "run_id": run_id}))
        threading.Thread(target=reader, daemon=True).start()
        started = time.monotonic()
        next_stats = time.monotonic() + 60
        next_beat = 0.0
        while not stop.is_set() and p.poll() is None:
            stop.wait(1.0)
            if time.monotonic() >= next_beat:
                next_beat = time.monotonic() + HEARTBEAT_EVERY_S
                try:
                    hcon = connect(root)
                    try:
                        heartbeat(hcon, run_id)
                    finally:
                        hcon.close()
                except sqlite3.Error as exc:
                    _log(f"heartbeat failed: {exc}")
            if time.monotonic() >= next_stats:
                next_stats = time.monotonic() + 60
                try:
                    p.stdin.write("stats\n")
                    p.stdin.flush()
                except OSError:
                    pass
                _update_stats(root, run_id, lines)
                try:
                    _prune_tick(root, state)
                except Exception as exc:
                    _log(f"retention failed: {exc}")
        if p.poll() is None:
            try:
                p.stdin.write("stop\n")
                p.stdin.flush()
            except OSError:
                pass
            try:
                p.wait(timeout=120)
            except subprocess.TimeoutExpired:
                p.kill()
        time.sleep(0.5)
        try:
            ready.unlink()
        except OSError:
            pass
        _update_stats(root, run_id, lines, final=True, exit_code=p.returncode)
        _log(f"machine collector {run_id} exited {p.returncode}")
        if not stop.is_set():  # crashed: restart, with backoff if it keeps failing
            backoff = 1.0 if time.monotonic() - started > 300 else min(backoff * 2, 300)
            stop.wait(backoff)
    return 0


def _update_stats(root: Path, run_id: str, lines: list[str], final: bool = False, exit_code: int | None = None) -> None:
    from .store import connect, set_collector_stat
    stats = None
    for ln in reversed(lines):
        try:
            d = json.loads(ln)
            if isinstance(d, dict) and "received" in d:
                stats = d
                break
        except ValueError:
            continue
    con = connect(root)
    try:
        for k, v in (stats or {}).items():
            if isinstance(v, (int, bool)):
                set_collector_stat(con, run_id, k, int(v))
        if final:
            con.execute("UPDATE runs SET ended_ns=?, exit_code=? WHERE id=?", (time.time_ns(), exit_code, run_id))
        con.commit()
    finally:
        con.close()


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd == "run":
        return run_linux() if not NT else serve_windows()
    if cmd == "serve":
        return serve_windows()
    if cmd == "scope":
        print(effective_scope_text())
        return 0
    raise SystemExit("usage: whyfs machine run|serve|scope")
