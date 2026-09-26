from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .ebpf_bcc import BCCCollector, BCCUnavailable, install_signal_stop
from .store import connect, set_collector_stat

STATE_NAME = "daemon.json"
LOG_NAME = "daemon.log"


def _state_path(root: Path) -> Path:
    return root / ".whyfs" / STATE_NAME


def _log_path(root: Path) -> Path:
    return root / ".whyfs" / LOG_NAME


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def read_state(root: Path) -> dict | None:
    p = _state_path(root)
    try:
        state = json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    if not _pid_alive(int(state.get("pid", -1))):
        try:
            p.unlink()
        except OSError:
            pass
        return None
    return state


def _write_state(root: Path, state: dict) -> None:
    p = _state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n")
    os.replace(tmp, p)


def _clear_state(root: Path, pid: int) -> None:
    p = _state_path(root)
    try:
        state = json.loads(p.read_text())
        if int(state.get("pid", -1)) == pid:
            p.unlink()
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass


def run_foreground(root: Path, *, capture_all: bool = False, quiet: bool = False) -> int:
    root = root.resolve()
    (root / ".whyfs").mkdir(parents=True, exist_ok=True)
    existing = read_state(root)
    if existing and int(existing.get("pid", -1)) != os.getpid():
        raise SystemExit(f"whyfs daemon already running as pid {existing['pid']} for {root}")

    run_id = "daemon-" + uuid.uuid4().hex
    started = time.time_ns()
    con = connect(root)
    con.execute(
        "INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
        (run_id, started, str(root), "whyfs daemon", str(root), "ebpf-bcc"),
    )
    con.commit()
    con.close()

    collector = BCCCollector(root, run_id, capture_all=capture_all)
    try:
        collector.start()
    except BCCUnavailable as exc:
        con = connect(root)
        con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (time.time_ns(), 2, run_id))
        con.commit(); con.close()
        raise SystemExit(str(exc))
    except Exception as exc:
        con = connect(root)
        con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (time.time_ns(), 2, run_id))
        con.commit(); con.close()
        raise

    state = {
        "pid": os.getpid(),
        "run_id": run_id,
        "workspace": str(root),
        "backend": "ebpf-bcc",
        "capture_all": bool(capture_all),
        "started_ns": started,
    }
    _write_state(root, state)
    if not quiet:
        print(f"whyfs daemon: watching {root} · pid {os.getpid()} · run {run_id[:15]}", file=sys.stderr)

    stop = threading.Event()
    install_signal_stop(stop)
    exit_code = 0
    try:
        while not stop.is_set():
            collector.poll(100)
    except KeyboardInterrupt:
        pass
    except Exception:
        exit_code = 1
        raise
    finally:
        stats = collector.stop()
        ended = time.time_ns()
        con = connect(root)
        con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (ended, exit_code, run_id))
        for key, value in vars(stats).items():
            set_collector_stat(con, run_id, key, int(value))
        con.close()
        _clear_state(root, os.getpid())
        if not quiet:
            print(
                f"whyfs daemon: stopped · events {stats.submitted} · filtered {stats.filtered} "
                f"· drops {stats.kernel_drops} · unresolved-fd {stats.unresolved_fd}",
                file=sys.stderr,
            )
    return exit_code


def start_background(root: Path, *, capture_all: bool = False) -> dict:
    root = root.resolve()
    (root / ".whyfs").mkdir(parents=True, exist_ok=True)
    existing = read_state(root)
    if existing:
        return existing

    log_path = _log_path(root)
    log = open(log_path, "ab", buffering=0)
    args = [sys.executable, "-m", "whyfs", "_daemon-worker", "--workspace", str(root)]
    if capture_all:
        args.append("--all-files")
    proc = subprocess.Popen(
        args,
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
        close_fds=True,
    )
    log.close()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        state = read_state(root)
        if state:
            return state
        if proc.poll() is not None:
            tail = ""
            try:
                tail = log_path.read_text(errors="replace")[-4000:]
            except OSError:
                pass
            raise SystemExit(f"whyfs daemon failed to start (exit {proc.returncode}).\n{tail}".rstrip())
        time.sleep(0.05)
    proc.terminate()
    raise SystemExit(f"whyfs daemon did not become ready; see {log_path}")


def stop_background(root: Path, timeout: float = 5.0) -> bool:
    root = root.resolve()
    state = read_state(root)
    if not state:
        return False
    pid = int(state["pid"])
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            _clear_state(root, pid)
            return True
        time.sleep(0.05)
    raise SystemExit(f"whyfs daemon pid {pid} did not stop within {timeout:.1f}s")


def status(root: Path) -> dict:
    root = root.resolve()
    state = read_state(root)
    result = {"running": bool(state), "workspace": str(root)}
    if state:
        result.update(state)
    lp = _log_path(root)
    result["log"] = str(lp)
    return result


def capability_report() -> dict:
    linux = sys.platform.startswith("linux")
    report = {
        "linux": linux,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "bcc_importable": False,
        "bpf_fs": Path("/sys/fs/bpf").exists(),
        "btf_vmlinux": Path("/sys/kernel/btf/vmlinux").exists(),
        "cap_bpf": None,
        "cap_perfmon": None,
    }
    try:
        import bcc  # type: ignore  # noqa:F401
        report["bcc_importable"] = True
    except Exception:
        pass

    # Linux capability bit numbers: CAP_PERFMON=38, CAP_BPF=39.
    try:
        status_text = Path("/proc/self/status").read_text()
        line = next(x for x in status_text.splitlines() if x.startswith("CapEff:"))
        mask = int(line.split()[1], 16)
        report["cap_perfmon"] = bool(mask & (1 << 38))
        report["cap_bpf"] = bool(mask & (1 << 39))
    except Exception:
        pass
    report["ready"] = bool(
        linux
        and report["bcc_importable"]
        and (report["euid"] == 0 or (report["cap_bpf"] and report["cap_perfmon"]))
    )
    return report
