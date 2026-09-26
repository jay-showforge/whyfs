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
from .privsep import Store, open_state_dirfd, open_state_file, replace_state_file

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


# State files live in the user-controlled .whyfs directory but may be written
# by a root daemon: every access goes through an O_NOFOLLOW directory fd.
def _load_state(root: Path) -> dict | None:
    if not (root / ".whyfs").is_dir():
        return None
    try:
        fd = open_state_file(root, STATE_NAME, os.O_RDONLY)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            return json.loads(fh.read(1 << 20))
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _unlink_state(root: Path) -> None:
    try:
        dfd = open_state_dirfd(root)
    except OSError:
        return
    try:
        os.unlink(STATE_NAME, dir_fd=dfd)  # unlink never follows the final component
    except OSError:
        pass
    finally:
        os.close(dfd)


def read_state(root: Path) -> dict | None:
    state = _load_state(root)
    if state is None:
        return None
    if not _pid_alive(int(state.get("pid", -1))):
        _unlink_state(root)
        return None
    return state


def _write_state(root: Path, state: dict) -> None:
    replace_state_file(root, STATE_NAME, (json.dumps(state, indent=2) + "\n").encode())


def _clear_state(root: Path, pid: int) -> None:
    state = _load_state(root)
    if state is not None and int(state.get("pid", -1)) == pid:
        _unlink_state(root)


def run_foreground(root: Path, *, capture_all: bool = False, quiet: bool = False) -> int:
    root = root.resolve()
    os.close(open_state_dirfd(root))
    existing = read_state(root)
    if existing and int(existing.get("pid", -1)) != os.getpid():
        raise SystemExit(f"whyfs daemon already running as pid {existing['pid']} for {root}")

    run_id = "daemon-" + uuid.uuid4().hex
    started = time.time_ns()
    # Forked before any BPF state exists; runs as the workspace owner when we are root.
    store = Store(root).start()
    store.call("begin_run", run_id, started, str(root))

    ensure_kernel_headers()
    collector = BCCCollector(root, run_id, capture_all=capture_all, store=store)
    try:
        collector.start()
    except BCCUnavailable as exc:
        store.call("end_run", run_id, time.time_ns(), 2, {})
        store.close()
        raise SystemExit(str(exc))
    except Exception:
        store.call("end_run", run_id, time.time_ns(), 2, {})
        store.close()
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
            collector.poll(50)
    except KeyboardInterrupt:
        pass
    except Exception:
        exit_code = 1
        raise
    finally:
        stats = collector.stop()
        ended = time.time_ns()
        final = {k: int(v) for k, v in vars(stats).items()}
        final.update(writer_rows=collector.writer.written, writer_batches=collector.writer.batches,
                     writer_max_batch=collector.writer.max_batch)
        store.call("end_run", run_id, ended, exit_code, final)
        store.close()
        _clear_state(root, os.getpid())
        if not quiet:
            print(
                f"whyfs daemon: stopped · events {stats.submitted} · filtered {stats.filtered} "
                f"· kernel drops {stats.kernel_drops} · queue drops {stats.queue_drops} "
                f"· unresolved-fd {stats.unresolved_fd}",
                file=sys.stderr,
            )
    return exit_code


def start_background(root: Path, *, capture_all: bool = False) -> dict:
    root = root.resolve()
    os.close(open_state_dirfd(root))
    existing = read_state(root)
    if existing:
        return existing

    log_path = _log_path(root)
    log = os.fdopen(open_state_file(root, LOG_NAME, os.O_WRONLY | os.O_CREAT | os.O_APPEND), "ab", buffering=0)
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


def _kernel_headers_present() -> bool:
    rel = os.uname().release if hasattr(os, "uname") else ""
    return Path("/sys/kernel/kheaders.tar.xz").exists() or Path(f"/lib/modules/{rel}/build").exists()


def ensure_kernel_headers() -> bool:
    """BCC compiles against kernel headers.  WSL2 kernels ship them as the
    in-kernel `kheaders` module; load it when running privileged."""
    if _kernel_headers_present():
        return True
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        subprocess.run(["modprobe", "kheaders"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return _kernel_headers_present()


def capability_report() -> dict:
    linux = sys.platform.startswith("linux")
    report = {
        "linux": linux,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "bcc_importable": False,
        "bpf_fs": Path("/sys/fs/bpf").exists(),
        "btf_vmlinux": Path("/sys/kernel/btf/vmlinux").exists(),
        "kernel_headers": _kernel_headers_present() if linux else False,
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
        and report["kernel_headers"]
        and (report["euid"] == 0 or (report["cap_bpf"] and report["cap_perfmon"]))
    )
    return report
