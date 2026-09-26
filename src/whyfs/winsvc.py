"""Windows: `whyfs daemon start/stop/status` through the whyfs service.

Kernel tracing (ETW) needs administrator rights, so collection runs in the `whyfs`
Windows service (native/windows/whyfs-svc.c), installed once.  Everyday use needs no
elevation: this module asks the service over a local named pipe to start or stop the
native collector for one workspace.  The service identifies the caller by
impersonation, records only the caller's processes, and writes the caller's store as
the caller.  Run bookkeeping (the `runs` row and final statistics) is written here, by
the user, like the Linux daemon's.
"""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .store import STATE_DIR, connect, set_collector_stat

PIPE = r"\\.\pipe\whyfs-service"
SERVICE = "whyfs"
STATE_NAME = "daemon.json"
INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "whyfs"
BINARIES = ("whyfs-svc.exe", "whyfs-collect-win.exe")  # SQLite: Windows' own System32\winsqlite3.dll


class ServiceUnavailable(RuntimeError):
    pass


def _machine() -> str:
    m = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "")
    return {"AMD64": "x64", "ARM64": "arm64"}.get(m.upper(), m.lower())


def bundled_binaries() -> Path:
    """Prebuilt native binaries shipped inside the package for this architecture."""
    return Path(__file__).resolve().parent / "_bin" / f"win-{_machine()}"


def request(obj: dict, timeout: float = 240.0) -> dict:
    deadline = time.monotonic() + 10
    while True:
        try:
            f = open(PIPE, "r+b", buffering=0)
            break
        except FileNotFoundError:
            raise ServiceUnavailable(
                "the whyfs service is not running. Install it once, as administrator:  whyfs service install")
        except OSError as exc:  # ERROR_PIPE_BUSY: every instance in use, retry briefly
            if getattr(exc, "winerror", None) == 231 and time.monotonic() < deadline:
                ctypes.windll.kernel32.WaitNamedPipeW(PIPE, 2000)
                continue
            raise ServiceUnavailable(f"cannot reach the whyfs service: {exc}") from exc
    with f:
        f.write((json.dumps(obj) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = f.read(65536)
            if not chunk:
                break
            buf += chunk
    if not buf.strip():
        raise ServiceUnavailable("the whyfs service closed the connection without a reply")
    return json.loads(buf.decode("utf-8", "replace"))


def _temp_roots() -> list[str]:
    roots = []
    for var in ("TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            r = os.path.realpath(v)
            if r not in roots:
                roots.append(r)
    return roots


def _state_path(root: Path) -> Path:
    return root / STATE_DIR / STATE_NAME


def start(root: Path, *, capture_all: bool = False) -> dict:
    root = root.resolve()
    con = connect(root)  # creates .whyfs and the store as this user
    run_id = "daemon-" + uuid.uuid4().hex
    existing = _load(root)
    if existing:
        st = request({"op": "status", "workspace": str(root)})
        if st.get("running"):
            con.close()
            return existing
    con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                (run_id, time.time_ns(), str(root), "whyfs daemon", str(root), "etw-native"))
    con.commit()
    con.close()
    rep = request({"op": "start", "workspace": str(root), "run_id": run_id, "temp_roots": _temp_roots(),
                   "capture_all": bool(capture_all)})
    if not rep.get("ok"):
        _end_run(root, run_id, 2, {})
        raise SystemExit(f"whyfs daemon: {rep.get('error', 'service refused the request')}")
    state = {"pid": rep["pid"], "run_id": run_id, "workspace": rep["workspace"], "backend": "etw-native",
             "collector": "native", "collector_pid": rep["pid"], "session": rep.get("session"),
             "capture_all": bool(capture_all), "started_ns": time.time_ns()}
    _state_path(root).write_text(json.dumps(state, indent=2) + "\n")
    return state


def _load(root: Path) -> dict | None:
    try:
        return json.loads(_state_path(root).read_text())
    except (OSError, ValueError):
        return None


def _end_run(root: Path, run_id: str, exit_code: int, stats: dict) -> None:
    con = connect(root)
    con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (time.time_ns(), exit_code, run_id))
    for k, v in stats.items():
        if isinstance(v, (int, float)):
            set_collector_stat(con, run_id, k, int(v))
    con.commit()
    con.close()


def stop(root: Path) -> bool:
    root = root.resolve()
    state = _load(root)
    rep = request({"op": "stop", "workspace": str(root)})
    if not rep.get("ok") and rep.get("error"):
        raise SystemExit(f"whyfs daemon: {rep['error']}")
    if rep.get("running") is False and not state:
        return False
    stats = rep.get("stats") or {}
    if state:
        _end_run(root, state["run_id"], 0 if rep.get("ok") else 1, stats)
        try:
            _state_path(root).unlink()
        except OSError:
            pass
    if not rep.get("ok"):
        raise SystemExit(f"whyfs daemon: collector ended with exit code {rep.get('exit_code')}; see %ProgramData%\\whyfs\\logs")
    return True


def status(root: Path) -> dict:
    root = root.resolve()
    result = {"running": False, "workspace": str(root)}
    try:
        st = request({"op": "status", "workspace": str(root)})
    except ServiceUnavailable as exc:
        result["service"] = str(exc)
        return result
    state = _load(root) or {}
    result.update(state)
    result.update({"running": bool(st.get("running")), "backend": "etw-native"})
    if st.get("crashed"):
        result["crashed"] = True
        result["exit_code"] = st.get("exit_code")
    return result


# ---------------------------------------------------------------- service install / uninstall (elevated)
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_elevated(args: list[str]) -> int:
    """Re-run `python -m whyfs service ...` elevated (UAC prompt); wait for it."""
    import ctypes.wintypes as wt

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wt.HWND), ("lpVerb", wt.LPCWSTR),
                    ("lpFile", wt.LPCWSTR), ("lpParameters", wt.LPCWSTR), ("lpDirectory", wt.LPCWSTR), ("nShow", ctypes.c_int),
                    ("hInstApp", wt.HINSTANCE), ("lpIDList", ctypes.c_void_p), ("lpClass", wt.LPCWSTR), ("hkeyClass", wt.HKEY),
                    ("dwHotKey", wt.DWORD), ("hIcon", wt.HANDLE), ("hProcess", wt.HANDLE)]

    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW), fMask=0x40, lpVerb="runas", lpFile=sys.executable,
                             lpParameters=subprocess.list2cmdline(["-m", "whyfs", *args]), nShow=0)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        raise SystemExit("elevation was declined or failed")
    ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wt.DWORD()
    ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return code.value


def service_install(source: Path | None = None) -> int:
    if not is_admin():
        return _run_elevated(["service", "install"] + ([f"--from={source}"] if source else []))
    src = Path(source) if source else bundled_binaries()
    missing = [b for b in BINARIES if not (src / b).exists()]
    if missing:
        raise SystemExit(f"native binaries missing in {src}: {', '.join(missing)}")
    subprocess.run([str(INSTALL_DIR / "whyfs-svc.exe"), "uninstall"], capture_output=True) if (INSTALL_DIR / "whyfs-svc.exe").exists() else None
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)  # Program Files: writable by administrators only
    for b in BINARIES:
        shutil.copy2(src / b, INSTALL_DIR / b)
    (INSTALL_DIR / "sqlite3.dll").unlink(missing_ok=True)  # bundled by earlier builds; no longer used
    r = subprocess.run([str(INSTALL_DIR / "whyfs-svc.exe"), "install"], capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
    return r.returncode


def service_uninstall() -> int:
    if not is_admin():
        return _run_elevated(["service", "uninstall"])
    exe = INSTALL_DIR / "whyfs-svc.exe"
    if exe.exists():
        r = subprocess.run([str(exe), "uninstall"], capture_output=True, text=True)
        print((r.stdout + r.stderr).strip())
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    return 0


def service_state() -> dict:
    out = subprocess.run(["sc.exe", "query", SERVICE], capture_output=True, text=True).stdout
    state = "not installed"
    for line in out.splitlines():
        if "STATE" in line:
            state = line.split()[-1].lower()
    return {"service": state, "install_dir": str(INSTALL_DIR),
            "binaries_installed": all((INSTALL_DIR / b).exists() for b in BINARIES),
            "bundled_binaries": str(bundled_binaries()), "architecture": _machine()}
