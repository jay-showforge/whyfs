"""macOS platform layer (docs/MACOS.md).

Everything here is macOS-specific; the shared modules call it only under
``sys.platform == "darwin"``:

  collector   the native Endpoint Security collector (native/whyfs-collect.c built with
              -DWHYFS_MACOS + native/macos/whyfs-es.c): located, or built from source
  identity    "mac:DEV:INO" (APFS has no inode generation), and the on-disk form of a path
  processes   libproc / sysctl facts (macOS has no /proc)
  api         the local socket's peer credentials (LOCAL_PEERCRED / LOCAL_PEERPID)
  service     `whyfs machine run` under launchd (org.tenzorpipe.whyfs): the collector
              supervisor, the local API socket, heartbeats, retention
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

LABEL = "org.tenzorpipe.whyfs"                      # launchd job label
PLIST = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
INSTALL = Path("/Library/WhyFS")                     # installed code (pkg)
BASE = Path("/Library/Application Support/WhyFS")    # machine store, configuration
SOCKET_PATH = "/var/run/whyfs/api.sock"
SOURCE = Path(__file__).resolve().parent / "native" / "whyfs-collect.c"
ES_SOURCE = Path(__file__).resolve().parent / "native" / "macos" / "whyfs-es.c"
ENTITLEMENTS = Path(__file__).resolve().parent / "native" / "macos" / "whyfs-collect.entitlements"


def paths() -> dict:
    return {"base": BASE, "root": BASE / "machine", "config": BASE / "config.json", "scope": BASE / "scope.conf",
            "default_scope": INSTALL / "scope-default.conf", "generated_scope": Path("/var/run/whyfs/scope-default.conf"),
            "log": Path("/Library/Logs/WhyFS/machine.log")}


# ---------------------------------------------------------------- collector
class CollectorUnavailable(RuntimeError):
    pass


def build_collector(out: Path, *, sign: str | None = "-") -> Path:
    """Compile the collector (warnings on) and, unless ``sign`` is None, sign it with the Endpoint
    Security entitlement (``-``: ad hoc, which only a system without SIP enforcement accepts; a
    Developer ID identity and its provisioning profile are needed anywhere else)."""
    cc = shutil.which("clang") or shutil.which("cc")
    if not cc:
        raise CollectorUnavailable("building the collector needs the Xcode command line tools (clang)")
    tmp = out.with_name(f".{out.name}.{os.getpid()}")
    r = subprocess.run([cc, "-O2", "-Wall", "-Wextra", "-Wno-sign-compare", "-Wno-unused-parameter",
                        "-Wno-missing-field-initializers", "-DWHYFS_MACOS", "-mmacosx-version-min=13.0",
                        "-o", str(tmp), str(SOURCE), "-lsqlite3", "-lEndpointSecurity", "-lbsm"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise CollectorUnavailable("could not build the macOS collector:\n" + r.stderr.strip()[-4000:])
    if r.stderr.strip():
        print(r.stderr.strip(), file=sys.stderr)  # warnings are reported, never hidden
    if sign is not None:
        s = subprocess.run(["codesign", "-s", sign, "-f", "--entitlements", str(ENTITLEMENTS), str(tmp)],
                           capture_output=True, text=True)
        if s.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise CollectorUnavailable("codesign failed: " + s.stderr.strip())
    os.chmod(tmp, 0o755)
    os.replace(tmp, out)
    return out


def _source_digest() -> str:
    h = hashlib.sha256()
    for p in (SOURCE, ES_SOURCE, ENTITLEMENTS):
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def collector_binary() -> Path:
    """The installed collector, a developer override (WHYFS_COLLECT), or a cached local build."""
    override = os.environ.get("WHYFS_COLLECT")
    if override:  # developer override; a root service still runs only a root-controlled file
        o = Path(override).resolve()
        if os.geteuid() == 0 and not (_is_root_owned_private(o) and _is_root_owned_private(o.parent)):
            raise CollectorUnavailable(f"refusing WHYFS_COLLECT={override}: not root-owned and root-only-writable")
        return o
    inst = INSTALL / "bin" / "whyfs-collect"
    if inst.is_file():
        return inst
    base = Path("/var/root/Library/Caches/whyfs") if os.geteuid() == 0 else Path.home() / "Library" / "Caches" / "whyfs"
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    out = base / f"whyfs-collect-{_source_digest()}"
    return out if out.exists() else build_collector(out)


# ---------------------------------------------------------------- file identity and paths
def file_id(path: str) -> str | None:
    """The identity the collector records for a file: "mac:DEV:INO".  macOS reports no inode
    generation (APFS st_gen is 0), so this is weaker than Linux's; see compare in label.py."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return f"mac:{st.st_dev & 0xFFFFFFFF}:{st.st_ino}"


F_GETPATH = 50


def true_path(p: str) -> str:
    """The on-disk form of ``p`` as Endpoint Security reports it: symbolic links resolved
    (/tmp -> /private/tmp) and each existing component in its stored case (APFS is usually
    case-insensitive).  A tail that does not exist is kept as given."""
    head, tail = p, []
    while True:
        try:
            fd = os.open(head, os.O_RDONLY | getattr(os, "O_EVTONLY", 0x8000) | os.O_NONBLOCK)
        except OSError:
            parent, leaf = os.path.split(head)
            if not leaf or parent == head:
                return p
            tail.append(leaf)
            head = parent
            continue
        try:
            import fcntl
            buf = fcntl.fcntl(fd, F_GETPATH, b"\0" * 1024)
            real = buf.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")
        except OSError:
            return p
        finally:
            os.close(fd)
        return os.path.join(real, *reversed(tail)) if tail else real


# ---------------------------------------------------------------- processes (libproc, sysctl)
class _BSDInfo(ctypes.Structure):
    _fields_ = [("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32), ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32), ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32), ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32), ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32), ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32), ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32), ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64)]


_LIBC: list = []


def _libc():
    if not _LIBC:
        _LIBC.append(ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True))
    return _LIBC[0]


def _bsdinfo(pid: int) -> _BSDInfo | None:
    info = _BSDInfo()
    n = _libc().proc_pidinfo(ctypes.c_int(pid), 3, ctypes.c_uint64(0), ctypes.byref(info), ctypes.sizeof(info))  # PROC_PIDTBSDINFO
    return info if n == ctypes.sizeof(info) else None


def proc_start_ns(pid: int) -> int | None:
    i = _bsdinfo(pid)
    return i.pbi_start_tvsec * 1_000_000_000 + i.pbi_start_tvusec * 1000 if i else None


def process_user(pid: int) -> str | None:
    i = _bsdinfo(pid)
    return f"uid:{i.pbi_ruid}" if i else None


def process_image(pid: int) -> str | None:
    buf = ctypes.create_string_buffer(4096)
    n = _libc().proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(len(buf)))
    return buf.value.decode("utf-8", "surrogateescape") if n > 0 else None


def process_command(pid: int) -> str | None:
    """The command line (KERN_PROCARGS2; readable for the caller's own processes, or as root)."""
    libc = _libc()
    mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
    size = ctypes.c_size_t(0)
    if libc.sysctl(mib, 3, None, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0 or size.value < 4:
        return None
    buf = ctypes.create_string_buffer(size.value)
    if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return None
    raw = buf.raw[:size.value]
    argc = struct.unpack("i", raw[:4])[0]
    rest = raw[4:]
    exe_end = rest.find(b"\0")
    i = exe_end
    while i < len(rest) and rest[i] == 0:
        i += 1
    args = rest[i:].split(b"\0")[:argc]
    return " ".join(a.decode("utf-8", "replace") for a in args).strip() or None


def parent_and_image(pid: int) -> tuple[int | None, str | None, str | None]:
    i = _bsdinfo(pid)
    if not i:
        return None, None, None
    return int(i.pbi_ppid), process_image(pid), process_command(pid)


# ---------------------------------------------------------------- local API peer
SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID = 0, 0x001, 0x002
_XUCRED = "<IIh2x16I"  # struct xucred: cr_version, cr_uid, cr_ngroups, cr_groups[16]


def peer_credentials(sock) -> tuple[int, int]:
    """(pid, uid) of the process at the other end of a connected Unix socket, from the kernel."""
    raw = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize(_XUCRED))
    uid = struct.unpack(_XUCRED, raw[:struct.calcsize(_XUCRED)])[1]
    pid = struct.unpack("i", sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4)[:4])[0]
    return pid, uid


# ---------------------------------------------------------------- the machine service (launchd)
READY_NAME = "machine-ready.json"
ES_STATE_NAME = "endpoint-security.json"  # the collector's last Endpoint Security client result


def _log(msg: str) -> None:
    p = paths()["log"]
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        print(msg, file=sys.stderr)


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def endpoint_security_state() -> dict | None:
    try:
        return json.loads((paths()["root"] / ".whyfs" / ES_STATE_NAME).read_text())
    except (OSError, ValueError):
        return None


def collector_ready() -> bool:
    try:
        st = json.loads((paths()["root"] / ".whyfs" / READY_NAME).read_text())
    except (OSError, ValueError):
        return False
    pid = int(st.get("collector_pid") or 0)
    try:
        return bool(pid) and (os.kill(pid, 0) or True)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def serve() -> int:
    """`whyfs machine run` under launchd, as root: supervises the Endpoint Security collector
    (restarted with backoff if it exits), serves the local API socket, heartbeats, retention."""
    from .api import serve_unix
    from .machine import _prune_tick, _update_stats, scope_files
    from .observation import HEARTBEAT_EVERY_S, close_unclean_runs, heartbeat
    from .store import connect

    if os.geteuid() != 0:
        raise SystemExit(f"the machine service runs as root (launchd: {LABEL})")
    p = paths()
    root = p["root"]
    p["base"].mkdir(parents=True, exist_ok=True)
    os.chmod(p["base"], 0o755)
    root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    con = connect(root)  # the store exists before the API and the writer open it
    try:
        closed = close_unclean_runs(con)  # a crashed predecessor ends at its last heartbeat: a recorded gap
    finally:
        con.close()
    if closed:
        _log(f"closed {len(closed)} run(s) that ended unexpectedly")
    stop = threading.Event()
    for s in (signal.SIGTERM, signal.SIGINT):
        signal.signal(s, lambda *_: stop.set())
    Path(SOCKET_PATH).parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(Path(SOCKET_PATH).parent, 0o755)
    serve_unix(root, SOCKET_PATH, stop=stop)
    state: dict = {"next_prune": time.monotonic() + 300}
    backoff = 1.0
    ready = root / ".whyfs" / READY_NAME
    es_state = root / ".whyfs" / ES_STATE_NAME
    binary = collector_binary()
    while not stop.is_set():
        run_id = "machine-" + uuid.uuid4().hex
        con = connect(root)
        close_unclean_runs(con)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                    (run_id, time.time_ns(), str(root), "whyfs machine", str(root), "es-native"))
        con.commit()
        con.close()
        args = [str(binary), "--es", "--machine", "--root", str(root), "--run-id", run_id]
        for f in scope_files():
            args += ["--scope", f]
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
        _log(f"machine collector started: run {run_id} pid {proc.pid}")
        lines: list[str] = []

        def reader(proc=proc, run_id=run_id, lines=lines):
            for x in proc.stdout:
                if not x.strip():
                    continue
                lines.append(x)
                try:
                    d = json.loads(x)
                except ValueError:
                    continue
                if d.get("ready"):
                    _write_json(ready, {"collector_pid": proc.pid, "run_id": run_id})
                    _write_json(es_state, {"result": "SUCCESS", "time_ns": time.time_ns()})
                elif d.get("error") == "es_new_client":
                    _write_json(es_state, {"result": d.get("name"), "code": d.get("result"), "time_ns": time.time_ns()})
                    _log(f"Endpoint Security client not created: {d.get('name')}")
        threading.Thread(target=reader, daemon=True).start()
        started = time.monotonic()
        next_stats = time.monotonic() + 60
        next_beat = 0.0
        while not stop.is_set() and proc.poll() is None:
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
                    proc.send_signal(signal.SIGUSR1)  # the collector prints its counters
                except ProcessLookupError:
                    pass
                time.sleep(0.2)
                _update_stats(root, run_id, lines)
                try:
                    _prune_tick(root, state)
                except Exception as exc:
                    _log(f"retention failed: {exc}")
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)  # final drain: everything received is stored
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        time.sleep(0.5)
        try:
            ready.unlink()
        except OSError:
            pass
        _update_stats(root, run_id, lines, final=True, exit_code=proc.returncode)
        _log(f"machine collector {run_id} exited {proc.returncode}")
        if not stop.is_set():  # crashed or refused: restart, with backoff if it keeps failing
            backoff = 1.0 if time.monotonic() - started > 300 else min(backoff * 2, 300)
            stop.wait(backoff)
    return 0


def launchd_state() -> dict:
    """The launchd job, as `whyfs status` / `whyfs doctor` report it."""
    r = subprocess.run(["launchctl", "print", f"system/{LABEL}"], capture_output=True, text=True)
    out = {"label": LABEL, "loaded": r.returncode == 0, "plist": str(PLIST), "plist_installed": PLIST.exists()}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("state = "):
            out["state"] = line.split("=", 1)[1].strip()
        elif line.startswith("pid = "):
            out["pid"] = int(line.split("=", 1)[1].strip())
    return out


def capability_report() -> dict:
    es = endpoint_security_state()
    try:
        binary = str(collector_binary()) if (INSTALL / "bin" / "whyfs-collect").exists() or os.environ.get("WHYFS_COLLECT") else None
    except CollectorUnavailable:
        binary = None
    job = launchd_state()
    return {"platform": "macos", "backend": "es-native", "collector": binary, "service": job,
            "endpoint_security": es, "sip": subprocess.run(["csrutil", "status"], capture_output=True, text=True).stdout.strip(),
            "ready": bool(job.get("loaded")) and collector_ready()}


def _is_root_owned_private(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return not stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
