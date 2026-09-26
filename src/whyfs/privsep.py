"""Privilege separation for the root eBPF daemon.

The collector must run as root to load BPF programs, but the evidence store
lives in ``<workspace>/.whyfs``, a directory the workspace owner controls.  A
root process opening files there could be redirected by a planted symlink
(check-then-open is racy), and root-owned 0644 database files would leak to
other local users and break unprivileged queries under WAL.

So when the daemon is root and the workspace belongs to someone else, every
SQLite access runs in a forked child that has dropped to the workspace owner's
uid/gid.  The root side only *sends* pickled batches and reads back integers;
it never unpickles data from the unprivileged side.  Root-written state files
(daemon.json / daemon.log) are opened relative to an O_NOFOLLOW directory fd.
"""
from __future__ import annotations

import os
import pickle
import stat
import struct
import sys
import threading
import traceback
from pathlib import Path

from .store import STATE_DIR, connect, ingest_events, set_collector_stat


def workspace_owner(root: Path) -> tuple[int, int]:
    st = os.stat(root)
    return st.st_uid, st.st_gid


def needs_privsep(root: Path) -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0 and workspace_owner(root)[0] != 0


def open_state_dirfd(root: Path) -> int:
    """Open ``root/.whyfs`` without following a symlink, creating it 0700 and
    owned by the workspace owner.  Raises PermissionError on a symlink."""
    d = root / STATE_DIR
    try:
        os.mkdir(d, 0o700)
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            uid, gid = workspace_owner(root)
            os.chown(d, uid, gid, follow_symlinks=False)
    except FileExistsError:
        pass
    try:
        return os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise PermissionError(f"refusing unsafe whyfs state directory {d}: {exc}") from exc


def open_state_file(root: Path, name: str, flags: int) -> int:
    """Open a state file by name inside ``.whyfs`` with O_NOFOLLOW, mode 0600,
    owned by the workspace owner when created by root."""
    dfd = open_state_dirfd(root)
    try:
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        if os.geteuid() == 0:
            uid, gid = workspace_owner(root)
            st = os.fstat(fd)
            if st.st_nlink > 1:  # a hard link to someone else's file
                os.close(fd)
                raise PermissionError(f"refusing hard-linked whyfs state file {name}")
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o600)
        return fd
    finally:
        os.close(dfd)


def replace_state_file(root: Path, name: str, data: bytes) -> None:
    tmp = name + ".tmp"
    fd = open_state_file(root, tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    dfd = open_state_dirfd(root)
    try:
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)  # rename never follows links
    finally:
        os.close(dfd)


# --------------------------------------------------------------- store proxy
def _begin_run(con, run_id: str, started: int, root: str) -> int:
    con.execute(
        "INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
        (run_id, started, root, "whyfs daemon", root, "ebpf-bcc"),
    )
    con.commit()
    return 1


def _end_run(con, run_id: str, ended: int, exit_code: int, stats: dict) -> int:
    con.execute("UPDATE runs SET ended_ns=?,exit_code=? WHERE id=?", (ended, exit_code, run_id))
    for key, value in stats.items():
        set_collector_stat(con, run_id, key, int(value))
    con.commit()
    return 1


_OPS = {
    "ingest": lambda con, events: ingest_events(con, events),
    "begin_run": _begin_run,
    "end_run": _end_run,
}


def _read_exact(fd: int, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = os.read(fd, n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return bytes(buf)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _serve(root: Path, rfd: int, wfd: int) -> None:
    con = connect(root)
    try:
        while True:
            try:
                (n,) = struct.unpack("!Q", _read_exact(rfd, 8))
            except EOFError:
                return
            op, args = pickle.loads(_read_exact(rfd, n))  # sent by our root parent
            try:
                result, ok = int(_OPS[op](con, *args)), 1
            except Exception:
                traceback.print_exc(file=sys.stderr)
                result, ok = 0, 0
            _write_all(wfd, struct.pack("!qB", result, ok))
    finally:
        con.close()


def _adopt_state_dir(root: Path, uid: int, gid: int) -> None:
    """Hand a state directory left behind by an earlier root run (and its
    regular files) to the workspace owner, so the unprivileged store worker
    can use it.  Nothing is followed: symlinks and hard links are skipped."""
    dfd = open_state_dirfd(root)
    try:
        os.fchown(dfd, uid, gid)
        os.fchmod(dfd, 0o700)
        for name in os.listdir(dfd):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
            except OSError:
                continue  # a symlink (ELOOP) or vanished
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
                    os.fchown(fd, uid, gid)
                    os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
    finally:
        os.close(dfd)


class Store:
    """SQLite access for the daemon: in-process, or in a child running as the
    workspace owner when the daemon is root (see module docstring)."""

    def __init__(self, root: Path):
        self.root = root
        self.lock = threading.Lock()
        self.pid: int | None = None
        self._con = None
        self.privsep = needs_privsep(root)

    def start(self) -> "Store":
        if not self.privsep:
            self._con = connect(self.root)
            return self
        uid, gid = workspace_owner(self.root)
        _adopt_state_dir(self.root, uid, gid)
        req_r, req_w = os.pipe()
        rep_r, rep_w = os.pipe()
        pid = os.fork()
        if pid == 0:  # child: drop privileges for good, then serve
            code = 1
            try:
                os.close(req_w)
                os.close(rep_r)
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
                if os.getuid() != uid or os.geteuid() != uid:
                    raise PermissionError("privilege drop failed")
                os.umask(0o077)
                _serve(self.root, req_r, rep_w)
                code = 0
            except BaseException:
                traceback.print_exc(file=sys.stderr)
            finally:
                os._exit(code)
        os.close(req_r)
        os.close(rep_w)
        self.pid, self._w, self._r = pid, req_w, rep_r
        return self

    def call(self, op: str, *args) -> int:
        with self.lock:
            if not self.privsep:
                return int(_OPS[op](self._con, *args))
            payload = pickle.dumps((op, args), protocol=pickle.HIGHEST_PROTOCOL)
            _write_all(self._w, struct.pack("!Q", len(payload)) + payload)
            result, ok = struct.unpack("!qB", _read_exact(self._r, 9))
            if not ok:
                raise RuntimeError(f"whyfs store worker failed on {op}")
            return result

    def ingest(self, events: list[dict]) -> int:
        return self.call("ingest", events)

    def close(self) -> None:
        with self.lock:
            if self.privsep and self.pid:
                os.close(self._w)
                os.close(self._r)
                os.waitpid(self.pid, 0)
                self.pid = None
            elif self._con is not None:
                self._con.close()
                self._con = None
