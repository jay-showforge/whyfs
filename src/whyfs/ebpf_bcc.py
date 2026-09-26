from __future__ import annotations

"""Optional BCC/eBPF capture backend for whyfs.

This backend is intentionally isolated from the query/store layer. Importing this
module does not require BCC; BCC is imported only when ``BCCCollector.start`` is
called.  That lets the normal CLI, tests, and v0.1 LD_PRELOAD fallback work on
machines without an eBPF toolchain.

The kernel side emits compact events through a BPF ring buffer.  User space
resolves file descriptors to canonical paths and batches the normalized events
into SQLite.  The BPF program emits only the first read/write observation per
(open file descriptor, process, direction) and clears that state on close,
which prevents one event per read(2)/write(2) syscall.
"""

import ctypes as ct
import os
import queue
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .store import connect, ingest_events, normalize

AT_FDCWD = -100

# Keep these synchronized with the C enum in BPF_SOURCE.
EV_OPEN = 1
EV_READ = 2
EV_WRITE = 3
EV_RENAME = 4
EV_UNLINK = 5
EV_EXEC = 6
EV_FORK = 7
EV_EXIT = 8
EV_MMAP_READ = 9


BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define PATH_N 256
#define AT_FDCWD_VALUE -100

enum event_type {
    EV_OPEN = 1,
    EV_READ = 2,
    EV_WRITE = 3,
    EV_RENAME = 4,
    EV_UNLINK = 5,
    EV_EXEC = 6,
    EV_FORK = 7,
    EV_EXIT = 8,
    EV_MMAP_READ = 9,
};

struct event_t {
    u64 ts_ns;
    u32 tgid;
    u32 tid;
    u32 aux_pid;
    s32 fd;
    s32 dirfd;
    s32 dirfd2;
    u32 flags;
    u32 type;
    u32 truncated;
    char comm[TASK_COMM_LEN];
    char path[PATH_N];
    char path2[PATH_N];
};

struct pending_open_t {
    s32 dirfd;
    u32 flags;
    u32 truncated;
    char path[PATH_N];
};

struct pending_rename_t {
    s32 dirfd;
    s32 dirfd2;
    u32 truncated;
    char path[PATH_N];
    char path2[PATH_N];
};

struct pending_unlink_t {
    s32 dirfd;
    u32 truncated;
    char path[PATH_N];
};

struct io_key_t {
    u32 tgid;
    s32 fd;
    u8 direction; /* 1=read, 2=write */
};

BPF_HASH(pending_open, u64, struct pending_open_t);
BPF_HASH(pending_rename, u64, struct pending_rename_t);
BPF_HASH(pending_unlink, u64, struct pending_unlink_t);
BPF_HASH(io_seen, struct io_key_t, u8);
BPF_ARRAY(drop_count, u64, 1);
BPF_RINGBUF_OUTPUT(events, 256);

static __always_inline void ident(struct event_t *e) {
    u64 id = bpf_get_current_pid_tgid();
    e->tgid = id >> 32;
    e->tid = (u32)id;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int submit(struct event_t *e) {
    int rc = events.ringbuf_output(e, sizeof(*e), 0);
    if (rc) {
        u32 k = 0;
        u64 *v = drop_count.lookup(&k);
        if (v) __sync_fetch_and_add(v, 1);
    }
    return 0;
}

static __always_inline int read_user_path(char dst[PATH_N], const char *src, u32 *trunc) {
    int n = bpf_probe_read_user_str(dst, PATH_N, src);
    if (n == PATH_N) *trunc = 1;
    return n;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_open_t p = {};
    p.dirfd = args->dfd;
    p.flags = args->flags;
    read_user_path(p.path, (const char *)args->filename, &p.truncated);
    pending_open.update(&id, &p);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_open_t *p = pending_open.lookup(&id);
    if (!p) return 0;
    if (args->ret >= 0) {
        struct event_t e = {};
        ident(&e);
        e.type = EV_OPEN;
        e.fd = args->ret;
        e.dirfd = p->dirfd;
        e.flags = p->flags;
        e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        submit(&e);
    }
    pending_open.delete(&id);
    return 0;
}

static __always_inline int emit_io(s32 fd, u8 direction, u32 type) {
    if (fd < 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct io_key_t key = {.tgid = id >> 32, .fd = fd, .direction = direction};
    u8 one = 1;
    u8 *old = io_seen.lookup(&key);
    if (old) return 0;
    io_seen.update(&key, &one);
    struct event_t e = {};
    ident(&e);
    e.type = type;
    e.fd = fd;
    return submit(&e);
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) { return emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_pread64) { return emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_readv) { return emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_write) { return emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) { return emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_writev) { return emit_io(args->fd, 2, EV_WRITE); }

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    if (args->fd >= 0) return emit_io(args->fd, 1, EV_MMAP_READ);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 id = bpf_get_current_pid_tgid();
    struct io_key_t r = {.tgid = id >> 32, .fd = args->fd, .direction = 1};
    struct io_key_t w = {.tgid = id >> 32, .fd = args->fd, .direction = 2};
    io_seen.delete(&r);
    io_seen.delete(&w);
    return 0;
}

/* Successful rename-family syscalls.  One thread cannot nest these syscalls,
 * so a single pending slot keyed by pid_tgid is sufficient. */
TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t p = {};
    p.dirfd = AT_FDCWD_VALUE; p.dirfd2 = AT_FDCWD_VALUE;
    read_user_path(p.path, (const char *)args->oldname, &p.truncated);
    read_user_path(p.path2, (const char *)args->newname, &p.truncated);
    pending_rename.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_rename) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t *p = pending_rename.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t e = {}; ident(&e); e.type = EV_RENAME;
        e.dirfd = p->dirfd; e.dirfd2 = p->dirfd2; e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        __builtin_memcpy(e.path2, p->path2, PATH_N);
        submit(&e);
    }
    pending_rename.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t p = {};
    p.dirfd = args->olddfd; p.dirfd2 = args->newdfd;
    read_user_path(p.path, (const char *)args->oldname, &p.truncated);
    read_user_path(p.path2, (const char *)args->newname, &p.truncated);
    pending_rename.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_renameat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t *p = pending_rename.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t e = {}; ident(&e); e.type = EV_RENAME;
        e.dirfd = p->dirfd; e.dirfd2 = p->dirfd2; e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        __builtin_memcpy(e.path2, p->path2, PATH_N);
        submit(&e);
    }
    pending_rename.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t p = {};
    p.dirfd = args->olddfd;
    p.dirfd2 = args->newdfd;
    read_user_path(p.path, (const char *)args->oldname, &p.truncated);
    read_user_path(p.path2, (const char *)args->newname, &p.truncated);
    pending_rename.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_rename_t *p = pending_rename.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t e = {};
        ident(&e); e.type = EV_RENAME;
        e.dirfd = p->dirfd; e.dirfd2 = p->dirfd2; e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        __builtin_memcpy(e.path2, p->path2, PATH_N);
        submit(&e);
    }
    pending_rename.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_unlink_t p = {};
    p.dirfd = AT_FDCWD_VALUE;
    read_user_path(p.path, (const char *)args->pathname, &p.truncated);
    pending_unlink.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_unlink) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_unlink_t *p = pending_unlink.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t e = {}; ident(&e); e.type = EV_UNLINK; e.dirfd = p->dirfd; e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        submit(&e);
    }
    pending_unlink.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_unlink_t p = {};
    p.dirfd = args->dfd;
    read_user_path(p.path, (const char *)args->pathname, &p.truncated);
    pending_unlink.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_unlink_t *p = pending_unlink.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t e = {};
        ident(&e); e.type = EV_UNLINK; e.dirfd = p->dirfd; e.truncated = p->truncated;
        __builtin_memcpy(e.path, p->path, PATH_N);
        submit(&e);
    }
    pending_unlink.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t e = {};
    ident(&e); e.type = EV_EXEC;
    /* User space resolves /proc/<tgid>/exe and cmdline.  Avoid depending on
     * sched_process_exec's __data_loc filename layout here. */
    return submit(&e);
}

TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct event_t e = {};
    e.ts_ns = bpf_ktime_get_ns();
    e.type = EV_FORK;
    e.tgid = args->child_pid;
    e.tid = args->child_pid;
    e.aux_pid = args->parent_pid;
    __builtin_memcpy(e.comm, args->child_comm, TASK_COMM_LEN);
    return submit(&e);
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    struct event_t e = {};
    ident(&e); e.type = EV_EXIT;
    return submit(&e);
}
"""


class KernelEvent(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("tgid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("aux_pid", ct.c_uint32),
        ("fd", ct.c_int32),
        ("dirfd", ct.c_int32),
        ("dirfd2", ct.c_int32),
        ("flags", ct.c_uint32),
        ("type", ct.c_uint32),
        ("truncated", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("path", ct.c_char * 256),
        ("path2", ct.c_char * 256),
    ]


def _bytestr(v: bytes | ct.Array) -> str:
    raw = bytes(v)
    return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")


def _safe_proc_link(pid: int, item: str) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/{item}")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _proc_cmdline(pid: int) -> list[str]:
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        return []
    return [p.decode("utf-8", "replace") for p in data.split(b"\0") if p]


def _proc_ppid(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split(":", 1)[1].strip())
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        pass
    return None


def _redact_cmdline(argv: list[str]) -> str:
    # Duplicated lightly here to keep the collector independent of argparse/CLI.
    import shlex

    sensitive = ("password", "passwd", "token", "secret", "api-key", "apikey", "authorization")
    out: list[str] = []
    secret_next = False
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


def _resolve_raw(pid: int, dirfd: int, raw: str) -> str | None:
    if not raw:
        return None
    if raw.startswith("/"):
        return os.path.realpath(os.path.normpath(raw))
    if dirfd == AT_FDCWD:
        base = _safe_proc_link(pid, "cwd")
    else:
        base = _safe_proc_link(pid, f"fd/{dirfd}")
    if not base:
        return None
    return os.path.realpath(os.path.normpath(os.path.join(base, raw)))


def _resolve_fd(pid: int, fd: int) -> str | None:
    p = _safe_proc_link(pid, f"fd/{fd}")
    if not p:
        return None
    if p.endswith(" (deleted)"):
        p = p[: -len(" (deleted)")]
    if not p.startswith("/"):
        return None
    return os.path.realpath(os.path.normpath(p))


def _within(path: str | None, root: Path, capture_all: bool) -> bool:
    if not path:
        return False
    if capture_all:
        return True
    try:
        return os.path.commonpath((path, str(root))) == str(root)
    except ValueError:
        return False


@dataclass
class CollectorStats:
    submitted: int = 0
    filtered: int = 0
    unresolved_fd: int = 0
    truncated_paths: int = 0
    kernel_drops: int = 0


class BatchWriter(threading.Thread):
    """Single SQLite writer so capture callbacks never block on a commit."""

    def __init__(self, root: Path, q: "queue.Queue[dict | None]", batch_size: int = 512, flush_ms: int = 100):
        super().__init__(name="whyfs-sqlite-writer", daemon=True)
        self.root = root
        self.q = q
        self.batch_size = batch_size
        self.flush_s = flush_ms / 1000.0
        self.written = 0
        self.error: BaseException | None = None

    def run(self) -> None:
        con = connect(self.root)
        batch: list[dict] = []
        deadline = time.monotonic() + self.flush_s
        try:
            while True:
                timeout = max(0.0, deadline - time.monotonic())
                try:
                    item = self.q.get(timeout=timeout)
                except queue.Empty:
                    item = ...
                if item is None:
                    if batch:
                        self.written += ingest_events(con, batch)
                    return
                if item is not ...:
                    batch.append(item)
                if len(batch) >= self.batch_size or time.monotonic() >= deadline:
                    if batch:
                        self.written += ingest_events(con, batch)
                        batch.clear()
                    deadline = time.monotonic() + self.flush_s
        except BaseException as exc:  # surfaced by collector.stop()
            self.error = exc
        finally:
            con.close()


class BCCUnavailable(RuntimeError):
    pass


class BCCCollector:
    """System-wide Linux provenance collector backed by BCC/eBPF.

    The collector is intentionally a foreground primitive.  ``whyfs daemon``
    owns lifecycle/pidfile semantics around it.
    """

    def __init__(self, root: Path, run_id: str, *, capture_all: bool = False):
        self.root = root.resolve()
        self.run_id = run_id
        self.capture_all = capture_all
        self.stats = CollectorStats()
        self.fd_paths: dict[tuple[int, int], str] = {}
        self.q: "queue.Queue[dict | None]" = queue.Queue(maxsize=65536)
        self.writer = BatchWriter(self.root, self.q)
        self.bpf = None
        self._stopped = False

    def _put(self, event: dict) -> None:
        try:
            self.q.put_nowait(event)
            self.stats.submitted += 1
        except queue.Full:
            # Do not backpressure the observed workload.  We count the loss and
            # make it visible in status; evidence is never silently invented.
            self.stats.kernel_drops += 1

    def _process_event(self, _ctx, data, size) -> None:
        if size < ct.sizeof(KernelEvent):
            return
        e = ct.cast(data, ct.POINTER(KernelEvent)).contents
        pid = int(e.tgid)
        typ = int(e.type)
        ts = int(e.ts_ns)
        if e.truncated:
            self.stats.truncated_paths += 1

        if typ == EV_FORK:
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "process",
                "pid": pid,
                "ppid": int(e.aux_pid),
                "exe": None,
                "cwd": _safe_proc_link(pid, "cwd"),
                "command": None,
                "source": "ebpf",
            })
            return

        if typ == EV_EXEC:
            exe = _safe_proc_link(pid, "exe") or _bytestr(e.path) or None
            argv = _proc_cmdline(pid)
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "process",
                "pid": pid,
                "ppid": _proc_ppid(pid),
                "exe": exe,
                "cwd": _safe_proc_link(pid, "cwd"),
                "command": _redact_cmdline(argv) if argv else exe,
                "source": "ebpf",
            })
            return

        if typ == EV_EXIT:
            # PID reuse cannot inherit stale descriptor lineage.
            stale = [k for k in self.fd_paths if k[0] == pid]
            for k in stale:
                self.fd_paths.pop(k, None)
            return

        if typ == EV_OPEN:
            raw = _bytestr(e.path)
            path = _resolve_fd(pid, int(e.fd)) or _resolve_raw(pid, int(e.dirfd), raw)
            if path:
                self.fd_paths[(pid, int(e.fd))] = path
            if not _within(path, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            # Open itself is evidence of access intent.  Actual read/write
            # events below are what query.py treats as causal I/O.
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "open",
                "pid": pid,
                "ppid": _proc_ppid(pid),
                "path": path,
                "read": False,
                "write": False,
                "flags": int(e.flags),
                "api": "ebpf:openat",
                "source": "ebpf",
            })
            return

        if typ in (EV_READ, EV_MMAP_READ, EV_WRITE):
            path = self.fd_paths.get((pid, int(e.fd))) or _resolve_fd(pid, int(e.fd))
            if not path:
                self.stats.unresolved_fd += 1
                return
            self.fd_paths[(pid, int(e.fd))] = path
            if not _within(path, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "io",
                "pid": pid,
                "ppid": _proc_ppid(pid),
                "path": path,
                "read": typ in (EV_READ, EV_MMAP_READ),
                "write": typ == EV_WRITE,
                "api": "ebpf:mmap" if typ == EV_MMAP_READ else "ebpf:rw",
                "source": "ebpf",
            })
            return

        if typ == EV_RENAME:
            a = _resolve_raw(pid, int(e.dirfd), _bytestr(e.path))
            b = _resolve_raw(pid, int(e.dirfd2), _bytestr(e.path2))
            if not (self.capture_all or _within(a, self.root, False) or _within(b, self.root, False)):
                self.stats.filtered += 1
                return
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "rename",
                "pid": pid,
                "ppid": _proc_ppid(pid),
                "path": a,
                "path2": b,
                "api": "ebpf:renameat2",
                "source": "ebpf",
            })
            return

        if typ == EV_UNLINK:
            a = _resolve_raw(pid, int(e.dirfd), _bytestr(e.path))
            if not _within(a, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            self._put({
                "run_id": self.run_id,
                "ts_ns": ts,
                "kind": "unlink",
                "pid": pid,
                "ppid": _proc_ppid(pid),
                "path": a,
                "api": "ebpf:unlinkat",
                "source": "ebpf",
            })

    def start(self) -> None:
        try:
            from bcc import BPF  # type: ignore
        except Exception as exc:
            raise BCCUnavailable(
                "BCC is not installed. On Debian/Ubuntu install bpfcc-tools, "
                "python3-bpfcc, clang and matching kernel headers."
            ) from exc

        self.writer.start()
        try:
            self.bpf = BPF(text=BPF_SOURCE)
            self.bpf["events"].open_ring_buffer(self._process_event)
        except BaseException:
            self.q.put(None)
            self.writer.join(timeout=2)
            raise

    def poll(self, timeout_ms: int = 100) -> None:
        if self.bpf is None:
            raise RuntimeError("collector not started")
        self.bpf.ring_buffer_poll(timeout_ms)

    def kernel_drop_count(self) -> int:
        if self.bpf is None:
            return 0
        try:
            table = self.bpf["drop_count"]
            return int(table[ct.c_int(0)].value)
        except Exception:
            return 0

    def stop(self) -> CollectorStats:
        if self._stopped:
            return self.stats
        self._stopped = True
        self.stats.kernel_drops += self.kernel_drop_count()
        self.q.put(None)
        self.writer.join(timeout=10)
        if self.writer.is_alive():
            raise RuntimeError("whyfs SQLite writer did not stop cleanly")
        if self.writer.error:
            raise RuntimeError("whyfs SQLite writer failed") from self.writer.error
        return self.stats


def install_signal_stop(stop_event: threading.Event) -> None:
    def handler(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
