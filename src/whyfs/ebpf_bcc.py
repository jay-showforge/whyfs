from __future__ import annotations

"""Optional BCC/eBPF capture backend for whyfs.

This backend is intentionally isolated from the query/store layer. Importing this
module does not require BCC; BCC is imported only when ``BCCCollector.start`` is
called.  That lets the normal CLI, tests, and v0.1 LD_PRELOAD fallback work on
machines without an eBPF toolchain.

Kernel side (BCC, BTF fentry/fexit + tracepoints) -> BPF ring buffer:

* File access is observed at the VFS/LSM layer, not per syscall.  Every file
  open -- read(2)/write(2) family, io_uring (libuv/Node >= 1.45 route async fs
  through io_uring by default), sendfile/copy_file_range/splice -- passes
  ``security_file_open`` and ``security_file_permission``; mmap passes
  ``security_mmap_file``.  Syscall tracepoints are blind to io_uring.
* The absolute path of an opened file is resolved *in the kernel* with
  ``bpf_d_path`` and keyed by the kernel ``struct file *``; reads and writes
  carry only that pointer.  No user-space fd table, no /proc/<pid>/fd races.
* Rename/unlink are observed in ``do_renameat2``/``do_unlinkat`` (shared by the
  syscalls and io_uring), with success taken from the fexit return value.
* Process identity (exec filename, argv, parent) is captured in the kernel at
  exec time, so short-lived processes are attributed after they exit.
* PIDs are reported in the collector's PID namespace (WSL2/containers); tasks
  in other namespaces (e.g. other WSL distributions) are not recorded.
* Records are built directly inside ring-buffer reservations (never on the
  512-byte BPF stack).  Reservation failures are counted, never hidden.

User space replays the ordered stream (cwd model for relative rename/unlink/exec
names, file-pointer -> path map) and batches normalized events into SQLite on a
single writer thread so the observed workload is never blocked on a commit.

Each observed process instance receives a per-run key (``pid`` column); the real
namespace pid is kept in ``os_pid``.  A re-used PID never merges two processes.
"""

import ctypes as ct
import os
import queue
import signal
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from .store import connect, ingest_events

AT_FDCWD = -100
O_CLOEXEC = 0o2000000
PID_BITS = 22  # pid_max never exceeds 2**22 on Linux
PATH_N = 512

# Keep these synchronized with the C enum in BPF_SOURCE.
EV_OPEN = 1        # file opened: kernel file pointer + absolute path (bpf_d_path)
EV_READ = 2        # first read of an open file by a process
EV_WRITE = 3       # first write of an open file by a process
EV_RENAME = 4
EV_UNLINK = 5
EV_EXEC = 6
EV_FORK = 7
EV_EXIT = 8
EV_MMAP_READ = 9
EV_CHDIR = 13
EV_FCHDIR = 14
EV_MMAP_WRITE = 15

TRUNC_TOO_LONG = 1
TRUNC_UNREADABLE = 2


BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#define PATH_N 512
#define AT_FDCWD_VALUE -100
#define WF_MAY_WRITE 0x2
#define WF_MAY_READ 0x4
#define WF_PROT_WRITE 0x2
#define WF_MAP_SHARED 0x1
#define WF_ENAMETOOLONG 36
#define WF_MAX_NS_LEVELS 8

enum event_type {
    EV_OPEN = 1, EV_READ = 2, EV_WRITE = 3, EV_RENAME = 4, EV_UNLINK = 5,
    EV_EXEC = 6, EV_FORK = 7, EV_EXIT = 8, EV_MMAP_READ = 9,
    EV_CHDIR = 13, EV_FCHDIR = 14, EV_MMAP_WRITE = 15,
};

/* Common 80-byte header; path-bearing records append 1 or 2 PATH_N buffers. */
struct hdr_t {
    u64 ts_ns;
    u64 file;      /* struct file * (open/io/mmap/fchdir) or dirfd file (rename/unlink) */
    u64 file2;     /* second dirfd file (rename) */
    u32 tgid;      /* thread-group id in the collector's PID namespace */
    u32 tid;       /* root-namespace thread id (informational) */
    u32 aux_pid;   /* parent tgid (fork/exec), namespace-relative */
    u32 type;
    s32 fd;        /* open: 1 if directory; exec: argv length */
    s32 dirfd;
    s32 dirfd2;
    u32 flags;
    u32 truncated; /* bit0: path too long, bit1: path unreadable */
    u32 ino;       /* low 32 bits of the inode number (diagnostic) */
    char comm[TASK_COMM_LEN];
};
struct path_ev { struct hdr_t h; char path[PATH_N]; };
struct path2_ev { struct hdr_t h; char path[PATH_N]; char path2[PATH_N]; };

struct io_key_t { u64 file; u64 ino; u32 tgid; u32 dir; };

struct pend_rename_t { u64 f1; u64 f2; s32 d1; s32 d2; u32 trunc; u32 pad; char a[PATH_N]; char b[PATH_N]; };
struct pend_unlink_t { u64 f1; s32 d1; u32 trunc; char a[PATH_N]; };

BPF_TABLE("lru_hash", struct io_key_t, u8, io_seen, 262144);
BPF_HASH(pending_rename, u64, struct pend_rename_t, 4096);
BPF_HASH(pending_unlink, u64, struct pend_unlink_t, 4096);
BPF_HASH(pending_chdir, u64, u64, 4096);
BPF_HASH(pending_fchdir, u64, s32, 4096);
BPF_PERCPU_ARRAY(scratch_rename, struct pend_rename_t, 1);
BPF_PERCPU_ARRAY(scratch_unlink, struct pend_unlink_t, 1);
BPF_ARRAY(drop_count, u64, 1);
BPF_RINGBUF_OUTPUT(events, 4096);

static __always_inline void wf_count_drop(void) {
    u32 k = 0;
    u64 *v = drop_count.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
}

/* PIDs are reported in the collector's PID namespace, identified by inode
 * (NS_INUM).  bpf_get_current_pid_tgid() returns root-namespace ids, which on
 * WSL2 and in containers differ from what the user (and /proc in user space)
 * sees.  The level cannot be learned reliably from user space (NSpid lists only
 * levels visible from the /proc mount), so the task's upid chain is searched. */
static __always_inline u32 wf_task_ns_tgid(struct task_struct *t) {
    struct task_struct *leader = 0;
    struct pid *p = 0;
    unsigned int level = 0;
    if (!t) return 0;
    bpf_probe_read_kernel(&leader, sizeof(leader), &t->group_leader);
    if (!leader) return 0;
    bpf_probe_read_kernel(&p, sizeof(p), &leader->thread_pid);
    if (!p) return 0;
    bpf_probe_read_kernel(&level, sizeof(level), &p->level);
#pragma unroll
    for (int i = 0; i < WF_MAX_NS_LEVELS; i++) {
        if (i > level) break;
        struct upid up = {};
        struct pid_namespace *ns = 0;
        unsigned int inum = 0;
        bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[i]);
        ns = up.ns;
        if (!ns) continue;
        bpf_probe_read_kernel(&inum, sizeof(inum), &ns->ns.inum);
        if (inum == NS_INUM) return up.nr;
    }
    return 0;
}

static __always_inline u32 wf_cur_tgid(void) {
    return wf_task_ns_tgid((struct task_struct *)bpf_get_current_task());
}

static __always_inline void wf_hdr(struct hdr_t *h, u32 tgid, u32 type) {
    h->ts_ns = bpf_ktime_get_ns();
    h->tgid = tgid;
    h->tid = (u32)bpf_get_current_pid_tgid();
    h->aux_pid = 0; h->type = type; h->fd = -1;
    h->dirfd = AT_FDCWD_VALUE; h->dirfd2 = AT_FDCWD_VALUE;
    h->flags = 0; h->truncated = 0; h->ino = 0; h->file = 0; h->file2 = 0;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

/* struct file * behind descriptor fd of the current task (0 if none). */
static __always_inline u64 wf_fd_file(s32 fd) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = 0;
    struct fdtable *fdt = 0;
    struct file **fda = 0;
    struct file *f = 0;
    unsigned int max = 0;
    if (fd < 0) return 0;
    bpf_probe_read_kernel(&files, sizeof(files), &t->files);
    if (!files) return 0;
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) return 0;
    bpf_probe_read_kernel(&max, sizeof(max), &fdt->max_fds);
    if ((unsigned int)fd >= max) return 0;
    bpf_probe_read_kernel(&fda, sizeof(fda), &fdt->fd);
    if (!fda) return 0;
    bpf_probe_read_kernel(&f, sizeof(f), &fda[fd]);
    return (u64)f;
}

static __always_inline void wf_read_kstr(char *dst, const char *src, u32 *trunc) {
    int n = bpf_probe_read_kernel_str(dst, PATH_N, src);
    if (n == PATH_N) *trunc |= 1;
    if (n < 0) { dst[0] = 0; *trunc |= 2; }
}

static __always_inline void wf_read_ustr(char *dst, u64 src, u32 *trunc) {
    int n = bpf_probe_read_user_str(dst, PATH_N, (const void *)src);
    if (n == PATH_N) *trunc |= 1;
    if (n < 0) { dst[0] = 0; *trunc |= 2; }
}

/* ---------------- file open: absolute path resolved in the kernel ---------------- */
KFUNC_PROBE(security_file_open, struct file *file) {
    struct inode *inode = file->f_inode;
    if (!inode) return 0;
    umode_t mode = inode->i_mode;
    if (!S_ISREG(mode) && !S_ISDIR(mode)) return 0;
    u32 tgid = wf_cur_tgid();
    if (!tgid) return 0;
    u64 ino = inode->i_ino;
    /* A (re)used struct file starts a new open description: forget old dedup. */
    u32 root_tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_key_t r = {.file = (u64)file, .ino = ino, .tgid = root_tgid, .dir = 1};
    struct io_key_t w = {.file = (u64)file, .ino = ino, .tgid = root_tgid, .dir = 2};
    io_seen.delete(&r);
    io_seen.delete(&w);
    struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
    if (!e) { wf_count_drop(); return 0; }
    wf_hdr(&e->h, tgid, EV_OPEN);
    e->h.file = (u64)file;
    e->h.ino = (u32)ino;
    e->h.flags = file->f_flags;
    e->h.fd = S_ISDIR(mode) ? 1 : 0;
    long n = bpf_d_path(&file->f_path, e->path, PATH_N);
    if (n < 0) { e->path[0] = 0; e->h.truncated = (n == -WF_ENAMETOOLONG) ? 1 : 2; }
    events.ringbuf_submit(e, 0);
    return 0;
}

/* First read/write of an open file by a process (sync syscalls, io_uring,
 * sendfile/splice/copy_file_range all reach rw_verify_area). */
static __always_inline int wf_emit_io(struct file *file, u32 dir, u32 type) {
    struct inode *inode = file->f_inode;
    if (!inode) return 0;
    if (!S_ISREG(inode->i_mode)) return 0;
    u64 ino = inode->i_ino;
    struct io_key_t k = {.file = (u64)file, .ino = ino, .tgid = bpf_get_current_pid_tgid() >> 32, .dir = dir};
    if (io_seen.lookup(&k)) return 0;
    u32 tgid = wf_cur_tgid();
    if (!tgid) return 0;
    u8 one = 1;
    io_seen.update(&k, &one);
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    wf_hdr(e, tgid, type);
    e->file = (u64)file;
    e->ino = (u32)ino;
    events.ringbuf_submit(e, 0);
    return 0;
}

KFUNC_PROBE(security_file_permission, struct file *file, int mask) {
    if (mask & WF_MAY_WRITE) return wf_emit_io(file, 2, EV_WRITE);
    if (mask & WF_MAY_READ) return wf_emit_io(file, 1, EV_READ);
    return 0;
}

KFUNC_PROBE(security_mmap_file, struct file *file, unsigned long prot, unsigned long flags) {
    if (!file) return 0;
    if ((prot & WF_PROT_WRITE) && (flags & WF_MAP_SHARED)) wf_emit_io(file, 2, EV_MMAP_WRITE);
    return wf_emit_io(file, 1, EV_MMAP_READ);
}

/* ---------------- rename / unlink (syscalls and io_uring) ---------------- */
KFUNC_PROBE(do_renameat2, int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags) {
    u32 z = 0;
    struct pend_rename_t *p = scratch_rename.lookup(&z);
    if (!p) return 0;
    const char *a = 0, *b = 0;
    p->trunc = 0;
    p->d1 = olddfd; p->d2 = newdfd;
    p->f1 = olddfd == AT_FDCWD_VALUE ? 0 : wf_fd_file(olddfd);
    p->f2 = newdfd == AT_FDCWD_VALUE ? 0 : wf_fd_file(newdfd);
    bpf_probe_read_kernel(&a, sizeof(a), &from->name);
    bpf_probe_read_kernel(&b, sizeof(b), &to->name);
    wf_read_kstr(p->a, a, &p->trunc);
    wf_read_kstr(p->b, b, &p->trunc);
    u64 id = bpf_get_current_pid_tgid();
    pending_rename.update(&id, p);
    return 0;
}
KRETFUNC_PROBE(do_renameat2, int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pend_rename_t *p = pending_rename.lookup(&id);
    if (!p) return 0;
    if (ret == 0) {
        u32 tgid = wf_cur_tgid();
        if (tgid) {
            struct path2_ev *e = events.ringbuf_reserve(sizeof(struct path2_ev));
            if (e) {
                wf_hdr(&e->h, tgid, EV_RENAME);
                e->h.dirfd = p->d1; e->h.dirfd2 = p->d2; e->h.file = p->f1; e->h.file2 = p->f2;
                e->h.truncated = p->trunc;
                bpf_probe_read_kernel(e->path, PATH_N, p->a);
                bpf_probe_read_kernel(e->path2, PATH_N, p->b);
                events.ringbuf_submit(e, 0);
            } else {
                wf_count_drop();
            }
        }
    }
    pending_rename.delete(&id);
    return 0;
}

KFUNC_PROBE(do_unlinkat, int dfd, struct filename *name) {
    u32 z = 0;
    struct pend_unlink_t *p = scratch_unlink.lookup(&z);
    if (!p) return 0;
    const char *a = 0;
    p->trunc = 0;
    p->d1 = dfd;
    p->f1 = dfd == AT_FDCWD_VALUE ? 0 : wf_fd_file(dfd);
    bpf_probe_read_kernel(&a, sizeof(a), &name->name);
    wf_read_kstr(p->a, a, &p->trunc);
    u64 id = bpf_get_current_pid_tgid();
    pending_unlink.update(&id, p);
    return 0;
}
KRETFUNC_PROBE(do_unlinkat, int dfd, struct filename *name, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pend_unlink_t *p = pending_unlink.lookup(&id);
    if (!p) return 0;
    if (ret == 0) {
        u32 tgid = wf_cur_tgid();
        if (tgid) {
            struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
            if (e) {
                wf_hdr(&e->h, tgid, EV_UNLINK);
                e->h.dirfd = p->d1; e->h.file = p->f1; e->h.truncated = p->trunc;
                bpf_probe_read_kernel(e->path, PATH_N, p->a);
                events.ringbuf_submit(e, 0);
            } else {
                wf_count_drop();
            }
        }
    }
    pending_unlink.delete(&id);
    return 0;
}

/* ---------------- cwd changes (needed for relative rename/unlink/exec names) ---------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
    u64 id = bpf_get_current_pid_tgid();
    u64 uptr = (u64)args->filename;
    pending_chdir.update(&id, &uptr);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
    u64 id = bpf_get_current_pid_tgid();
    u64 *uptr = pending_chdir.lookup(&id);
    if (!uptr) return 0;
    if (args->ret == 0) {
        u32 tgid = wf_cur_tgid();
        if (tgid) {
            struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
            if (e) {
                wf_hdr(&e->h, tgid, EV_CHDIR);
                /* read at exit: getname() has faulted the page in by now */
                wf_read_ustr(e->path, *uptr, &e->h.truncated);
                events.ringbuf_submit(e, 0);
            } else {
                wf_count_drop();
            }
        }
    }
    pending_chdir.delete(&id);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
    u64 id = bpf_get_current_pid_tgid();
    s32 fd = (s32)args->fd;
    pending_fchdir.update(&id, &fd);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
    u64 id = bpf_get_current_pid_tgid();
    s32 *fd = pending_fchdir.lookup(&id);
    if (!fd) return 0;
    if (args->ret == 0) {
        u32 tgid = wf_cur_tgid();
        if (tgid) {
            struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
            if (e) {
                wf_hdr(e, tgid, EV_FCHDIR);
                e->fd = *fd;
                e->file = wf_fd_file(*fd);
                events.ringbuf_submit(e, 0);
            } else {
                wf_count_drop();
            }
        }
    }
    pending_fchdir.delete(&id);
    return 0;
}

/* ---------------- process lifecycle ---------------- */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    u32 tgid = wf_cur_tgid();
    if (!tgid) return 0;
    struct path2_ev *e = events.ringbuf_reserve(sizeof(struct path2_ev));
    if (!e) { wf_count_drop(); return 0; }
    wf_hdr(&e->h, tgid, EV_EXEC);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *rp = 0;
    bpf_probe_read_kernel(&rp, sizeof(rp), &t->real_parent);
    e->h.aux_pid = wf_task_ns_tgid(rp);
    /* Executed file name as passed to execve (resolved against cwd in user space). */
    TP_DATA_LOC_READ_STR(e->path, filename, PATH_N);
    /* argv, NUL separated, captured while the new image is alive. */
    unsigned long as = t->mm->arg_start;
    unsigned long ae = t->mm->arg_end;
    long len = (long)(ae - as);
    if (len > PATH_N - 1) { len = PATH_N - 1; e->h.truncated |= 1; }
    if (len > 0) {
        bpf_probe_read_user(e->path2, len & (PATH_N - 1), (void *)as);
        e->h.fd = (s32)len;
    } else {
        e->h.fd = 0;
    }
    events.ringbuf_submit(e, 0);
    return 0;
}

/* Raw tracepoint so that threads (CLONE_THREAD) can be told apart from new
 * processes: only a child whose pid == tgid is a new thread group. */
RAW_TRACEPOINT_PROBE(sched_process_fork) {
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    u32 cpid = child->pid;
    u32 ctgid = child->tgid;
    if (cpid != ctgid) return 0;
    u32 ns_child = wf_task_ns_tgid(child);
    if (!ns_child) return 0;
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    wf_hdr(e, ns_child, EV_FORK);
    e->tid = cpid;
    e->aux_pid = wf_task_ns_tgid(parent);
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), child->comm);
    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)id != (u32)(id >> 32)) return 0;  /* only the thread-group leader */
    u32 tgid = wf_cur_tgid();
    if (!tgid) return 0;
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    wf_hdr(e, tgid, EV_EXIT);
    events.ringbuf_submit(e, 0);
    return 0;
}
"""


class EventHeader(ct.Structure):
    _fields_ = [
        ("ts_ns", ct.c_uint64),
        ("file", ct.c_uint64),
        ("file2", ct.c_uint64),
        ("tgid", ct.c_uint32),
        ("tid", ct.c_uint32),
        ("aux_pid", ct.c_uint32),
        ("type", ct.c_uint32),
        ("fd", ct.c_int32),
        ("dirfd", ct.c_int32),
        ("dirfd2", ct.c_int32),
        ("flags", ct.c_uint32),
        ("truncated", ct.c_uint32),
        ("ino", ct.c_uint32),
        ("comm", ct.c_char * 16),
    ]


class KernelEvent(ct.Structure):
    """Largest record layout (header + two paths); smaller records share the prefix."""

    _fields_ = EventHeader._fields_ + [
        ("path", ct.c_char * PATH_N),
        ("path2", ct.c_char * PATH_N),
    ]


HDR_SIZE = ct.sizeof(EventHeader)
OFF_PATH = KernelEvent.path.offset
OFF_PATH2 = KernelEvent.path2.offset


def _field_bytes(data: int, size: int, offset: int, n: int = PATH_N) -> bytes:
    """Raw bytes of a path field, bounded by the record size.

    NB: never use bytes() on a ctypes c_char array for these fields -- it stops
    at the first NUL, which silently truncates NUL-separated argv to argv[0].
    """
    avail = size - offset
    if avail <= 0:
        return b""
    return ct.string_at(data + offset, min(n, avail))


def _cstr(b: bytes) -> str:
    return b.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")


def _safe_proc_link(pid: int, item: str) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/{item}")
    except (FileNotFoundError, PermissionError, OSError):
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


def _clean_link(p: str | None) -> str | None:
    if not p:
        return None
    if p.endswith(" (deleted)"):
        p = p[: -len(" (deleted)")]
    if not p.startswith("/"):
        return None  # pipe:[..], socket:[..], anon_inode:...
    return p


def _canon(p: str) -> str:
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
    unresolved_fd: int = 0     # I/O on a file whose open was not observed (opened before the collector)
    truncated_paths: int = 0   # path longer than the kernel buffer
    kernel_drops: int = 0      # BPF ring-buffer reservations that failed
    queue_drops: int = 0       # user-space queue full (workload never blocked)
    received: int = 0          # records consumed from the ring buffer
    proc_fallbacks: int = 0    # cwd lookups that had to consult /proc
    unreadable_paths: int = 0  # path string could not be read


class _BoundedMap(OrderedDict):
    """Insertion-ordered dict that evicts its oldest entries past ``limit``."""

    def __init__(self, limit: int):
        super().__init__()
        self.limit = limit

    def put(self, k, v) -> None:
        self[k] = v
        self.move_to_end(k)
        while len(self) > self.limit:
            self.popitem(last=False)


class BatchWriter(threading.Thread):
    """Single SQLite writer so capture callbacks never block on a commit."""

    def __init__(self, root: Path, q: "queue.Queue[dict | None]", batch_size: int = 512, flush_ms: int = 100):
        super().__init__(name="whyfs-sqlite-writer", daemon=True)
        self.root = root
        self.q = q
        self.batch_size = batch_size
        self.flush_s = flush_ms / 1000.0
        self.written = 0
        self.batches = 0
        self.max_batch = 0
        self.error: BaseException | None = None

    def _flush(self, con, batch: list[dict]) -> None:
        self.written += ingest_events(con, batch)
        self.batches += 1
        self.max_batch = max(self.max_batch, len(batch))
        batch.clear()

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
                        self._flush(con, batch)
                    return
                if item is not ...:
                    batch.append(item)
                if len(batch) >= self.batch_size or time.monotonic() >= deadline:
                    if batch:
                        self._flush(con, batch)
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
        # kernel struct file * -> absolute path (only paths whyfs may need:
        # workspace files, temp-root files, and directories for dirfd names)
        self.files = _BoundedMap(400_000)
        self.cwd: dict[int, str] = {}
        self.image: dict[int, tuple[str | None, str | None]] = {}  # pid -> (exe, command)
        self.pkey: dict[int, int] = {}
        self._seq = 0
        self.q: "queue.Queue[dict | None]" = queue.Queue(maxsize=262144)
        self.writer = BatchWriter(self.root, self.q)
        self.bpf = None
        self.pidns: dict = {}
        self._stopped = False
        # bpf_ktime_get_ns() is CLOCK_MONOTONIC; the store and the preload
        # backend use wall-clock ns.  One offset keeps ordering and makes
        # timestamps human-meaningful.
        self.clock_offset = time.time_ns() - time.monotonic_ns()
        # Derived temporaries: compilers and bundlers route workspace data
        # through temp files (gcc: cc1 -> /tmp/ccXXXX.s -> as).  Such a path is
        # kept, although outside the workspace, only when it was *written by a
        # process that had already read workspace files* and it lives under a
        # temp root; later reads of that exact path are kept too.  This bridges
        # observed lineage without capturing arbitrary out-of-workspace activity.
        self.temp_roots = tuple(sorted({
            _canon(p) for p in ("/tmp", "/var/tmp", "/dev/shm", os.environ.get("TMPDIR") or "/tmp")
        }))
        self._read_workspace: set[int] = set()        # process keys
        self._derived = _BoundedMap(200_000)

    def _is_temp(self, path: str) -> bool:
        return any(_within(path, Path(r), False) for r in self.temp_roots)

    # ---------------------------------------------------------------- identity
    def key(self, pid: int) -> int:
        """Per-run process-instance key.  PIDs that predate the collector keep
        key == pid; every fork observed by the collector gets a fresh key."""
        k = self.pkey.get(pid)
        if k is None:
            k = pid
            self.pkey[pid] = k
            self._announce_existing(pid)
        return k

    def _announce_existing(self, pid: int) -> None:
        exe = _clean_link(_safe_proc_link(pid, "exe"))
        argv = self._proc_cmdline(pid)
        self.image[pid] = (exe, _redact_cmdline(argv) if argv else exe)
        self._put({
            "run_id": self.run_id, "ts_ns": time.time_ns(), "kind": "process",
            "pid": pid, "os_pid": pid, "ppid": None, "parent_key": None,
            "exe": exe, "cwd": self._cwd(pid), "command": self.image[pid][1], "source": "ebpf",
        })

    @staticmethod
    def _proc_cmdline(pid: int) -> list[str]:
        try:
            data = Path(f"/proc/{pid}/cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, OSError):
            return []
        return [p.decode("utf-8", "replace") for p in data.split(b"\0") if p]

    def _cwd(self, pid: int) -> str | None:
        c = self.cwd.get(pid)
        if c is None:
            link = _safe_proc_link(pid, "cwd")
            if link:
                self.stats.proc_fallbacks += 1
                c = _canon(link)
                self.cwd[pid] = c
        return c

    def _resolve(self, pid: int, dirfd: int, dir_file: int, raw: str) -> str | None:
        if not raw:
            return None
        if raw.startswith("/"):
            return _canon(raw)
        base = self._cwd(pid) if dirfd == AT_FDCWD else self.files.get(dir_file)
        if not base:
            return None
        return _canon(os.path.join(base, raw))

    def _keep_path(self, path: str, is_dir: bool) -> bool:
        return is_dir or _within(path, self.root, self.capture_all) or self._is_temp(path)

    # ---------------------------------------------------------------- output
    def _put(self, event: dict) -> None:
        try:
            self.q.put_nowait(event)
            self.stats.submitted += 1
        except queue.Full:
            # Do not backpressure the observed workload.  We count the loss and
            # make it visible in status; evidence is never silently invented.
            self.stats.queue_drops += 1

    def _file_event(self, pid: int, ts: int, kind: str, path: str | None, **extra) -> None:
        self._put({
            "run_id": self.run_id, "ts_ns": ts, "kind": kind,
            "pid": self.key(pid), "os_pid": pid, "path": path, "source": "ebpf", **extra,
        })

    # ---------------------------------------------------------------- events
    def _process_event(self, _ctx, data, size) -> None:
        if size < HDR_SIZE:
            return
        e = ct.cast(data, ct.POINTER(EventHeader)).contents
        self.stats.received += 1
        pid = int(e.tgid)
        typ = int(e.type)
        ts = int(e.ts_ns) + self.clock_offset
        if e.truncated & 1:
            self.stats.truncated_paths += 1
        if e.truncated & 2:
            self.stats.unreadable_paths += 1

        if typ == EV_OPEN:
            path = _cstr(_field_bytes(data, size, OFF_PATH))
            if not path.startswith("/") or e.truncated:
                # Unusable path (too long / unreadable / not reachable from the
                # task's root).  Counted above; never guessed.
                self.files.pop(int(e.file), None)
                self.stats.filtered += 1
                return
            path = os.path.normpath(path)  # kernel d_path is already symlink-free
            is_dir = bool(e.fd == 1)
            if self._keep_path(path, is_dir):
                self.files.put(int(e.file), path)
            else:
                self.files.pop(int(e.file), None)
            if is_dir or not _within(path, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            # Open itself is evidence of access intent.  Actual read/write
            # events below are what query.py treats as causal I/O.
            self._file_event(pid, ts, "open", path, read=False, write=False, flags=int(e.flags), api="ebpf:open")
            return

        if typ in (EV_READ, EV_MMAP_READ, EV_WRITE, EV_MMAP_WRITE):
            path = self.files.get(int(e.file))
            if not path:
                # Either filtered at open (not workspace/temp) or opened before
                # the collector started; the latter is counted separately.
                self.stats.filtered += 1
                return
            is_write = typ in (EV_WRITE, EV_MMAP_WRITE)
            api = "ebpf:mmap" if typ in (EV_MMAP_READ, EV_MMAP_WRITE) else "ebpf:rw"
            if _within(path, self.root, self.capture_all):
                if not is_write and _within(path, self.root, False):
                    self._read_workspace.add(self.key(pid))
                self._file_event(pid, ts, "io", path, read=not is_write, write=is_write, api=api)
                return
            if is_write and self.key(pid) in self._read_workspace and self._is_temp(path):
                self._derived.put(path, None)
                self._file_event(pid, ts, "io", path, read=False, write=True, api=api + ":derived-temp")
                return
            if not is_write and path in self._derived:
                self._read_workspace.add(self.key(pid))  # carries workspace-derived data
                self._file_event(pid, ts, "io", path, read=True, write=False, api=api + ":derived-temp")
                return
            self.stats.filtered += 1
            return

        if typ == EV_FORK:
            parent = int(e.aux_pid)
            self._seq += 1
            child_key = (self._seq << PID_BITS) | pid
            parent_key = self.key(parent) if parent else None
            self.pkey[pid] = child_key
            pc = self._cwd(parent) if parent else None
            if pc:
                self.cwd[pid] = pc
            else:
                self.cwd.pop(pid, None)
            exe, cmd = self.image.get(parent, (None, None))
            self.image[pid] = (exe, cmd)
            self._put({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": child_key, "os_pid": pid, "ppid": parent or None, "parent_key": parent_key,
                "exe": exe, "cwd": self.cwd.get(pid), "command": cmd, "source": "ebpf",
            })
            return

        if typ == EV_EXEC:
            k = self.key(pid)
            filename = _cstr(_field_bytes(data, size, OFF_PATH))
            exe = self._resolve(pid, AT_FDCWD, 0, filename) if filename else None
            if not exe:
                exe = _clean_link(_safe_proc_link(pid, "exe"))
            n = max(0, min(int(e.fd), PATH_N - 1))
            raw_argv = _field_bytes(data, size, OFF_PATH2, n)
            argv = [a.decode("utf-8", "replace") for a in raw_argv.split(b"\0") if a]
            command = _redact_cmdline(argv) if argv else exe
            self.image[pid] = (exe, command)
            ppid = int(e.aux_pid)
            self._put({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": k, "os_pid": pid, "ppid": ppid or None,
                "parent_key": self.pkey.get(ppid, ppid) if ppid else None,
                "exe": exe, "cwd": self._cwd(pid), "command": command, "source": "ebpf",
            })
            # Raw evidence of the image boundary: the query layer attributes a
            # write to the program image that performed it (see query._image_start).
            self._put({
                "run_id": self.run_id, "ts_ns": ts, "kind": "exec", "pid": k, "os_pid": pid,
                "path": exe, "api": "ebpf:exec", "source": "ebpf",
            })
            return

        if typ == EV_EXIT:
            self.cwd.pop(pid, None)
            self.image.pop(pid, None)
            # Keep pkey: late events of this pid still belong to this instance
            # until a new fork re-assigns the pid.
            return

        if typ == EV_CHDIR:
            c = self._resolve(pid, AT_FDCWD, 0, _cstr(_field_bytes(data, size, OFF_PATH)))
            if c:
                self.cwd[pid] = c
            return

        if typ == EV_FCHDIR:
            c = self.files.get(int(e.file))
            if c:
                self.cwd[pid] = c
            else:
                self.cwd.pop(pid, None)  # unknown now; fall back to /proc lazily
            return

        if typ == EV_RENAME:
            a = self._resolve(pid, int(e.dirfd), int(e.file), _cstr(_field_bytes(data, size, OFF_PATH)))
            b = self._resolve(pid, int(e.dirfd2), int(e.file2), _cstr(_field_bytes(data, size, OFF_PATH2)))
            if not (self.capture_all or _within(a, self.root, False) or _within(b, self.root, False)
                    or (a in self._derived)):
                self.stats.filtered += 1
                return
            if a in self._derived and b and self._is_temp(b):
                self._derived.put(b, None)
            # Keep file-pointer paths consistent with the move.
            if a and b:
                for fp, p in list(self.files.items()):
                    if p == a:
                        self.files[fp] = b
                    elif p.startswith(a + os.sep):
                        self.files[fp] = b + p[len(a):]
            self._file_event(pid, ts, "rename", a, path2=b, api="ebpf:rename")
            return

        if typ == EV_UNLINK:
            a = self._resolve(pid, int(e.dirfd), int(e.file), _cstr(_field_bytes(data, size, OFF_PATH)))
            if a in self._derived:
                self._derived.pop(a, None)
                self._file_event(pid, ts, "unlink", a, api="ebpf:unlink:derived-temp")
                return
            if not _within(a, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            self._file_event(pid, ts, "unlink", a, api="ebpf:unlink")

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        try:
            from bcc import BPF  # type: ignore
        except Exception as exc:
            raise BCCUnavailable(
                "BCC is not installed. On Debian/Ubuntu install bpfcc-tools, "
                "python3-bpfcc, clang and matching kernel headers."
            ) from exc
        if not BPF.support_kfunc():
            raise BCCUnavailable(
                "this kernel/BCC lacks BTF fentry (kfunc) support, which whyfs needs to observe "
                "file I/O at the VFS layer (including io_uring)."
            )

        self.writer.start()
        try:
            level, inum = pid_namespace_identity()
            self.pidns = {"level_visible": level, "inum": inum}
            self.bpf = BPF(text=BPF_SOURCE, cflags=[f"-DNS_INUM={inum}U"])
            self.bpf["events"].open_ring_buffer(self._process_event)
        except BaseException:
            self.q.put(None)
            self.writer.join(timeout=2)
            raise

    def poll(self, timeout_ms: int = 100) -> None:
        if self.bpf is None:
            raise RuntimeError("collector not started")
        self.bpf.ring_buffer_poll(timeout_ms)

    def drain(self) -> None:
        """Consume everything already committed to the ring buffer."""
        if self.bpf is None:
            return
        for _ in range(1000):
            before = self.stats.received
            self.bpf.ring_buffer_consume()
            if self.stats.received == before:
                break

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
        self.drain()
        self.stats.kernel_drops += self.kernel_drop_count()
        self.q.put(None)
        self.writer.join(timeout=60)
        if self.writer.is_alive():
            raise RuntimeError("whyfs SQLite writer did not stop cleanly")
        if self.writer.error:
            raise RuntimeError("whyfs SQLite writer failed") from self.writer.error
        return self.stats


def pid_namespace_identity() -> tuple[int, int]:
    """(visible nesting depth, inode) of this process's PID namespace.

    The kernel program identifies the namespace by inode; the depth reported by
    NSpid is informational only (it counts levels visible from the /proc mount).
    """
    level = 0
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("NSpid:"):
            level = len(line.split()[1:]) - 1
            break
    link = os.readlink("/proc/self/ns/pid")  # "pid:[4026531836]"
    inum = int(link[link.index("[") + 1: link.index("]")])
    return level, inum


def install_signal_stop(stop_event: threading.Event) -> None:
    def handler(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
