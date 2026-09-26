from __future__ import annotations

"""Optional BCC/eBPF capture backend for whyfs.

This backend is intentionally isolated from the query/store layer. Importing this
module does not require BCC; BCC is imported only when ``BCCCollector.start`` is
called.  That lets the normal CLI, tests, and v0.1 LD_PRELOAD fallback work on
machines without an eBPF toolchain.

Kernel side: syscall/sched tracepoints emit compact records into a BPF ring
buffer.  Records are built directly inside the ring-buffer reservation (never on
the 512-byte BPF stack), and syscall-entry state is staged through per-CPU
scratch maps.  Process identity (exec filename, argv, parent) is captured *in
the kernel at exec time*, so short-lived processes are attributed correctly even
after they have exited.

User space: a deterministic resolver replays the ordered event stream to
maintain, per process, the current working directory and the fd -> path table
(open / dup / close / close_range / O_CLOEXEC-at-exec / fork inheritance).
``/proc`` is only a fallback for processes that predate the collector, because
by the time an event is processed the observed process may have exited or
re-used the descriptor.  Normalized events are batched into SQLite by a single
writer thread so the observed workload is never blocked on a commit.

Each observed process instance receives a per-run key (``pid`` column); the real
OS pid is kept in ``os_pid``.  A re-used PID therefore never merges two
processes' lineage.
"""

import ctypes as ct
import os
import queue
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .store import connect, ingest_events

AT_FDCWD = -100
O_CLOEXEC = 0o2000000
O_CREAT_WRONLY_TRUNC = 0o100 | 0o1 | 0o1000  # creat(2) semantics
PID_BITS = 22  # pid_max never exceeds 2**22 on Linux

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
EV_DUP = 10
EV_CLOSE = 11
EV_CLOSE_RANGE = 12
EV_CHDIR = 13
EV_FCHDIR = 14
EV_MMAP_WRITE = 15


BPF_SOURCE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#define PATH_N 256
#define AT_FDCWD_VALUE -100
#define PROT_WRITE_V 0x2
#define MAP_SHARED_V 0x01
#define F_DUPFD_V 0
#define F_DUPFD_CLOEXEC_V 1030
#define O_CLOEXEC_V 02000000
#define CREAT_FLAGS (0100 | 01 | 01000)

enum event_type {
    EV_OPEN = 1, EV_READ = 2, EV_WRITE = 3, EV_RENAME = 4, EV_UNLINK = 5,
    EV_EXEC = 6, EV_FORK = 7, EV_EXIT = 8, EV_MMAP_READ = 9, EV_DUP = 10,
    EV_CLOSE = 11, EV_CLOSE_RANGE = 12, EV_CHDIR = 13, EV_FCHDIR = 14,
    EV_MMAP_WRITE = 15,
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

/* Syscall-entry state.  Only the *user pointers* are staged: path strings are
 * read at syscall exit, after the kernel's own getname() has faulted the page
 * in.  Reading at entry fails (silently, EFAULT) for strings on not-yet-touched
 * pages, e.g. .rodata literals of a freshly exec'd short-lived binary. */
struct pending_t {
    u64 uptr;
    u64 uptr2;
    s32 dirfd;
    s32 dirfd2;
    s32 fd;
    u32 flags;
};

struct io_key_t {
    u32 tgid;
    s32 fd;
    u32 direction; /* 1=read, 2=write */
};

BPF_HASH(pending_open, u64, struct pending_t, 16384);
BPF_HASH(pending_rename, u64, struct pending_t, 4096);
BPF_HASH(pending_unlink, u64, struct pending_t, 4096);
BPF_HASH(pending_chdir, u64, struct pending_t, 4096);
BPF_HASH(pending_dup, u64, struct pending_t, 4096);
BPF_HASH(pending_fchdir, u64, s32, 4096);
BPF_TABLE("lru_hash", struct io_key_t, u8, io_seen, 131072);
BPF_ARRAY(drop_count, u64, 1);
BPF_RINGBUF_OUTPUT(events, 4096);

static __always_inline void wf_count_drop(void) {
    u32 k = 0;
    u64 *v = drop_count.lookup(&k);
    if (v) __sync_fetch_and_add(v, 1);
}

/* PIDs are reported in the *collector's* PID namespace, identified by inode
 * (NS_INUM, supplied at load time).  bpf_get_current_pid_tgid() returns
 * root-namespace ids, which on WSL2 and in containers differ from what the user
 * (and /proc in user space) sees.  The nesting level cannot be learned reliably
 * from user space (NSpid only lists levels visible from the /proc mount), so
 * the task's upid chain is searched for the matching namespace.  Tasks outside
 * the collector's namespace -- e.g. other WSL distributions sharing the kernel
 * -- yield 0 and are not recorded. */
#define WF_MAX_NS_LEVELS 8
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

/* Reserve a zero-initialized header; path strings are NUL-terminated at [0]. */
static __always_inline struct event_t *wf_reserve(u32 type) {
    u32 tgid = wf_task_ns_tgid((struct task_struct *)bpf_get_current_task());
    if (!tgid) return 0;  /* not in the collector's PID namespace */
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) { wf_count_drop(); return 0; }
    u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->tgid = tgid;
    e->tid = (u32)id;  /* root-namespace thread id; informational only */
    e->aux_pid = 0; e->fd = -1; e->dirfd = AT_FDCWD_VALUE; e->dirfd2 = AT_FDCWD_VALUE;
    e->flags = 0; e->type = type; e->truncated = 0;
    e->path[0] = 0; e->path2[0] = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline void wf_read_user_path(char *dst, u64 src, u32 *trunc) {
    int n = bpf_probe_read_user_str(dst, PATH_N, (const void *)src);
    if (n == PATH_N) *trunc = 1;
    if (n < 0) { dst[0] = 0; *trunc |= 2; /* 2 = unreadable path */ }
}

static __always_inline void wf_reset_io(u32 tgid, s32 fd) {
    struct io_key_t r = {.tgid = tgid, .fd = fd, .direction = 1};
    struct io_key_t w = {.tgid = tgid, .fd = fd, .direction = 2};
    io_seen.delete(&r);
    io_seen.delete(&w);
}

/* ---------------- open family ---------------- */
static __always_inline int wf_stage_open(s32 dirfd, const char *name, u32 flags) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.uptr = (u64)name; p.dirfd = dirfd; p.flags = flags; p.dirfd2 = AT_FDCWD_VALUE; p.fd = -1;
    pending_open.update(&id, &p);
    return 0;
}

static __always_inline int wf_finish_open(long ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_open.lookup(&id);
    if (!p) return 0;
    if (ret >= 0) {
        wf_reset_io(id >> 32, (s32)ret);
        struct event_t *e = wf_reserve(EV_OPEN);
        if (e) {
            e->fd = (s32)ret; e->dirfd = p->dirfd; e->flags = p->flags;
            wf_read_user_path(e->path, p->uptr, &e->truncated);
            events.ringbuf_submit(e, 0);
        }
    }
    pending_open.delete(&id);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) { return wf_stage_open(args->dfd, (const char *)args->filename, args->flags); }
TRACEPOINT_PROBE(syscalls, sys_exit_openat) { return wf_finish_open(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_open) { return wf_stage_open(AT_FDCWD_VALUE, (const char *)args->filename, args->flags); }
TRACEPOINT_PROBE(syscalls, sys_exit_open) { return wf_finish_open(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_creat) { return wf_stage_open(AT_FDCWD_VALUE, (const char *)args->pathname, CREAT_FLAGS); }
TRACEPOINT_PROBE(syscalls, sys_exit_creat) { return wf_finish_open(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_openat2) {
    u64 fl = 0;
    bpf_probe_read_user(&fl, sizeof(fl), (void *)args->how);
    return wf_stage_open(args->dfd, (const char *)args->filename, (u32)fl);
}
TRACEPOINT_PROBE(syscalls, sys_exit_openat2) { return wf_finish_open(args->ret); }

/* ---------------- first read/write per open description ---------------- */
static __always_inline int wf_emit_io(s32 fd, u32 direction, u32 type) {
    if (fd < 0) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct io_key_t key = {.tgid = id >> 32, .fd = fd, .direction = direction};
    u8 one = 1;
    if (io_seen.lookup(&key)) return 0;
    io_seen.update(&key, &one);
    struct event_t *e = wf_reserve(type);
    if (!e) return 0;
    e->fd = fd;
    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) { return wf_emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_pread64) { return wf_emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_readv) { return wf_emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_preadv) { return wf_emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_preadv2) { return wf_emit_io(args->fd, 1, EV_READ); }
TRACEPOINT_PROBE(syscalls, sys_enter_write) { return wf_emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) { return wf_emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_writev) { return wf_emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_pwritev) { return wf_emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_pwritev2) { return wf_emit_io(args->fd, 2, EV_WRITE); }
TRACEPOINT_PROBE(syscalls, sys_enter_copy_file_range) {
    wf_emit_io(args->fd_in, 1, EV_READ);
    return wf_emit_io(args->fd_out, 2, EV_WRITE);
}
TRACEPOINT_PROBE(syscalls, sys_enter_sendfile64) {
    wf_emit_io(args->in_fd, 1, EV_READ);
    return wf_emit_io(args->out_fd, 2, EV_WRITE);
}
TRACEPOINT_PROBE(syscalls, sys_enter_splice) {
    wf_emit_io(args->fd_in, 1, EV_READ);
    return wf_emit_io(args->fd_out, 2, EV_WRITE);
}

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    s32 fd = (s32)args->fd;
    if (fd < 0) return 0;
    if ((args->prot & PROT_WRITE_V) && (args->flags & MAP_SHARED_V))
        wf_emit_io(fd, 2, EV_MMAP_WRITE);
    return wf_emit_io(fd, 1, EV_MMAP_READ);
}

/* ---------------- descriptor table changes ---------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u64 id = bpf_get_current_pid_tgid();
    s32 fd = (s32)args->fd;
    wf_reset_io(id >> 32, fd);
    struct event_t *e = wf_reserve(EV_CLOSE);
    if (!e) return 0;
    e->fd = fd;
    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close_range) {
    struct event_t *e = wf_reserve(EV_CLOSE_RANGE);
    if (!e) return 0;
    e->fd = (s32)args->fd;
    e->dirfd = (s32)(args->max_fd > 0x7fffffff ? 0x7fffffff : args->max_fd);
    e->flags = (u32)args->flags;
    events.ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int wf_stage_dup(s32 oldfd, u32 flags) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.fd = oldfd; p.flags = flags;
    pending_dup.update(&id, &p);
    return 0;
}
static __always_inline int wf_finish_dup(long ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_dup.lookup(&id);
    if (!p) return 0;
    if (ret >= 0) {
        wf_reset_io(id >> 32, (s32)ret);
        struct event_t *e = wf_reserve(EV_DUP);
        if (e) {
            e->fd = (s32)ret; e->dirfd = p->fd; e->flags = p->flags;
            events.ringbuf_submit(e, 0);
        }
    }
    pending_dup.delete(&id);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_dup) { return wf_stage_dup((s32)args->fildes, 0); }
TRACEPOINT_PROBE(syscalls, sys_exit_dup) { return wf_finish_dup(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_dup2) { return wf_stage_dup((s32)args->oldfd, 0); }
TRACEPOINT_PROBE(syscalls, sys_exit_dup2) { return wf_finish_dup(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_dup3) { return wf_stage_dup((s32)args->oldfd, (u32)args->flags); }
TRACEPOINT_PROBE(syscalls, sys_exit_dup3) { return wf_finish_dup(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) {
    if (args->cmd == F_DUPFD_V) return wf_stage_dup((s32)args->fd, 0);
    if (args->cmd == F_DUPFD_CLOEXEC_V) return wf_stage_dup((s32)args->fd, O_CLOEXEC_V);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fcntl) { return wf_finish_dup(args->ret); }

/* ---------------- cwd changes ---------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.uptr = (u64)args->filename;
    pending_chdir.update(&id, &p);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_chdir.lookup(&id);
    if (!p) return 0;
    if (args->ret == 0) {
        struct event_t *e = wf_reserve(EV_CHDIR);
        if (e) {
            wf_read_user_path(e->path, p->uptr, &e->truncated);
            events.ringbuf_submit(e, 0);
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
        struct event_t *e = wf_reserve(EV_FCHDIR);
        if (e) { e->fd = *fd; events.ringbuf_submit(e, 0); }
    }
    pending_fchdir.delete(&id);
    return 0;
}

/* ---------------- rename / unlink ---------------- */
static __always_inline int wf_stage_rename(s32 d1, const char *a, s32 d2, const char *b) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.dirfd = d1; p.dirfd2 = d2; p.uptr = (u64)a; p.uptr2 = (u64)b;
    pending_rename.update(&id, &p);
    return 0;
}
static __always_inline int wf_finish_rename(long ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_rename.lookup(&id);
    if (!p) return 0;
    if (ret == 0) {
        struct event_t *e = wf_reserve(EV_RENAME);
        if (e) {
            e->dirfd = p->dirfd; e->dirfd2 = p->dirfd2;
            wf_read_user_path(e->path, p->uptr, &e->truncated);
            wf_read_user_path(e->path2, p->uptr2, &e->truncated);
            events.ringbuf_submit(e, 0);
        }
    }
    pending_rename.delete(&id);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    return wf_stage_rename(AT_FDCWD_VALUE, (const char *)args->oldname, AT_FDCWD_VALUE, (const char *)args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_exit_rename) { return wf_finish_rename(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    return wf_stage_rename(args->olddfd, (const char *)args->oldname, args->newdfd, (const char *)args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_exit_renameat) { return wf_finish_rename(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    return wf_stage_rename(args->olddfd, (const char *)args->oldname, args->newdfd, (const char *)args->newname);
}
TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) { return wf_finish_rename(args->ret); }

static __always_inline int wf_stage_unlink(s32 dirfd, const char *name) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t p = {};
    p.dirfd = dirfd; p.uptr = (u64)name;
    pending_unlink.update(&id, &p);
    return 0;
}
static __always_inline int wf_finish_unlink(long ret) {
    u64 id = bpf_get_current_pid_tgid();
    struct pending_t *p = pending_unlink.lookup(&id);
    if (!p) return 0;
    if (ret == 0) {
        struct event_t *e = wf_reserve(EV_UNLINK);
        if (e) {
            e->dirfd = p->dirfd;
            wf_read_user_path(e->path, p->uptr, &e->truncated);
            events.ringbuf_submit(e, 0);
        }
    }
    pending_unlink.delete(&id);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) { return wf_stage_unlink(AT_FDCWD_VALUE, (const char *)args->pathname); }
TRACEPOINT_PROBE(syscalls, sys_exit_unlink) { return wf_finish_unlink(args->ret); }
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) { return wf_stage_unlink(args->dfd, (const char *)args->pathname); }
TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) { return wf_finish_unlink(args->ret); }

/* ---------------- process lifecycle ---------------- */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct event_t *e = wf_reserve(EV_EXEC);
    if (!e) return 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *rp = 0;
    bpf_probe_read_kernel(&rp, sizeof(rp), &t->real_parent);
    e->aux_pid = wf_task_ns_tgid(rp);
    /* Executed file name as passed to execve (resolved against cwd in user space). */
    TP_DATA_LOC_READ_STR(e->path, filename, PATH_N);
    /* argv, NUL separated, captured while the new image is still alive. */
    unsigned long as = t->mm->arg_start;
    unsigned long ae = t->mm->arg_end;
    long len = (long)(ae - as);
    if (len > PATH_N - 1) { len = PATH_N - 1; e->truncated = 1; }
    if (len > 0) {
        bpf_probe_read_user(e->path2, len & (PATH_N - 1), (void *)as);
        e->fd = (s32)len;
    } else {
        e->fd = 0;
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
    if (!ns_child) return 0;  /* not in the collector's PID namespace */
    struct event_t *e = events.ringbuf_reserve(sizeof(struct event_t));
    if (!e) { wf_count_drop(); return 0; }
    e->ts_ns = bpf_ktime_get_ns();
    e->type = EV_FORK;
    e->tgid = ns_child;
    e->tid = cpid;
    e->aux_pid = wf_task_ns_tgid(parent);
    e->fd = -1; e->dirfd = AT_FDCWD_VALUE; e->dirfd2 = AT_FDCWD_VALUE; e->flags = 0; e->truncated = 0;
    e->path[0] = 0; e->path2[0] = 0;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), child->comm);
    events.ringbuf_submit(e, 0);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)id != (u32)(id >> 32)) return 0;  /* only the thread-group leader */
    struct event_t *e = wf_reserve(EV_EXIT);
    if (!e) return 0;
    events.ringbuf_submit(e, 0);
    return 0;
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


def _resolve_fd(pid: int, fd: int) -> str | None:
    p = _clean_link(_safe_proc_link(pid, f"fd/{fd}"))
    return _canon(p) if p else None


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
    kernel_drops: int = 0      # BPF ring-buffer reservations that failed
    queue_drops: int = 0       # user-space queue full (workload never blocked)
    received: int = 0          # records consumed from the ring buffer
    proc_fallbacks: int = 0    # resolutions that had to consult /proc
    unreadable_paths: int = 0  # path string could not be read from user memory


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
        # (os_pid, fd) -> (canonical path, close-on-exec)
        self.fd_paths: dict[tuple[int, int], tuple[str, bool]] = {}
        self.cwd: dict[int, str] = {}
        self.image: dict[int, tuple[str | None, str | None]] = {}  # pid -> (exe, command)
        self.pkey: dict[int, int] = {}
        self._seq = 0
        self.q: "queue.Queue[dict | None]" = queue.Queue(maxsize=262144)
        self.writer = BatchWriter(self.root, self.q)
        self.bpf = None
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
        self._derived: dict[str, None] = {}           # insertion-ordered, bounded
        self._derived_max = 200_000

    def _is_temp(self, path: str) -> bool:
        return any(_within(path, Path(r), False) for r in self.temp_roots)

    def _mark_derived(self, path: str) -> None:
        self._derived[path] = None
        if len(self._derived) > self._derived_max:
            self._derived.pop(next(iter(self._derived)))

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

    def _fd_path(self, pid: int, fd: int) -> str | None:
        hit = self.fd_paths.get((pid, fd))
        if hit:
            return hit[0]
        p = _resolve_fd(pid, fd)
        if p:
            self.stats.proc_fallbacks += 1
            self.fd_paths[(pid, fd)] = (p, False)
        return p

    def _resolve(self, pid: int, dirfd: int, raw: str) -> str | None:
        if not raw:
            return None
        if raw.startswith("/"):
            return _canon(raw)
        base = self._cwd(pid) if dirfd == AT_FDCWD else self._fd_path(pid, dirfd)
        if not base:
            return None
        return _canon(os.path.join(base, raw))

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
        if size < ct.sizeof(KernelEvent):
            return
        e = ct.cast(data, ct.POINTER(KernelEvent)).contents
        self.stats.received += 1
        pid = int(e.tgid)
        typ = int(e.type)
        ts = int(e.ts_ns) + self.clock_offset
        if e.truncated & 1:
            self.stats.truncated_paths += 1
        if e.truncated & 2:
            self.stats.unreadable_paths += 1

        if typ == EV_FORK:
            parent = int(e.aux_pid)
            self._seq += 1
            child_key = (self._seq << PID_BITS) | pid
            parent_key = self.key(parent)
            self.pkey[pid] = child_key
            pc = self._cwd(parent)
            if pc:
                self.cwd[pid] = pc
            else:
                self.cwd.pop(pid, None)
            for k in [k for k in self.fd_paths if k[0] == pid]:
                del self.fd_paths[k]
            for (p, fd), v in list(self.fd_paths.items()):
                if p == parent:
                    self.fd_paths[(pid, fd)] = v
            exe, cmd = self.image.get(parent, (None, None))
            self.image[pid] = (exe, cmd)
            self._put({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": child_key, "os_pid": pid, "ppid": parent, "parent_key": parent_key,
                "exe": exe, "cwd": self.cwd.get(pid), "command": cmd, "source": "ebpf",
            })
            return

        if typ == EV_EXEC:
            k = self.key(pid)
            filename = _bytestr(e.path)
            exe = self._resolve(pid, AT_FDCWD, filename) if filename else None
            if not exe:
                exe = _clean_link(_safe_proc_link(pid, "exe"))
            n = max(0, min(int(e.fd), 255))
            # NB: bytes(ctypes c_char array) stops at the first NUL, which would
            # silently keep only argv[0]; read the raw field memory instead.
            raw_argv = ct.string_at(ct.addressof(e) + KernelEvent.path2.offset, n)
            argv = [a.decode("utf-8", "replace") for a in raw_argv.split(b"\0") if a]
            command = _redact_cmdline(argv) if argv else exe
            # Close-on-exec descriptors disappear without a close(2).
            for fk in [fk for fk, v in self.fd_paths.items() if fk[0] == pid and v[1]]:
                del self.fd_paths[fk]
            self.image[pid] = (exe, command)
            ppid = int(e.aux_pid)
            self._put({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": k, "os_pid": pid, "ppid": ppid,
                "parent_key": self.pkey.get(ppid, ppid) if ppid else None,
                "exe": exe, "cwd": self._cwd(pid), "command": command, "source": "ebpf",
            })
            return

        if typ == EV_EXIT:
            for fk in [fk for fk in self.fd_paths if fk[0] == pid]:
                del self.fd_paths[fk]
            self.cwd.pop(pid, None)
            self.image.pop(pid, None)
            # Keep pkey: late events of this pid still belong to this instance
            # until a new fork re-assigns the pid.
            return

        if typ == EV_DUP:
            new_fd, old_fd = int(e.fd), int(e.dirfd)
            hit = self.fd_paths.get((pid, old_fd))
            if hit:
                self.fd_paths[(pid, new_fd)] = (hit[0], bool(int(e.flags) & O_CLOEXEC))
            else:
                self.fd_paths.pop((pid, new_fd), None)
            return

        if typ == EV_CLOSE:
            self.fd_paths.pop((pid, int(e.fd)), None)
            return

        if typ == EV_CLOSE_RANGE:
            lo, hi = int(e.fd), int(e.dirfd)
            cloexec_only = bool(int(e.flags) & 4)  # CLOSE_RANGE_CLOEXEC marks, not closes
            if not cloexec_only:
                for fk in [fk for fk in self.fd_paths if fk[0] == pid and lo <= fk[1] <= hi]:
                    del self.fd_paths[fk]
            else:
                for fk, v in list(self.fd_paths.items()):
                    if fk[0] == pid and lo <= fk[1] <= hi:
                        self.fd_paths[fk] = (v[0], True)
            return

        if typ == EV_CHDIR:
            c = self._resolve(pid, AT_FDCWD, _bytestr(e.path))
            if c:
                self.cwd[pid] = c
            return

        if typ == EV_FCHDIR:
            c = self._fd_path(pid, int(e.fd))
            if c:
                self.cwd[pid] = c
            return

        if typ == EV_OPEN:
            fd = int(e.fd)
            raw = _bytestr(e.path)
            if raw.startswith("/"):
                path = _canon(raw)
            else:
                # /proc is authoritative only while the same descriptor still
                # names the same file; otherwise replay the cwd/dirfd model.
                live = _resolve_fd(pid, fd)
                if live and (not raw or os.path.basename(live) == os.path.basename(os.path.normpath(raw))):
                    path = live
                else:
                    path = self._resolve(pid, int(e.dirfd), raw) or (live if not raw else None)
            if path:
                self.fd_paths[(pid, fd)] = (path, bool(int(e.flags) & O_CLOEXEC))
            else:
                self.fd_paths.pop((pid, fd), None)
            if not _within(path, self.root, self.capture_all):
                self.stats.filtered += 1
                return
            # Open itself is evidence of access intent.  Actual read/write
            # events below are what query.py treats as causal I/O.
            self._file_event(pid, ts, "open", path, read=False, write=False, flags=int(e.flags), api="ebpf:open")
            return

        if typ in (EV_READ, EV_MMAP_READ, EV_WRITE, EV_MMAP_WRITE):
            path = self._fd_path(pid, int(e.fd))
            if not path:
                self.stats.unresolved_fd += 1
                return
            is_write = typ in (EV_WRITE, EV_MMAP_WRITE)
            api = "ebpf:mmap" if typ in (EV_MMAP_READ, EV_MMAP_WRITE) else "ebpf:rw"
            if _within(path, self.root, self.capture_all):
                if not is_write and _within(path, self.root, False):
                    self._read_workspace.add(self.key(pid))
                self._file_event(pid, ts, "io", path, read=not is_write, write=is_write, api=api)
                return
            if is_write and self.key(pid) in self._read_workspace and self._is_temp(path):
                self._mark_derived(path)
                self._file_event(pid, ts, "io", path, read=False, write=True, api=api + ":derived-temp")
                return
            if not is_write and path in self._derived:
                self._read_workspace.add(self.key(pid))  # carries workspace-derived data
                self._file_event(pid, ts, "io", path, read=True, write=False, api=api + ":derived-temp")
                return
            self.stats.filtered += 1
            return

        if typ == EV_RENAME:
            a = self._resolve(pid, int(e.dirfd), _bytestr(e.path))
            b = self._resolve(pid, int(e.dirfd2), _bytestr(e.path2))
            if not (self.capture_all or _within(a, self.root, False) or _within(b, self.root, False)
                    or (a in self._derived)):
                self.stats.filtered += 1
                return
            if a in self._derived and b and self._is_temp(b):
                self._mark_derived(b)
            # Keep open descriptors pointing at the renamed file consistent.
            if a and b:
                for fk, v in list(self.fd_paths.items()):
                    if v[0] == a:
                        self.fd_paths[fk] = (b, v[1])
            self._file_event(pid, ts, "rename", a, path2=b, api="ebpf:rename")
            return

        if typ == EV_UNLINK:
            a = self._resolve(pid, int(e.dirfd), _bytestr(e.path))
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

        self.writer.start()
        try:
            level, inum = pid_namespace_identity()
            self.pidns = {"level": level, "inum": inum}
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
    """(nesting level, inode) of this process's PID namespace.

    Level 0 is the initial namespace; WSL2 distributions and containers run in
    nested namespaces (level >= 1).  The kernel program reports pids at this
    level and verifies the namespace by inode.
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
