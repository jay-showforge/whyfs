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
import stat
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
QUEUE_RECORDS = 262144  # bound on records waiting for the SQLite writer
HANDOFF_BATCH = 512     # records per handoff batch (= the writer's SQLite batch size)

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

/* value: bitmask of directions already reported (1 = read, 2 = write) */
struct io_key_t { u64 file; u64 ino; u32 tgid; u32 pad; };

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

/* Batched notification: waking the collector on every event costs the traced
 * workload an irq_work + context switch per file.  Events are committed
 * without a wakeup and the collector drains on a short timer; a wakeup is
 * forced only once WF_WAKE_BYTES are pending, so bursts never overflow. */
#define WF_WAKE_BYTES (1 << 20)
static __always_inline u64 wf_wake(void) {
    return events.ringbuf_query(BPF_RB_AVAIL_DATA) > WF_WAKE_BYTES ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

/* ---- diagnostics (compiled out of the production program) ----
 * WF_PROFILE: per-program counters in wf_prof[prog * 16 + metric]
 *   metric 0 calls, 1 early exits (no work), 2 map lookups, 3 map updates,
 *   4 map deletes, 5 ring-buffer records, 6 ring-buffer bytes, 7 upid walks,
 *   9 namespace fast-path misses, 10 foreign tasks (not in our pid namespace).
 * WF_PROFILE_TIME (with WF_PROFILE): nanoseconds spent in sections,
 *   8 namespace translation, 11 bpf_d_path, 12 io_seen map operations,
 *   13 ring-buffer reserve/fill/submit, 14 exec filename + argv copies,
 *   15 io_seen update (12 = io_seen lookup in I/O hooks, reset op at open).
 * WF_NULL_MASK: bit p set -> program p returns immediately (hook-dispatch
 *   ablation for measurement only). */
#define P_OPEN 0
#define P_PERM 1
#define P_MMAP 2
#define P_REN_E 3
#define P_REN_X 4
#define P_UNL_E 5
#define P_UNL_X 6
#define P_CHDIR_E 7
#define P_CHDIR_X 8
#define P_FCHDIR_E 9
#define P_FCHDIR_X 10
#define P_EXEC 11
#define P_FORK 12
#define P_EXIT 13
#define P_NSWALK 14
#ifdef WF_PROFILE
BPF_PERCPU_ARRAY(wf_prof, u64, 256);
static __always_inline void wf_p_add(u32 k, u64 n) {
    u64 *v = wf_prof.lookup(&k);
    if (v) *v += n;
}
#define WF_P(prog, m) wf_p_add((prog) * 16 + (m), 1)
#define WF_PB(prog, n) wf_p_add((prog) * 16 + 6, (n))
#else
#define WF_P(prog, m) do {} while (0)
#define WF_PB(prog, n) do {} while (0)
#endif
#ifdef WF_NULL_MASK
#define WF_ENTER(prog) do { WF_P(prog, 0); if ((WF_NULL_MASK) & (1u << (prog))) return 0; } while (0)
#else
#define WF_ENTER(prog) WF_P(prog, 0)
#endif
#define WF_EMIT(prog, sz) do { WF_P(prog, 5); WF_PB(prog, (sz)); } while (0)
#if defined(WF_PROFILE) && defined(WF_PROFILE_TIME)
#define WF_T0(v) u64 v = bpf_ktime_get_ns()
#define WF_T1(prog, m, v) wf_p_add((prog) * 16 + (m), bpf_ktime_get_ns() - (v))
#else
#define WF_T0(v) do {} while (0)
#define WF_T1(prog, m, v) do {} while (0)
#endif

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
static __always_inline u32 wf_task_ns_tgid(struct task_struct *t, u32 prog) {
    WF_P(P_NSWALK, 7);  /* total */
    WF_P(prog, 7);      /* per calling program */
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

static __always_inline u32 wf_cur_tgid(u32 prog) {
    /* Fast path: one helper when the current task lives directly in the
     * collector's namespace (the common case).  Tasks in nested namespaces
     * (containers) fall back to the upid walk. */
    WF_T0(t_ns);
    struct bpf_pidns_info ns = {};
    u32 r = 0;
    if (bpf_get_ns_current_pid_tgid(NS_DEV, NS_INUM, &ns, sizeof(ns)) == 0 && ns.tgid) {
        r = ns.tgid;
    } else {
        WF_P(prog, 9);
        r = wf_task_ns_tgid((struct task_struct *)bpf_get_current_task(), prog);
        if (!r) WF_P(prog, 10);
    }
    WF_T1(prog, 8, t_ns);
    return r;
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
    WF_ENTER(P_OPEN);
    struct inode *inode = file->f_inode;
    if (!inode) return 0;
    umode_t mode = inode->i_mode;
    if (!S_ISREG(mode) && !S_ISDIR(mode)) { WF_P(P_OPEN, 1); return 0; }
    u32 tgid = wf_cur_tgid(P_OPEN);
    if (!tgid) { WF_P(P_OPEN, 1); return 0; }
    u64 ino = inode->i_ino;
    /* A (re)used struct file starts a new open description: forget old dedup. */
    u32 root_tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_key_t k = {.file = (u64)file, .ino = ino, .tgid = root_tgid};
    /* Required: freed struct file memory is re-used by later opens, and stale
     * state would suppress the new open's first read/write (tests:
     * IoSeenSemanticsTests).  Cheaper resets were measured and rejected:
     * results/v02-ioseen/IOSEEN_REPORT.md. */
    WF_T0(t_map);
    io_seen.delete(&k);
    WF_T1(P_OPEN, 12, t_map);
    WF_P(P_OPEN, 4);
    WF_T0(t_rb);
    struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
    if (!e) { wf_count_drop(); return 0; }
    WF_EMIT(P_OPEN, sizeof(struct path_ev));
    wf_hdr(&e->h, tgid, EV_OPEN);
    e->h.file = (u64)file;
    e->h.ino = (u32)ino;
    e->h.flags = file->f_flags;
    e->h.fd = S_ISDIR(mode) ? 1 : 0;
    WF_T1(P_OPEN, 13, t_rb);
    WF_T0(t_dp);
    long n = bpf_d_path(&file->f_path, e->path, PATH_N);
    WF_T1(P_OPEN, 11, t_dp);
    if (n < 0) { e->path[0] = 0; e->h.truncated = (n == -WF_ENAMETOOLONG) ? 1 : 2; }
    WF_T0(t_sub);
    events.ringbuf_submit(e, wf_wake());
    WF_T1(P_OPEN, 13, t_sub);
    return 0;
}

/* First read/write of an open file by a process (sync syscalls, io_uring,
 * sendfile/splice/copy_file_range all reach rw_verify_area). */
static __always_inline int wf_emit_io(struct file *file, u32 dir, u32 type, u32 prog) {
    struct inode *inode = file->f_inode;
    if (!inode) return 0;
    if (!S_ISREG(inode->i_mode)) { WF_P(prog, 1); return 0; }
    u64 ino = inode->i_ino;
    struct io_key_t k = {.file = (u64)file, .ino = ino, .tgid = bpf_get_current_pid_tgid() >> 32};
    WF_T0(t_lk);
    u8 *seen = io_seen.lookup(&k);
    WF_T1(prog, 12, t_lk);
    WF_P(prog, 2);
    u8 mask = seen ? *seen : 0;
    if (mask & dir) { WF_P(prog, 1); return 0; }
    u32 tgid = wf_cur_tgid(prog);
    if (!tgid) return 0;
    mask |= dir;
    WF_T0(t_up);
    io_seen.update(&k, &mask);
    WF_T1(prog, 15, t_up);  /* update ns kept apart from lookup ns (12) */
    WF_P(prog, 3);
    WF_T0(t_rb);
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    WF_EMIT(prog, sizeof(struct hdr_t));
    wf_hdr(e, tgid, type);
    e->file = (u64)file;
    e->ino = (u32)ino;
    events.ringbuf_submit(e, wf_wake());
    WF_T1(prog, 13, t_rb);
    return 0;
}

KFUNC_PROBE(security_file_permission, struct file *file, int mask) {
    WF_ENTER(P_PERM);
    if (mask & WF_MAY_WRITE) return wf_emit_io(file, 2, EV_WRITE, P_PERM);
    if (mask & WF_MAY_READ) return wf_emit_io(file, 1, EV_READ, P_PERM);
    WF_P(P_PERM, 1);
    return 0;
}

KFUNC_PROBE(security_mmap_file, struct file *file, unsigned long prot, unsigned long flags) {
    WF_ENTER(P_MMAP);
    if (!file) { WF_P(P_MMAP, 1); return 0; }
    if ((prot & WF_PROT_WRITE) && (flags & WF_MAP_SHARED)) wf_emit_io(file, 2, EV_MMAP_WRITE, P_MMAP);
    return wf_emit_io(file, 1, EV_MMAP_READ, P_MMAP);
}

/* ---------------- rename / unlink (syscalls and io_uring) ---------------- */
KFUNC_PROBE(do_renameat2, int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags) {
    WF_ENTER(P_REN_E);
    u32 z = 0;
    struct pend_rename_t *p = scratch_rename.lookup(&z);
    WF_P(P_REN_E, 2);
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
    WF_P(P_REN_E, 3);
    return 0;
}
KRETFUNC_PROBE(do_renameat2, int olddfd, struct filename *from, int newdfd, struct filename *to, unsigned int flags, int ret) {
    WF_ENTER(P_REN_X);
    u64 id = bpf_get_current_pid_tgid();
    struct pend_rename_t *p = pending_rename.lookup(&id);
    WF_P(P_REN_X, 2);
    if (!p) return 0;
    if (ret == 0) {
        u32 tgid = wf_cur_tgid(P_REN_X);
        if (tgid) {
            struct path2_ev *e = events.ringbuf_reserve(sizeof(struct path2_ev));
            if (e) {
                WF_EMIT(P_REN_X, sizeof(struct path2_ev));
                wf_hdr(&e->h, tgid, EV_RENAME);
                e->h.dirfd = p->d1; e->h.dirfd2 = p->d2; e->h.file = p->f1; e->h.file2 = p->f2;
                e->h.truncated = p->trunc;
                bpf_probe_read_kernel(e->path, PATH_N, p->a);
                bpf_probe_read_kernel(e->path2, PATH_N, p->b);
                events.ringbuf_submit(e, wf_wake());
            } else {
                wf_count_drop();
            }
        }
    }
    pending_rename.delete(&id);
    WF_P(P_REN_X, 4);
    return 0;
}

KFUNC_PROBE(do_unlinkat, int dfd, struct filename *name) {
    WF_ENTER(P_UNL_E);
    u32 z = 0;
    struct pend_unlink_t *p = scratch_unlink.lookup(&z);
    WF_P(P_UNL_E, 2);
    if (!p) return 0;
    const char *a = 0;
    p->trunc = 0;
    p->d1 = dfd;
    p->f1 = dfd == AT_FDCWD_VALUE ? 0 : wf_fd_file(dfd);
    bpf_probe_read_kernel(&a, sizeof(a), &name->name);
    wf_read_kstr(p->a, a, &p->trunc);
    u64 id = bpf_get_current_pid_tgid();
    pending_unlink.update(&id, p);
    WF_P(P_UNL_E, 3);
    return 0;
}
KRETFUNC_PROBE(do_unlinkat, int dfd, struct filename *name, int ret) {
    WF_ENTER(P_UNL_X);
    u64 id = bpf_get_current_pid_tgid();
    struct pend_unlink_t *p = pending_unlink.lookup(&id);
    WF_P(P_UNL_X, 2);
    if (!p) return 0;
    if (ret == 0) {
        u32 tgid = wf_cur_tgid(P_UNL_X);
        if (tgid) {
            struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
            if (e) {
                WF_EMIT(P_UNL_X, sizeof(struct path_ev));
                wf_hdr(&e->h, tgid, EV_UNLINK);
                e->h.dirfd = p->d1; e->h.file = p->f1; e->h.truncated = p->trunc;
                bpf_probe_read_kernel(e->path, PATH_N, p->a);
                events.ringbuf_submit(e, wf_wake());
            } else {
                wf_count_drop();
            }
        }
    }
    pending_unlink.delete(&id);
    WF_P(P_UNL_X, 4);
    return 0;
}

/* ---------------- cwd changes (needed for relative rename/unlink/exec names) ---------------- */
TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
    WF_ENTER(P_CHDIR_E);
    u64 id = bpf_get_current_pid_tgid();
    u64 uptr = (u64)args->filename;
    pending_chdir.update(&id, &uptr);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
    WF_ENTER(P_CHDIR_X);
    u64 id = bpf_get_current_pid_tgid();
    u64 *uptr = pending_chdir.lookup(&id);
    if (!uptr) return 0;
    if (args->ret == 0) {
        u32 tgid = wf_cur_tgid(P_CHDIR_X);
        if (tgid) {
            struct path_ev *e = events.ringbuf_reserve(sizeof(struct path_ev));
            if (e) {
                wf_hdr(&e->h, tgid, EV_CHDIR);
                /* read at exit: getname() has faulted the page in by now */
                wf_read_ustr(e->path, *uptr, &e->h.truncated);
                events.ringbuf_submit(e, wf_wake());
            } else {
                wf_count_drop();
            }
        }
    }
    pending_chdir.delete(&id);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
    WF_ENTER(P_FCHDIR_E);
    u64 id = bpf_get_current_pid_tgid();
    s32 fd = (s32)args->fd;
    pending_fchdir.update(&id, &fd);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
    WF_ENTER(P_FCHDIR_X);
    u64 id = bpf_get_current_pid_tgid();
    s32 *fd = pending_fchdir.lookup(&id);
    if (!fd) return 0;
    if (args->ret == 0) {
        u32 tgid = wf_cur_tgid(P_FCHDIR_X);
        if (tgid) {
            struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
            if (e) {
                wf_hdr(e, tgid, EV_FCHDIR);
                e->fd = *fd;
                e->file = wf_fd_file(*fd);
                events.ringbuf_submit(e, wf_wake());
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
    WF_ENTER(P_EXEC);
    u32 tgid = wf_cur_tgid(P_EXEC);
    if (!tgid) { WF_P(P_EXEC, 1); return 0; }
    WF_T0(t_rb);
    struct path2_ev *e = events.ringbuf_reserve(sizeof(struct path2_ev));
    if (!e) { wf_count_drop(); return 0; }
    WF_EMIT(P_EXEC, sizeof(struct path2_ev));
    wf_hdr(&e->h, tgid, EV_EXEC);
    WF_T1(P_EXEC, 13, t_rb);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *rp = 0;
    WF_T0(t_ns);
    bpf_probe_read_kernel(&rp, sizeof(rp), &t->real_parent);
    e->h.aux_pid = wf_task_ns_tgid(rp, P_EXEC);
    WF_T1(P_EXEC, 8, t_ns);
    WF_T0(t_cp);
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
    WF_T1(P_EXEC, 14, t_cp);
    WF_T0(t_sub);
    events.ringbuf_submit(e, wf_wake());
    WF_T1(P_EXEC, 13, t_sub);
    return 0;
}

/* Raw tracepoint so that threads (CLONE_THREAD) can be told apart from new
 * processes: only a child whose pid == tgid is a new thread group. */
RAW_TRACEPOINT_PROBE(sched_process_fork) {
    WF_ENTER(P_FORK);
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
    u32 cpid = child->pid;
    u32 ctgid = child->tgid;
    if (cpid != ctgid) { WF_P(P_FORK, 1); return 0; }
    WF_T0(t_ns);
    u32 ns_child = wf_task_ns_tgid(child, P_FORK);
    WF_T1(P_FORK, 8, t_ns);
    if (!ns_child) { WF_P(P_FORK, 1); return 0; }
    WF_T0(t_rb);
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    WF_EMIT(P_FORK, sizeof(struct hdr_t));
    wf_hdr(e, ns_child, EV_FORK);
    e->tid = cpid;
    WF_T1(P_FORK, 13, t_rb);
    /* sched_process_fork always fires in the forking task: parent == current. */
    e->aux_pid = (parent == (struct task_struct *)bpf_get_current_task()) ? wf_cur_tgid(P_FORK)
                                                                          : wf_task_ns_tgid(parent, P_FORK);
    WF_T0(t_sub);
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), child->comm);
    events.ringbuf_submit(e, wf_wake());
    WF_T1(P_FORK, 13, t_sub);
    return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    WF_ENTER(P_EXIT);
    u64 id = bpf_get_current_pid_tgid();
    if ((u32)id != (u32)(id >> 32)) { WF_P(P_EXIT, 1); return 0; }  /* only the thread-group leader */
    u32 tgid = wf_cur_tgid(P_EXIT);
    if (!tgid) { WF_P(P_EXIT, 1); return 0; }
    WF_T0(t_rb);
    struct hdr_t *e = events.ringbuf_reserve(sizeof(struct hdr_t));
    if (!e) { wf_count_drop(); return 0; }
    WF_EMIT(P_EXIT, sizeof(struct hdr_t));
    wf_hdr(e, tgid, EV_EXIT);
    events.ringbuf_submit(e, wf_wake());
    WF_T1(P_EXIT, 13, t_rb);
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


def kfunc_supported(BPF) -> bool:
    """BTF fentry (BPF trampoline) support.  BCC's own BPF.support_kfunc() (0.29) returns
    False on every architecture except x86_64, but arm64 kernels have had trampolines since
    6.0 and BCC's attach path is architecture-neutral; ask the kernel instead: BTF plus the
    trampoline link symbol and an architecture trampoline implementation."""
    if BPF.support_kfunc():
        return True
    try:
        from bcc import libbcc  # type: ignore
        if not libbcc.lib.bpf_has_kernel_btf():
            return False
    except Exception:
        return False
    return all(BPF.ksymname(s) != -1 for s in ("bpf_trampoline_link_prog", "arch_prepare_bpf_trampoline"))


def _redact_cmdline(argv: list[str]) -> str:
    from whyfs.redact import redact_argv as _r  # the one shared policy (argv pass + command-text pass)

    return _r(argv)


def _clean_link(p: str | None) -> str | None:
    if not p:
        return None
    if p.endswith(" (deleted)"):
        p = p[: -len(" (deleted)")]
    if not p.startswith("/"):
        return None  # pipe:[..], socket:[..], anon_inode:...
    return p


def _canon(p: str) -> str:
    # realpath() alone: it resolves '..' after expanding the symlinks before it,
    # as the kernel does.  normpath() first would collapse 'link/..' lexically.
    return os.path.realpath(p)


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

    def __init__(self, root: Path, q: "queue.Queue[dict | None]", batch_size: int = 512, flush_ms: int = 100,
                 store=None):
        super().__init__(name="whyfs-sqlite-writer", daemon=True)
        self.root = root
        self.store = store  # privsep.Store: SQLite runs as the workspace owner
        self.q = q
        self.batch_size = batch_size
        self.flush_s = flush_ms / 1000.0
        self.written = 0
        self.batches = 0
        self.max_batch = 0
        self.error: BaseException | None = None

    def _flush(self, con, batch: list[dict]) -> None:
        self.written += self.store.ingest(batch) if self.store is not None else ingest_events(con, batch)
        self.batches += 1
        self.max_batch = max(self.max_batch, len(batch))
        batch.clear()

    def run(self) -> None:
        con = connect(self.root) if self.store is None else None
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
                if isinstance(item, list):  # ordered handoff batch from BCCCollector._flush_pending
                    batch.extend(item)
                elif item is not ...:
                    batch.append(item)
                if len(batch) >= self.batch_size or time.monotonic() >= deadline:
                    if batch:
                        self._flush(con, batch)
                    deadline = time.monotonic() + self.flush_s
        except BaseException as exc:  # surfaced by collector.stop()
            self.error = exc
        finally:
            if con is not None:
                con.close()


class BCCUnavailable(RuntimeError):
    pass


class BCCCollector:
    """System-wide Linux provenance collector backed by BCC/eBPF.

    The collector is intentionally a foreground primitive.  ``whyfs daemon``
    owns lifecycle/pidfile semantics around it.
    """

    def __init__(self, root: Path, run_id: str, *, capture_all: bool = False, store=None,
                 extra_cflags: list[str] | None = None):
        self.root = root.resolve()
        self.run_id = run_id
        self.capture_all = capture_all
        self.extra_cflags = list(extra_cflags or [])  # diagnostics only (WF_PROFILE, WF_NULL_MASK)
        self.stats = CollectorStats()
        # kernel struct file * -> absolute path (only paths whyfs may need:
        # workspace files, temp-root files, and directories for dirfd names)
        self.files = _BoundedMap(400_000)
        self.cwd: dict[int, str] = {}
        self.image: dict[int, tuple[str | None, str | None]] = {}  # pid -> (exe, command)
        self.pkey: dict[int, int] = {}
        self.proc_rows = _BoundedMap(200_000)          # key -> latest process row (in memory)
        self.pending_exec: dict[int, list[dict]] = {}  # exec boundaries of not-yet-relevant keys
        self.relevant: set[int] = set()                # keys whose rows are persisted
        self._seq = 0
        # Records go to the writer thread in ordered batches, one queue item per
        # ring-buffer drain cycle (or per HANDOFF_BATCH records): a handoff per
        # record woke the writer ~3,000 times per 300-process build
        # (results/v02-daemon-gap/).  Same bound as before: QUEUE_RECORDS records.
        self._pending: list[dict] = []
        self.q: "queue.Queue[list[dict] | None]" = queue.Queue(maxsize=QUEUE_RECORDS // HANDOFF_BATCH)
        self.writer = BatchWriter(self.root, self.q, store=store)
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
        # whyfs's own state directory (<workspace>/.whyfs: the store, daemon.json) is
        # not workspace data: its activity is never evidence (KNOWN_ISSUES KI-1).
        # Only this exact directory; other directories named .whyfs are user data.
        self.state_dir = self.root / ".whyfs"

    def _in_ws(self, path: str | None, capture_all: bool) -> bool:
        if not path or _within(path, self.state_dir, False):
            return False
        return _within(path, self.root, capture_all)

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
        self._record_process({
            "run_id": self.run_id, "ts_ns": time.time_ns(), "kind": "process",
            "pid": pid, "os_pid": pid, "ppid": None, "parent_key": None,
            "exe": exe, "cwd": self._cwd(pid), "command": self.image[pid][1], "source": "ebpf",
        })

    # Privacy: the kernel sees every process in the namespace.  Process rows
    # (command lines!) and exec boundaries are held in memory and persisted
    # only for processes that produce stored evidence, plus a bounded chain of
    # their ancestors for parentage -- not for unrelated activity on the host.
    MAX_ANCESTORS = 8

    def _record_process(self, row: dict) -> None:
        k = row["pid"]
        old = self.proc_rows.get(k)
        if old:
            merged = dict(old)
            merged.update({x: v for x, v in row.items() if v is not None})
            merged["ts_ns"] = old["ts_ns"]
            row = merged
        self.proc_rows.put(k, row)
        if k in self.relevant:
            self._put(dict(row))

    def _record_exec(self, event: dict) -> None:
        k = event["pid"]
        if k in self.relevant:
            self._put(event)
        else:
            lst = self.pending_exec.setdefault(k, [])
            if len(lst) < 16:
                lst.append(event)

    def _make_relevant(self, k: int) -> None:
        for _ in range(self.MAX_ANCESTORS + 1):
            if k is None or k in self.relevant:
                return
            self.relevant.add(k)
            row = self.proc_rows.get(k)
            if row:
                self._put(dict(row))
            for ev in self.pending_exec.pop(k, []):
                self._put(ev)
            k = row.get("parent_key") if row else None

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

    def _resolve(self, pid: int, dirfd: int, dir_file: int, raw: str, *, follow_final: bool) -> str | None:
        """Absolute path for a name passed to a syscall.

        ``follow_final`` mirrors the syscall: exec and chdir follow a final
        symlink; rename and unlink act on the link itself.  The base (cwd model
        or directory file object) is already canonical: it comes from kernel
        d_path or from an earlier canonicalization.  So a single-component name
        is joined to it with no filesystem access; only names with '/' or '..'
        canonicalize their parent (physically, via realpath).  Per-event
        realpath() walks measurably slowed exec-heavy workloads
        (results/v02-hotpath/HOTPATH_REPORT.md) and wrongly followed a final
        symlink for rename/unlink."""
        if not raw:
            return None
        if raw.startswith("/"):
            base, rel = None, raw
        else:
            base = self._cwd(pid) if dirfd == AT_FDCWD else self.files.get(dir_file)
            if not base:
                return None
            rel = raw
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if base and len(parts) == 1 and parts[0] != "..":
            path = os.path.join(base, parts[0])
        else:
            full = os.path.join(base, rel) if base else rel
            parent, name = os.path.split(full.rstrip("/") or "/")
            if name in ("", ".", ".."):
                return _canon(full)  # names a directory reference: resolve it physically
            path = os.path.join(_canon(parent), name)
        if follow_final:
            try:
                if stat.S_ISLNK(os.lstat(path).st_mode):
                    return _canon(path)
            except OSError:
                pass
        return path

    def _keep_path(self, path: str, is_dir: bool) -> bool:
        return is_dir or self._in_ws(path, self.capture_all) or self._is_temp(path)

    # ---------------------------------------------------------------- output
    def _put(self, event: dict) -> None:
        self._pending.append(event)
        if len(self._pending) >= HANDOFF_BATCH:
            self.flush_pending()

    def flush_pending(self) -> None:
        """Hand the records gathered so far to the writer as one ordered batch.
        Called at the end of every ring-buffer drain (poll/drain/stop), so no
        record waits longer than one poll interval, as before."""
        if not self._pending:
            return
        batch, self._pending = self._pending, []
        try:
            self.q.put_nowait(batch)
            self.stats.submitted += len(batch)
        except queue.Full:
            # Do not backpressure the observed workload.  We count the loss and
            # make it visible in status; evidence is never silently invented.
            self.stats.queue_drops += len(batch)

    def _file_event(self, pid: int, ts: int, kind: str, path: str | None, **extra) -> None:
        k = self.key(pid)
        self._make_relevant(k)
        self._put({
            "run_id": self.run_id, "ts_ns": ts, "kind": kind,
            "pid": k, "os_pid": pid, "path": path, "source": "ebpf", **extra,
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
            if is_dir or not self._in_ws(path, self.capture_all):
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
            if self._in_ws(path, self.capture_all):
                if not is_write and self._in_ws(path, False):
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
            self._record_process({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": child_key, "os_pid": pid, "ppid": parent or None, "parent_key": parent_key,
                "exe": exe, "cwd": self.cwd.get(pid), "command": cmd, "source": "ebpf",
            })
            return

        if typ == EV_EXEC:
            k = self.key(pid)
            filename = _cstr(_field_bytes(data, size, OFF_PATH))
            exe = self._resolve(pid, AT_FDCWD, 0, filename, follow_final=True) if filename else None
            if not exe:
                exe = _clean_link(_safe_proc_link(pid, "exe"))
            n = max(0, min(int(e.fd), PATH_N - 1))
            raw_argv = _field_bytes(data, size, OFF_PATH2, n)
            argv = [a.decode("utf-8", "replace") for a in raw_argv.split(b"\0") if a]
            command = _redact_cmdline(argv) if argv else exe
            self.image[pid] = (exe, command)
            ppid = int(e.aux_pid)
            self._record_process({
                "run_id": self.run_id, "ts_ns": ts, "kind": "process",
                "pid": k, "os_pid": pid, "ppid": ppid or None,
                "parent_key": self.pkey.get(ppid, ppid) if ppid else None,
                "exe": exe, "cwd": self._cwd(pid), "command": command, "source": "ebpf",
            })
            # Raw evidence of the image boundary: the query layer attributes a
            # write to the program image that performed it (see query._image_start).
            self._record_exec({
                "run_id": self.run_id, "ts_ns": ts, "kind": "exec", "pid": k, "os_pid": pid,
                "path": exe, "api": "ebpf:exec", "source": "ebpf",
            })
            return

        if typ == EV_EXIT:
            k = self.pkey.get(pid)
            if k is not None and k not in self.relevant:
                self.pending_exec.pop(k, None)  # can no longer become relevant
            self.cwd.pop(pid, None)
            self.image.pop(pid, None)
            # Keep pkey: late events of this pid still belong to this instance
            # until a new fork re-assigns the pid.
            return

        if typ == EV_CHDIR:
            c = self._resolve(pid, AT_FDCWD, 0, _cstr(_field_bytes(data, size, OFF_PATH)), follow_final=True)
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
            a = self._resolve(pid, int(e.dirfd), int(e.file), _cstr(_field_bytes(data, size, OFF_PATH)), follow_final=False)
            b = self._resolve(pid, int(e.dirfd2), int(e.file2), _cstr(_field_bytes(data, size, OFF_PATH2)), follow_final=False)
            if not (self.capture_all or self._in_ws(a, False) or self._in_ws(b, False)
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
            a = self._resolve(pid, int(e.dirfd), int(e.file), _cstr(_field_bytes(data, size, OFF_PATH)), follow_final=False)
            if a in self._derived:
                self._derived.pop(a, None)
                self._file_event(pid, ts, "unlink", a, api="ebpf:unlink:derived-temp")
                return
            if not self._in_ws(a, self.capture_all):
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
        if not kfunc_supported(BPF):
            raise BCCUnavailable(
                "this kernel/BCC lacks BTF fentry (kfunc) support, which whyfs needs to observe "
                "file I/O at the VFS layer (including io_uring)."
            )

        self.writer.start()
        try:
            self.load_programs()
            self.bpf["events"].open_ring_buffer(self._process_event)
        except BaseException:
            self.q.put(None)
            self.writer.join(timeout=2)
            raise

    def load_programs(self) -> None:
        """Compile, load and attach the BPF programs only.  The native collector
        (native_collect.NativeIngest) consumes the ring buffer instead of Python."""
        from bcc import BPF  # type: ignore

        if not kfunc_supported(BPF):
            raise BCCUnavailable(
                "this kernel/BCC lacks BTF fentry (kfunc) support, which whyfs needs to observe "
                "file I/O at the VFS layer (including io_uring)."
            )
        level, inum = pid_namespace_identity()
        self.pidns = {"level_visible": level, "inum": inum}
        self.bpf = BPF(text=BPF_SOURCE, cflags=[f"-DNS_INUM={inum}U", f"-DNS_DEV={pid_namespace_kdev()}ULL",
                                               *self.extra_cflags])

    def poll(self, timeout_ms: int = 100) -> None:
        if self.bpf is None:
            raise RuntimeError("collector not started")
        # Kernel side submits without wakeups (see wf_wake): wait up to the
        # timeout for a forced wakeup, then drain whatever has been committed.
        self.bpf.ring_buffer_poll(timeout_ms)
        self.bpf.ring_buffer_consume()
        self.flush_pending()

    def drain(self) -> None:
        """Consume everything already committed to the ring buffer, then hand
        every gathered record to the writer (also when BPF never loaded)."""
        if self.bpf is not None:
            for _ in range(1000):
                before = self.stats.received
                self.bpf.ring_buffer_consume()
                if self.stats.received == before:
                    break
        self.flush_pending()

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


def pid_namespace_kdev() -> int:
    """nsfs device of our PID namespace, in the kernel's internal dev_t
    encoding (major << 20 | minor) that bpf_get_ns_current_pid_tgid expects."""
    st = os.stat("/proc/self/ns/pid")
    return (os.major(st.st_dev) << 20) | os.minor(st.st_dev)


def install_signal_stop(stop_event: threading.Event) -> None:
    def handler(_sig, _frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
