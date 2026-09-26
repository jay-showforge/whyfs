"""Regression tests for the v0.2 eBPF user-space resolver.

Each test replays a synthetic, kernel-ordered event stream for fake PIDs that do
not exist on this machine, so /proc cannot rescue a wrong model: the resolver
must get the answer from the event stream alone (as it must for short-lived
processes that exit before user space processes their events).
"""
import ctypes as ct
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import whyfs.ebpf_bcc as m
from whyfs.query import impact, why
from whyfs.store import connect, ingest_events

FAKE = 4_000_000  # above any realistic live pid; /proc/<FAKE> does not exist


def ev(typ, pid, *, fd=-1, dirfd=m.AT_FDCWD, dirfd2=m.AT_FDCWD, flags=0, aux=0, path=b"", path2=b"", ts=None):
    e = m.KernelEvent()
    e.ts_ns = ts if ts is not None else time.monotonic_ns()
    e.tgid = pid
    e.tid = pid
    e.aux_pid = aux
    e.fd = fd
    e.dirfd = dirfd
    e.dirfd2 = dirfd2
    e.flags = flags
    e.type = typ
    e.path = path
    ct.memmove(ct.addressof(e) + m.KernelEvent.path2.offset, path2, min(len(path2), 256))
    return e


class Harness:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.c = m.BCCCollector(self.root, "run")
        # Seed a pre-existing parent whose cwd is the workspace.
        self.c.pkey[FAKE] = FAKE
        self.c.cwd[FAKE] = str(self.root)

    def feed(self, *events):
        for e in events:
            self.c._process_event(None, ct.addressof(e), ct.sizeof(e))

    def drained(self):
        out = []
        while not self.c.q.empty():
            out.append(self.c.q.get_nowait())
        return out


class ResolverRegressionTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.h = Harness(self.root)

    def tearDown(self):
        self.td.cleanup()

    def writes(self, items):
        return [(x["os_pid"], x["path"]) for x in items if x["kind"] == "io" and x["write"]]

    def reads(self, items):
        return [(x["os_pid"], x["path"]) for x in items if x["kind"] == "io" and x["read"]]

    # Bug: bytes() on a ctypes char array stops at the first NUL -> argv[0] only.
    def test_exec_keeps_full_argv(self):
        child = FAKE + 1
        argv = b"tr\0a-z\0A-Z\0"
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"/usr/bin/tr", path2=argv, fd=len(argv)),
        )
        procs = [x for x in self.h.drained() if x["kind"] == "process" and x["os_pid"] == child]
        self.assertEqual(procs[-1]["command"], "tr a-z A-Z")
        self.assertEqual(procs[-1]["exe"], "/usr/bin/tr")

    # Bug: kernel timestamps are CLOCK_MONOTONIC; the store is wall-clock.
    def test_timestamps_are_wall_clock(self):
        self.h.feed(ev(m.EV_OPEN, FAKE, fd=3, path=str(self.root / "x").encode(), ts=time.monotonic_ns()))
        got = [x for x in self.h.drained() if x["kind"] == "open"][0]
        self.assertLess(abs(got["ts_ns"] - time.time_ns()), 5_000_000_000)

    # Bug: a short-lived child's relative paths were resolved via /proc/<pid>/cwd
    # after it had exited.  The cwd model (fork inheritance + chdir) must do it.
    def test_relative_paths_of_exited_child_use_cwd_model(self):
        child = FAKE + 2
        (self.root / "sub").mkdir()
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_CHDIR, child, path=b"sub"),
            ev(m.EV_OPEN, child, fd=3, path=b"in.txt"),
            ev(m.EV_READ, child, fd=3),
            ev(m.EV_EXIT, child),
        )
        self.assertEqual(self.reads(self.h.drained()), [(child, str(self.root / "sub" / "in.txt"))])

    # Bug: shell redirection (open fd3; dup2(3,1); close 3; exec; write fd1) lost the output.
    def test_dup2_redirection_attributes_output(self):
        child = FAKE + 3
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_OPEN, child, fd=3, path=b"out.txt", flags=os.O_WRONLY | os.O_CREAT | os.O_TRUNC),
            ev(m.EV_DUP, child, fd=1, dirfd=3),
            ev(m.EV_CLOSE, child, fd=3),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"/usr/bin/tr", path2=b"tr\0", fd=3),
            ev(m.EV_WRITE, child, fd=1),
        )
        self.assertEqual(self.writes(self.h.drained()), [(child, str(self.root / "out.txt"))])

    # Bug: after close(), a pipe/socket re-using the fd number was attributed to the old file.
    def test_closed_fd_reused_by_pipe_is_not_the_old_file(self):
        self.h.feed(
            ev(m.EV_OPEN, FAKE, fd=5, path=b"input.txt"),
            ev(m.EV_READ, FAKE, fd=5),
            ev(m.EV_CLOSE, FAKE, fd=5),
            ev(m.EV_WRITE, FAKE, fd=5),  # fd 5 is now a pipe (no open event)
        )
        items = self.h.drained()
        self.assertEqual(self.writes(items), [])
        self.assertEqual(self.h.c.stats.unresolved_fd, 1)

    def test_close_range_forgets_descriptors(self):
        self.h.feed(
            ev(m.EV_OPEN, FAKE, fd=7, path=b"a.txt"),
            ev(m.EV_CLOSE_RANGE, FAKE, fd=3, dirfd=100),
            ev(m.EV_WRITE, FAKE, fd=7),
        )
        self.assertEqual(self.writes(self.h.drained()), [])

    # Bug: O_CLOEXEC descriptors vanish at exec without close(2).
    def test_cloexec_descriptor_dropped_at_exec(self):
        child = FAKE + 4
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_OPEN, child, fd=4, path=b"secret-ish.txt", flags=m.O_CLOEXEC),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"/bin/true", path2=b"true\0", fd=5),
            ev(m.EV_WRITE, child, fd=4),
        )
        self.assertEqual(self.writes(self.h.drained()), [])

    def test_fork_inherits_descriptors(self):
        child = FAKE + 5
        self.h.feed(
            ev(m.EV_OPEN, FAKE, fd=9, path=b"log.txt"),
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_WRITE, child, fd=9),
        )
        self.assertEqual(self.writes(self.h.drained()), [(child, str(self.root / "log.txt"))])

    # Bug: (run_id, pid) merged distinct processes when the OS re-used a PID.
    def test_pid_reuse_gets_distinct_process_keys(self):
        reused = FAKE + 6
        self.h.feed(
            ev(m.EV_FORK, reused, aux=FAKE),
            ev(m.EV_OPEN, reused, fd=3, path=b"first.txt"),
            ev(m.EV_WRITE, reused, fd=3),
            ev(m.EV_EXIT, reused),
            ev(m.EV_FORK, reused, aux=FAKE),
            ev(m.EV_OPEN, reused, fd=3, path=b"second.txt"),
            ev(m.EV_WRITE, reused, fd=3),
        )
        w = [(x["pid"], x["path"]) for x in self.h.drained() if x["kind"] == "io" and x["write"]]
        self.assertEqual(len(w), 2)
        self.assertNotEqual(w[0][0], w[1][0], "a re-used PID must not share a process key")
        self.assertTrue(all(k & ((1 << m.PID_BITS) - 1) == reused for k, _ in w))

    # Bug (fd reuse race): /proc/<pid>/fd/N consulted late could name a *different*
    # file.  A live process whose fd now names another file must not override the event path.
    def test_open_prefers_event_path_over_mismatched_live_fd(self):
        other = self.root / "other.txt"
        other.write_text("x")
        me = os.getpid()
        self.h.c.pkey[me] = me
        self.h.c.cwd[me] = str(self.root)
        fd = os.open(other, os.O_RDONLY)
        try:
            self.h.feed(ev(m.EV_OPEN, me, fd=fd, path=b"really-opened.txt"))
        finally:
            os.close(fd)
        opens = [x["path"] for x in self.h.drained() if x["kind"] == "open"]
        self.assertEqual(opens, [str(self.root / "really-opened.txt")])

    # Bug: gcc's cc1 -> /tmp/ccXXXX.s -> as chain was cut by workspace filtering.
    def test_derived_temporaries_bridge_lineage_but_nothing_else(self):
        cc1, asm, unrelated = FAKE + 7, FAKE + 8, FAKE + 9
        tmp = tempfile.gettempdir() + "/ccWHYFS.s"
        self.h.feed(
            ev(m.EV_FORK, cc1, aux=FAKE),
            ev(m.EV_OPEN, cc1, fd=3, path=b"u.c"), ev(m.EV_READ, cc1, fd=3),
            ev(m.EV_OPEN, cc1, fd=4, path=tmp.encode()), ev(m.EV_WRITE, cc1, fd=4),
            ev(m.EV_FORK, asm, aux=FAKE),
            ev(m.EV_OPEN, asm, fd=3, path=tmp.encode()), ev(m.EV_READ, asm, fd=3),
            ev(m.EV_OPEN, asm, fd=4, path=b"u.o"), ev(m.EV_WRITE, asm, fd=4),
            # A process that never read workspace data: its /tmp write stays private.
            ev(m.EV_FORK, unrelated, aux=FAKE),
            ev(m.EV_OPEN, unrelated, fd=3, path=b"/tmp/unrelated-scratch"), ev(m.EV_WRITE, unrelated, fd=3),
            # Non-temp out-of-workspace writes are never kept, even from a workspace reader.
            ev(m.EV_OPEN, cc1, fd=5, path=b"/etc/whyfs-should-not-appear"), ev(m.EV_WRITE, cc1, fd=5),
        )
        items = self.h.drained()
        paths = {x["path"] for x in items if x["kind"] == "io"}
        self.assertIn(tmp, paths)
        self.assertIn(str(self.root / "u.o"), paths)
        self.assertNotIn("/tmp/unrelated-scratch", paths)
        self.assertNotIn("/etc/whyfs-should-not-appear", paths)

        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), "ebpf-bcc"))
        ingest_events(con, items)
        w = why(con, str(self.root / "u.o"))
        self.assertIn(str(self.root / "u.c"), w["inputs_via_temporaries"])
        imp = {b for _a, b, _e, _r in impact(con, str(self.root / "u.c"))}
        self.assertIn(str(self.root / "u.o"), imp)
        con.close()

    # Bug: a rename was reported as the file's creator and lineage stopped there.
    def test_why_and_impact_follow_rename(self):
        cp, mv = FAKE + 10, FAKE + 11
        items = []
        self.h.feed(
            ev(m.EV_FORK, cp, aux=FAKE),
            ev(m.EV_OPEN, cp, fd=3, path=b"src.txt"), ev(m.EV_READ, cp, fd=3),
            ev(m.EV_OPEN, cp, fd=4, path=b"copy.txt"), ev(m.EV_WRITE, cp, fd=4),
            ev(m.EV_FORK, mv, aux=FAKE),
            ev(m.EV_RENAME, mv, path=b"copy.txt", path2=b"final.txt"),
        )
        items = self.h.drained()
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), "ebpf-bcc"))
        ingest_events(con, items)
        w = why(con, str(self.root / "final.txt"))
        self.assertEqual(w["pid"], cp)
        self.assertEqual(w["inputs"], [str(self.root / "src.txt")])
        self.assertEqual(w["renamed_from"][0]["from"], str(self.root / "copy.txt"))
        imp = {b for _a, b, _e, _r in impact(con, str(self.root / "src.txt"))}
        self.assertIn(str(self.root / "final.txt"), imp)
        con.close()

    def test_v01_database_migrates_in_place(self):
        d = self.root / "legacy"
        (d / ".whyfs").mkdir(parents=True)
        raw = sqlite3.connect(d / ".whyfs" / "whyfs.db")
        raw.executescript(
            "CREATE TABLE runs(id TEXT PRIMARY KEY, started_ns INTEGER NOT NULL, ended_ns INTEGER, cwd TEXT NOT NULL,"
            " command TEXT NOT NULL, exit_code INTEGER, workspace TEXT NOT NULL);"
            "CREATE TABLE processes(run_id TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER, exe TEXT, cwd TEXT,"
            " first_seen_ns INTEGER NOT NULL, PRIMARY KEY(run_id,pid));"
            "CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, ts_ns INTEGER NOT NULL,"
            " pid INTEGER NOT NULL, ppid INTEGER, kind TEXT NOT NULL, path TEXT, path2 TEXT, is_read INTEGER DEFAULT 0,"
            " is_write INTEGER DEFAULT 0, flags INTEGER, api TEXT);"
        )
        raw.close()
        con = connect(d)
        cols = {r[1] for r in con.execute("PRAGMA table_info(processes)")}
        self.assertTrue({"os_pid", "parent_key", "command", "source"} <= cols)
        cols = {r[1] for r in con.execute("PRAGMA table_info(events)")}
        self.assertTrue({"os_pid", "source"} <= cols)
        con.close()


class BpfSourceStaticChecks(unittest.TestCase):
    """The shipped v0.2.0-alpha program never loaded: 572-byte events were built
    on the 512-byte BPF stack.  Guard the construction rules without a kernel."""

    def test_events_are_built_in_ringbuf_reservations(self):
        src = m.BPF_SOURCE
        self.assertIn("ringbuf_reserve", src)
        self.assertNotIn("ringbuf_output", src)
        self.assertNotIn("struct event_t e =", src)
        self.assertNotIn("struct pending_rename_t p =", src)

    def test_path_strings_are_read_at_syscall_exit(self):
        """Reading a path at sys_enter fails (EFAULT, silently) for strings on
        pages not yet faulted in, e.g. .rodata of a freshly exec'd binary.  The
        live test caught this; entry probes must only stage the user pointer."""
        src = m.BPF_SOURCE
        for enter in ("sys_enter_openat)", "sys_enter_chdir)", "sys_enter_renameat2)", "sys_enter_unlinkat)"):
            body = src[src.index(enter):src.index("}", src.index(enter))]
            self.assertNotIn("read_user", body, enter)
        self.assertIn("uptr", src)

    def test_all_open_variants_and_copy_paths_are_traced(self):
        src = m.BPF_SOURCE
        for tp in ("sys_exit_openat", "sys_exit_open", "sys_exit_creat", "sys_exit_openat2",
                   "sys_enter_copy_file_range", "sys_enter_sendfile64", "sys_exit_dup2", "sys_exit_dup3",
                   "sys_enter_close", "sys_exit_chdir", "sys_exit_fchdir", "sched_process_fork"):
            self.assertIn(tp, src)


if __name__ == "__main__":
    unittest.main()
