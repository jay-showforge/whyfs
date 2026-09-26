"""Regression tests for the v0.2 eBPF user-space resolver.

Each test replays a synthetic, kernel-ordered event stream for fake PIDs that do
not exist on this machine, so /proc cannot rescue a wrong model: the resolver
must get the answer from the event stream alone (as it must for short-lived
processes that exit before user space processes their events).

Kernel contract (see ebpf_bcc.BPF_SOURCE): EV_OPEN carries the kernel
``struct file *`` and the absolute path resolved in-kernel; EV_READ/EV_WRITE/
EV_MMAP_* carry only the file pointer; rename/unlink/chdir/exec carry raw names
resolved against the cwd model or a directory file pointer.
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
_ptr = [0xFFFF888000100000]


def new_file() -> int:
    _ptr[0] += 0x100
    return _ptr[0]


def ev(typ, pid, *, file=0, file2=0, fd=-1, dirfd=m.AT_FDCWD, dirfd2=m.AT_FDCWD, flags=0, aux=0,
       path=b"", path2=b"", trunc=0, ts=None):
    e = m.KernelEvent()
    e.ts_ns = ts if ts is not None else time.monotonic_ns()
    e.tgid = pid
    e.tid = pid
    e.aux_pid = aux
    e.type = typ
    e.file = file
    e.file2 = file2
    e.fd = fd
    e.dirfd = dirfd
    e.dirfd2 = dirfd2
    e.flags = flags
    e.truncated = trunc
    ct.memmove(ct.addressof(e) + m.OFF_PATH, path, min(len(path), m.PATH_N))
    ct.memmove(ct.addressof(e) + m.OFF_PATH2, path2, min(len(path2), m.PATH_N))
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

    def p(self, rel: str) -> bytes:
        return str(self.root / rel).encode()

    def writes(self, items):
        return [(x["os_pid"], x["path"]) for x in items if x["kind"] == "io" and x["write"]]

    def reads(self, items):
        return [(x["os_pid"], x["path"]) for x in items if x["kind"] == "io" and x["read"]]

    def touch(self, pid, rel):
        """A workspace write, which makes ``pid`` relevant enough to persist."""
        f = new_file()
        return (ev(m.EV_OPEN, pid, file=f, fd=0, path=self.p(rel), flags=os.O_WRONLY | os.O_CREAT),
                ev(m.EV_WRITE, pid, file=f))

    def db(self, items):
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), "ebpf-bcc"))
        ingest_events(con, items)
        return con

    # Bug: bytes() on a ctypes char array stops at the first NUL -> argv[0] only.
    def test_exec_keeps_full_argv(self):
        child = FAKE + 1
        argv = b"tr\0a-z\0A-Z\0"
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"/usr/bin/tr", path2=argv, fd=len(argv)),
            *self.touch(child, "tr-out.txt"),
        )
        procs = [x for x in self.h.drained() if x["kind"] == "process" and x["os_pid"] == child]
        self.assertEqual(procs[-1]["command"], "tr a-z A-Z")
        self.assertEqual(procs[-1]["exe"], "/usr/bin/tr")

    # Bug: kernel timestamps are CLOCK_MONOTONIC; the store is wall-clock.
    def test_timestamps_are_wall_clock(self):
        self.h.feed(ev(m.EV_OPEN, FAKE, file=new_file(), fd=0, path=self.p("x"), ts=time.monotonic_ns()))
        got = [x for x in self.h.drained() if x["kind"] == "open"][0]
        self.assertLess(abs(got["ts_ns"] - time.time_ns()), 5_000_000_000)

    # Bug: a short-lived child's relative names were resolved via /proc/<pid>/cwd
    # after it had exited.  The cwd model (fork inheritance + chdir) must do it.
    def test_relative_rename_of_exited_child_uses_cwd_model(self):
        child = FAKE + 2
        (self.root / "sub").mkdir()
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_CHDIR, child, path=b"sub"),
            ev(m.EV_RENAME, child, path=b"a.txt", path2=b"b.txt"),
            ev(m.EV_EXIT, child),
        )
        r = [x for x in self.h.drained() if x["kind"] == "rename"][0]
        self.assertEqual((r["path"], r["path2"]), (str(self.root / "sub" / "a.txt"), str(self.root / "sub" / "b.txt")))

    # Bug: exec'd programs whose name is relative ("./tool") after a chdir.
    def test_relative_exec_name_uses_cwd_model(self):
        child = FAKE + 12
        (self.root / "bin").mkdir()
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_CHDIR, child, path=b"bin"),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"./tool", path2=b"./tool\0", fd=7),
            *self.touch(child, "tool-out.txt"),
        )
        procs = [x for x in self.h.drained() if x["kind"] == "process" and x["os_pid"] == child]
        self.assertEqual(procs[-1]["exe"], str(self.root / "bin" / "tool"))

    # Bug (v0.2.0-alpha): shell redirection (open fd3; dup2(3,1); close 3; exec;
    # write fd1) lost the output.  I/O is now keyed by the kernel file object.
    def test_redirected_output_is_attributed_to_the_execd_program(self):
        child, f = FAKE + 3, new_file()
        self.h.feed(
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_OPEN, child, file=f, fd=0, path=self.p("out.txt"), flags=os.O_WRONLY | os.O_CREAT),
            ev(m.EV_EXEC, child, aux=FAKE, path=b"/usr/bin/tr", path2=b"tr\0", fd=3),
            ev(m.EV_WRITE, child, file=f),
        )
        items = self.h.drained()
        self.assertEqual(self.writes(items), [(child, str(self.root / "out.txt"))])
        proc = [x for x in items if x["kind"] == "process" and x["os_pid"] == child][-1]
        self.assertEqual(proc["exe"], "/usr/bin/tr")

    # Bug (v0.2.0-alpha): after close(), a pipe re-using the fd number was
    # attributed to the old file.  Unknown file objects are never guessed.
    def test_io_on_unknown_file_object_is_not_attributed(self):
        f = new_file()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=f, fd=0, path=self.p("input.txt")),
            ev(m.EV_READ, FAKE, file=f),
            ev(m.EV_WRITE, FAKE, file=new_file()),  # some other file object
        )
        items = self.h.drained()
        self.assertEqual(self.writes(items), [])
        self.assertEqual(self.reads(items), [(FAKE, str(self.root / "input.txt"))])

    # The kernel re-uses struct file memory: a new open with the same pointer
    # must replace the old mapping (events are processed in kernel order).
    def test_file_pointer_reuse_follows_the_latest_open(self):
        f = new_file()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=f, fd=0, path=self.p("first.txt")),
            ev(m.EV_READ, FAKE, file=f),
            ev(m.EV_OPEN, FAKE, file=f, fd=0, path=self.p("second.txt")),
            ev(m.EV_WRITE, FAKE, file=f),
        )
        items = self.h.drained()
        self.assertEqual(self.reads(items), [(FAKE, str(self.root / "first.txt"))])
        self.assertEqual(self.writes(items), [(FAKE, str(self.root / "second.txt"))])

    def test_inherited_open_file_is_attributed_to_the_child(self):
        child, f = FAKE + 5, new_file()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=f, fd=0, path=self.p("log.txt")),
            ev(m.EV_FORK, child, aux=FAKE),
            ev(m.EV_WRITE, child, file=f),
        )
        self.assertEqual(self.writes(self.h.drained()), [(child, str(self.root / "log.txt"))])

    # Bug: (run_id, pid) merged distinct processes when the OS re-used a PID.
    def test_pid_reuse_gets_distinct_process_keys(self):
        reused, f1, f2 = FAKE + 6, new_file(), new_file()
        self.h.feed(
            ev(m.EV_FORK, reused, aux=FAKE),
            ev(m.EV_OPEN, reused, file=f1, fd=0, path=self.p("first.txt")),
            ev(m.EV_WRITE, reused, file=f1),
            ev(m.EV_EXIT, reused),
            ev(m.EV_FORK, reused, aux=FAKE),
            ev(m.EV_OPEN, reused, file=f2, fd=0, path=self.p("second.txt")),
            ev(m.EV_WRITE, reused, file=f2),
        )
        w = [(x["pid"], x["path"]) for x in self.h.drained() if x["kind"] == "io" and x["write"]]
        self.assertEqual(len(w), 2)
        self.assertNotEqual(w[0][0], w[1][0], "a re-used PID must not share a process key")
        self.assertTrue(all(k & ((1 << m.PID_BITS) - 1) == reused for k, _ in w))

    # Paths the kernel could not render are counted, never guessed or stored.
    def test_truncated_or_unreadable_open_path_is_not_stored(self):
        f = new_file()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=f, fd=0, path=b"", trunc=m.TRUNC_TOO_LONG),
            ev(m.EV_WRITE, FAKE, file=f),
        )
        self.assertEqual(self.writes(self.h.drained()), [])
        self.assertEqual(self.h.c.stats.truncated_paths, 1)

    # renameat(dirfd, ...) names are resolved against the directory's file object.
    def test_dirfd_relative_rename_uses_directory_file(self):
        d = new_file()
        (self.root / "out").mkdir()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=d, fd=1, path=self.p("out")),
            ev(m.EV_RENAME, FAKE, dirfd=7, file=d, dirfd2=7, file2=d, path=b"tmp.bin", path2=b"final.bin"),
        )
        r = [x for x in self.h.drained() if x["kind"] == "rename"][0]
        self.assertEqual((r["path"], r["path2"]), (str(self.root / "out" / "tmp.bin"), str(self.root / "out" / "final.bin")))

    # Bug: gcc's cc1 -> /tmp/ccXXXX.s -> as chain was cut by workspace filtering.
    def test_derived_temporaries_bridge_lineage_but_nothing_else(self):
        cc1, asm, unrelated = FAKE + 7, FAKE + 8, FAKE + 9
        tmp = os.path.realpath(tempfile.gettempdir()) + "/ccWHYFS.s"
        fu, ft, ft2, fo, fx, fe = (new_file() for _ in range(6))
        self.h.feed(
            ev(m.EV_FORK, cc1, aux=FAKE),
            ev(m.EV_OPEN, cc1, file=fu, fd=0, path=self.p("u.c")), ev(m.EV_READ, cc1, file=fu),
            ev(m.EV_OPEN, cc1, file=ft, fd=0, path=tmp.encode()), ev(m.EV_WRITE, cc1, file=ft),
            ev(m.EV_FORK, asm, aux=FAKE),
            ev(m.EV_OPEN, asm, file=ft2, fd=0, path=tmp.encode()), ev(m.EV_READ, asm, file=ft2),
            ev(m.EV_OPEN, asm, file=fo, fd=0, path=self.p("u.o")), ev(m.EV_WRITE, asm, file=fo),
            # A process that never read workspace data: its /tmp write stays private.
            ev(m.EV_FORK, unrelated, aux=FAKE),
            ev(m.EV_OPEN, unrelated, file=fx, fd=0, path=b"/tmp/unrelated-scratch"), ev(m.EV_WRITE, unrelated, file=fx),
            # Non-temp out-of-workspace writes are never kept, even from a workspace reader.
            ev(m.EV_OPEN, cc1, file=fe, fd=0, path=b"/etc/whyfs-should-not-appear"), ev(m.EV_WRITE, cc1, file=fe),
        )
        items = self.h.drained()
        paths = {x["path"] for x in items if x["kind"] == "io"}
        self.assertIn(tmp, paths)
        self.assertIn(str(self.root / "u.o"), paths)
        self.assertNotIn("/tmp/unrelated-scratch", paths)
        self.assertNotIn("/etc/whyfs-should-not-appear", paths)
        con = self.db(items)
        w = why(con, str(self.root / "u.o"))
        self.assertIn(str(self.root / "u.c"), w["inputs_via_temporaries"])
        imp = {b for _a, b, _e, _r in impact(con, str(self.root / "u.c"))}
        self.assertIn(str(self.root / "u.o"), imp)
        con.close()

    # Bug: a rename was reported as the file's creator and lineage stopped there.
    def test_why_and_impact_follow_rename(self):
        cp, mv, fs, fc = FAKE + 10, FAKE + 11, new_file(), new_file()
        self.h.feed(
            ev(m.EV_FORK, cp, aux=FAKE),
            ev(m.EV_OPEN, cp, file=fs, fd=0, path=self.p("src.txt")), ev(m.EV_READ, cp, file=fs),
            ev(m.EV_OPEN, cp, file=fc, fd=0, path=self.p("copy.txt")), ev(m.EV_WRITE, cp, file=fc),
            ev(m.EV_FORK, mv, aux=FAKE),
            ev(m.EV_RENAME, mv, path=b"copy.txt", path2=b"final.txt"),
        )
        con = self.db(self.h.drained())
        w = why(con, str(self.root / "final.txt"))
        self.assertEqual(w["pid"], cp)
        self.assertEqual(w["inputs"], [str(self.root / "src.txt")])
        self.assertEqual(w["renamed_from"][0]["from"], str(self.root / "copy.txt"))
        imp = {b for _a, b, _e, _r in impact(con, str(self.root / "src.txt"))}
        self.assertIn(str(self.root / "final.txt"), imp)
        con.close()

    # Bug: runuser -> env -> bash -> python is ONE process with several images;
    # why() merged /etc/passwd (read by runuser) into python's inputs.
    def test_why_counts_only_reads_of_the_writing_program_image(self):
        proc, fpw, fin, fout = FAKE + 13, new_file(), new_file(), new_file()
        self.h.feed(
            ev(m.EV_FORK, proc, aux=FAKE),
            ev(m.EV_OPEN, proc, file=fpw, fd=0, path=self.p("pre-exec-config.txt")), ev(m.EV_READ, proc, file=fpw),
            ev(m.EV_EXEC, proc, aux=FAKE, path=b"/usr/bin/python3", path2=b"python3\0job.py\0", fd=15),
            ev(m.EV_OPEN, proc, file=fin, fd=0, path=self.p("in.txt")), ev(m.EV_READ, proc, file=fin),
            ev(m.EV_OPEN, proc, file=fout, fd=0, path=self.p("out.txt")), ev(m.EV_WRITE, proc, file=fout),
        )
        items = self.h.drained()
        self.assertTrue(any(x["kind"] == "exec" for x in items), "exec boundary must be stored as raw evidence")
        con = self.db(items)
        w = why(con, str(self.root / "out.txt"))
        self.assertEqual(w["inputs"], [str(self.root / "in.txt")])
        con.close()

    # Bug: impact() attributed every write of a long-lived reader, including
    # writes made *before* it read the file.
    def test_impact_respects_read_before_write_order(self):
        fa, fb, fc = new_file(), new_file(), new_file()
        self.h.feed(
            ev(m.EV_OPEN, FAKE, file=fa, fd=0, path=self.p("earlier.txt")), ev(m.EV_WRITE, FAKE, file=fa),
            ev(m.EV_OPEN, FAKE, file=fb, fd=0, path=self.p("input.txt")), ev(m.EV_READ, FAKE, file=fb),
            ev(m.EV_OPEN, FAKE, file=fc, fd=0, path=self.p("later.txt")), ev(m.EV_WRITE, FAKE, file=fc),
        )
        con = self.db(self.h.drained())
        imp = {b for _a, b, _e, _r in impact(con, str(self.root / "input.txt"))}
        self.assertEqual(imp, {str(self.root / "later.txt")})
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


class ProcessPrivacyTests(unittest.TestCase):
    """The kernel sees every process in the namespace; preload only ever saw
    the traced command tree.  Process rows (command lines) and exec boundaries
    must be persisted only for processes that produced stored evidence, plus a
    bounded ancestor chain for parentage."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.h = Harness(self.root)

    def tearDown(self):
        self.td.cleanup()

    def touch_by(self, pid):
        f = new_file()
        return (ev(m.EV_OPEN, pid, file=f, fd=0, path=str(self.root / f"o{pid}").encode(), flags=os.O_WRONLY),
                ev(m.EV_WRITE, pid, file=f))

    def test_unrelated_process_command_line_is_not_stored(self):
        other = FAKE + 40
        f = new_file()
        self.h.feed(
            ev(m.EV_FORK, other, aux=FAKE),
            ev(m.EV_EXEC, other, aux=FAKE, path=b"/usr/bin/mysql",
               path2=b"mysql\0-u\0admin\0secretdb\0", fd=26),
            ev(m.EV_OPEN, other, file=f, fd=0, path=b"/home/someone/.my.cnf"),
            ev(m.EV_READ, other, file=f),
            ev(m.EV_EXIT, other),
        )
        items = self.h.drained()
        self.assertEqual([x for x in items if x.get("os_pid") == other], [])
        self.assertNotIn("secretdb", repr(items))
        self.assertEqual(self.h.c.pending_exec, {})

    def test_writer_and_its_ancestors_are_persisted_with_exec_boundaries(self):
        make, cc = FAKE + 41, FAKE + 42
        f = new_file()
        self.h.feed(
            ev(m.EV_FORK, make, aux=FAKE),
            ev(m.EV_EXEC, make, aux=FAKE, path=b"/usr/bin/make", path2=b"make\0-j8\0", fd=9),
            ev(m.EV_FORK, cc, aux=make),
            ev(m.EV_EXEC, cc, aux=make, path=b"/usr/bin/cc", path2=b"cc\0-c\0a.c\0", fd=12),
            ev(m.EV_OPEN, cc, file=f, fd=0, path=str(self.root / "a.o").encode(), flags=os.O_WRONLY),
            ev(m.EV_WRITE, cc, file=f),
        )
        items = self.h.drained()
        procs = {}
        for x in items:
            if x["kind"] == "process":
                procs[x["os_pid"]] = x
        self.assertEqual(procs[cc]["command"], "cc -c a.c")
        self.assertEqual(procs[make]["command"], "make -j8")
        self.assertEqual(procs[cc]["parent_key"], procs[make]["pid"])
        execs = [x for x in items if x["kind"] == "exec" and x["os_pid"] == cc]
        writes = [x for x in items if x["kind"] == "io" and x["write"]]
        self.assertEqual(len(execs), 1)
        self.assertLess(execs[0]["ts_ns"], writes[0]["ts_ns"])
        # Persisted before the evidence that made it relevant.
        self.assertLess(items.index(procs[cc]), items.index(writes[0]))

    def test_ancestor_chain_is_bounded(self):
        chain = [FAKE + 100 + i for i in range(20)]
        parent = FAKE
        for pid in chain:
            self.h.feed(ev(m.EV_FORK, pid, aux=parent),
                        ev(m.EV_EXEC, pid, aux=parent, path=b"/bin/sh", path2=b"sh\0", fd=3))
            parent = pid
        self.h.feed(*self.touch_by(chain[-1]))
        procs = {x["os_pid"] for x in self.h.drained() if x["kind"] == "process"}
        self.assertEqual(len(procs), m.BCCCollector.MAX_ANCESTORS + 1)
        self.assertIn(chain[-1], procs)
        self.assertNotIn(chain[0], procs)

    def test_relevant_process_later_exec_is_stored_immediately(self):
        p = FAKE + 43
        self.h.feed(ev(m.EV_FORK, p, aux=FAKE), *self.touch_by(p),
                    ev(m.EV_EXEC, p, aux=FAKE, path=b"/usr/bin/tr", path2=b"tr\0", fd=3))
        procs = [x for x in self.h.drained() if x["kind"] == "process" and x["os_pid"] == p]
        self.assertEqual(procs[-1]["exe"], "/usr/bin/tr")


class StateDirectoryHardeningTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()

    def tearDown(self):
        self.td.cleanup()

    def test_symlinked_state_directory_is_refused(self):
        from whyfs import privsep
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (self.root / ".whyfs").symlink_to(elsewhere)
        with self.assertRaises(PermissionError):
            connect(self.root)
        with self.assertRaises(PermissionError):
            privsep.open_state_dirfd(self.root)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_symlinked_database_file_is_refused(self):
        (self.root / ".whyfs").mkdir()
        victim = self.root / "victim"
        victim.write_text("keep")
        (self.root / ".whyfs" / "whyfs.db").symlink_to(victim)
        with self.assertRaises(PermissionError):
            connect(self.root)
        self.assertEqual(victim.read_text(), "keep")

    def test_symlinked_daemon_state_file_is_not_followed(self):
        from whyfs import privsep
        (self.root / ".whyfs").mkdir()
        victim = self.root / "victim"
        victim.write_text("keep")
        (self.root / ".whyfs" / "daemon.json.tmp").symlink_to(victim)
        with self.assertRaises(OSError):
            privsep.replace_state_file(self.root, "daemon.json", b"{}")
        self.assertEqual(victim.read_text(), "keep")

    def test_state_is_private(self):
        connect(self.root).close()
        d = self.root / ".whyfs"
        self.assertEqual(d.stat().st_mode & 0o777, 0o700)
        self.assertEqual((d / "whyfs.db").stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root")
    def test_root_daemon_store_runs_as_workspace_owner(self):
        from whyfs import privsep
        uid, gid = 65534, 65534  # nobody
        os.chown(self.root, uid, gid)
        store = privsep.Store(self.root).start()
        self.assertTrue(store.privsep)
        store.call("begin_run", "r1", 1, str(self.root))
        n = store.ingest([{"run_id": "r1", "ts_ns": 2, "kind": "open", "pid": 7,
                           "path": str(self.root / "x"), "source": "ebpf"}])
        store.call("end_run", "r1", 3, 0, {"kernel_drops": 0})
        store.close()
        self.assertEqual(n, 1)
        d = self.root / ".whyfs"
        for p in [d, *d.iterdir()]:
            st = p.lstat()
            self.assertEqual((st.st_uid, st.st_gid), (uid, gid), p)
            self.assertEqual(st.st_mode & 0o077, 0, p)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root")
    def test_root_owned_state_left_by_older_run_is_adopted_without_following_links(self):
        # Found by the graduation harness: a .whyfs created earlier by root made
        # the unprivileged store worker fail with "unable to open database file".
        from whyfs import privsep
        uid, gid = 65534, 65534
        connect(self.root).close()  # root-owned .whyfs and whyfs.db
        victim = Path(self.td.name + "-victim")
        victim.write_text("keep")
        self.addCleanup(victim.unlink)
        (self.root / ".whyfs" / "planted").symlink_to(victim)
        os.chown(self.root, uid, gid)
        store = privsep.Store(self.root).start()
        store.call("begin_run", "r2", 1, str(self.root))
        store.close()
        self.assertEqual((self.root / ".whyfs" / "whyfs.db").stat().st_uid, uid)
        self.assertEqual(victim.stat().st_uid, 0, "a symlink target must never be chowned")


class BpfSourceStaticChecks(unittest.TestCase):
    """Guard kernel-program construction rules without needing a kernel."""

    def test_events_are_built_in_ringbuf_reservations(self):
        # The shipped v0.2.0-alpha program never loaded: 572-byte events were
        # built on the 512-byte BPF stack.
        src = m.BPF_SOURCE
        self.assertIn("ringbuf_reserve", src)
        self.assertNotIn("ringbuf_output", src)
        self.assertNotIn("struct event_t e =", src)
        self.assertNotIn("struct path_ev e =", src)

    def test_file_io_is_observed_at_the_vfs_layer(self):
        # Syscall tracepoints are blind to io_uring (libuv >= 1.45 / Node):
        # a real Vite build issued 97 io_uring file requests invisible to them.
        src = m.BPF_SOURCE
        for hook in ("KFUNC_PROBE(security_file_open", "KFUNC_PROBE(security_file_permission",
                     "KFUNC_PROBE(security_mmap_file", "KFUNC_PROBE(do_renameat2", "KRETFUNC_PROBE(do_renameat2",
                     "KFUNC_PROBE(do_unlinkat", "KRETFUNC_PROBE(do_unlinkat", "bpf_d_path"):
            self.assertIn(hook, src)
        for gone in ("sys_enter_read)", "sys_enter_write)", "sys_enter_openat)"):
            self.assertNotIn(gone, src)

    def test_user_strings_are_read_at_syscall_exit(self):
        # Reading at sys_enter fails (EFAULT, silently) for strings on pages not
        # yet faulted in, e.g. .rodata of a freshly exec'd binary.
        src = m.BPF_SOURCE
        body = src[src.index("sys_enter_chdir)"):src.index("}", src.index("sys_enter_chdir)"))]
        self.assertNotIn("read_user", body)
        self.assertIn("wf_read_ustr(e->path, *uptr", src)

    def test_ring_buffer_does_not_wake_the_collector_per_event(self):
        # A wakeup per event cost the traced workload an irq_work and a context
        # switch per file (>10% on exec-heavy builds).
        src = m.BPF_SOURCE
        self.assertNotIn("ringbuf_submit(e, 0)", src)
        self.assertIn("BPF_RB_NO_WAKEUP", src)
        self.assertIn("BPF_RB_FORCE_WAKEUP", src)

    def test_pids_are_namespace_relative(self):
        src = m.BPF_SOURCE
        self.assertIn("NS_INUM", src)
        self.assertIn("wf_task_ns_tgid", src)
        # Fast path for the collector's own namespace; the upid walk must stay
        # as the fallback for tasks in nested namespaces (containers).
        body = src[src.index("wf_cur_tgid(void)"):]
        body = body[:body.index("\n}")]
        self.assertIn("bpf_get_ns_current_pid_tgid(NS_DEV, NS_INUM", body)
        self.assertIn("return wf_task_ns_tgid(", body)

    def test_io_dedup_is_reset_by_one_delete_per_open(self):
        src = m.BPF_SOURCE
        body = src[src.index("KFUNC_PROBE(security_file_open"):]
        body = body[:body.index("\n}")]
        self.assertEqual(body.count("io_seen.delete"), 1)


if __name__ == "__main__":
    unittest.main()
