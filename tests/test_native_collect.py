"""The native collector (src/whyfs/native/whyfs-collect.c) must implement exactly the
event model of BCCCollector._process_event, which stays the executable specification.

* Every resolver-regression and process-privacy test re-runs on the native collector.
* Differential fuzzing: random kernel-ordered streams (forks, execs with hostile argv,
  opens/io on workspace/temp/outside files, symlinked directories, '..', renames,
  unlinks, chdir/fchdir, exits, PID reuse, file-pointer reuse, non-UTF-8 names) go
  through both implementations; the handed-off records and counters must be identical.
* The native writer's SQLite rows equal store.ingest_events() of the same records.
"""
import ctypes as ct
import os
import random
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import whyfs.ebpf_bcc as m
from whyfs import native_collect
from whyfs.store import connect, ingest_events

import test_ebpf_resolver as base

OK, WHY = native_collect.available()
TMPDIR = None  # a real temp-root directory for derived-temporary paths


def setUpModule():
    global TMPDIR
    TMPDIR = tempfile.TemporaryDirectory(prefix="whyfs-diff-", dir=os.path.realpath(tempfile.gettempdir()))


def tearDownModule():
    TMPDIR.cleanup()


class NativeHarness:
    """base.Harness API on the native collector: feed() collects raw ring payloads;
    drained() replays the whole stream so far and returns the records not yet returned."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.events: list[bytes] = []
        self.returned = 0
        self.temp_roots = m.BCCCollector(self.root, "run").temp_roots
        self.c = SimpleNamespace(stats=None, pending_exec=None)

    def feed(self, *events):
        self.events += [bytes(e) for e in events]

    def drained(self):
        recs, stats = native_collect.replay(self.events, root=self.root, temp_roots=self.temp_roots,
                                            seeds=[(base.FAKE, self.root)])
        self.c.stats = SimpleNamespace(**stats)
        self.c.pending_exec = {} if stats["pending_exec"] == 0 else {"pending": stats["pending_exec"]}
        out, self.returned = recs[self.returned:], len(recs)
        return out


@unittest.skipUnless(OK, f"native collector unavailable: {WHY}")
class NativeResolverRegressionTests(base.ResolverRegressionTests):
    harness_cls = NativeHarness


@unittest.skipUnless(OK, f"native collector unavailable: {WHY}")
class NativeProcessPrivacyTests(base.ProcessPrivacyTests):
    harness_cls = NativeHarness


# ---------------------------------------------------------------- differential
STAT_KEYS = ("submitted", "filtered", "unresolved_fd", "truncated_paths", "queue_drops", "received",
             "proc_fallbacks", "unreadable_paths")


def python_run(root, raw, clock_offset, seeds, capture_all=False):
    c = m.BCCCollector(root, "run", capture_all=capture_all)
    c.clock_offset = clock_offset
    for pid, cwd in seeds:
        c.pkey[pid] = pid
        c.cwd[pid] = str(cwd)
    buf = ct.create_string_buffer(m.ct.sizeof(m.KernelEvent) + 16)
    for r in raw:
        ct.memmove(buf, r, len(r))
        c._process_event(None, ct.addressof(buf), len(r))
    c.flush_pending()
    out = []
    while not c.q.empty():
        out.extend(c.q.get_nowait())
    return out, {k: int(getattr(c.stats, k)) for k in STAT_KEYS}, c


def mask_announce_ts(recs):
    """Rows announced from /proc carry time.time_ns() at announcement; everything
    else is derived from kernel timestamps and must match exactly."""
    # Announced (pre-existing) processes keep key == pid; forked ones get seq << PID_BITS.
    return [dict(x, ts_ns=0) if x["kind"] == "process" and x["pid"] < (1 << m.PID_BITS) else x for x in recs]


class StreamGen:
    """Random but kernel-plausible event streams over a small hostile file tree."""

    ARGS = [b"make", b"-j8", b"--token", b"hunter2", b"--password=pw", b"API_KEY=x", b"a b", b"it's", b"",
            b"\xff\xfe", b"caf\xc3\xa9", b"\xe2\x84\xaaEY=1", b"--Authorization", b"Bearer", b"x=y=z",
            b"\xe2\x82", b"\xf0\x9f\x98\x80", b"$(rm -rf)", b"--apikey", b"SECRET_FILE=/etc/x",
            # U+212A KELVIN SIGN lowers to 'k'; U+0130 lowers to 'i' + U+0307 (must not match)
            b"API\xe2\x84\xaaEY=abc", b"--TO\xe2\x84\xaaEN", b"to\xe2\x84\xaaen", b"\xc4\xb0TOKEN", b"AUTHOR\xc4\xb0ZATION=1"]

    def __init__(self, root: Path, rnd: random.Random):
        self.root, self.r = root, rnd
        self.tmpdir = Path(TMPDIR.name)
        for d in ("sub", "sub/deep", "real", "out", ".whyfs", "sub/.whyfs"):
            (root / d).mkdir(parents=True, exist_ok=True)
        if not (root / "alias").exists():
            os.symlink(root / "real", root / "alias")
            os.symlink(root / "sub" / "deep", root / "dl")
            os.symlink(root / "loop1", root / "loop2")
            os.symlink(root / "loop2", root / "loop1")
            os.symlink("../real", root / "sub" / "rel")
            (root / "real" / "tool").write_text("#!/bin/sh\n")
            os.symlink(root / "real" / "tool", root / "toollink")
        self.names = [b"a.txt", b"b.txt", b"sub/c.txt", b"alias/d.txt", b"dl/../e.txt", b"../x.txt", b"./f.txt",
                      b"sub/rel/g.txt", b"loop1/h", b"sub/", b".", b"..", b"out/o.bin", b"n\xffu.txt", b"toollink",
                      b"real/tool", b"sub//c.txt", b"dl/..", b"alias/../a.txt", b".whyfs/daemon.json", b".whyfs/../y.txt"]
        self.abs_paths = [str(root / "a.txt").encode(), str(root / "sub" / "c.txt").encode(), str(root / "out").encode(),
                          str(root / "real").encode(), str(self.tmpdir / "cc1.s").encode(), str(self.tmpdir / "cc2.o").encode(),
                          b"/etc/hostname", b"/usr/lib/x.so", str(root / "n\udcff.txt").encode("utf-8", "surrogateescape"),
                          str(root).encode() + b"/./sub/../a.txt", str(root).encode() + b"x/sibling.txt", b"relative/path",
                          str(root / "alias" / "d.txt").encode(), str(root / "out" / "o.bin").encode(),
                          str(root / ".whyfs" / "whyfs.db").encode(), str(root / "sub" / ".whyfs" / "u.txt").encode()]
        self.pids = [base.FAKE] + [base.FAKE + i for i in range(1, 7)]
        self.files = [0xFFFF888000200000 + 0x100 * i for i in range(12)]
        self.ts = time.monotonic_ns()

    def ev(self, typ, pid, **kw):
        self.ts += self.r.randint(1, 5000)
        return bytes(base.ev(typ, pid, ts=self.ts, **kw))

    def stream(self, n):
        R, out = self.r, []
        for _ in range(n):
            pid = R.choice(self.pids)
            op = R.random()
            if op < 0.08:
                out.append(self.ev(m.EV_FORK, pid, aux=R.choice(self.pids + [0])))
            elif op < 0.16:
                argv = b"\0".join(R.choice(self.ARGS) for _ in range(R.randint(0, 6))) + b"\0"
                fd = R.choice([len(argv), len(argv) - 1, 0, -3, 600])
                path = R.choice(self.names + self.abs_paths + [b"", b"/usr/bin/tr"])
                out.append(self.ev(m.EV_EXEC, pid, aux=R.choice(self.pids + [0]), path=path, path2=argv, fd=fd))
            elif op < 0.40:
                f = R.choice(self.files)
                trunc = R.choice([0] * 12 + [1, 2, 3])
                out.append(self.ev(m.EV_OPEN, pid, file=f, fd=R.choice([0, 0, 0, 1]), path=R.choice(self.abs_paths),
                                   flags=R.choice([0, os.O_WRONLY | os.O_CREAT, os.O_RDWR]), trunc=trunc))
            elif op < 0.65:
                out.append(self.ev(R.choice([m.EV_READ, m.EV_WRITE, m.EV_MMAP_READ, m.EV_MMAP_WRITE]), pid,
                                   file=R.choice(self.files + [0xDEAD])))
            elif op < 0.73:
                d1, d2 = R.choice([m.AT_FDCWD, m.AT_FDCWD, 5]), R.choice([m.AT_FDCWD, m.AT_FDCWD, 6])
                out.append(self.ev(m.EV_RENAME, pid, dirfd=d1, dirfd2=d2, file=R.choice(self.files), file2=R.choice(self.files),
                                   path=R.choice(self.names + self.abs_paths), path2=R.choice(self.names + self.abs_paths)))
            elif op < 0.80:
                out.append(self.ev(m.EV_UNLINK, pid, dirfd=R.choice([m.AT_FDCWD, 5]), file=R.choice(self.files),
                                   path=R.choice(self.names + self.abs_paths)))
            elif op < 0.87:
                out.append(self.ev(m.EV_CHDIR, pid, path=R.choice(self.names + self.abs_paths)))
            elif op < 0.91:
                out.append(self.ev(m.EV_FCHDIR, pid, file=R.choice(self.files)))
            elif op < 0.97:
                out.append(self.ev(m.EV_EXIT, pid))
            else:
                out.append(self.ev(99, pid))  # unknown record type: ignored by both
        # the ring hands out short records too: header-only I/O, one-path records
        return [r[: R.choice([len(r), len(r), m.HDR_SIZE, m.OFF_PATH2, m.HDR_SIZE + 7])] for r in out]


@unittest.skipUnless(OK, f"native collector unavailable: {WHY}")
class DifferentialTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()

    def tearDown(self):
        self.td.cleanup()

    def compare(self, raw, *, capture_all=False, seeds=None):
        seeds = seeds if seeds is not None else [(base.FAKE, self.root)]
        py, pst, c = python_run(self.root, raw, 1_700_000_000_000_000_000, seeds, capture_all)
        nat, nst = native_collect.replay(raw, root=self.root, temp_roots=c.temp_roots, seeds=seeds,
                                         clock_offset=1_700_000_000_000_000_000, capture_all=capture_all)
        self.assertEqual(len(py), len(nat))
        for i, (a, b) in enumerate(zip(mask_announce_ts(py), mask_announce_ts(nat))):
            self.assertEqual(a, b, f"record {i} differs")
        self.assertEqual(pst, {k: nst[k] for k in STAT_KEYS})
        self.assertEqual(len(c.pending_exec), nst["pending_exec"])
        return py

    def test_random_streams_are_identical(self):
        total = 0
        for seed in range(250):
            g = StreamGen(self.root, random.Random(seed))
            total += len(self.compare(g.stream(160), capture_all=seed % 10 == 9))
        self.assertGreater(total, 3000, "the fuzzer must exercise stored evidence, not only filtering")

    def test_long_stream_with_many_processes(self):
        g = StreamGen(self.root, random.Random(12345))
        g.pids = [base.FAKE + i for i in range(40)]
        self.compare(g.stream(6000))

    def test_writer_rows_equal_python_ingest(self):
        g = StreamGen(self.root, random.Random(7))
        raw = g.stream(1500)
        py, _pst, c = python_run(self.root, raw, 1_700_000_000_000_000_000, [(base.FAKE, self.root)])
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), "ebpf-native"))
        con.commit()
        con.close()
        import subprocess
        with tempfile.NamedTemporaryFile(delete=False) as f:
            for r in raw:
                f.write(len(r).to_bytes(4, "little") + r)
        try:
            args = [str(native_collect.binary()), "--replay", f.name, "--root", str(self.root), "--run-id", "run",
                    "--seed", f"{base.FAKE}:{self.root}", "--clock-offset", "1700000000000000000"]
            for t in c.temp_roots:
                args += ["--temp-root", t]
            p = subprocess.run(args, capture_output=True, text=True)
        finally:
            os.unlink(f.name)
        self.assertEqual(p.returncode, 0, p.stderr)
        import json
        st = json.loads(p.stdout.splitlines()[-1])
        self.assertEqual(st["writer_rows"], len(py))
        with tempfile.TemporaryDirectory() as td2:
            ref = connect(Path(td2))
            ref.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                        (str(self.root), "t", str(self.root), "ebpf-native"))
            # surrogate-escaped (non-UTF-8) names: Python's sqlite3 cannot bind them; store the raw bytes
            # the way the native writer does, so the comparison covers them too.
            ref.text_factory = bytes
            ref.row_factory = None
            fixed = [{k: (v.encode("utf-8", "surrogateescape").decode("utf-8", "replace") if isinstance(v, str) else v)
                      for k, v in x.items()} for x in py]
            ingest_events(ref, fixed)
            want_ev = ref.execute("SELECT ts_ns,pid,ppid,kind,path,path2,is_read,is_write,flags,api,source,os_pid FROM events ORDER BY id").fetchall()
            want_pr = ref.execute("SELECT pid,ppid,exe,cwd,command,source,first_seen_ns,os_pid,parent_key FROM processes ORDER BY pid").fetchall()
            ref.close()
        got = sqlite3.connect(self.root / ".whyfs" / "whyfs.db")
        got.text_factory = lambda b: b.decode("utf-8", "replace").encode()
        got_ev = got.execute("SELECT ts_ns,pid,ppid,kind,path,path2,is_read,is_write,flags,api,source,os_pid FROM events ORDER BY id").fetchall()
        got_pr = got.execute("SELECT pid,ppid,exe,cwd,command,source,first_seen_ns,os_pid,parent_key FROM processes ORDER BY pid").fetchall()
        got.close()
        strip = lambda rows: [r[:6] + (0,) + r[7:] if r[0] < (1 << m.PID_BITS) else r for r in rows]  # noqa: E731
        self.assertEqual(got_ev, want_ev)
        self.assertEqual(strip(got_pr), strip(want_pr))


if __name__ == "__main__":
    unittest.main()
