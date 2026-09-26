import ctypes as ct
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from whyfs.daemon import capability_report
from whyfs.ebpf_bcc import BCCCollector, EV_OPEN, EV_READ, EV_WRITE, KernelEvent
from whyfs.store import connect, ingest_events


class EbpfUserspaceTests(unittest.TestCase):
    def test_fd_resolution_and_workspace_filtering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            p = root / "data.txt"
            p.write_text("hello")
            collector = BCCCollector(root, "test-run")
            fd = os.open(p, os.O_RDONLY)
            try:
                e = KernelEvent()
                e.ts_ns = time.time_ns()
                e.tgid = os.getpid()
                e.tid = os.getpid()
                e.type = EV_OPEN
                e.fd = fd
                e.dirfd = -100
                e.flags = os.O_RDONLY
                e.path = b"data.txt"
                collector._process_event(None, ct.addressof(e), ct.sizeof(e))

                r = KernelEvent()
                r.ts_ns = time.time_ns()
                r.tgid = os.getpid()
                r.tid = os.getpid()
                r.type = EV_READ
                r.fd = fd
                collector._process_event(None, ct.addressof(r), ct.sizeof(r))
            finally:
                os.close(fd)

            got = [collector.q.get_nowait(), collector.q.get_nowait()]
            self.assertEqual(got[0]["kind"], "open")
            self.assertEqual(got[0]["path"], str(p))
            self.assertEqual(got[1]["kind"], "io")
            self.assertTrue(got[1]["read"])
            self.assertEqual(got[1]["path"], str(p))

    def test_outside_workspace_filtered(self):
        with tempfile.TemporaryDirectory() as td, tempfile.NamedTemporaryFile() as outside:
            root = Path(td).resolve()
            collector = BCCCollector(root, "test-run")
            e = KernelEvent()
            e.ts_ns = time.time_ns()
            e.tgid = os.getpid()
            e.tid = os.getpid()
            e.type = EV_OPEN
            e.fd = outside.file.fileno()
            e.dirfd = -100
            e.flags = os.O_RDONLY
            collector._process_event(None, ct.addressof(e), ct.sizeof(e))
            self.assertTrue(collector.q.empty())
            self.assertEqual(collector.stats.filtered, 1)

    def test_batched_ingest_preserves_raw_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            con = connect(root)
            con.execute(
                "INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                ("r", 1, str(root), "test", str(root), "ebpf-bcc"),
            )
            events = [
                {"run_id": "r", "ts_ns": 2, "kind": "process", "pid": 10, "ppid": 1,
                 "exe": "/bin/test", "cwd": str(root), "command": "test --x", "source": "ebpf"},
                {"run_id": "r", "ts_ns": 3, "kind": "io", "pid": 10, "ppid": 1,
                 "path": str(root / "a"), "read": True, "write": False, "api": "ebpf:rw", "source": "ebpf"},
                {"run_id": "r", "ts_ns": 4, "kind": "io", "pid": 10, "ppid": 1,
                 "path": str(root / "b"), "read": False, "write": True, "api": "ebpf:rw", "source": "ebpf"},
            ]
            self.assertEqual(ingest_events(con, events), 3)
            pr = con.execute("SELECT command,source FROM processes WHERE run_id='r' AND pid=10").fetchone()
            self.assertEqual(pr["command"], "test --x")
            self.assertEqual(pr["source"], "ebpf")
            rows = con.execute("SELECT is_read,is_write,source FROM events ORDER BY ts_ns").fetchall()
            self.assertEqual([(r["is_read"], r["is_write"]) for r in rows], [(1, 0), (0, 1)])
            self.assertTrue(all(r["source"] == "ebpf" for r in rows))
            con.close()

    def test_doctor_is_machine_readable(self):
        report = capability_report()
        for key in ("linux", "bcc_importable", "bpf_fs", "cap_bpf", "cap_perfmon", "ready"):
            self.assertIn(key, report)
        self.assertIsInstance(report["ready"], bool)


if __name__ == "__main__":
    unittest.main()
