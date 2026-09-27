"""Observation integrity over synthetic stores (the forced-outage scenario, query side):
a crashed run is closed at its last heartbeat and becomes a recorded gap; a file created before
the outage keeps a complete origin; a file that appeared during the gap gets no creator and its
label says it appeared while whyfs was not recording; a file created after recovery is complete.
The live version of the scenario, with a real kill and restart, is scripts/outage_gate.py.
"""
import os
import tempfile
import time
import unittest
from pathlib import Path

from whyfs import api, label, observation
from whyfs.store import connect, ingest_events

S = 10**9
U1 = "S-1-5-21-1-2-3-1001" if os.name == "nt" else "uid:1001"
PY = r"C:\Python313\python.exe" if os.name == "nt" else "/usr/bin/python3"


class OutageTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.con = connect(self.root)
        now = time.time_ns()
        self.t0 = now - 600 * S           # run r1 starts 10 minutes ago
        self.crash = now - 300 * S        # r1's last heartbeat: it was killed after this
        self.restart = now - 240 * S      # r2 starts 60 s later
        self.k = 100

    def tearDown(self):
        self.con.close()
        self.td.cleanup()

    def run_row(self, rid, start):
        self.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                         (rid, start, str(self.root), "t", str(self.root), "test"))
        self.con.commit()

    def write(self, run, name, ts):
        self.k += 1
        ingest_events(self.con, [{"run_id": run, "kind": "process", "pid": self.k, "os_pid": self.k, "ts_ns": ts - S,
                                  "ppid": None, "parent_key": None, "exe": PY, "cwd": str(self.root),
                                  "command": f"python make_{name}", "source": "test", "user": U1}])
        f = self.root / name
        f.write_text(name)
        os.utime(f, ns=(ts, ts))
        ingest_events(self.con, [{"run_id": run, "kind": "io", "pid": self.k, "os_pid": self.k, "ts_ns": ts,
                                  "path": str(f), "source": "test", "read": False, "write": True, "api": "ebpf:rw",
                                  "file_id": label.current_file_id(str(f))}])
        return f

    def scenario(self):
        self.run_row("r1", self.t0)
        a = self.write("r1", "A.txt", self.t0 + 60 * S)
        observation.heartbeat(self.con, "r1")
        self.con.execute("UPDATE collector_stats SET value=? WHERE run_id='r1' AND key=?",
                         (self.crash, observation.HEARTBEAT_KEY))
        self.con.commit()
        # r1 is killed: no end is recorded.  File B appears while nothing is recording.
        b = self.root / "B.txt"
        b.write_text("b")
        t_b = self.crash + 20 * S
        os.utime(b, ns=(t_b, t_b))
        # recovery: the next run closes r1 at its last heartbeat
        closed = observation.close_unclean_runs(self.con)
        self.run_row("r2", self.restart)
        observation.heartbeat(self.con, "r2")
        c = self.write("r2", "C.txt", self.restart + 30 * S)
        return a, b, c, closed

    def test_crashed_run_is_closed_at_its_last_heartbeat(self):
        _a, _b, _c, closed = self.scenario()
        self.assertEqual(closed, ["r1"])
        end, code = self.con.execute("SELECT ended_ns, exit_code FROM runs WHERE id='r1'").fetchone()
        self.assertEqual(end, self.crash)
        self.assertEqual(code, -1)
        ivs = observation.intervals(self.con)
        self.assertTrue(ivs[0]["unclean"])
        gaps = observation.gaps(ivs, self.t0)
        self.assertEqual(len(gaps), 1)
        self.assertEqual((gaps[0]["from"], gaps[0]["to"]), (self.crash, self.restart))
        self.assertTrue(gaps[0]["after_crash"])

    def test_file_a_complete_file_b_unknown_file_c_complete(self):
        a, b, c = self.scenario()[:3]
        la, lb_, lc = (label.explain_file(self.con, str(p)) for p in (a, b, c))
        # A: created while recording without loss -> complete origin; the outage is a later gap
        self.assertEqual(la["status"], "labelled")
        self.assertTrue(la["observation"]["complete"], la["observation"])
        self.assertTrue(any("stopped unexpectedly" in g for g in la["observation"]["later_gaps"]), la["observation"])
        # B: appeared during the gap -> no creator, and the label says why
        self.assertEqual(lb_["status"], "no-record")
        self.assertNotIn("created_by", lb_)
        self.assertFalse(lb_["observation"]["complete"])
        gap = lb_["observation"]["file_time_in_gap"]
        self.assertIsNotNone(gap, lb_["observation"])
        self.assertTrue(gap["after_crash"])
        self.assertTrue(any("while whyfs was not recording" in g for g in lb_["observation"]["gaps"]))
        self.assertIn("not recording", label.render_label(lb_))
        # C: created after recovery -> complete, no later gaps
        self.assertEqual(lc["status"], "labelled")
        self.assertTrue(lc["observation"]["complete"], lc["observation"])
        self.assertEqual(lc["observation"]["later_gaps"], [])

    def test_status_lists_the_gap(self):
        self.scenario()
        r = api.handle({"user": U1, "admin": True, "pid": os.getpid()}, self.root, {"v": 1, "op": "status", "params": {}})
        self.assertTrue(r["ok"], r.get("error"))
        gaps = r["result"]["recording_gaps"]
        self.assertTrue(gaps and gaps[0]["after_crash"] and 55 <= gaps[0]["seconds"] <= 65, gaps)

    def test_a_silent_current_run_is_not_recording_now(self):
        self.run_row("r1", self.t0)
        a = self.write("r1", "A.txt", self.t0 + 60 * S)
        self.con.execute("INSERT INTO collector_stats(run_id,key,value) VALUES('r1',?,?)",
                         (observation.HEARTBEAT_KEY, self.t0 + 120 * S))
        self.con.commit()
        obs = label.explain_file(self.con, str(a))["observation"]
        self.assertTrue(obs["complete"])
        self.assertTrue(any("not recording now" in g for g in obs["later_gaps"]), obs)

    def test_file_older_than_the_first_recording(self):
        self.run_row("r1", self.t0)
        old = self.root / "old.txt"
        old.write_text("o")
        os.utime(old, ns=(self.t0 - 3600 * S, self.t0 - 3600 * S))
        lb = label.explain_file(self.con, str(old))
        self.assertEqual(lb["status"], "no-record")
        self.assertTrue(any("before whyfs started recording" in g for g in lb["observation"]["gaps"]), lb["observation"])


if __name__ == "__main__":
    unittest.main()
