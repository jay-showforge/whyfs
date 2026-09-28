"""The label of a file with a long history (rebuilt hundreds or thousands of times).

`whyfs label` describes the file as it is now; its cost must not grow with the number of
generations the path has had, and nothing about the current generation may be lost or taken
from an older one.  `whyfs history FILE --limit 0` and `whyfs impact FILE` keep everything.

* the current creator, inputs, agent session, process chain, observation and identity after
  hundreds of generations -- identical to a computation that reads the whole history;
* an older generation (other program, other inputs, other session) never leaks into the label;
* deletion and recreation start a new generation; a move into place keeps its lineage;
* recording gaps before the current generation stay recorded;
* the complete history stays queryable (count matches reality);
* the label says when readers/dependents come from recent activity only;
* the API returns the same label;
* the number of SQL statements a label runs is bounded (the long-history performance gate).
"""
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from whyfs import api, label, observation, query
from whyfs.store import connect, ingest_events

S = 10**9
U1 = "S-1-5-21-1-2-3-1001" if os.name == "nt" else "uid:1001"
SHELL = r"C:\Windows\System32\cmd.exe" if os.name == "nt" else "/bin/sh"
TOOL = r"C:\tools\gen.exe" if os.name == "nt" else "/usr/bin/gen"
FINAL = r"C:\tools\final.exe" if os.name == "nt" else "/usr/bin/final"
READER = r"C:\tools\consume.exe" if os.name == "nt" else "/usr/bin/consume"


class History:
    """A store holding ``n`` generations of one file, each: a shell deletes it, a fresh `gen`
    process reads src.txt and writes it, a fresh `consume` process reads it and writes
    derived-<i>.txt.  The last generation is special: `final` reads other.txt and writes it
    inside a registered agent session.  An optional recording gap sits before the last one."""

    def __init__(self, root: Path, n: int, gap: bool = False, move_in: bool = False):
        self.root, self.n = root, n
        self.con = connect(root)
        self.t = time.time_ns() - (4 * n + 400) * S
        self.k = 100
        self.run = "r1"
        self._run_row("r1", self.t - S)
        self.f = root / "out.txt"
        self.src, self.other = root / "src.txt", root / "other.txt"
        for p in (self.src, self.other):
            p.write_text(p.name)
        shell = self.proc(SHELL, "build loop")
        rows = []
        for i in range(n - 1):
            rows += self._gen(shell, i)
        ingest_events(self.con, rows)
        if gap:  # the collector crashed: nothing recorded for a while, then it recovered
            observation.heartbeat(self.con, "r1")
            self.con.execute("UPDATE collector_stats SET value=? WHERE run_id='r1' AND key=?",
                             (self.t, observation.HEARTBEAT_KEY))
            self.con.commit()
            self.t += 120 * S
            observation.close_unclean_runs(self.con)
            self._run_row("r2", self.t)
            self.run = "r2"
            shell = self.proc(SHELL, "build loop")
            self.t += 10 * S
        # the current generation
        ingest_events(self.con, [self._ev(shell, "unlink", self.f)])
        self.session_root = self.proc(SHELL, "agent shell", os_pid=5000)
        self.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                         "source,confidence) VALUES('NOW','MyAgent',?,5000,?,'regenerate out',?,'registered','t')",
                         (U1, self.t - S, self.t - 2 * S))
        self.con.commit()
        fin = self.proc(FINAL, "final other.txt out.txt", parent=self.session_root)
        target = self.root / "out.tmp" if move_in else self.f
        self.f.write_text("current")
        fid = label.current_file_id(str(self.f))
        ingest_events(self.con, [self._ev(fin, "io", self.other, read=True),
                                 self._ev(fin, "io", target, write=True, file_id=None if move_in else fid)])
        if move_in:
            ingest_events(self.con, [self._ev(fin, "rename", target, path2=self.f, file_id=fid)])
        self.con.commit()

    def _run_row(self, rid, start):
        self.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                         (rid, start, str(self.root), "t", str(self.root), "test"))
        self.con.commit()

    def proc(self, exe, cmd, parent=None, os_pid=None):
        self.k += 1
        self.t += 1000
        ingest_events(self.con, [{"run_id": self.run, "kind": "process", "pid": self.k, "os_pid": os_pid or self.k,
                                  "ts_ns": self.t, "ppid": None, "parent_key": parent, "exe": exe, "cwd": str(self.root),
                                  "command": cmd, "source": "test", "user": U1}])
        return self.k

    def _ev(self, pid, kind, path, *, read=False, write=False, path2=None, file_id=None):
        self.t += 1000
        e = {"run_id": self.run, "kind": kind, "pid": pid, "os_pid": pid, "ts_ns": self.t, "path": str(path),
             "source": "test", "read": read, "write": write, "api": "test:rw"}
        if path2:
            e["path2"] = str(path2)
        if file_id:
            e["file_id"] = file_id
        return e

    def _gen(self, shell, i):
        rows = [self._ev(shell, "unlink", self.f)]
        self.k += 1
        g = self.k
        self.t += 1000
        rows.append({"run_id": self.run, "kind": "process", "pid": g, "os_pid": g, "ts_ns": self.t, "ppid": None,
                     "parent_key": shell, "exe": TOOL, "cwd": str(self.root), "command": f"gen src.txt out.txt #{i}",
                     "source": "test", "user": U1})
        rows += [self._ev(g, "io", self.src, read=True), self._ev(g, "io", self.f, write=True, file_id=f"old-{i}")]
        self.k += 1
        c = self.k
        self.t += 1000
        rows.append({"run_id": self.run, "kind": "process", "pid": c, "os_pid": c, "ts_ns": self.t, "ppid": None,
                     "parent_key": shell, "exe": READER, "cwd": str(self.root), "command": f"consume out.txt #{i}",
                     "source": "test", "user": U1})
        rows += [self._ev(c, "io", self.f, read=True), self._ev(c, "io", self.root / f"derived-{i}.txt", write=True)]
        return rows


CURRENT = ("status", "created_ns", "last_written_ns", "created_by", "process_chain", "inputs", "inputs_hidden",
           "inputs_via_temporaries", "shared_by_outputs", "renamed_from", "agent", "intent", "causal_why",
           "observation", "identity", "history", "user", "evidence")


def full_history_label(con, path):
    """The same label computed over the file's whole history (no recent-activity window)."""
    with mock.patch.object(query, "RECENT_EVENTS", 10**9), mock.patch.object(label, "RECENT_EVENTS", 10**9), \
            mock.patch.object(label, "LABEL_RECENT_READERS", 10**9):
        return label.explain_file(con, path)


class LongHistoryTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)  # runs after each test's own cleanups (the store's close)
        self.root = Path(self.td.name).resolve()

    def test_current_generation_after_600_generations(self):
        h = History(self.root, 600)
        self.addCleanup(h.con.close)
        lb = label.explain_file(h.con, str(h.f))
        self.assertEqual(lb["status"], "labelled")
        self.assertEqual(os.path.basename(lb["created_by"]["exe"]).lower(), os.path.basename(FINAL).lower())
        self.assertEqual(lb["created_by"]["command"], "final other.txt out.txt")
        self.assertEqual([os.path.basename(p) for p in lb["inputs"]], ["other.txt"])  # not src.txt: no old generation
        self.assertEqual((lb["agent"] or {}).get("session_id"), "NOW")
        self.assertEqual(lb["intent"]["task"], "regenerate out")
        self.assertEqual(lb["identity"]["check"], "match")
        self.assertTrue(lb["observation"]["complete"])
        # the current generation began at its own write, not at the first of 600
        self.assertEqual(lb["created_ns"], lb["last_written_ns"])
        # identical to a computation over the whole history
        full = full_history_label(h.con, str(h.f))
        for k in CURRENT:
            self.assertEqual(lb[k], full[k], k)
        # dependents and readers come from recent activity: a subset of the full set, and the label says so
        self.assertTrue(lb["scope"]["recent_only"])
        complete = {(d["from"], d["to"]) for d in query.impact_details(h.con, str(h.f))}
        recent = {(d["from"], d["to"]) for d in lb["dependents"]}
        self.assertTrue(recent and recent <= complete)
        # the most recent consumers' outputs (the full-history label listed the 50 oldest)
        self.assertIn(os.path.join(str(h.root), "derived-598.txt"), {e[1] for e in recent})
        self.assertIn("Long history", label.render_label(lb))

    def test_short_history_is_unchanged(self):
        h = History(self.root, 8)
        self.addCleanup(h.con.close)
        lb, full = label.explain_file(h.con, str(h.f)), full_history_label(h.con, str(h.f))
        self.assertNotIn("scope", lb)
        self.assertEqual(lb, full)

    def test_complete_history_stays_queryable(self):
        h = History(self.root, 300)
        self.addCleanup(h.con.close)
        rows = query.history(h.con, str(h.f), limit=0)
        writes = [r for r in rows if r["kind"] == "io"]
        self.assertEqual(len(writes), 300)  # 299 old generations + the current one
        self.assertEqual(len(query.history(h.con, str(h.f))), 20)  # the default page
        n_db = h.con.execute("SELECT COUNT(*) FROM events WHERE path=? AND is_write=1", (str(h.f),)).fetchone()[0]
        self.assertEqual(len(writes), n_db)
        creators = {os.path.basename(r["exe"] or "").lower() for r in writes}
        self.assertEqual(creators, {os.path.basename(TOOL).lower(), os.path.basename(FINAL).lower()})
        # the full impact walk still reaches every consumer's output
        full = query.impact_details(h.con, str(h.f))
        self.assertEqual(len({d["to"] for d in full}), 299)

    def test_move_into_place_keeps_lineage(self):
        h = History(self.root, 400, move_in=True)
        self.addCleanup(h.con.close)
        lb = label.explain_file(h.con, str(h.f))
        self.assertEqual(lb["status"], "labelled")
        self.assertEqual(os.path.basename(lb["created_by"]["exe"]).lower(), os.path.basename(FINAL).lower())
        self.assertEqual(os.path.basename(lb["renamed_from"][0]["from"]), "out.tmp")
        self.assertEqual(lb["identity"]["check"], "match")
        full = full_history_label(h.con, str(h.f))
        for k in CURRENT:
            self.assertEqual(lb[k], full[k], k)

    def test_recording_gap_before_the_current_generation_is_kept(self):
        h = History(self.root, 300, gap=True)
        self.addCleanup(h.con.close)
        lb = label.explain_file(h.con, str(h.f))
        full = full_history_label(h.con, str(h.f))
        self.assertEqual(lb["observation"], full["observation"])
        runs = h.con.execute("SELECT id, exit_code FROM runs ORDER BY started_ns").fetchall()
        self.assertEqual([r[0] for r in runs], ["r1", "r2"])
        self.assertEqual(runs[0][1], -1)  # the crashed run is a recorded gap
        self.assertTrue(observation.intervals(h.con))

    def test_api_returns_the_same_label(self):
        h = History(self.root, 300)
        self.addCleanup(h.con.close)
        r = api.handle({"user": U1, "admin": True, "pid": os.getpid()}, self.root,
                       {"v": 1, "op": "get_file_provenance", "params": {"path": str(h.f)}})
        self.assertTrue(r["ok"], r)
        direct = label.explain_file(h.con, str(h.f))
        for k in CURRENT + ("scope",):
            self.assertEqual(r["result"][k], direct[k], k)


    def test_standard_user_through_the_visibility_views(self):
        # a standard user's queries go through TEMP views that shadow the tables (whyfs.access):
        # the label must work there too, and read the same as an administrator's for their own files
        h = History(self.root, 600)
        self.addCleanup(h.con.close)
        ctx = {"user": U1, "admin": False, "pid": os.getpid()}
        r = api.handle(ctx, self.root, {"v": 1, "op": "get_file_provenance", "params": {"path": str(h.f)}})
        self.assertTrue(r["ok"], r)
        admin = api.handle({**ctx, "admin": True}, self.root, {"v": 1, "op": "get_file_provenance", "params": {"path": str(h.f)}})
        for k in CURRENT + ("scope", "dependents"):
            self.assertEqual(r["result"][k], admin["result"][k], k)
        hist = api.handle(ctx, self.root, {"v": 1, "op": "history", "params": {"path": str(h.f), "limit": 0}})
        self.assertEqual(len([x for x in hist["result"] if x["kind"] == "io"]), 600)


class LongHistoryCostTests(unittest.TestCase):
    """The long-history performance gate: the statements a label runs do not grow with the
    number of generations (a deterministic count, not a timing)."""

    def statements(self, h: History) -> int:
        n = [0]
        con = sqlite3.connect(str(h.root / ".whyfs" / "whyfs.db"))
        con.row_factory = sqlite3.Row
        con.set_trace_callback(lambda s: n.__setitem__(0, n[0] + 1))
        label.explain_file(con, str(h.f))
        con.close()
        return n[0]

    def test_statement_count_is_bounded(self):
        counts = {}
        for n in (1, 100, 300, 1000):
            with tempfile.TemporaryDirectory() as d:
                h = History(Path(d).resolve(), n)
                h.con.close()
                counts[n] = self.statements(h)
        self.assertEqual(counts[1000], counts[300], counts)  # flat past the recent window
        self.assertLessEqual(counts[1000], 500, counts)     # bounded: the window, 50 readers, the current generation


if __name__ == "__main__":
    unittest.main()
