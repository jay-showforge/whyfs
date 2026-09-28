"""Provenance labels over synthetic stores: identity, staleness, visibility, agents, retention, API.

The live product gate (scripts/product_gate.py) exercises the collectors; these tests pin the
query-side rules that decide what a label may claim:
* never attach an old record to a new file at the same path (identity mismatch, or content
  removed after the record and replaced by an unobserved writer);
* a file found by identity (hard link) is labelled from its observed writes;
* a user sees only their own processes' evidence; an administrator sees all;
* agents: detected only from image path + command line; registered sessions need a matching
  root process instance; intent only from supplied task text;
* retention keeps strong records and expires weak ones.
"""
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from whyfs import agents, api, label, retention
from whyfs.access import open_for, restrict
from whyfs.store import connect, ingest_events, normalize

T0 = time.time_ns() - 10 * 60 * 10**9
U1, U2 = ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002") if os.name == "nt" else ("uid:1001", "uid:1002")


class Store:
    def __init__(self, root: Path):
        self.root = root
        self.con = connect(root)
        self.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('r',?,?,?,?,?)",
                         (T0, str(root), "t", str(root), "test"))
        self.con.commit()
        self.k = 100

    def proc(self, exe, cmd, user=U1, parent=None, os_pid=None, ts=None):
        self.k += 1
        ingest_events(self.con, [{"run_id": "r", "kind": "process", "pid": self.k, "os_pid": os_pid or self.k, "ts_ns": ts or T0,
                                  "ppid": None, "parent_key": parent, "exe": exe, "cwd": str(self.root), "command": cmd,
                                  "source": "test", "user": user}])
        return self.k

    def ev(self, pid, kind, path, ts, *, read=False, write=False, path2=None, file_id=None, api="ebpf:rw"):
        e = {"run_id": "r", "kind": kind, "pid": pid, "os_pid": pid, "ts_ns": ts, "path": str(path), "source": "test",
             "read": read, "write": write, "api": api}
        if path2:
            e["path2"] = str(path2)
        if file_id:
            e["file_id"] = file_id
        ingest_events(self.con, [e])


@unittest.skipUnless(os.name == "nt", "8.3 short names are a Windows file-system feature")
class ShortNameTests(unittest.TestCase):
    def test_short_path_queries_find_long_path_evidence(self):
        import ctypes
        with tempfile.TemporaryDirectory() as d:
            longdir = Path(os.path.realpath(d)) / "a-long-directory-name"
            longdir.mkdir()
            (longdir / "out.txt").write_text("x")
            buf = ctypes.create_unicode_buffer(32768)
            n = ctypes.windll.kernel32.GetShortPathNameW(str(longdir / "out.txt"), buf, len(buf))
            if not n or "~" not in buf.value:
                self.skipTest("8.3 name generation is disabled on this volume")
            self.assertEqual(normalize(buf.value), str(longdir / "out.txt"))
            # a file that does not exist yet under a short directory name
            self.assertEqual(normalize(os.path.join(os.path.dirname(buf.value), "new.txt")), str(longdir / "new.txt"))


class LabelTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.s = Store(self.root)
        self.f = self.root / "out.txt"
        self.f.write_text("x")
        self.inp = self.root / "in.txt"
        self.inp.write_text("i")

    def tearDown(self):
        self.s.con.close()
        self.td.cleanup()

    def _written(self, fid, exe="/usr/bin/gen", ts=T0 + 10):
        p = self.s.proc(exe, f"{exe} in.txt out.txt")
        self.s.ev(p, "io", self.inp, ts - 1, read=True)
        self.s.ev(p, "io", self.f, ts, write=True, file_id=fid)
        return p

    def test_identity_match_labels(self):
        self._written(label.current_file_id(str(self.f)))
        lb = label.explain_file(self.s.con, str(self.f))
        self.assertEqual(lb["status"], "labelled")
        self.assertEqual(lb["identity"]["check"], "match")
        self.assertEqual(lb["inputs"], [normalize(self.inp)])
        self.assertEqual(lb["user"], U1)
        self.assertIsNone(lb["agent"])
        self.assertIsNone(lb["intent"]["task"])
        self.assertIn("does not infer intent", lb["intent"]["note"])

    def test_identity_mismatch_is_never_attached(self):
        cur = label.current_file_id(str(self.f))
        other = cur[:-1] + ("0" if cur[-1] != "0" else "1")
        if cur.startswith("lnx:"):  # a different inode on the same device
            parts = cur.split(":")
            parts[3] = str(int(parts[3]) + 1)
            other = ":".join(parts)
        self._written(other)
        lb = label.explain_file(self.s.con, str(self.f))
        self.assertEqual(lb["status"], "not-observed")
        self.assertIn("different identity", lb["note"])
        self.assertIn("previous_file_at_path", lb)
        self.assertNotIn("created_by", lb)

    def test_removed_then_unobserved_replacement_is_not_attached(self):
        p = self._written(None)
        self.s.ev(p, "unlink", self.f, T0 + 20, api="ebpf:unlink")  # deleted; the file there now was never seen written
        lb = label.explain_file(self.s.con, str(self.f))
        self.assertEqual(lb["status"], "not-observed")
        self.assertIn("deleted", lb["note"])

    def test_observed_recreation_labels_the_new_writer(self):
        p = self._written(None)
        self.s.ev(p, "unlink", self.f, T0 + 20, api="ebpf:unlink")
        q = self.s.proc("/usr/bin/other", "other")
        self.s.ev(q, "io", self.f, T0 + 30, write=True)
        lb = label.explain_file(self.s.con, str(self.f))
        self.assertEqual(lb["status"], "labelled")
        self.assertEqual(lb["created_by"]["exe"], "/usr/bin/other")
        self.assertEqual([h["action"] for h in lb["history"]][:3], ["written", "deleted", "written"])

    def test_moved_away_then_unobserved_file_is_not_attached(self):
        p = self._written(None)
        self.s.ev(p, "rename", self.f, T0 + 20, path2=self.root / "elsewhere.txt", api="ebpf:rename")
        lb = label.explain_file(self.s.con, str(self.f))
        self.assertEqual(lb["status"], "not-observed")
        self.assertIn("moved away", lb["note"])

    def test_found_by_identity_hard_link(self):
        link = self.root / "link.txt"
        try:
            os.link(self.f, link)
        except OSError:
            self.skipTest("hard links unsupported here")
        self._written(label.current_file_id(str(self.f)))
        lb = label.explain_file(self.s.con, str(link))
        self.assertEqual(lb["status"], "labelled")
        self.assertIn("found by file identity", lb["note"])

    def test_no_record(self):
        lb = label.explain_file(self.s.con, str(self.root / "never.txt"))
        self.assertEqual(lb["status"], "no-record")

    def test_render_has_the_label_fields(self):
        self._written(label.current_file_id(str(self.f)))
        txt = label.render_label(label.explain_file(self.s.con, str(self.f)))
        for k in ("File:", "Created:", "User:", "Created by:", "Agent:", "Task:", "Why:", "Inputs:", "History:", "Evidence:"):
            self.assertIn(k, txt)


class VisibilityTests(unittest.TestCase):
    def test_user_sees_own_admin_sees_all(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            s = Store(root)
            a, b = root / "a.txt", root / "b.txt"
            a.write_text("a"); b.write_text("b")
            pa = s.proc("/bin/a", "a", user=U1)
            pb = s.proc("/bin/b", "b", user=U2)
            s.ev(pa, "io", a, T0 + 5, write=True)
            s.ev(pb, "io", b, T0 + 6, write=True)
            s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,started_ns,source,confidence) "
                          "VALUES('s2','X',?,?, 'registered','t')", (U2, T0))
            s.con.commit()
            s.con.close()
            c1 = open_for(root, U1, admin=False)
            self.assertEqual(label.explain_file(c1, str(a))["status"], "labelled")
            self.assertEqual(label.explain_file(c1, str(b))["status"], "no-record")
            self.assertEqual(c1.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0], 0)
            self.assertEqual(c1.execute("SELECT COUNT(*) FROM processes").fetchone()[0], 1)
            c1.close()
            ca = open_for(root, None, admin=True)
            self.assertEqual(label.explain_file(ca, str(b))["status"], "labelled")
            ca.close()
            with self.assertRaises(PermissionError):
                open_for(root, None, admin=False)


class AgentTests(unittest.TestCase):
    def test_detection_needs_layout_and_command_not_a_name(self):
        yes = [
            (r"C:\Users\j\AppData\Roaming\Claude\claude-code\2.1.281\claude.exe", "claude.exe --output-format stream-json"),
            ("/home/j/.local/share/claude/versions/1.0.93/claude", "claude"),
            ("/usr/bin/node", "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js --resume"),
            (r"C:\Program Files\nodejs\node.exe", r"node C:\Users\j\AppData\Roaming\npm\node_modules\@openai\codex\bin\codex.js"),
            ("/usr/bin/node", "node /opt/n/lib/node_modules/@google/gemini-cli/dist/index.js"),
        ]
        no = [("/tmp/claude", "claude"), (r"C:\tools\claude.exe", "claude.exe"), ("/usr/bin/python3", "python3 claude-code.py"),
              ("/usr/bin/node", "node app.js --claude-code"), (None, "claude")]
        for exe, cmd in yes:
            self.assertIsNotNone(agents.detect(exe, cmd), exe)
        for exe, cmd in no:
            self.assertIsNone(agents.detect(exe, cmd), exe)
        self.assertEqual(agents.detect(yes[0][0], yes[0][1])["agent_version"], "2.1.281")

    def _chain(self, s):
        root = s.proc("/usr/bin/python3", "python3 my_agent.py", os_pid=5000, ts=T0)
        sh = s.proc("/bin/sh", "sh -c gen", parent=root, ts=T0 + 1)
        gen = s.proc("/usr/bin/gen", "gen out", parent=sh, ts=T0 + 2)
        return root, sh, gen

    def test_registered_session_inherited_through_ancestry(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d).resolve())
            _root, _sh, gen = self._chain(s)
            s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                          "source,confidence) VALUES('S1','MyAgent',?,5000,?,'fix the checkout page',?,'registered','t')",
                          (U1, T0, T0 - 1))
            s.con.commit()
            sess = agents.session_for(s.con, "r", gen, T0 + 10)
            self.assertEqual(sess["session_id"], "S1")
            self.assertEqual(sess["depth"], 2)
            self.assertEqual(sess["task"], "fix the checkout page")
            s.con.close()

    def test_pid_reuse_is_not_the_session(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d).resolve())
            _root, _sh, gen = self._chain(s)
            # the session's root was an earlier process that had PID 5000 (started an hour before)
            s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,started_ns,"
                          "source,confidence) VALUES('OLD','MyAgent',?,5000,?,?,'registered','t')",
                          (U1, T0 - 3600 * 10**9, T0 - 3600 * 10**9))
            s.con.commit()
            self.assertIsNone(agents.session_for(s.con, "r", gen, T0 + 10))
            s.con.close()

    def test_other_users_session_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d).resolve())
            _root, _sh, gen = self._chain(s)
            s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,started_ns,"
                          "source,confidence) VALUES('X','MyAgent',?,5000,?,?,'registered','t')", (U2, T0, T0 - 1))
            s.con.commit()
            self.assertIsNone(agents.session_for(s.con, "r", gen, T0 + 10))
            s.con.close()

    def test_detected_agent_ancestor(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d).resolve())
            cc = s.proc("/home/j/.local/share/claude/versions/1.0.93/claude", "claude")
            sh = s.proc("/bin/bash", "bash -c x", parent=cc)
            sess = agents.session_for(s.con, "r", sh, T0 + 5)
            self.assertEqual(sess["source"], "detected")
            self.assertEqual(sess["agent_name"], "Claude Code")
            self.assertIsNone(sess["task"])
            s.con.close()


class RetentionTests(unittest.TestCase):
    def test_weak_expire_strong_stay(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d).resolve())
            day = 86_400 * 10**9
            old = time.time_ns() - 60 * day
            reader = s.proc("/bin/cat", "cat cfg", ts=old)
            writer = s.proc("/bin/gen", "gen", ts=old)
            s.ev(reader, "io", "/x/cfg", old, read=True)              # pure consumer: weak
            s.ev(writer, "io", "/x/in", old, read=True)               # an input of a writer: strong
            s.ev(writer, "io", "/x/out", old + 1, write=True)         # strong
            r = retention.prune(s.con, {"weak_retention_days": 30, "retention_days": 365})
            self.assertEqual(r["weak_events"], 1)
            left = {x[0] for x in s.con.execute("SELECT path FROM events")}
            self.assertEqual(left, {normalize("/x/in"), normalize("/x/out")})
            self.assertEqual(s.con.execute("SELECT COUNT(*) FROM processes WHERE pid=?", (reader,)).fetchone()[0], 0)
            s.con.close()


class ApiTests(unittest.TestCase):
    def test_session_root_must_belong_to_requester(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            connect(root).close()
            me = api._process_user(os.getpid())
            ok = api.handle({"user": me, "admin": False, "pid": os.getpid()}, root,
                            {"v": 1, "op": "session_start", "params": {"agent_name": "T", "root_pid": os.getpid(),
                                                                         "task": "use token=SECRETVAL_T"}})
            self.assertTrue(ok["ok"], ok)
            bad = api.handle({"user": "uid:424242" if os.name != "nt" else "S-1-5-21-9-9-9-9", "admin": False, "pid": 1}, root,
                             {"v": 1, "op": "session_start", "params": {"agent_name": "T", "root_pid": os.getpid()}})
            self.assertFalse(bad["ok"])
            self.assertIn("another user", bad["error"])
            con = connect(root)
            task = con.execute("SELECT task FROM agent_sessions").fetchone()[0]
            con.close()
            self.assertNotIn("SECRETVAL", task)
            sid = ok["result"]["session_id"]
            other = api.handle({"user": "uid:424242" if os.name != "nt" else "S-1-5-21-9-9-9-9", "admin": False, "pid": 1}, root,
                               {"v": 1, "op": "session_end", "params": {"session_id": sid}})
            self.assertFalse(other["ok"])

    def test_unknown_op_and_version(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            connect(root).close()
            ctx = {"user": U1, "admin": False, "pid": 1}
            self.assertFalse(api.handle(ctx, root, {"v": 1, "op": "nope"})["ok"])
            self.assertFalse(api.handle(ctx, root, {"v": 9, "op": "status"})["ok"])
            self.assertFalse(api.handle(ctx, root, {"v": 1, "op": "get_file_provenance", "params": {"path": "rel.txt"}})["ok"])


if __name__ == "__main__":
    unittest.main()
