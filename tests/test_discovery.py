"""The human and agent discovery surface over synthetic stores:
* impact never calls a file safe to remove; specific vs ambiguous (long-running program) dependents;
* observation gaps: collector downtime, reported loss, cut-off process chains;
* search_files filters (name, path, creator, user, agent, session, time, action) and visibility;
* list_agent_sessions: one detected session per process instance across collector restarts;
* the WhyFS window's local server: launch token, cookie, header, Host and operation checks.
"""
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from whyfs import api, label, ui
from whyfs.store import connect, ingest_events

T0 = time.time_ns() - 10 * 60 * 10**9
S = 10**9
U1, U2 = ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002") if os.name == "nt" else ("uid:1001", "uid:1002")
PY = r"C:\Python313\python.exe" if os.name == "nt" else "/usr/bin/python3"
CLAUDE = (r"C:\Users\u\AppData\Roaming\Claude\claude-code\2.1.0\claude.exe" if os.name == "nt"
          else "/home/u/.local/share/claude/versions/2.1.0/claude")


class Store:
    def __init__(self, root: Path, runs=(("r", T0, None),)):
        self.root, self.con, self.k = root, connect(root), 100
        for rid, start, end in runs:
            self.con.execute("INSERT INTO runs(id,started_ns,ended_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?,?)",
                             (rid, start, end, str(root), "t", str(root), "test"))
        self.con.commit()

    def proc(self, exe, cmd, user=U1, parent=None, run="r", os_pid=None, ts=None):
        self.k += 1
        ingest_events(self.con, [{"run_id": run, "kind": "process", "pid": self.k, "os_pid": os_pid or self.k,
                                  "ts_ns": ts or T0, "ppid": None, "parent_key": parent, "exe": exe, "cwd": str(self.root),
                                  "command": cmd, "source": "test", "user": user}])
        return self.k

    def ev(self, pid, kind, path, ts, *, read=False, write=False, path2=None, run="r", file_id=None):
        e = {"run_id": run, "kind": kind, "pid": pid, "os_pid": pid, "ts_ns": ts, "path": str(path), "source": "test",
             "read": read, "write": write, "api": "ebpf:rw"}
        if file_id:
            e["file_id"] = file_id
        if path2:
            e["path2"] = str(path2)
        ingest_events(self.con, [e])

    def make(self, pid, path, t, inputs=()):
        for i, p in enumerate(inputs):
            self.ev(pid, "io", p, t + i, read=True)
        self.ev(pid, "io", path, t + 100, write=True)


class Base(unittest.TestCase):
    runs = (("r", T0, None),)

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.s = Store(self.root, self.runs)

    def tearDown(self):
        self.s.con.close()
        self.td.cleanup()

    def f(self, name):
        p = self.root / name
        p.write_text(name)
        return p

    def call(self, op, params, user=None, admin=True):
        r = api.handle({"user": user or U1, "admin": admin, "pid": os.getpid()}, self.root, {"v": 1, "op": op, "params": params})
        self.assertTrue(r["ok"], r.get("error"))
        return r["result"]


class ImpactTests(Base):
    def test_no_observed_dependents_is_never_called_safe(self):
        src = self.f("src.txt")
        p = self.s.proc(PY, "python gen.py")
        self.s.make(p, src, T0 + S)
        lb = label.explain_file(self.s.con, str(src))
        im = lb["impact"]
        self.assertTrue(im["no_observed_dependents"])
        self.assertIn("does not mean it is safe to remove", im["summary"])
        self.assertNotIn("is safe to remove", im["summary"].replace("does not mean it is safe to remove", ""))
        self.assertEqual(im["generated_outputs"], [])

    def test_generated_outputs_and_readers(self):
        src, out = self.f("src.txt"), self.f("out.txt")
        a = self.s.proc(PY, "python make_src.py")
        self.s.make(a, src, T0 + S)
        b = self.s.proc(PY, "python build.py")
        self.s.make(b, out, T0 + 5 * S, inputs=[src])
        c = self.s.proc("/usr/bin/cat" if os.name != "nt" else r"C:\Windows\System32\findstr.exe", "cat src.txt")
        self.s.ev(c, "io", src, T0 + 8 * S, read=True)
        im = label.explain_file(self.s.con, str(src))["impact"]
        self.assertEqual(im["generated_outputs"], [str(out)])
        self.assertFalse(im["no_observed_dependents"])
        self.assertEqual(len(im["readers"]), 2)  # build.py's python and the viewer; not the creator itself
        self.assertIn("1 file was observed being generated", im["summary"])
        out_im = label.explain_file(self.s.con, str(out))["impact"]
        self.assertTrue(out_im["is_generated"])
        self.assertIn("rerunning that process may recreate it", out_im["summary"])

    def test_long_running_reader_is_only_possibly_affecting(self):
        src = self.f("notes.md")
        a = self.s.proc(PY, "python w.py")
        self.s.make(a, src, T0 + S)
        agent = self.s.proc(CLAUDE, "claude")
        self.s.ev(agent, "io", src, T0 + 2 * S, read=True)
        for i in range(label.AMBIGUOUS_SHARED + 5):
            self.s.ev(agent, "io", self.root / f"other{i}.txt", T0 + 3 * S + i, write=True)
        im = label.explain_file(self.s.con, str(src))["impact"]
        self.assertEqual(im["generated_outputs"], [])
        self.assertEqual(len(im["possibly_affected"]), label.AMBIGUOUS_SHARED + 5)
        self.assertIn("whether they depend on it is not observable", im["summary"])


class GapTests(Base):
    runs = (("r1", T0, T0 + 60 * S), ("r2", T0 + 120 * S, None))

    def test_downtime_and_loss_after_creation_are_later_gaps(self):
        src = self.f("a.txt")
        p = self.s.proc(PY, "python w.py", run="r1")
        self.s.ev(p, "io", src, T0 + 10 * S, write=True, run="r1", file_id=label.current_file_id(str(src)))
        obs = label.explain_file(self.s.con, str(src))["observation"]
        self.assertTrue(obs["complete"], obs)  # recorded, without loss, when it was created
        self.assertTrue(any("not recording" in g for g in obs["later_gaps"]), obs["later_gaps"])
        self.s.con.execute("INSERT INTO collector_stats(run_id,key,value) VALUES('r2','kernel_drops',7)")
        self.s.con.commit()
        obs = label.explain_file(self.s.con, str(src))["observation"]
        self.assertTrue(any("7 lost" in g for g in obs["later_gaps"]), obs["later_gaps"])
        self.assertIn("Evidence is incomplete", label.explain_file(self.s.con, str(src))["impact"]["summary"])

    def test_loss_in_the_creating_session_makes_the_origin_incomplete(self):
        src = self.f("l.txt")
        p = self.s.proc(PY, "python w.py", run="r1")
        self.s.ev(p, "io", src, T0 + 10 * S, write=True, run="r1", file_id=label.current_file_id(str(src)))
        self.s.con.execute("INSERT INTO collector_stats(run_id,key,value) VALUES('r1','lost_file',3)")
        self.s.con.commit()
        obs = label.explain_file(self.s.con, str(src))["observation"]
        self.assertFalse(obs["complete"])
        self.assertTrue(any("3 lost" in g for g in obs["gaps"]), obs["gaps"])

    def test_continuous_recording_without_loss_is_complete(self):
        self.s.con.execute("UPDATE runs SET ended_ns=NULL WHERE id='r1'")
        self.s.con.execute("DELETE FROM runs WHERE id='r2'")
        self.s.con.commit()
        src = self.f("b.txt")
        p = self.s.proc(PY, "python w.py", run="r1")
        self.s.ev(p, "io", src, T0 + 10 * S, write=True, run="r1", file_id=label.current_file_id(str(src)))
        obs = label.explain_file(self.s.con, str(src))["observation"]
        self.assertTrue(obs["complete"], obs["gaps"])


class SearchTests(Base):
    def setUp(self):
        super().setUp()
        s = self.s
        self.app = self.f("app.js")
        self.lib = self.f("lib.py")
        self.gone = self.f("tmp.log")
        self.theirs = self.f("theirs.txt")
        node = s.proc("/usr/bin/node" if os.name != "nt" else r"C:\Program Files\nodejs\node.exe", "node build.js")
        s.make(node, self.app, T0 + S)
        self.agent = s.proc(CLAUDE, "claude")
        child = s.proc(PY, "python gen.py", parent=self.agent)
        s.make(child, self.lib, T0 + 2 * S)
        s.ev(child, "io", self.gone, T0 + 3 * S, write=True)
        s.ev(child, "unlink", self.gone, T0 + 4 * S)
        other = s.proc(PY, "python x.py", user=U2)
        s.make(other, self.theirs, T0 + 5 * S)

    def paths(self, rows):
        return sorted(os.path.basename(r["path"]) for r in rows)

    def test_filters(self):
        self.assertEqual(self.paths(self.call("search_files", {"name": "app.js"})), ["app.js"])
        self.assertEqual(self.paths(self.call("search_files", {"creator": "python", "action": "created"})),
                         ["lib.py", "theirs.txt", "tmp.log"])
        self.assertEqual(self.paths(self.call("search_files", {"action": "deleted"})), ["tmp.log"])
        self.assertEqual(self.paths(self.call("search_files", {"agent": "Claude"})), ["lib.py", "tmp.log"])
        self.assertEqual(self.paths(self.call("search_files", {"since_ns": T0 + 4 * S + 1})), ["theirs.txt"])
        self.assertEqual(self.paths(self.call("search_files", {"until_ns": T0 + S + 200})), ["app.js"])
        self.assertEqual(self.paths(self.call("search_files", {"path": str(self.root)})),
                         ["app.js", "lib.py", "theirs.txt", "tmp.log"])
        row = next(r for r in self.call("search_files", {"name": "lib.py"}))
        self.assertEqual(row["agent"]["agent_name"], "Claude Code")
        self.assertTrue(row["created_in_range"])

    def test_session_filter(self):
        sessions = self.call("list_agent_sessions", {})
        self.assertEqual([d["agent_name"] for d in sessions], ["Claude Code"])
        rows = self.call("search_files", {"session_id": sessions[0]["session_id"]})
        self.assertEqual(self.paths(rows), ["lib.py", "tmp.log"])

    def test_visibility(self):
        mine = self.paths(self.call("search_files", {}, user=U1, admin=False))
        self.assertNotIn("theirs.txt", mine)
        self.assertEqual(self.call("search_files", {"user": "1002"}, user=U1, admin=False), [])

    def test_detected_session_listed_once_across_collector_runs(self):
        self.s.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('r9',?,?,?,?,?)",
                           (T0 + 60 * S, str(self.root), "t", str(self.root), "test"))
        self.s.con.commit()
        # the same claude process (same OS pid and start) seen again by the next collector run
        row = self.s.con.execute("SELECT os_pid, first_seen_ns FROM processes WHERE pid=?", (self.agent,)).fetchone()
        again = self.s.proc(CLAUDE, "claude", run="r9", os_pid=row[0], ts=row[1])
        child = self.s.proc(PY, "python late.py", parent=again, run="r9")
        late = self.f("late.txt")
        self.s.ev(child, "io", late, T0 + 70 * S, write=True, run="r9")
        sessions = self.call("list_agent_sessions", {})
        self.assertEqual(len(sessions), 1)
        rows = self.call("search_files", {"session_id": sessions[0]["session_id"]})
        self.assertEqual(self.paths(rows), ["late.txt", "lib.py", "tmp.log"])


class WindowServerTests(unittest.TestCase):
    def setUp(self):
        self.srv = ui._Server()
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()
        self.calls = []
        self._orig = ui.call
        ui.call = lambda op, params: (self.calls.append((op, params)), {"ok": True, "result": {"op": op}})[1]

    def tearDown(self):
        ui.call = self._orig
        self.srv.shutdown()
        self.srv.server_close()

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=5)
        h = {"Host": host or f"127.0.0.1:{self.srv.port}"}
        h.update(headers or {})
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def cookie(self):
        t = self.srv.new_launch_token()
        r, _ = self.req("GET", f"/launch?t={t}&file=%2Fx%2Fa.txt")
        self.assertEqual(r.status, 303)
        self.assertIn("HttpOnly", r.getheader("Set-Cookie"))
        self.assertIn("SameSite=Strict", r.getheader("Set-Cookie"))
        self.assertTrue(r.getheader("Location").startswith("/#file="))
        return r.getheader("Set-Cookie").split(";")[0], t

    def test_launch_token_is_single_use_and_required(self):
        r, _ = self.req("GET", "/launch?t=nope")
        self.assertEqual(r.status, 403)
        ck, t = self.cookie()
        r, _ = self.req("GET", f"/launch?t={t}")
        self.assertEqual(r.status, 403)
        r, _ = self.req("GET", "/")
        self.assertEqual(r.status, 403)
        r, body = self.req("GET", "/", headers={"Cookie": ck})
        self.assertEqual(r.status, 200)
        self.assertIn(b"<title>WhyFS</title>", body)

    def test_api_needs_cookie_header_and_host(self):
        ck, _ = self.cookie()
        ok_h = {"Cookie": ck, "X-Whyfs": "1", "Content-Type": "application/json"}
        body = {"op": "search_files", "params": {"name": "a"}}
        self.assertEqual(self.req("POST", "/api", body, {"X-Whyfs": "1"})[0].status, 403)
        self.assertEqual(self.req("POST", "/api", body, {"Cookie": ck})[0].status, 403)
        self.assertEqual(self.req("POST", "/api", body, ok_h, host="evil.example:80")[0].status, 421)
        self.assertEqual(self.req("POST", "/api", body, dict(ok_h, Origin="http://evil.example"))[0].status, 403)
        r, data = self.req("POST", "/api", body, ok_h)
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(data)["result"], {"op": "search_files"})
        r, data = self.req("POST", "/api", {"op": "forget", "params": {}}, ok_h)
        self.assertFalse(json.loads(data)["ok"])
        r, data = self.req("POST", "/api", {"op": "session_start", "params": {}}, ok_h)
        self.assertFalse(json.loads(data)["ok"])
        self.assertEqual([c[0] for c in self.calls], ["search_files"])

    def test_token_endpoint_needs_the_master_secret(self):
        self.assertEqual(self.req("POST", "/token", {}, {"Authorization": "Bearer x"})[0].status, 403)
        r, data = self.req("POST", "/token", {}, {"Authorization": f"Bearer {self.srv.master}"})
        self.assertEqual(r.status, 200)
        self.assertTrue(self.srv.use_launch_token(json.loads(data)["t"]))


@unittest.skipIf(os.name == "nt", "XDG runtime directories are POSIX")
class WindowStateDirTests(unittest.TestCase):
    def test_only_the_users_own_private_runtime_dir(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)
            self.assertTrue(ui._own_private_dir(d))
            os.chmod(d, 0o755)
            self.assertFalse(ui._own_private_dir(d))
        if os.getuid() != 0:
            self.assertFalse(ui._own_private_dir("/"))  # someone else's (root's)
        self.assertFalse(ui._own_private_dir("/nonexistent/whyfs"))


class JsonLiteTests(unittest.TestCase):
    """The CLI fast path's JSON (no `json` import) is byte-identical to the json package."""
    SAMPLES = [{}, [], "s", 1, -2.5, None, True, [[[]]], {"1": {"2": {"3": []}}},
               {"a": [], "b": {}, "c": [1, 2.5, -0.0, 1e300, 1e-7, True, False, None, "é \"\\\n\t\x00😀"]},
               {"nested": {"x": [{"y": [1, [2, [3, {}]]]}], "k": "v"}, "n": 10**20}]

    def test_dumps_matches_json(self):
        from whyfs import jsonlite
        for o in self.SAMPLES + [float("nan"), [float("inf"), float("-inf")], {1: "int key", None: 0, True: 1}]:
            self.assertEqual(jsonlite.dumps(o, indent=2), json.dumps(o, indent=2, default=str))
            self.assertEqual(jsonlite.dumps(o), json.dumps(o, default=str, separators=(",", ":")))
        self.assertEqual(jsonlite.dumps({"p": Path("x")}), json.dumps({"p": Path("x")}, default=str, separators=(",", ":")))

    def test_loads_matches_json(self):
        from whyfs import jsonlite
        for o in self.SAMPLES:
            text = json.dumps(o, indent=1)
            self.assertEqual(jsonlite.loads(" " + text + "\n"), json.loads(text))
            self.assertEqual(jsonlite.loads(text.encode()), json.loads(text))
        for bad in ("", "{", '{"a":1} x', "[1,]"):
            with self.assertRaises(ValueError):
                jsonlite.loads(bad)

    def test_fast_path_imports_no_json_package(self):
        import subprocess
        import sys
        # -S: no site packages, so a local .pth (pywin32, editable installs) cannot import re first;
        # the shipped runtime has none either.  Only what WhyFS itself imports is counted.
        code = ("import sys; before = set(sys.modules); import whyfs.client, whyfs.jsonlite; "
                "new = set(sys.modules) - before; print('json' in new, 're' in new)")
        out = subprocess.run([sys.executable, "-S", "-c", code], capture_output=True, text=True,
                             cwd=str(Path(__file__).resolve().parents[1] / "src")).stdout.split()
        self.assertEqual(out, ["False", "False"])


class CliTimeTests(unittest.TestCase):
    def test_when(self):
        from whyfs.cli import _when
        now = time.time_ns()
        self.assertAlmostEqual(_when("2h") / 1e9, (now - 2 * 3600e9) / 1e9, delta=5)
        self.assertLess(_when("today"), now)
        self.assertGreater(_when("today", end=True), now)
        self.assertEqual(_when("2026-09-27", end=True) - _when("2026-09-27"), 86400 * 10**9)
        with self.assertRaises(SystemExit):
            _when("next tuesday")


if __name__ == "__main__":
    unittest.main()
