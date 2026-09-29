"""`whyfs ask`: compact answers over synthetic stores (the evidence rules are the label's).

One test per agent task class (generated artifact, multi-step chain, dependency impact, renamed
output, agent-produced files, unknown origin in an observation gap, the generator that actually
ran, downstream dependents without a safety claim, the most recent build's changes, a known
origin), plus identity mismatch, per-user visibility, determinism, bounded lists, the API and
the CLI.  Every answer is checked for its facts, its uncertainty qualifiers, the absence of bulk
(no process chains, no reads by bystanders, no version-control bookkeeping), and its size.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from whyfs import api, ask, label
from whyfs.access import restrict
from whyfs.store import connect, ingest_events

T0 = time.time_ns() - 20 * 60 * 10**9
S = 10**9
U1, U2 = ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002") if os.name == "nt" else ("uid:1001", "uid:1002")
PY = r"C:\Python\python.exe" if os.name == "nt" else "/usr/bin/python3.12"
SH = r"C:\Windows\System32\cmd.exe" if os.name == "nt" else "/bin/bash"
FORBIDDEN_BULK = ("process_chain", "history", "readers", "raw_events", "outputs", "parent", "run_id", "process_key",
                  "created_by", "observation", "impact", "evidence", "schema")


def size(d) -> int:
    return len(json.dumps(d, ensure_ascii=False, separators=(", ", ": ")).encode())


class Store:
    def __init__(self, root: Path, run="r", start=T0):
        self.root = root
        self.con = connect(root)
        self.run = run
        self.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                         (run, start, str(root), "t", str(root), "test"))
        self.con.commit()
        self.k = 100

    def proc(self, exe, cmd, user=U1, parent=None, ts=T0, os_pid=None):
        self.k += 1
        ingest_events(self.con, [{"run_id": self.run, "kind": "process", "pid": self.k, "os_pid": os_pid or self.k,
                                  "ts_ns": ts, "ppid": None, "parent_key": parent, "exe": exe, "cwd": str(self.root),
                                  "command": cmd, "source": "test", "user": user}])
        return self.k

    def read(self, pid, rel, ts):
        ingest_events(self.con, [{"run_id": self.run, "kind": "io", "pid": pid, "os_pid": pid, "ts_ns": ts,
                                  "path": str(self.root / rel), "source": "test", "read": True, "write": False,
                                  "api": "ebpf:rw"}])

    def write(self, pid, rel, ts, content="x"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        ingest_events(self.con, [{"run_id": self.run, "kind": "io", "pid": pid, "os_pid": pid, "ts_ns": ts, "path": str(p),
                                  "source": "test", "read": False, "write": True, "api": "ebpf:rw",
                                  "file_id": label.current_file_id(str(p))}])

    def rename(self, pid, a, b, ts):
        (self.root / b).parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.root / a, self.root / b)
        ingest_events(self.con, [{"run_id": self.run, "kind": "rename", "pid": pid, "os_pid": pid, "ts_ns": ts,
                                  "path": str(self.root / a), "path2": str(self.root / b), "source": "test",
                                  "api": "ebpf:rename", "file_id": label.current_file_id(str(self.root / b))}])

    def source(self, rel, content="s"):
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        (self.root / rel).write_text(content)

    def ask(self, q, **params):
        """Answers use the platform's separators; the tests compare them in '/' form."""
        a = ask.ask(self.con, q, {"base": str(self.root), **params})
        return json.loads(json.dumps(a).replace("\\\\", "/")) if os.sep == "\\" else a


class AskBase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.s = Store(Path(os.path.realpath(self._td.name)))
        self.addCleanup(lambda: self.s.con.close())  # whichever connection is current (Windows cannot delete an open db)

    def assertCompact(self, ans, limit):
        keys = set()

        def walk(x):
            if isinstance(x, dict):
                keys.update(x)
                for v in x.values():
                    walk(v)
            elif isinstance(x, list):
                for v in x:
                    walk(v)
        walk(ans)
        for k in FORBIDDEN_BULK:
            self.assertNotIn(k, keys, f"bulk field {k!r} in {ans}")
        self.assertLessEqual(size(ans), limit, ans)
        text = json.dumps(ans).replace("\\\\", "/")
        self.assertNotIn(str(self.s.root).replace("\\", "/") + "/", text, "paths under the base must be relative")

    def build(self, src="src/banner.json", out="dist/banner.txt", tool="tools/build.py", at=T0 + 10 * S):
        s = self.s
        s.source(src)
        s.source(tool)
        sh = s.proc(SH, "bash", ts=at - 2 * S)
        p = s.proc(PY, f"python3 {tool}", parent=sh, ts=at - S)
        s.read(p, tool, at - S)
        s.read(p, src, at - S // 2)
        s.write(p, out, at)
        return p


class Questions(AskBase):
    # 1. generated artifact: what should I edit?
    def test_generated_artifact_sources(self):
        self.build()
        a = self.s.ask("sources", path=str(self.s.root / "dist/banner.txt"))
        self.assertEqual(a["status"], "observed")
        self.assertTrue(a["attributable"])
        self.assertTrue(a["generated"])
        self.assertEqual(sorted(a["edit"]), ["src/banner.json", "tools/build.py"])
        self.assertEqual(a["chain"][0]["by"], "python3 tools/build.py")
        self.assertCompact(a, 700)

    # 2. multi-step chain: one call reaches the source behind the intermediate
    def test_multi_step_chain(self):
        s = self.s
        for f in ("src/release.json", "tools/stage1.py", "tools/stage2.py", "tools/build.py"):
            s.source(f)
        drv = s.proc(PY, "python3 tools/build.py", ts=T0 + S)
        st1 = s.proc(PY, "python3 tools/stage1.py", parent=drv, ts=T0 + 2 * S)
        s.read(st1, "tools/stage1.py", T0 + 2 * S)
        s.read(st1, "src/release.json", T0 + 3 * S)
        s.write(st1, ".build/release.json", T0 + 4 * S)
        st2 = s.proc(PY, "python3 tools/stage2.py", parent=drv, ts=T0 + 5 * S)
        s.read(st2, "tools/stage2.py", T0 + 5 * S)
        s.read(st2, ".build/release.json", T0 + 6 * S)
        s.write(st2, "dist/release.txt", T0 + 7 * S)
        a = s.ask("sources", path=str(s.root / "dist/release.txt"))
        self.assertEqual([c["file"] for c in a["chain"]], ["dist/release.txt", ".build/release.json"])
        self.assertIn("src/release.json", a["edit"])
        self.assertNotIn(".build/release.json", a["edit"], "a generated intermediate is rebuilt, not edited")
        self.assertCompact(a, 900)

    # 3. dependency impact: observed outputs; version-control bookkeeping is counted, not listed
    def test_dependents_of_a_source(self):
        s = self.s
        s.source("src/colors.json")
        s.source("tools/build.py")
        b = s.proc(PY, "python3 tools/build.py", ts=T0 + S)
        s.read(b, "src/colors.json", T0 + 2 * S)
        for i, out in enumerate(("dist/web.css", "dist/theme.json", "docs/palette.md")):
            s.write(b, out, T0 + (3 + i) * S)
        git = s.proc("/usr/bin/git", "git status", ts=T0 + 10 * S)   # a bystander: hashes the file, writes its index
        s.read(git, "src/colors.json", T0 + 11 * S)
        s.write(git, ".git/index", T0 + 12 * S)
        a = s.ask("dependents", path=str(s.root / "src/colors.json"))
        self.assertEqual(sorted(r["file"] for r in a["observed"]), ["dist/theme.json", "dist/web.css", "docs/palette.md"])
        self.assertTrue(all(r["via"] == "python3 tools/build.py" for r in a["observed"]))
        self.assertEqual(a["vcs_metadata"], 1)
        self.assertIs(a["observed_only"], True)
        self.assertIs(a["not_proof_of_safety"], True)
        self.assertCompact(a, 700)

    def test_a_broad_reader_is_summarised_not_listed(self):
        """An agent reads the source, then writes dozens of its own state files: each is only 'one of
        N' in the evidence, so they are counted under the program, with everything reached through them."""
        s = self.s
        s.source("src/colors.json")
        b = s.proc(PY, "python3 tools/build.py", ts=T0 + S)
        s.read(b, "src/colors.json", T0 + 2 * S)
        s.write(b, "dist/web.css", T0 + 3 * S)
        agent = s.proc("/usr/bin/node", "node /usr/local/bin/codex exec", ts=T0 + 5 * S)
        s.read(agent, "src/colors.json", T0 + 6 * S)
        for i in range(40):
            s.write(agent, f".codex/state_{i}.sqlite", T0 + 7 * S + i)
        other = s.proc("/usr/bin/sqlite3", "sqlite3 compact", ts=T0 + 20 * S)
        s.read(other, ".codex/state_0.sqlite", T0 + 21 * S)
        s.write(other, ".codex/compacted.db", T0 + 22 * S)
        a = s.ask("dependents", path=str(s.root / "src/colors.json"))
        self.assertEqual([r["file"] for r in a["observed"]], ["dist/web.css"])
        self.assertEqual(a["broad_readers"][0], {"via": "node /usr/local/bin/codex exec", "wrote": 40})
        self.assertIn({"via": "through a broad reader's outputs", "wrote": 1}, a["broad_readers"])
        self.assertIn("not observable", a["broad_readers_note"])
        self.assertIs(a["not_proof_of_safety"], True)
        self.assertCompact(a, 900)

    def test_changes_group_by_the_parent_image_at_fork_time(self):
        """`bash -lc "python3 build.py && git diff"`: bash runs git in its own process at the end;
        the build is not grouped under git."""
        s = self.s
        sh = s.proc("/usr/bin/git", "git diff -- dist", ts=T0 + S)   # its image at the end: git
        ingest_events(s.con, [{"run_id": "r", "kind": "exec", "pid": sh, "os_pid": sh, "ts_ns": T0 + S,
                               "path": "/bin/bash", "source": "test", "api": "ebpf:exec"}])
        b = s.proc(PY, "python3 tools/build_deploy.py", parent=sh, ts=T0 + 2 * S)
        s.write(b, "dist/api.json", T0 + 3 * S)
        ingest_events(s.con, [{"run_id": "r", "kind": "exec", "pid": sh, "os_pid": sh, "ts_ns": T0 + 5 * S,
                               "path": "/usr/bin/git", "source": "test", "api": "ebpf:exec"}])
        a = s.ask("changes", under=str(s.root), since_ns=T0)
        self.assertEqual(a["groups"][0]["by"], "python3 tools/build_deploy.py")

    # 4. renamed generated file: its origin and sources follow the move
    def test_renamed_generated_file(self):
        s = self.s
        s.source("src/title.txt")
        g = s.proc(PY, "python3 tools/gen.py", ts=T0 + S)
        s.read(g, "src/title.txt", T0 + 2 * S)
        s.write(g, "build/summary.tmp", T0 + 3 * S)
        mv = s.proc("/usr/bin/mv", "mv build/summary.tmp dist/summary.txt", ts=T0 + 5 * S)
        s.rename(mv, "build/summary.tmp", "dist/summary.txt", T0 + 6 * S)
        o = s.ask("origin", path=str(s.root / "dist/summary.txt"))
        self.assertEqual(o["status"], "observed")
        self.assertEqual(o["moved_from"], ["build/summary.tmp"])
        self.assertEqual(o["written_by"]["cmd"], "python3 tools/gen.py")
        src = s.ask("sources", path=str(s.root / "dist/summary.txt"))
        self.assertIn("src/title.txt", src["edit"])
        self.assertCompact(o, 600)

    # 5. agent-produced files: one question by the supplied task, filtered to a directory
    def test_files_of_a_task(self):
        s = self.s
        root = s.proc(PY, "python3 agent.py", os_pid=5000, ts=T0)
        s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                      "source,confidence) VALUES('S-audit','FixtureAgent',?,5000,?,'Dependency audit for checkout',?,"
                      "'registered','t')", (U1, T0, T0 - 1))
        s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                      "source,confidence) VALUES('S-other','FixtureAgent',?,6000,?,'Cache maintenance',?,'registered','t')",
                      (U1, T0, T0 - 1))
        s.con.commit()
        tool = s.proc(PY, "python3 tools/dependency_audit.py", parent=root, ts=T0 + S)
        s.write(tool, "work/alpha.md", T0 + 2 * S)
        s.write(tool, "work/beta.json", T0 + 3 * S)
        s.write(tool, "notes/elsewhere.txt", T0 + 3 * S)
        maint = s.proc(PY, "python3 tools/maintenance.py", ts=T0 + 4 * S)
        s.write(maint, "work/gamma.md", T0 + 5 * S)
        # the same task text in an earlier session that worked elsewhere: counted, not listed
        old = s.proc(PY, "python3 agent.py", os_pid=8000, ts=T0 - 100 * S)
        s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                      "source,confidence) VALUES('S-audit-old','FixtureAgent',?,8000,?,'Dependency audit for checkout',?,"
                      "'registered','t')", (U1, T0 - 100 * S, T0 - 101 * S))
        s.con.commit()
        s.write(s.proc(PY, "python3 tools/dependency_audit.py", parent=old, ts=T0 - 99 * S), "elsewhere/alpha.md", T0 - 98 * S)
        a = s.ask("session", task="dependency audit", under=str(s.root / "work"))
        self.assertEqual([m["session"] for m in a["matched"]], ["S-audit"])
        self.assertEqual(a["matched_elsewhere"], 1)
        self.assertEqual(a["matched"][0]["task"], "Dependency audit for checkout")
        self.assertEqual(a["matched"][0]["source"], "registered")
        self.assertEqual(sorted(f["path"] for f in a["files"]), ["work/alpha.md", "work/beta.json"])
        self.assertEqual([o["path"] for o in a["other_writers_under"]], ["work/gamma.md"])
        self.assertCompact(a, 900)
        none = s.ask("session", task="no such task")
        self.assertEqual(none["matched"], [])
        self.assertIn("never infers", none["note"])

    # 6. unknown origin: decisive at once -- not attributable, and why
    def test_unknown_origin_in_an_observation_gap(self):
        s = self.s
        s.con.execute("UPDATE runs SET ended_ns=? WHERE id='r'", (T0 + 60 * S,))
        s.con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('r2',?,?,?,?,?)",
                      (T0 + 400 * S, str(s.root), "t", str(s.root), "test"))
        s.con.commit()
        s.source("vendor/cache/module.dat")
        t = (T0 + 200 * S) / S
        os.utime(s.root / "vendor/cache/module.dat", (t, t))
        bystander = s.proc("/usr/bin/sha256sum", "sha256sum vendor/cache/module.dat", ts=T0 + 500 * S)
        s.read(bystander, "vendor/cache/module.dat", T0 + 501 * S)   # later reads are not an origin
        o = s.ask("origin", path=str(s.root / "vendor/cache/module.dat"))
        self.assertEqual(o["status"], "unknown")
        self.assertIs(o["attributable"], False)
        self.assertEqual(o["reason"], "observation_gap")
        self.assertIn("from", o["gap"])
        self.assertNotIn("written_by", o)
        self.assertCompact(o, 500)
        src = s.ask("sources", path=str(s.root / "vendor/cache/module.dat"))
        self.assertIsNone(src["edit"])
        self.assertIs(src["attributable"], False)

    def test_unknown_origin_without_a_gap(self):
        self.s.source("vendor/x.bin")
        o = self.s.ask("origin", path=str(self.s.root / "vendor/x.bin"))
        self.assertEqual((o["status"], o["attributable"], o["reason"]), ("unknown", False, "no_observed_write"))
        self.assertCompact(o, 500)

    # 7. two candidate generators: the answer names the one that ran
    def test_the_generator_that_actually_ran(self):
        s = self.s
        for f in ("tools/pack_zip.py", "tools/pack_tar.py", "src/manifest.json"):
            s.source(f)
        p = s.proc(PY, "python3 tools/pack_tar.py --out dist/package.json", ts=T0 + S)
        s.read(p, "tools/pack_tar.py", T0 + S)
        s.read(p, "src/manifest.json", T0 + 2 * S)
        s.write(p, "dist/package.json", T0 + 3 * S)
        o = s.ask("origin", path=str(s.root / "dist/package.json"))
        self.assertIn("tools/pack_tar.py", o["written_by"]["cmd"])
        self.assertNotIn("pack_zip", json.dumps(o))

    # 8. downstream dependency: named, and never a safety claim
    def test_downstream_dependent_without_a_safety_claim(self):
        s = self.s
        s.source("cache/schema.idx")
        c = s.proc(PY, "python3 tools/compile_bundle.py", ts=T0 + S)
        s.read(c, "cache/schema.idx", T0 + 2 * S)
        s.write(c, "dist/app.bundle", T0 + 3 * S)
        a = s.ask("dependents", path=str(s.root / "cache/schema.idx"))
        self.assertEqual(a["observed"], [{"file": "dist/app.bundle", "via": "python3 tools/compile_bundle.py"}])
        self.assertIs(a["not_proof_of_safety"], True)
        leaf = s.ask("dependents", path=str(s.root / "dist/app.bundle"))
        self.assertEqual((leaf["observed"], leaf["count"]), ([], 0))
        self.assertIs(leaf["not_proof_of_safety"], True)
        self.assertIs(leaf["observed_only"], True)

    # 9. the most recent build's changes, grouped under the build driver
    def test_recent_build_changes(self):
        s = self.s
        old = s.proc(PY, "python3 tools/build_deploy.py --region old", ts=T0 + S)
        s.write(old, "dist/api.json", T0 + 2 * S)
        s.write(old, "docs/reference.md", T0 + 2 * S)
        new = s.proc(PY, "python3 tools/build_deploy.py", ts=T0 + 100 * S)
        child = s.proc(PY, "python3 tools/render.py", parent=new, ts=T0 + 101 * S)
        s.write(new, "dist/api.json", T0 + 102 * S)
        s.write(child, "dist/web.js", T0 + 103 * S)
        s.write(new, "logs/build-summary.json", T0 + 104 * S)
        git = s.proc("/usr/bin/git", "git add -A", ts=T0 + 110 * S)
        s.write(git, ".git/index", T0 + 111 * S)
        a = s.ask("changes", under=str(s.root), since_ns=T0)
        g = a["groups"][0]
        self.assertEqual(g["by"], "python3 tools/build_deploy.py")
        self.assertEqual(sorted(g["written"]), ["dist/api.json", "dist/web.js", "logs/build-summary.json"])
        self.assertEqual(a["vcs_metadata"], 1)
        self.assertEqual(a["groups"][1]["written"], ["docs/reference.md"], "a file appears once: at its newest change")
        self.assertCompact(a, 900)

    # 10. known origin: a minimal answer
    def test_known_origin_is_minimal(self):
        self.build()
        o = self.s.ask("origin", path=str(self.s.root / "dist/banner.txt"))
        self.assertEqual(o["status"], "observed")
        self.assertIs(o["attributable"], True)
        self.assertIs(o["complete"], True)
        self.assertIsNone(o["agent"])
        self.assertEqual(set(o), {"q", "path", "status", "attributable", "written_by", "user", "agent", "complete"})
        self.assertCompact(o, 350)


class Integrity(AskBase):
    def test_identity_mismatch_is_not_attributed(self):
        s = self.s
        self.build(out="dist/out.txt")
        os.unlink(s.root / "dist/out.txt")
        (s.root / "dist/out.txt").write_text("replaced while nothing observed")
        o = s.ask("origin", path=str(s.root / "dist/out.txt"))
        self.assertEqual((o["status"], o["attributable"], o["reason"]), ("replaced", False, "identity_mismatch"))
        self.assertEqual(o["previous_file"]["cmd"], "python3 tools/build.py")

    def test_registered_agent_and_supplied_task_are_kept_apart(self):
        s = self.s
        root = s.proc(PY, "python3 agent.py", os_pid=7000, ts=T0)
        s.con.execute("INSERT INTO agent_sessions(session_id,agent_name,user,root_os_pid,root_start_ns,task,started_ns,"
                      "source,confidence) VALUES('S1','MyAgent',?,7000,?,'fix the checkout',?,'registered','t')",
                      (U1, T0, T0 - 1))
        s.con.commit()
        g = s.proc(PY, "python3 gen.py", parent=root, ts=T0 + S)
        s.write(g, "out.txt", T0 + 2 * S)
        o = s.ask("origin", path=str(s.root / "out.txt"))
        self.assertEqual(o["agent"], {"name": "MyAgent", "session": "S1", "source": "registered", "task": "fix the checkout"})

    def test_detected_agent_has_no_task(self):
        s = self.s
        cc = s.proc("/home/j/.local/share/claude/versions/1.0.93/claude", "claude", ts=T0)
        sh = s.proc(SH, "bash -c x", parent=cc, ts=T0 + S)
        s.write(sh, "made.txt", T0 + 2 * S)
        o = s.ask("origin", path=str(s.root / "made.txt"))
        self.assertEqual(o["agent"]["source"], "detected")
        self.assertNotIn("task", o["agent"])

    def test_other_users_evidence_is_invisible(self):
        s = self.s
        p = s.proc(PY, "python3 secret_build.py", user=U2, ts=T0 + S)
        s.write(p, "theirs.txt", T0 + 2 * S)
        restrict(s.con, U1)
        o = ask.ask(s.con, "origin", {"path": str(s.root / "theirs.txt"), "base": str(s.root)})
        self.assertEqual((o["status"], o["attributable"]), ("unknown", False))
        self.assertNotIn("secret_build", json.dumps(o))

    def test_deterministic(self):
        self.build()
        a = [json.dumps(self.s.ask(q, path=str(self.s.root / "dist/banner.txt")), sort_keys=True)
             for q in ("origin", "sources", "dependents") for _ in range(2)]
        self.assertEqual(a[0], a[1])
        self.assertEqual(a[2], a[3])
        self.assertEqual(a[4], a[5])

    def test_lists_are_bounded_with_counts(self):
        s = self.s
        s.source("src/big.json")
        for i in range(60):  # sixty precise dependents (one reader, one output each)
            b = s.proc(PY, f"python3 tools/render.py {i}", ts=T0 + S + i * 1000)
            s.read(b, "src/big.json", T0 + 2 * S + i * 1000)
            s.write(b, f"dist/out{i:02d}.txt", T0 + 3 * S + i * 1000)
        a = s.ask("dependents", path=str(s.root / "src/big.json"))
        self.assertEqual(len(a["observed"]), ask.LIST_MAX)
        self.assertEqual(a["observed_more"], 60 - ask.LIST_MAX)
        self.assertEqual(a["count"], 60)
        self.assertLessEqual(size(a), 2500)


class Interfaces(AskBase):
    def test_api_operation(self):
        self.build()
        r = api.handle({"user": U1, "admin": True, "pid": os.getpid()}, self.s.root,
                       {"v": 1, "op": "ask", "params": {"question": "origin", "path": str(self.s.root / "dist/banner.txt"),
                                                        "base": str(self.s.root)}})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["result"]["written_by"]["cmd"], "python3 tools/build.py")
        bad = api.handle({"user": U1, "admin": True, "pid": os.getpid()}, self.s.root,
                         {"v": 1, "op": "ask", "params": {"question": "what"}})
        self.assertFalse(bad["ok"])

    def test_cli_in_a_workspace(self):
        self.build()
        self.s.con.close()
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        run = lambda *args: subprocess.run([sys.executable, "-m", "whyfs", *args], cwd=self.s.root, env=env,  # noqa: E731
                                           capture_output=True, text=True)
        p = run("ask", "origin", "dist/banner.txt")
        self.assertEqual(p.returncode, 0, p.stderr)
        o = json.loads(p.stdout)
        self.assertEqual((o["path"], o["status"]), (os.path.join("dist", "banner.txt"), "observed"))
        idx = run("ask")
        self.assertIn("origin FILE", idx.stdout)
        self.assertLess(len(idx.stdout.encode()), 900)
        sch = json.loads(run("ask", "--schema").stdout)
        self.assertEqual(sorted(sch["questions"]), ["changes", "dependents", "origin", "session", "sources"])
        top = run("--help").stdout
        self.assertIn("whyfs ask", top)
        self.s.con = connect(self.s.root)


if __name__ == "__main__":
    unittest.main()
