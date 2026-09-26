"""Platform-neutral query semantics over canonical records (runs on every OS).

Each test writes canonical records (schema.validate_record) straight into a store and asks
why / impact / history, so the rules hold whichever collector produced the evidence.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from whyfs.query import history, impact, impact_details, why  # noqa: E402
from whyfs.schema import validate_record  # noqa: E402
from whyfs.store import connect, ingest_events  # noqa: E402


class Recorder:
    def __init__(self, root: Path, source="ebpf"):
        self.root, self.src, self.t, self.recs, self.cons = root, source, 1_700_000_000_000_000_000, [], []

    def p(self, name):
        return str(self.root / name)

    def _add(self, **rec):
        self.t += 1000
        rec.setdefault("ts_ns", self.t)
        rec.update(run_id="run", source=self.src)
        validate_record(rec)
        self.recs.append(rec)

    def proc(self, key, exe, cmd, parent=None):
        self._add(kind="process", pid=key, os_pid=key, ppid=parent, parent_key=parent, exe=exe, cwd=None, command=cmd)
        self._add(kind="exec", pid=key, os_pid=key, path=exe, api=f"{self.src}:exec")

    def read(self, key, name, mapped=False):
        self._add(kind="io", pid=key, os_pid=key, path=self.p(name), read=True, write=False, api=f"{self.src}:{'mmap' if mapped else 'rw'}")

    def write(self, key, name, mapped=False):
        self._add(kind="io", pid=key, os_pid=key, path=self.p(name), read=False, write=True, api=f"{self.src}:{'mmap' if mapped else 'rw'}")

    def unlink(self, key, name):
        self._add(kind="unlink", pid=key, os_pid=key, path=self.p(name),
                  api="etw:delete" if self.src == "etw" else "ebpf:unlink")

    def store(self):
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), f"{self.src}-native"))
        ingest_events(con, self.recs)
        self.cons.append(con)  # closed in tearDown (Windows cannot delete an open database)
        return con


class QuerySemantics(unittest.TestCase):
    source = "ebpf"

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name).resolve()
        self.r = Recorder(self.root, self.source)
        self.r.proc(1, "/bin/sh" if os.name != "nt" else r"C:\Windows\System32\cmd.exe", "sh")

    def tearDown(self):
        for con in self.r.cons:
            con.close()
        self.td.cleanup()

    def names(self, paths):
        return sorted(Path(p).name for p in paths)

    def test_batch_outputs_are_marked_shared(self):
        r = self.r
        r.proc(2, "cl", "cl /c a.c b.c", 1)
        r.read(2, "a.c"); r.read(2, "b.c"); r.write(2, "b.obj"); r.write(2, "a.obj")
        con = r.store()
        w = why(con, r.p("a.obj"))
        self.assertEqual((self.names(w["inputs"]), w["shared_by_outputs"]), (["a.c", "b.c"], 1))
        edges = [e for e in impact_details(con, r.p("a.c")) if e["from"] == r.p("a.c")]
        self.assertTrue(edges and all(e["shared"] == 2 for e in edges))

    def test_single_output_is_exact(self):
        r = self.r
        r.proc(2, "gcc", "cc1 u.c", 1)
        r.read(2, "u.c"); r.write(2, "u.s")
        con = r.store()
        self.assertEqual(why(con, r.p("u.s"))["shared_by_outputs"], 0)
        self.assertEqual([e["shared"] for e in impact_details(con, r.p("u.c"))], [0])

    def test_mapped_output_counts_inputs_read_after_the_mapping(self):
        """MSVC link maps its output before mapping its inputs; bytes flow into a writable
        view until it is unmapped."""
        r = self.r
        r.proc(2, "link", "link a.obj b.obj", 1)
        r.write(2, "app.exe", mapped=True); r.read(2, "a.obj", mapped=True); r.read(2, "b.obj", mapped=True)
        con = r.store()
        self.assertEqual(self.names(why(con, r.p("app.exe"))["inputs"]), ["a.obj", "b.obj"])
        self.assertIn("app.exe", {Path(b).name for _a, b, _e, _x in impact(con, r.p("a.obj"))})

    def test_plain_write_before_read_is_not_an_input(self):
        r = self.r
        r.proc(2, "tool", "tool", 1)
        r.write(2, "out.txt"); r.read(2, "later.txt")
        con = r.store()
        self.assertEqual(why(con, r.p("out.txt"))["inputs"], [])

    def test_reading_back_ones_own_output_is_not_an_input(self):
        r = self.r
        r.proc(2, "cl", "cl /c x.c y.c", 1)
        r.read(2, "x.c"); r.write(2, "x.obj"); r.read(2, "x.obj"); r.read(2, "y.c"); r.write(2, "y.obj")
        con = r.store()
        self.assertNotIn("x.obj", self.names(why(con, r.p("y.obj"))["inputs"]))
        self.assertNotIn("y.obj", {Path(b).name for _a, b, _e, _x in impact(con, r.p("x.obj"))})
        self.assertIn("y.obj", {Path(b).name for _a, b, _e, _x in impact(con, r.p("x.obj"), include_noise=True)},
                      "the raw view keeps the evidence")

    def test_scratch_output_deleted_by_its_writer_is_hidden(self):
        r = self.r
        r.proc(2, "link", "link", 1)
        r.read(2, "in.obj"); r.write(2, "lnk123.tmp"); r.read(2, "lnk123.tmp"); r.unlink(2, "lnk123.tmp"); r.write(2, "app.exe")
        con = r.store()
        self.assertEqual(self.names(why(con, r.p("app.exe"))["inputs"]), ["in.obj"])
        self.assertEqual({Path(b).name for _a, b, _e, _x in impact(con, r.p("in.obj"))}, {"app.exe"})

    def test_history_counts_writes_and_renames(self):
        r = self.r
        r.proc(2, "tool", "tool", 1)
        r.read(2, "a"); r.write(2, "out"); r.write(2, "out2")
        con = r.store()
        self.assertEqual(len(history(con, r.p("out"))), 1)


class QuerySemanticsETW(QuerySemantics):
    source = "etw"


if __name__ == "__main__":
    unittest.main()
