"""Windows collector event model (whyfs-collect-win), exercised by replay.

The collector decodes ETW events into a small, documented record stream (the Windows
kernel contract, see whyfs-collect-win.c: rec_t / rec_write); `--replay FILE --emit`
runs exactly the live event model over such a stream.  These tests need no elevation.
Live ETW behaviour is covered by tests/test_windows_live.py and the Windows gate.
"""
import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from whyfs.query import history, impact, why  # noqa: E402
from whyfs.schema import validate_record  # noqa: E402
from whyfs.store import connect, ingest_events  # noqa: E402


def collector() -> Path | None:
    if os.name != "nt":
        return None
    arch = {"AMD64": "x64", "ARM64": "arm64"}.get((os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "")).upper())
    for p in (os.environ.get("WHYFS_COLLECT_WIN"), REPO / "src" / "whyfs" / "_bin" / f"win-{arch}" / "whyfs-collect-win.exe"):
        if p and Path(p).exists():
            return Path(p)
    return None


EXE = collector()
R_PROC_START, R_PROC_INFO, R_PROC_END, R_CREATE, R_CLEANUP, R_KEYINFO, R_READ, R_WRITE, R_DELETE_PATH, R_RENAME_PATH, \
    R_NAME_DELETE, R_MAP, R_CLOSE = range(1, 14)
OPEN, CREATE_NEW, OVERWRITE_IF = 0x01000000, 0x02000000, 0x05000000
DIRECTORY, DELETE_ON_CLOSE = 0x1, 0x1000


class Stream:
    """Builds a decoded kernel-record stream (little-endian, as rec_write writes it)."""

    def __init__(self, root: Path):
        self.root = root
        self.recs = []
        self.ts = time.time_ns()
        self.fo = 0xFFFF800000010000

    def new_fo(self):
        self.fo += 0x100
        return self.fo

    def add(self, typ, pid, *, ppid=0, flags=0, user=1, fo=0, key=0, s1=None, s2=None, s3=None, dt=1000):
        self.ts += dt
        b = struct.pack("<qIIIIIQQ", self.ts, typ, pid, ppid, flags, user, fo, key)
        for s in (s1, s2, s3):  # s3: the process's user SID string
            b += struct.pack("<I", 0xFFFFFFFF) if s is None else struct.pack("<I", len(s.encode())) + s.encode()
        self.recs.append(b)
        return self

    def p(self, rel):
        return str(self.root / rel)

    # process lifecycle: Kernel-Process start (image; user unknown = 2) + system-logger info (command line, user)
    def proc(self, pid, ppid, exe, cmd, user=1, info_after=0):
        self.add(R_PROC_START, pid, ppid=ppid, s1=exe, user=2)
        if not info_after:
            self.add(R_PROC_INFO, pid, ppid=ppid, s2=cmd, user=user)
        return self

    def info(self, pid, ppid, cmd, user=1):
        return self.add(R_PROC_INFO, pid, ppid=ppid, s2=cmd, user=user)

    def open(self, pid, fo, rel_or_abs, flags=OPEN):
        path = rel_or_abs if ":" in rel_or_abs[:3] or rel_or_abs.startswith("\\\\") else self.p(rel_or_abs)
        return self.add(R_CREATE, pid, fo=fo, flags=flags, s1=path)

    def read(self, pid, fo, key=0):
        return self.add(R_READ, pid, fo=fo, key=key)

    def write(self, pid, fo, key=0):
        return self.add(R_WRITE, pid, fo=fo, key=key)

    def replay(self, *extra):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".rec") as f:
            f.write(b"".join(self.recs))
        try:
            p = subprocess.run([str(EXE), "--replay", f.name, "--root", str(self.root), "--emit", "--run-id", "run",
                                "--temp-root", str(TEMPROOT), *extra], capture_output=True)
        finally:
            os.unlink(f.name)
        assert p.returncode == 0, p.stderr.decode(errors="replace")
        lines = p.stdout.decode().splitlines()
        stats = json.loads(lines[-1])
        out = []
        for line in lines[:-1]:
            d = json.loads(line)
            for k in ("path", "path2", "exe", "cwd", "command"):
                if isinstance(d.get(k), str):
                    d[k] = bytes.fromhex(d[k]).decode("utf-8", "surrogateescape")
            validate_record(d)  # every record the Windows collector emits is canonical
            out.append(d)
        return out, stats


TEMPROOT = Path(tempfile.gettempdir()) / "whyfs-model-temproot"
PY, CMD, CL = r"C:\Python313\python.exe", r"C:\Windows\System32\cmd.exe", r"C:\VS\cl.exe"
SHELL = 100


@unittest.skipUnless(EXE, "Windows collector binary not built (native/windows/build.ps1)")
class WindowsModelTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="whyfs-winmodel-")
        self.root = Path(self.td.name).resolve()
        TEMPROOT.mkdir(exist_ok=True)
        self.s = Stream(self.root)
        self.s.proc(SHELL, 4, CMD, "cmd.exe")

    def tearDown(self):
        self.td.cleanup()

    def db(self, items):
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('run',1,?,?,?,?)",
                    (str(self.root), "t", str(self.root), "etw-native"))
        ingest_events(con, items)
        return con

    def io(self, items, write):
        return [(x["os_pid"], Path(x["path"]).name) for x in items if x["kind"] == "io" and x["write"] == write]

    def test_read_then_write_lineage_and_parent(self):
        s, fi, fo = self.s, self.s.new_fo(), self.s.new_fo()
        s.proc(200, SHELL, PY, 'python.exe -c "copy"').open(200, fi, "in.txt").read(200, fi).open(200, fo, "out.txt", OVERWRITE_IF).write(200, fo)
        items, st = s.replay()
        con = self.db(items)
        w = why(con, str(self.root / "out.txt"))
        self.assertEqual((w["exe"], w["inputs"], w["command"]), (PY, [str(self.root / "in.txt")], 'python.exe -c "copy"'))
        self.assertEqual(w["parent"]["exe"], CMD)
        self.assertEqual(st["submitted"], len(items))
        con.close()

    def test_another_users_processes_are_not_recorded(self):
        s, f = self.s, self.s.new_fo()
        s.proc(300, SHELL, PY, "python.exe --token SECRETVALUE", user=0).open(300, f, "theirs.txt", OVERWRITE_IF).write(300, f)
        items, st = s.replay()
        self.assertEqual([x for x in items if x.get("os_pid") == 300], [])
        self.assertNotIn("SECRETVALUE", json.dumps(items))
        self.assertGreater(st["other_user"], 0)

    def test_evidence_waits_for_the_process_user_then_is_kept_or_dropped(self):
        """The user comes from the system-logger session, which can arrive after the file events."""
        s, f1, f2 = self.s, self.s.new_fo(), self.s.new_fo()
        s.proc(400, SHELL, PY, "", info_after=1).open(400, f1, "mine.txt", OVERWRITE_IF).write(400, f1).info(400, SHELL, "python.exe mine", user=1)
        s.proc(401, SHELL, PY, "", info_after=1).open(401, f2, "other.txt", OVERWRITE_IF).write(401, f2).info(401, SHELL, "python.exe other", user=0)
        items, st = s.replay()
        self.assertIn((400, "mine.txt"), self.io(items, True))
        self.assertNotIn((401, "other.txt"), self.io(items, True))
        self.assertEqual(st["user_unresolved"], 0)

    def test_first_read_per_open_and_every_reopen(self):
        s, f = self.s, self.s.new_fo()
        s.proc(500, SHELL, PY, "reader")
        for _ in range(3):
            s.open(500, f, "in.txt").read(500, f).read(500, f).read(500, f)
        items, _ = s.replay()
        self.assertEqual(self.io(items, False), [(500, "in.txt")] * 3)

    def test_file_object_reuse_follows_the_latest_open(self):
        s, f = self.s, self.s.new_fo()
        s.proc(600, SHELL, PY, "reuse").open(600, f, "a.txt").read(600, f).open(600, f, "b.txt", OVERWRITE_IF).write(600, f)
        items, _ = s.replay()
        self.assertEqual((self.io(items, False), self.io(items, True)), ([(600, "a.txt")], [(600, "b.txt")]))

    def test_inherited_handle_write_is_attributed_to_the_child(self):
        s, f = self.s, self.s.new_fo()
        s.open(SHELL, f, "redirected.txt", OVERWRITE_IF)          # cmd opens the redirection target
        s.proc(700, SHELL, r"C:\Windows\System32\findstr.exe", "findstr x").write(700, f)
        items, _ = s.replay()
        self.assertEqual(self.io(items, True), [(700, "redirected.txt")])

    def test_rename_and_directory_rename_rewrite_open_paths(self):
        s, fd, fx, fy = self.s, self.s.new_fo(), self.s.new_fo(), self.s.new_fo()
        s.proc(800, SHELL, PY, "mover")
        s.open(800, fx, r"build\x.txt", OVERWRITE_IF)
        s.open(800, fd, "build", OPEN | DIRECTORY)
        s.add(R_RENAME_PATH, 800, fo=fd, s1=s.p("dist"))            # move the directory
        s.write(800, fx)                                              # the open file is now dist\x.txt
        s.open(800, fy, r"dist\x.txt").add(R_RENAME_PATH, 800, fo=fy, s1=s.p(r"dist\final.txt"))
        items, _ = s.replay()
        self.assertEqual(self.io(items, True), [(800, "x.txt")])
        self.assertEqual([x["path"] for x in items if x["kind"] == "io"], [str(self.root / "dist" / "x.txt")])
        renames = [(Path(x["path"]).name, Path(x["path2"]).name) for x in items if x["kind"] == "rename"]
        self.assertEqual(renames, [("build", "dist"), ("x.txt", "final.txt")])
        con = self.db(items)
        w = why(con, str(self.root / "dist" / "final.txt"))
        self.assertEqual(w["renamed_from"][0]["from"], str(self.root / "dist" / "x.txt"))
        con.close()

    def test_delete_and_delete_on_close(self):
        s, f = self.s, self.s.new_fo()
        s.proc(900, SHELL, CMD, "del a.txt").add(R_DELETE_PATH, 900, s1=s.p("a.txt"))
        s.open(900, f, "scratch.tmp", CREATE_NEW | DELETE_ON_CLOSE).write(900, f).add(R_CLEANUP, 900, fo=f)
        items, _ = s.replay()
        unl = [(Path(x["path"]).name, x["api"]) for x in items if x["kind"] == "unlink"]
        self.assertEqual(unl, [("a.txt", "etw:delete"), ("scratch.tmp", "etw:delete-on-close")])

    def test_memory_mapped_reads_and_writes(self):
        s, fa, fo, ka, ko = self.s, self.s.new_fo(), self.s.new_fo(), 0xAAA0, 0xBBB0
        s.proc(1000, SHELL, r"C:\VS\link.exe", "link a.obj /OUT:app.exe")
        s.open(1000, fa, "a.obj").add(R_KEYINFO, 1000, fo=fa, key=ka).add(R_MAP, 1000, key=ka, flags=1)
        s.open(1000, fo, "app.exe", OVERWRITE_IF).add(R_KEYINFO, 1000, fo=fo, key=ko).add(R_MAP, 1000, key=ko, flags=4)
        items, _ = s.replay()
        self.assertEqual((self.io(items, False), self.io(items, True)), ([(1000, "a.obj")], [(1000, "app.exe")]))
        self.assertTrue(all(x["api"] == "etw:mmap" for x in items if x["kind"] == "io"))

    def test_file_key_is_retired_by_name_delete(self):
        s, f, k = self.s, self.s.new_fo(), 0xCCC0
        s.proc(1100, SHELL, PY, "k").open(1100, f, "old.txt").add(R_KEYINFO, 1100, fo=f, key=k)
        s.add(R_NAME_DELETE, 1100, key=k).add(R_MAP, 1100, key=k, flags=1)   # key reused by an unknown file
        items, _ = s.replay()
        self.assertEqual(self.io(items, False), [])

    def test_derived_temporaries_bridge_lineage(self):
        s = self.s
        tmp = str(TEMPROOT / "cc1234.s")
        fs, ft, ft2, fo = (s.new_fo() for _ in range(4))
        s.proc(1200, SHELL, r"C:\gcc\cc1.exe", "cc1 u.c").open(1200, fs, "u.c").read(1200, fs).open(1200, ft, tmp, OVERWRITE_IF).write(1200, ft)
        s.proc(1201, SHELL, r"C:\gcc\as.exe", "as").open(1201, ft2, tmp).read(1201, ft2).open(1201, fo, "u.o", OVERWRITE_IF).write(1201, fo)
        items, _ = s.replay()
        con = self.db(items)
        w = why(con, str(self.root / "u.o"))
        self.assertIn(str(self.root / "u.c"), w["inputs_via_temporaries"])
        con.close()

    def test_state_directory_is_not_evidence(self):
        s, f = self.s, self.s.new_fo()
        s.proc(1300, SHELL, PY, "whyfs why x").open(1300, f, r".whyfs\whyfs.db").read(1300, f).write(1300, f)
        items, _ = s.replay()
        self.assertEqual([x for x in items if x["kind"] != "process" and ".whyfs" in (x.get("path") or "")], [])

    def test_paths_are_matched_case_insensitively(self):
        s, f = self.s, self.s.new_fo()
        upper = str(self.root).upper() + r"\OUT.TXT"
        s.proc(1400, SHELL, PY, "case").open(1400, f, upper, OVERWRITE_IF).write(1400, f)
        items, _ = s.replay()
        self.assertEqual(self.io(items, True), [(1400, "OUT.TXT")])
        con = self.db(items)
        self.assertIsNotNone(why(con, str(self.root / "out.txt")), "lowercase query must find the uppercase evidence")
        con.close()

    def test_unrelated_process_command_line_is_not_stored(self):
        s, f = self.s, self.s.new_fo()
        s.proc(1500, SHELL, r"C:\db\mysql.exe", "mysql -u admin secretdb").open(1500, f, r"C:\elsewhere\my.cnf").read(1500, f).add(R_PROC_END, 1500)
        s.add(R_PROC_END, SHELL)
        items, st = s.replay()
        self.assertNotIn("secretdb", json.dumps(items))
        self.assertEqual(st["pending_exec"], 0)

    def test_batch_and_interleaved_outputs_are_marked_shared_not_guessed(self):
        """One MSVC `cl` compiling several files reads every source before writing any
        object: which source produced which object is not observable, and why() says so."""
        s = self.s
        f = [s.new_fo() for _ in range(8)]
        # batch: read a.c, b.c; write b.obj, a.obj
        s.proc(1700, SHELL, CL, "cl /c a.c b.c")
        s.open(1700, f[0], "a.c").read(1700, f[0]).open(1700, f[1], "b.c").read(1700, f[1])
        s.open(1700, f[2], "b.obj", OVERWRITE_IF).write(1700, f[2]).open(1700, f[3], "a.obj", OVERWRITE_IF).write(1700, f[3])
        # interleaved: read x.c, write x.obj, read y.c, write y.obj
        s.proc(1701, SHELL, CL, "tool x y")
        s.open(1701, f[4], "x.c").read(1701, f[4]).open(1701, f[5], "x.obj", OVERWRITE_IF).write(1701, f[5])
        s.open(1701, f[6], "y.c").read(1701, f[6]).open(1701, f[7], "y.obj", OVERWRITE_IF).write(1701, f[7])
        # single output: never marked
        fa, fb = s.new_fo(), s.new_fo()
        s.proc(1702, SHELL, CL, "cl /c u.c").open(1702, fa, "u.c").read(1702, fa).open(1702, fb, "u.obj", OVERWRITE_IF).write(1702, fb)
        items, _ = s.replay()
        con = self.db(items)
        shared = {n: why(con, str(self.root / n))["shared_by_outputs"] for n in ("a.obj", "b.obj", "x.obj", "y.obj", "u.obj")}
        con.close()
        self.assertEqual(shared, {"a.obj": 1, "b.obj": 1, "x.obj": 0, "y.obj": 1, "u.obj": 0})

    def test_reused_file_object_in_an_unrelated_process_is_not_attributed(self):
        """Regression: node probed for a missing symbols\\x.pdb (the Create failed), the kernel
        reused the file object for Chrome's pipe, and Chrome's pipe write was stored as a
        write of the workspace path."""
        s, f = self.s, self.s.new_fo()
        s.proc(1800, SHELL, r"C:\node\node.exe", "node build.js").open(1800, f, r"symbols\x.pdb")   # failed probe
        s.proc(1801, 4, r"C:\Chrome\chrome.exe", "chrome --no-startup-window").write(1801, f)       # unrelated process
        items, st = s.replay()
        self.assertEqual([x for x in items if x.get("os_pid") == 1801], [])
        self.assertEqual(self.io(items, True), [])
        self.assertEqual(st["foreign_file_object"], 1)

    def test_close_retires_the_file_object(self):
        s, f = self.s, self.s.new_fo()
        s.proc(1900, SHELL, PY, "x").open(1900, f, "a.txt").read(1900, f).add(R_CLOSE, 1900, fo=f).write(1900, f)
        items, _ = s.replay()
        self.assertEqual((self.io(items, False), self.io(items, True)), ([(1900, "a.txt")], []))

    def test_no_open_records_on_windows(self):
        """Kernel-File logs Create when it is issued: success is unknown, so no open evidence."""
        s, f = self.s, self.s.new_fo()
        s.proc(2000, SHELL, PY, "probe").open(2000, f, "maybe-missing.cfg")
        items, _ = s.replay()
        self.assertEqual([x for x in items if x["kind"] == "open"], [])
        self.assertEqual([x for x in items if x.get("os_pid") == 2000], [], "a probe alone does not make a process relevant")

    def test_impact_and_history(self):
        s, a, b, c = self.s, self.s.new_fo(), self.s.new_fo(), self.s.new_fo()
        s.proc(1600, SHELL, PY, "step1").open(1600, a, "src.txt").read(1600, a).open(1600, b, "mid.txt", OVERWRITE_IF).write(1600, b)
        s.proc(1601, SHELL, PY, "step2").open(1601, b, "mid.txt").read(1601, b).open(1601, c, "out.txt", OVERWRITE_IF).write(1601, c)
        items, _ = s.replay()
        con = self.db(items)
        self.assertEqual({Path(y).name for _x, y, _e, _r in impact(con, str(self.root / "src.txt"))}, {"mid.txt", "out.txt"})
        self.assertEqual(len(history(con, str(self.root / "out.txt"))), 1)
        con.close()


@unittest.skipUnless(EXE, "Windows collector binary not built")
class WindowsRedactionTests(unittest.TestCase):
    def red(self, cmd):
        return subprocess.run([str(EXE), "--redact", cmd], capture_output=True).stdout.decode()

    def test_secret_values_are_removed_and_the_raw_line_kept(self):
        cases = {
            "tool.exe --password hunter2 build": "tool.exe --password <redacted> build",
            "deploy /token:abc123 /v": "deploy /token:<redacted> /v",
            "set API_KEY=xyz && run": "set API_KEY=<redacted> && run",
            "curl --Authorization \"Bearer zzz\" https://x": "curl --Authorization \"<redacted>\" https://x",
            r'cmd /c "type C:\a.txt > b.txt"': r'cmd /c "type C:\a.txt > b.txt"',
            r"C:\Python313\python.exe -c print(1)": r"C:\Python313\python.exe -c print(1)",
        }
        for cmd, want in cases.items():
            self.assertEqual(self.red(cmd), want, cmd)


if __name__ == "__main__":
    unittest.main()
