"""macOS collector: Endpoint Security messages -> the shared event model -> the shared store.

These are REPLAY tests: deterministic, hand-written Endpoint Security message streams (the
normalized form `whyfs-collect --es-record` writes) go through the real translation
(native/macos/whyfs-es.c) and the real event model and writer (native/whyfs-collect.c).  They
prove the translation and everything after it; they are not live Endpoint Security tests
(scripts/macos_live_es.py is).
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

if sys.platform != "darwin":
    raise unittest.SkipTest("macOS collector (macOS only)")

from whyfs import macos  # noqa: E402
from whyfs.scope import defaults_text  # noqa: E402

BIN = None
_TD = None
T0 = 1_790_000_000_000_000_000
DEV = 16777230


def setUpModule():
    global BIN, _TD
    _TD = tempfile.TemporaryDirectory(prefix="whyfs-mac-")
    BIN = os.environ.get("WHYFS_TEST_COLLECTOR") or str(macos.build_collector(Path(_TD.name, "whyfs-collect"), sign=None))


def tearDownModule():
    _TD.cleanup()


def proc(pid, exe, *, ppid=1, ruid=501, pidver=None):
    return {"pid": pid, "pidver": pidver or pid * 7, "ppid": ppid, "ruid": ruid, "euid": ruid, "start": T0 - 10**9, "exe": exe}


def f(path, ino, dev=DEV, mode=0o100644):
    return {"path": path, "dev": dev, "ino": ino, "mode": mode}


class Stream:
    """Endpoint Security messages in delivery order, with increasing time and sequence numbers."""

    def __init__(self):
        self.msgs, self.t, self.seq = [], T0, 0

    def add(self, type, p, gap=0, **kw):
        self.t += 1000
        self.seq += 1 + gap
        m = {"type": type, "ts": self.t, "gseq": self.seq, "proc": p, **kw}
        self.msgs.append(m)
        return m

    # helpers for common shapes
    def spawn(self, parent, child_pid, exe, argv, cwd=None, ruid=None):
        child = proc(child_pid, parent["exe"], ppid=parent["pid"], ruid=parent["ruid"] if ruid is None else ruid)
        self.add("fork", parent, target=child)
        target = proc(child_pid, exe, ppid=parent["pid"], ruid=child["ruid"])
        self.add("exec", child, target=target, argv=argv, **({"cwd": cwd} if cwd else {}))
        return target

    def write(self, p, path, ino):
        self.add("open", p, f1=f(path, ino), fflag=0x0602)  # FWRITE|O_CREAT|O_TRUNC
        self.add("close", p, f1=f(path, ino), modified=1)

    def read(self, p, path, ino):
        self.add("open", p, f1=f(path, ino), fflag=0x0001)  # FREAD
        self.add("close", p, f1=f(path, ino), modified=0)


def run(stream_or_msgs, *, extra="", root=None, run_id="t", emit=True, record=None):
    msgs = stream_or_msgs.msgs if isinstance(stream_or_msgs, Stream) else stream_or_msgs
    with tempfile.TemporaryDirectory() as d:
        rp, dp, xp = Path(d, "in.jsonl"), Path(d, "default.conf"), Path(d, "extra.conf")
        rp.write_text("".join(json.dumps(m) + "\n" for m in msgs))
        dp.write_text(defaults_text(False, True))
        xp.write_text(extra)
        args = [BIN, "--es-replay", str(rp), "--machine", "--scope", str(dp), "--scope", str(xp),
                "--root", str(root or d), "--run-id", run_id]
        if emit:
            args.append("--emit")
        if record:
            args += ["--es-record", str(record)]
        p = subprocess.run(args, capture_output=True, text=True)
        if p.returncode != 0:
            raise AssertionError(f"collector exit {p.returncode}: {p.stderr}")
    lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    stats = lines[-1]
    recs = []
    for r in lines[:-1]:
        for k in ("path", "path2", "exe", "cwd", "command"):
            if isinstance(r.get(k), str):
                r[k] = bytes.fromhex(r[k]).decode("utf-8", "surrogateescape")
        recs.append(r)
    return recs, stats


def events(recs, **match):
    return [r for r in recs if r["kind"] != "process" and all(r.get(k) == v for k, v in match.items())]


def procs(recs):
    return {r["pid"]: r for r in recs if r["kind"] == "process"}


class ReplayTranslation(unittest.TestCase):
    def setUp(self):
        self.s = Stream()
        self.launchd = proc(1, "/sbin/launchd", ppid=0, ruid=0)
        self.shell = self.s.spawn(self.launchd, 300, "/bin/zsh", ["-zsh"], cwd="/Users/jay")

    def test_write_is_evidence_with_identity_and_ancestry(self):
        py = self.s.spawn(self.shell, 301, "/usr/bin/python3", ["python3", "gen.py"], cwd="/Users/jay/proj")
        self.s.write(py, "/Users/jay/proj/out.txt", 4242)
        recs, stats = run(self.s)
        w = events(recs, path="/Users/jay/proj/out.txt", write=True)
        self.assertEqual(len(w), 1, recs)
        self.assertEqual(w[0]["api"], "es:close-modified")
        self.assertEqual(w[0]["file_id"], f"mac:{DEV}:4242")
        self.assertEqual(w[0]["source"], "es")
        ps = procs(recs)
        me = ps[w[0]["pid"]]
        self.assertEqual(me["exe"], "/usr/bin/python3")
        self.assertEqual(me["command"], "python3 gen.py")
        self.assertEqual(me["cwd"], "/Users/jay/proj")
        self.assertEqual(me["user"], "uid:501")
        self.assertEqual(me["os_pid"], 301)
        parent = ps[me["parent_key"]]  # ancestry: the shell that forked it, kept with it
        self.assertEqual(parent["exe"], "/bin/zsh")
        self.assertEqual(parent["os_pid"], 300)
        self.assertEqual(stats["kernel_drops"], 0)

    def test_open_for_reading_is_the_read_and_close_unmodified_is_not_a_write(self):
        cc = self.s.spawn(self.shell, 302, "/usr/bin/cc", ["cc", "-c", "a.c"], cwd="/Users/jay/proj")
        self.s.read(cc, "/Users/jay/proj/a.c", 11)
        self.s.write(cc, "/Users/jay/proj/a.o", 12)
        recs, _ = run(self.s)
        rd = events(recs, path="/Users/jay/proj/a.c")
        self.assertEqual([(r["read"], r["write"], r["api"]) for r in rd], [(True, False, "es:open-read")])
        self.assertEqual(len(events(recs, path="/Users/jay/proj/a.o", write=True)), 1)
        self.assertLess(rd[0]["ts_ns"], events(recs, path="/Users/jay/proj/a.o")[0]["ts_ns"])  # order kept

    def test_rename_lineage_and_unlink(self):
        ed = self.s.spawn(self.shell, 303, "/usr/bin/vim", ["vim", "notes.md"], cwd="/Users/jay")
        self.s.write(ed, "/Users/jay/.notes.md.swp", 20)
        self.s.add("rename", ed, f1=f("/Users/jay/.notes.md.swp", 20), dir="/Users/jay", name="notes.md")
        self.s.add("rename", ed, f1=f("/Users/jay/notes.md", 20), f2=f("/Users/jay/archive.md", 21))  # onto an existing file
        self.s.add("unlink", ed, f1=f("/Users/jay/archive.md", 20))
        recs, _ = run(self.s)
        ren = events(recs, kind="rename")
        self.assertEqual([(r["path"], r["path2"], r["api"]) for r in ren],
                         [("/Users/jay/.notes.md.swp", "/Users/jay/notes.md", "es:rename"),
                          ("/Users/jay/notes.md", "/Users/jay/archive.md", "es:rename")])
        self.assertEqual([(r["path"], r["api"]) for r in events(recs, kind="unlink")], [("/Users/jay/archive.md", "es:unlink")])

    def test_path_reuse_records_each_files_own_identity(self):
        a = self.s.spawn(self.shell, 304, "/usr/bin/touch", ["gen1"])
        self.s.write(a, "/Users/jay/report.csv", 100)
        self.s.add("unlink", a, f1=f("/Users/jay/report.csv", 100))
        b = self.s.spawn(self.shell, 305, "/usr/bin/python3", ["python3", "gen2.py"])
        self.s.write(b, "/Users/jay/report.csv", 101)
        recs, _ = run(self.s)
        ids = [r["file_id"] for r in events(recs, path="/Users/jay/report.csv", write=True)]
        self.assertEqual(ids, [f"mac:{DEV}:100", f"mac:{DEV}:101"])

    def test_redaction_before_anything_is_stored(self):
        c = self.s.spawn(self.shell, 306, "/usr/bin/curl", ["curl", "--token", "s3cr3tvalue", "-H",
                                                             "Authorization: Bearer abc.def", "https://x"])
        self.s.write(c, "/Users/jay/dl.json", 30)
        recs, _ = run(self.s)
        me = procs(recs)[events(recs, path="/Users/jay/dl.json")[0]["pid"]]
        self.assertNotIn("s3cr3tvalue", me["command"])
        self.assertNotIn("abc.def", me["command"])
        self.assertIn("curl", me["command"])

    def test_scope_filtering_and_image_exclusion(self):
        app = self.s.spawn(self.shell, 307, "/Applications/Safari.app/Contents/MacOS/Safari", ["Safari"])
        self.s.write(app, "/Users/jay/Library/Caches/com.apple.Safari/x.db", 40)
        self.s.write(app, "/System/Library/x", 41)
        self.s.write(app, "/Library/Preferences/p.plist", 42)
        mds = proc(88, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mds",
                   ruid=0)
        self.s.write(mds, "/Users/jay/Documents/indexed.txt", 43)
        self.s.write(app, "/Users/jay/Downloads/page.html", 44)
        recs, stats = run(self.s)
        paths = {r["path"] for r in recs if r["kind"] != "process"}
        self.assertEqual(paths, {"/Users/jay/Downloads/page.html"})
        self.assertGreaterEqual(stats["excluded_image"], 1)
        self.assertGreater(stats["filtered"], 0)

    def test_derived_temporaries_carry_lineage(self):
        cc = self.s.spawn(self.shell, 308, "/usr/bin/cc", ["cc", "a.c"], cwd="/Users/jay/proj")
        tmp = "/private/var/folders/zz/abc/T/cc1.s"
        self.s.read(cc, "/Users/jay/proj/a.c", 50)
        self.s.write(cc, tmp, 51)
        asm = self.s.spawn(self.shell, 309, "/usr/bin/as", ["as", tmp], cwd="/Users/jay/proj")
        self.s.read(asm, tmp, 51)
        self.s.write(asm, "/Users/jay/proj/a.o", 52)
        recs, _ = run(self.s)
        apis = {(r["path"], r["api"]) for r in recs if r["kind"] != "process"}
        self.assertIn((tmp, "es:close-modified:derived-temp"), apis)
        self.assertIn((tmp, "es:open-read:derived-temp"), apis)
        self.assertIn(("/Users/jay/proj/a.o", "es:close-modified"), apis)

    def test_clone_copyfile_and_shared_writable_mmap(self):
        fd = self.s.spawn(self.shell, 310, "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", ["Finder"])
        self.s.add("clone", fd, f1=f("/Users/jay/a.key", 60), dir="/Users/jay", name="a copy.key", f2=f("/Users/jay/a copy.key", 61))
        self.s.add("copyfile", fd, f1=f("/Users/jay/b.txt", 62), dir="/Users/jay/Desktop", name="b.txt")
        db = self.s.spawn(self.shell, 311, "/usr/bin/sqlite3", ["sqlite3", "x.db"])
        self.s.add("mmap", db, f1=f("/Users/jay/x.db", 63), prot=3, mflags=0x0001)  # PROT_READ|WRITE, MAP_SHARED
        self.s.add("mmap", db, f1=f("/Users/jay/ro.bin", 64), prot=1, mflags=0x0002)  # private read
        recs, _ = run(self.s)
        io = {(r["path"], r["read"], r["write"], r["api"], r.get("file_id")) for r in recs if r["kind"] == "io"}
        self.assertIn(("/Users/jay/a.key", True, False, "es:clone", f"mac:{DEV}:60"), io)
        self.assertIn(("/Users/jay/a copy.key", False, True, "es:clone", f"mac:{DEV}:61"), io)
        self.assertIn(("/Users/jay/b.txt", True, False, "es:copyfile", f"mac:{DEV}:62"), io)
        self.assertIn(("/Users/jay/Desktop/b.txt", False, True, "es:copyfile", None), io)  # identity unknown: none, never guessed
        self.assertIn(("/Users/jay/x.db", False, True, "es:mmap", f"mac:{DEV}:63"), io)
        self.assertIn(("/Users/jay/ro.bin", True, False, "es:mmap", f"mac:{DEV}:64"), io)
        self.assertNotIn(("/Users/jay/ro.bin", False, True, "es:mmap", f"mac:{DEV}:64"), io)

    def test_directories_are_not_files(self):
        self.s.add("open", self.shell, f1=f("/Users/jay/proj", 70, mode=0o040755), fflag=1)
        recs, _ = run(self.s)
        self.assertEqual(events(recs, path="/Users/jay/proj"), [])

    def test_sequence_gaps_are_counted_as_lost_events(self):
        py = self.s.spawn(self.shell, 312, "/usr/bin/python3", ["python3"])
        self.s.add("open", py, gap=3, f1=f("/Users/jay/l.txt", 80), fflag=0x0602)
        self.s.add("close", py, gap=2, f1=f("/Users/jay/l.txt", 80), modified=1)
        _, stats = run(self.s)
        self.assertEqual(stats["kernel_drops"], 5)

    def test_users_are_recorded_per_process(self):
        root_proc = self.s.spawn(self.launchd, 313, "/usr/sbin/cron", ["cron"], ruid=0)
        self.s.write(root_proc, "/private/var/root/job.out", 90)
        py = self.s.spawn(self.shell, 314, "/usr/bin/python3", ["python3"])
        self.s.write(py, "/Users/jay/mine.txt", 91)
        recs, _ = run(self.s)
        ps = procs(recs)
        users = {r["path"]: ps[r["pid"]]["user"] for r in recs if r["kind"] == "io"}
        self.assertEqual(users, {"/private/var/root/job.out": "uid:0", "/Users/jay/mine.txt": "uid:501"})

    def test_record_then_replay_is_identical(self):
        py = self.s.spawn(self.shell, 315, "/usr/bin/python3", ["python3", "x.py", "--password", "hunter2"])
        self.s.read(py, "/Users/jay/in.csv", 95)
        self.s.write(py, "/Users/jay/out.csv", 96)
        with tempfile.TemporaryDirectory() as d:
            cap = Path(d, "cap.jsonl")
            first, s1 = run(self.s, record=cap)
            again, s2 = run([json.loads(x) for x in cap.read_text().splitlines()])
        self.assertEqual(first, again)
        self.assertEqual(s1["received"], s2["received"])


class ReplayIntoStore(unittest.TestCase):
    """The collector's writer fills a real store; the shared label, history and impact read it."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory(prefix="whyfs-mac-store-")
        self.addCleanup(self.td.cleanup)
        self.dir = Path(macos.true_path(self.td.name))  # /private/var/folders/..., as Endpoint Security reports it
        self.root = self.dir / "store"
        self.root.mkdir()
        from whyfs.store import connect
        con = connect(self.root)
        con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                    ("t", T0 - 10**9, str(self.root), "whyfs machine", str(self.root), "es-native"))
        con.commit()
        con.close()
        self.work = self.dir / "work"
        self.work.mkdir()

    def store(self, stream):
        run(stream, extra=f"include {self.work}\n", root=self.root, emit=False)
        from whyfs.store import connect
        con = connect(self.root)
        con.execute("UPDATE runs SET ended_ns=? WHERE id='t'", (time.time_ns(),))
        con.commit()
        return con

    def real(self, name, text="x"):
        p = self.work / name
        p.write_text(text)
        st = os.stat(p)
        return str(p), st.st_ino, st.st_dev & 0xFFFFFFFF

    def test_label_names_the_creator_inputs_and_dependents(self):
        from whyfs.label import explain_file
        src, si, dev = self.real("data.csv")
        out, oi, _ = self.real("report.txt")
        s = Stream()
        sh = proc(400, "/bin/zsh", ruid=os.getuid())
        py = s.spawn(sh, 401, "/usr/bin/python3", ["python3", "report.py"], cwd=str(self.work))
        s.add("open", py, f1=f(src, si, dev), fflag=1)
        s.add("open", py, f1=f(out, oi, dev), fflag=0x0602)
        s.add("close", py, f1=f(out, oi, dev), modified=1)
        cat = s.spawn(sh, 402, "/bin/cat", ["cat", "report.txt"], cwd=str(self.work))
        pub, pi, _ = self.real("published.txt")
        s.add("open", cat, f1=f(out, oi, dev), fflag=1)
        s.add("open", cat, f1=f(pub, pi, dev), fflag=0x0602)
        s.add("close", cat, f1=f(pub, pi, dev), modified=1)
        con = self.store(s)
        lb = explain_file(con, out)
        self.assertEqual(lb["status"], "labelled", lb)
        self.assertEqual(lb["created_by"]["exe"], "/usr/bin/python3")
        self.assertEqual(lb["created_by"]["cwd"], str(self.work))
        self.assertIn(src, [i["path"] if isinstance(i, dict) else i for i in lb["inputs"]])
        self.assertEqual(lb["identity"]["check"], "match")
        self.assertIn(pub, json.dumps(lb["dependents"]))
        hist = [h["kind"] for h in lb["history"]]
        self.assertIn("io", hist)

    def test_path_reuse_never_attaches_old_evidence(self):
        """The file observed at a path was replaced (unobserved) by another file: new inode."""
        from whyfs.label import explain_file
        out, oi, dev = self.real("reused.txt")
        s = Stream()
        sh = proc(410, "/bin/zsh", ruid=os.getuid())
        gen = s.spawn(sh, 411, "/usr/bin/python3", ["python3", "gen.py"], cwd=str(self.work))
        s.write(gen, out, oi)
        con = self.store(s)
        self.assertEqual(explain_file(con, out)["status"], "labelled")
        os.unlink(out)  # replaced while nothing was observed: APFS gives the new file a new inode
        Path(out).write_text("other")
        self.assertNotEqual(os.stat(out).st_ino, oi)
        lb = explain_file(con, out)
        self.assertEqual(lb["status"], "not-observed", lb)
        self.assertEqual(lb["identity"]["check"], "mismatch")
        self.assertEqual(lb["previous_file_at_path"]["written_by"], "/usr/bin/python3")

    def test_symlinked_and_case_variant_queries_find_the_file(self):
        from whyfs.label import explain_file
        out, oi, dev = self.real("Mixed.txt")
        s = Stream()
        sh = proc(420, "/bin/zsh", ruid=os.getuid())
        gen = s.spawn(sh, 421, "/usr/bin/python3", ["python3"], cwd=str(self.work))
        s.write(gen, out, oi)
        con = self.store(s)
        via_var = out.replace("/private/var/", "/var/", 1)  # the symlinked spelling users see
        self.assertEqual(explain_file(con, via_var)["status"], "labelled")
        case_insensitive = subprocess.run(["diskutil", "info", "/"], capture_output=True, text=True).stdout
        if "Case-sensitive" not in case_insensitive:
            self.assertEqual(explain_file(con, out.replace("Mixed.txt", "mixed.TXT"))["status"], "labelled")


class Identity(unittest.TestCase):
    def test_file_id_format_and_compare(self):
        from whyfs.label import compare_ids
        with tempfile.NamedTemporaryFile() as t:
            st = os.stat(t.name)
            self.assertEqual(macos.file_id(t.name), f"mac:{st.st_dev & 0xFFFFFFFF}:{st.st_ino}")
        self.assertEqual(compare_ids("mac:1:5", "mac:1:5"), "match")
        self.assertEqual(compare_ids("mac:1:5", "mac:1:6"), "mismatch")
        self.assertEqual(compare_ids("mac:1:5", "mac:2:5"), "unknown")  # a renumbered volume proves nothing
        self.assertEqual(compare_ids(None, "mac:1:5"), "unknown")

    def test_apfs_does_not_reuse_inode_numbers_for_a_recreated_path(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "x")
            seen = set()
            for _ in range(200):
                p.write_text("a")
                ino = os.stat(p).st_ino
                self.assertNotIn(ino, seen)
                seen.add(ino)
                p.unlink()

    def test_true_path_resolves_links_and_keeps_a_missing_tail(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertTrue(macos.true_path(d).startswith("/private/"))
            self.assertTrue(macos.true_path(os.path.join(d, "no", "such")).endswith("/no/such"))
        self.assertEqual(macos.true_path("/tmp"), "/private/tmp")


class PlatformHelpers(unittest.TestCase):
    def test_process_facts_come_from_libproc(self):
        from whyfs import agents
        me = os.getpid()
        parent, image, cmd = macos.parent_and_image(me)
        self.assertEqual(parent, os.getppid())
        self.assertTrue(image and os.path.basename(image).startswith("python"), image)
        self.assertIn("unittest", cmd or "")
        self.assertEqual(macos.process_user(me), f"uid:{os.getuid()}")
        start = agents.proc_start_ns(me)
        self.assertTrue(start and abs(time.time_ns() - start) < 3600 * 10**9)

    def test_peer_credentials_of_a_unix_socket(self):
        import socket
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b:
            pid, uid = macos.peer_credentials(a)
        self.assertEqual((pid, uid), (os.getpid(), os.getuid()))

    def test_paths_are_macos_locations(self):
        from whyfs import client, machine
        self.assertEqual(machine.paths()["root"], Path("/Library/Application Support/WhyFS/machine"))
        self.assertEqual(client.SOCKET_PATH, "/var/run/whyfs/api.sock")


if __name__ == "__main__":
    unittest.main()
