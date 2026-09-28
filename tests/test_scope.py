"""Machine scope policy: one rule language, three implementations (docs/MACHINE_MODE.md).

whyfs/scope.py is the reference; the Linux and Windows collectors parse the same rule files
and must classify every shared vector (tests/scope_vectors.json) identically.  The vectors
include the product rule: a user file anywhere (Desktop, Documents, a project, an arbitrary
directory) is in scope without any registration.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from whyfs.scope import Scope, defaults_text

HERE = Path(__file__).resolve().parent
V = json.loads((HERE / "scope_vectors.json").read_text(encoding="utf-8"))


class ReferenceTests(unittest.TestCase):
    def test_linux_vectors(self):
        s = Scope(False).add(V["linux_extra"])
        for p, want in V["linux"]:
            self.assertEqual(s.classify(p), want, p)
        for p, want in V["linux_images"]:
            self.assertEqual(s.image_excluded(p), want, p)

    def test_windows_vectors(self):
        s = Scope(True).add(V["windows_extra"])
        for p, want in V["windows"]:
            self.assertEqual(s.classify(p), want, p)
        for p, want in V["windows_images"]:
            self.assertEqual(s.image_excluded(p), want, p)

    def test_user_files_anywhere_are_in_scope_by_default(self):
        for nt, paths in ((False, ["/home/u/Desktop/r.csv", "/srv/x/y", "/opt/p/q", "/data/a"]),
                          (True, [r"C:\Users\U\Desktop\r.csv", r"D:\any\where.txt", r"C:\proj\dist\app.js"])):
            s = Scope(nt)
            for p in paths:
                self.assertEqual(s.classify(p), "in", p)

    def test_include_beats_default_exclude(self):
        s = Scope(False).add("include /usr/local/src\n")
        self.assertEqual(s.classify("/usr/local/src/proj/main.c"), "in")
        self.assertEqual(s.classify("/usr/local/lib/x.so"), "out")


def _native(exe, *, nt, extra):
    with tempfile.TemporaryDirectory() as d:
        f1, f2 = Path(d, "default.conf"), Path(d, "extra.conf")
        f1.write_text(defaults_text(nt), encoding="utf-8")
        f2.write_text(extra, encoding="utf-8")

        def run(flag, value):
            return subprocess.run([exe, "--scope", str(f1), "--scope", str(f2), flag, value],
                                  capture_output=True, check=True).stdout.decode()
        yield run


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux native collector")
class LinuxNativeTests(unittest.TestCase):
    def test_vectors(self):
        from whyfs import native_collect
        ok, why = native_collect.available()
        if not ok:
            self.skipTest(why)
        for run in _native(str(native_collect.binary()), nt=False, extra=V["linux_extra"]):
            for p, want in V["linux"]:
                self.assertEqual(run("--scope-classify", p), want, p)
            for p, want in V["linux_images"]:
                self.assertEqual(run("--scope-image", p), "1" if want else "0", p)


@unittest.skipUnless(os.name == "nt", "Windows native collector")
class WindowsNativeTests(unittest.TestCase):
    def test_vectors(self):
        from nativebin import win_collector  # the collector for this machine's architecture
        exe = win_collector()
        if not exe:
            self.skipTest("collector not built")
        exe = str(exe)
        for run in _native(exe, nt=True, extra=V["windows_extra"]):
            for p, want in V["windows"]:
                self.assertEqual(run("--scope-classify", p), want, p)
            for p, want in V["windows_images"]:
                self.assertEqual(run("--scope-image", p), "1" if want else "0", p)


if __name__ == "__main__":
    unittest.main()
