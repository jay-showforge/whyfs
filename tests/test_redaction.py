"""Command-line secret redaction: one policy, three implementations.

whyfs/redact.py is the reference; the Linux collector (whyfs-collect.c) and the Windows
collector (whyfs-collect-win.c) must produce exactly the same text for the shared vectors
(tests/redaction_vectors.json), and every wrapper form (sh -c, bash -c, cmd /c, PowerShell)
must reach the store without its secret values.  Every secret value in these tests contains
the marker SECRETVAL.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from whyfs.redact import redact_argv, redact_text

HERE = Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "redaction_vectors.json").read_text(encoding="utf-8"))["text"]
MARK = "SECRETVAL"

# Wrapper argv as the kernel/OS hands it over: the secrets sit inside one merged argument.
WRAPPERS = [
    (["sh", "-c", "deploy --token SECRETVAL1 --api-key=SECRETVAL2 && echo done"], ["sh", "-c", "deploy", "--token", "echo done"]),
    (["bash", "-c", "export API_KEY=SECRETVAL1; ./run --password 'SECRETVAL2 x' | tee log"], ["bash", "export API_KEY=", "./run --password", "tee log"]),
    (["bash", "-lc", "ACCESS_TOKEN=SECRETVAL1 PRIVATE_KEY=SECRETVAL2 make -j8"], ["bash", "-lc", "ACCESS_TOKEN=", "PRIVATE_KEY=", "make -j8"]),
    (["cmd.exe", "/c", '"C:\\Python313\\python.exe" -c "print(1)" --password SECRETVAL1 API_KEY=SECRETVAL2'], ["cmd.exe", "/c", "python.exe", "print(1)", "--password", "API_KEY="]),
    (["powershell", "-NoProfile", "-Command", "$env:API_KEY='SECRETVAL1'; Invoke-X -Token SECRETVAL2 -Name ok"], ["powershell", "-NoProfile", "$env:API_KEY=", "Invoke-X -Token", "-Name ok"]),
    (["sh", "-c", "deploy --token 'SECRETVAL1 with space'"], ["sh", "deploy --token"]),
    (["prog", "--auth-token", "SECRETVAL1", "--verbose"], ["prog", "--auth-token", "--verbose"]),
    (["curl", "-H", "Authorization: Bearer SECRETVAL1", "https://example.test/x"], ["curl", "Authorization: Bearer", "https://example.test/x"]),
    # a merged command line as an ordinary argument (no shell flag before it): its first "=" is not a KEY=VALUE split
    (["whyfs-collect", "--redact-text", 'cmd.exe /c ""py.exe" -c "x" --password SECRETVAL1 API_KEY=SECRETVAL2"'],
     ["whyfs-collect", "--password", "API_KEY="]),
    (["tool", "TOOL --TOKEN SECRETVAL1 --Api-Key=SECRETVAL2 Password=SECRETVAL3"], ["TOOL --TOKEN", "--Api-Key=", "Password="]),
    (["env", "PASSWORD=SECRETVAL1 with spaces"], ["env", "PASSWORD="]),  # one-word KEY: the whole value
]
# Raw Windows command lines (cmd.exe and PowerShell parse their own line; no argv exists).
WINDOWS_LINES = [
    ('C:\\WINDOWS\\system32\\cmd.exe /c ""C:\\Python313\\python.exe" -c "import sys; open(\'secret-out.txt\',\'w\').write(\'s\')" '
     '--password SECRETVAL1 API_KEY=SECRETVAL2"', ["cmd.exe /c", "python.exe", "secret-out.txt", "--password", "API_KEY="]),
    ('cmd /c "set "ACCESS_TOKEN=SECRETVAL1" && tool.exe /token:SECRETVAL2 /v"', ["cmd /c", "ACCESS_TOKEN=", "tool.exe /token:", "/v"]),
    ('powershell.exe -NoProfile -Command "& tool -Password SECRETVAL1; $Secret = \\"SECRETVAL2\\""', ["powershell.exe -NoProfile -Command", "& tool -Password", "$Secret"]),
    ('pwsh -c "Connect-Thing -ApiKey SECRETVAL1 -Credential:SECRETVAL2 -Name ok"', ["pwsh -c", "Connect-Thing -ApiKey", "-Credential:", "-Name ok"]),
]


class ReferenceTests(unittest.TestCase):
    def test_shared_vectors(self):
        for inp, want in VECTORS:
            with self.subTest(inp=inp):
                self.assertEqual(redact_text(inp), want)
                self.assertNotIn(MARK, want)

    def test_wrapper_argv_hides_secrets_keeps_the_rest(self):
        for argv, visible in WRAPPERS:
            with self.subTest(argv=argv):
                shown = redact_argv(argv)
                self.assertNotIn(MARK, shown)
                self.assertIn("<redacted>", shown)
                for part in visible:
                    self.assertIn(part, shown)

    def test_raw_windows_lines(self):
        for line, visible in WINDOWS_LINES:
            with self.subTest(line=line):
                shown = redact_text(line)
                self.assertNotIn(MARK, shown)
                for part in visible:
                    self.assertIn(part, shown)

    def test_ordinary_commands_unchanged(self):
        for argv in (["cc", "-O2", "-o", "out/token.o", "src/secret.c"], ["git", "commit", "-m", "rotate password docs"],
                     ["python", "-c", "print('api_key handling')"], ["node", "vite.js", "build", "--mode", "production"]):
            with self.subTest(argv=argv):
                import shlex
                self.assertEqual(redact_argv(argv), shlex.join(argv))

    def test_idempotent(self):
        for inp, want in VECTORS:
            self.assertEqual(redact_text(want), want)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux native collector")
class LinuxNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from whyfs import native_collect
        ok, why = native_collect.available()
        if not ok:
            raise unittest.SkipTest(f"native collector unavailable: {why}")
        cls.exe = str(native_collect.binary())

    def _run(self, *args):
        return subprocess.run([self.exe, *args], capture_output=True, check=True).stdout.decode("utf-8")

    def test_shared_vectors(self):
        for inp, want in VECTORS:
            if not inp:
                continue  # an empty argv element cannot be passed as the hook's value distinctly
            with self.subTest(inp=inp):
                self.assertEqual(self._run("--redact-text", inp), want)

    def test_argv_path_equals_reference(self):
        for argv, _ in WRAPPERS:
            with self.subTest(argv=argv):
                got = self._run("--redact-argv", *argv)
                self.assertEqual(got, redact_argv(argv))
                self.assertNotIn(MARK, got)


@unittest.skipUnless(os.name == "nt", "Windows native collector")
class WindowsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from nativebin import win_collector  # the collector for this machine's architecture
        exe = win_collector()
        if not exe:
            raise unittest.SkipTest("whyfs-collect-win.exe not built")
        cls.exe = str(exe)

    def _run(self, *args):
        return subprocess.run([self.exe, *args], capture_output=True, check=True).stdout.decode("utf-8")

    def test_shared_vectors(self):
        for inp, want in VECTORS:
            if not inp:
                continue
            with self.subTest(inp=inp):
                self.assertEqual(self._run("--redact-text", inp), want)

    def test_stored_form_of_raw_lines(self):
        for line, visible in WINDOWS_LINES + [(inp, []) for inp, _ in VECTORS if inp]:
            with self.subTest(line=line):
                shown = self._run("--redact", line)
                self.assertNotIn(MARK, shown)
                for part in visible:
                    self.assertIn(part, shown)


if __name__ == "__main__":
    unittest.main()
