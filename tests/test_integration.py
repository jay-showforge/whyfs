import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

class WhyFSIntegration(unittest.TestCase):
    def run_cli(self, cwd, *args, check=True):
        p = subprocess.run([sys.executable, "-m", "whyfs", *args], cwd=cwd, env=ENV,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check and p.returncode != 0:
            self.fail(f"cmd failed {args}:\nstdout={p.stdout}\nstderr={p.stderr}")
        return p

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux capture backend")
    def test_why_impact_history(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            self.run_cli(d,"init",".")
            (d/"raw.txt").write_text("hello\nsecond\n")
            self.run_cli(d,"trace","--workspace",".","--","bash","-c","tr a-z A-Z < raw.txt > upper.txt")
            self.run_cli(d,"trace","--workspace",".","--","bash","-c","wc -l < upper.txt > report.txt")
            w=self.run_cli(d,"why","upper.txt","--json")
            data=json.loads(w.stdout)
            self.assertTrue(data["path"].endswith("upper.txt"))
            self.assertTrue(any(x.endswith("raw.txt") for x in data["inputs"]))
            imp=json.loads(self.run_cli(d,"impact","raw.txt","--json").stdout)
            tos={Path(e["to"]).name for e in imp}
            self.assertIn("upper.txt",tos); self.assertIn("report.txt",tos)
            hist=json.loads(self.run_cli(d,"history","report.txt","--json").stdout)
            self.assertGreaterEqual(len(hist),1)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux capture backend")
    def test_input_opened_after_output_redirection_is_an_input(self):
        """`cmd input > output`: the shell opens the output before the command opens its
        input. The preload backend records opens, not writes, so an open-for-write must not
        bound which reads count as inputs (why) or which outputs follow a read (impact)."""
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); self.run_cli(d,"init",".")
            (d/"in.txt").write_text("a\nb\n")
            self.run_cli(d,"trace","--workspace",".","--","bash","-c","head -n 1 in.txt > mid.txt")
            self.run_cli(d,"trace","--workspace",".","--","bash","-c","sort mid.txt > out.txt")
            data=json.loads(self.run_cli(d,"why","mid.txt","--json").stdout)
            self.assertEqual([Path(p).name for p in data["inputs"]],["in.txt"])
            self.assertEqual(Path(data["exe"]).name,"head")
            self.assertEqual(Path(data["parent"]["exe"]).name,"bash")  # the traced shell
            tos={Path(e["to"]).name for e in json.loads(self.run_cli(d,"impact","in.txt","--json").stdout)}
            self.assertEqual(tos,{"mid.txt","out.txt"})

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux capture backend")
    def test_workspace_filter_is_default(self):
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); self.run_cli(d,"init",".")
            (d/"in.txt").write_text("x")
            self.run_cli(d,"trace","--workspace",".","--",sys.executable,"-c",
                         'from pathlib import Path; Path("out.txt").write_text(Path("in.txt").read_text())')
            data=json.loads(self.run_cli(d,"why","out.txt","--json").stdout)
            self.assertEqual([Path(p).name for p in data["inputs"]],["in.txt"])
            stats=json.loads(self.run_cli(d,"stats","--json").stdout)
            self.assertLess(stats["events"],20)


    @unittest.skipUnless(sys.platform.startswith("linux") and subprocess.run(["sh","-c","command -v gcc >/dev/null"],stdout=subprocess.DEVNULL).returncode==0, "Linux gcc")
    def test_preload_fallback_does_not_claim_static_binary_lineage(self):
        """v0.1 must fail honestly where v0.2 eBPF is supposed to win."""
        with tempfile.TemporaryDirectory() as td:
            d=Path(td); self.run_cli(d,"init",".")
            (d/"copy.c").write_text(
                '#include <stdio.h>\nint main(void){FILE*i=fopen("in.txt","r"),*o=fopen("out.txt","w");'
                'if(!i||!o)return 2;int c;while((c=fgetc(i))!=EOF)fputc(c,o);return 0;}\n'
            )
            cc=subprocess.run(["gcc","-static","-O2","copy.c","-o","copy"],cwd=d,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if cc.returncode != 0:
                self.skipTest("static libc unavailable")
            (d/"in.txt").write_text("x")
            self.run_cli(d,"trace","--workspace",".","--","./copy")
            why=self.run_cli(d,"why","out.txt","--json",check=False)
            self.assertNotEqual(why.returncode,0,why.stdout)

    def test_redaction_helper(self):
        sys.path.insert(0,str(ROOT/"src"))
        from whyfs.cli import redact_argv
        s=redact_argv(["curl","--token","abc123","--password=hunter2","ok"])
        self.assertNotIn("abc123",s); self.assertNotIn("hunter2",s); self.assertIn("<redacted>",s)

    def test_redaction_covers_common_key_names(self):
        """Regression: API_KEY=..., --access-key X, PRIVATE_KEY=..., *credential* were stored verbatim."""
        sys.path.insert(0,str(ROOT/"src"))
        from whyfs.cli import redact_argv
        s=redact_argv(["deploy","API_KEY=k1","--access-key","k2","PRIVATE_KEY=k3","db_credential=k4","ok"])
        for secret in ("k1","k2","k3","k4"):
            self.assertNotIn(secret,s)
        self.assertIn("ok",s)

if __name__ == "__main__": unittest.main()
