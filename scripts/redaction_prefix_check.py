#!/usr/bin/env python3
"""Evidence that the redaction regression tests fail on the pre-fix implementations.

  python scripts/redaction_prefix_check.py --old-cli OLD_cli.py [--old-win-exe OLD.exe] --out DIR

Runs the wrapper and raw-line cases of tests/test_redaction.py through the pre-fix Python
redactor (cli.redact_argv from an older cli.py) and, on Windows, the pre-fix collector's
--redact hook; writes DIR/prefix.json with the number of outputs that still contain a
secret.  Secret values are never written: outputs are stored with SECRETVAL* masked.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import test_redaction as T  # noqa: E402


def mask(s):
    return re.sub(r"SECRETVAL\d*", "<LEAKED>", s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--old-cli", required=True)
    ap.add_argument("--old-win-exe")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    ns = {}
    src = Path(a.old_cli).read_text(encoding="utf-8")
    fn = src[src.index("def redact_argv("):]
    fn = fn[:fn.index("\ndef ", 1)]
    exec("import shlex\n" + fn, ns)
    rep = {"python_argv": [], "windows_raw": []}
    for argv, _ in T.WRAPPERS:
        out = ns["redact_argv"](argv)
        rep["python_argv"].append({"leak": T.MARK in out, "shown": mask(out)})
    if a.old_win_exe:
        for line, _ in T.WINDOWS_LINES:
            out = subprocess.run([a.old_win_exe, "--redact", line], capture_output=True).stdout.decode("utf-8")
            rep["windows_raw"].append({"leak": T.MARK in out, "shown": mask(out)})
    rep["python_leaks"] = sum(r["leak"] for r in rep["python_argv"])
    rep["windows_leaks"] = sum(r["leak"] for r in rep["windows_raw"])
    Path(a.out).mkdir(parents=True, exist_ok=True)
    Path(a.out, "prefix.json").write_text(json.dumps(rep, indent=1))
    print(f"pre-fix python redact_argv: {rep['python_leaks']}/{len(rep['python_argv'])} wrapper cases leak; "
          f"pre-fix windows collector: {rep['windows_leaks']}/{len(rep['windows_raw'])} raw lines leak")


if __name__ == "__main__":
    main()
