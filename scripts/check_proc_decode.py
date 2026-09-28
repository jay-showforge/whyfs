"""Check (not a gate by itself; CI runs it): the Windows collector's direct decoding of process
records must agree with TDH on every record.  Starts the standalone machine collector with
WHYFS_DIAG_CHECK_PROC=1 (each record decoded both ways), spawns a mix of processes (native
exe, cmd, PowerShell, Python, with arguments and secrets to redact), and requires
proc_mismatch == 0 and that the fast path was taken.  Run elevated with the service stopped.

  python scripts\\check_proc_decode.py COLLECTOR.exe --out DIR
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from whyfs.scope import defaults_text  # noqa: E402
from whyfs.store import connect  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("collector")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    root = tempfile.mkdtemp(prefix="whyfs-procchk-", dir=os.path.expanduser("~"))
    connect(pathlib.Path(root)).close()
    sc = os.path.join(root, "scope.conf")
    open(sc, "w").write(defaults_text(True))
    c = subprocess.Popen([a.collector, "--machine", "--root", root, "--run-id", "procchk", "--session", "whyfs-procchk",
                          "--scope", sc], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, env=dict(os.environ, WHYFS_DIAG_CHECK_PROC="1"))
    c.stdout.readline()
    time.sleep(2)
    work = pathlib.Path(root) / "w"
    work.mkdir()
    for i in range(40):
        subprocess.run(["cmd", "/c", f"echo {i} > n{i}.txt && type n{i}.txt >nul"], cwd=work, check=True)
        subprocess.run([sys.executable, "-c", "import sys; open(sys.argv[1], 'w').write('x')", str(work / f"p{i}.txt"),
                        "--password", "hunter2", "café ☃"], check=True)
    subprocess.run(["powershell", "-NoProfile", "-Command", "$env:API_KEY='x'; 1..5 | % { Get-Date } | Out-Null"], check=True)
    time.sleep(8)
    c.stdin.write("stop\n")
    c.stdin.flush()
    so, se = c.communicate(timeout=180)
    for ln in se.splitlines():
        if "mismatch" in ln:
            print("  " + ln)
    stats = json.loads([ln for ln in so.splitlines() if ln.startswith("{")][-1])
    rep = {k: stats.get(k) for k in ("proc_fast", "proc_slow", "proc_mismatch", "received", "lost_file", "lost_sys")}
    ok = stats.get("proc_mismatch") == 0 and (stats.get("proc_fast") or 0) >= 160
    rep["ok"] = ok
    (out / "check_proc_decode.json").write_text(json.dumps(rep, indent=1))
    print(f"process-record decode check: {'PASS' if ok else 'FAIL'} {rep}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
