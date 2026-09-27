#!/usr/bin/env python3
"""Windows cost decomposition for the native-executable x300 workload (diagnostic harness).

Rotated rounds; the collector runs elevated as a plain process (same binary the service
runs), started before and stopped after each monitored run (its startup rundown is outside
the timed window).  Modes:

  A        no collector (baseline)
  EMPTY    both sessions, no providers/flags (session overhead only)
  KFILE    Kernel-File + Kernel-Process only, callbacks discard
  SYS      system logger PROCESS+VAMAP only, callbacks discard
  SYSNV    system logger PROCESS only (no VAMAP), callbacks discard
  ALL      everything enabled, callbacks discard (all kernel emission + delivery)
  FULL     the production collector (decode + model + SQLite)

  python scripts\\win_perf_decomp.py --out DIR [--rounds 20]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from whyfs.store import connect  # noqa: E402

EXE = REPO / "src" / "whyfs" / "_bin" / "win-x64" / "whyfs-collect-win.exe"
MODES = {
    "A": None,
    "EMPTY": {"WHYFS_DIAG_DISCARD": "1", "WHYFS_DIAG_NO_KFILE": "1", "WHYFS_DIAG_NO_SYS": "1"},
    "KFILE": {"WHYFS_DIAG_DISCARD": "1", "WHYFS_DIAG_NO_SYS": "1"},
    "SYS": {"WHYFS_DIAG_DISCARD": "1", "WHYFS_DIAG_NO_KFILE": "1"},
    "SYSNV": {"WHYFS_DIAG_DISCARD": "1", "WHYFS_DIAG_NO_KFILE": "1", "WHYFS_DIAG_NO_VAMAP": "1"},
    "ALL": {"WHYFS_DIAG_DISCARD": "1"},
    "FULL": {},
}
COPY_C = r"""#include <stdio.h>
int main(int argc,char **argv){ if(argc!=3) return 2; FILE *in=fopen(argv[1],"rb"), *out=fopen(argv[2],"wb");
  if(!in||!out) return 3; char b[8192]; size_t n; while((n=fread(b,1,sizeof b,in))>0) if(fwrite(b,1,n,out)!=n) return 4;
  fclose(in); fclose(out); return 0; }
"""
LOOP = r"for /L %i in (1,1,300) do @.\copy.exe raw.txt out-%i.txt"


def summary(xs):
    xs = sorted(xs)
    boots = []
    rnd = random.Random(7)
    for _ in range(2000):
        s = sorted(rnd.choice(xs) for _ in xs)
        boots.append(s[len(s) // 2])
    boots.sort()
    return {"median": xs[len(xs) // 2], "ci90": [boots[100], boots[1900]], "n": len(xs)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rounds", type=int, default=20)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ws = Path(os.environ["TEMP"]) / "whyfs-decomp-ws"
    ws.mkdir(exist_ok=True)
    (ws / "copy.c").write_text(COPY_C)
    (ws / "raw.txt").write_text("x" * 4096)
    vc = os.environ.get("WHYFS_VCVARS", r"C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat")
    subprocess.run(f'cmd /c ""{vc}" >nul && cl /nologo /O2 copy.c >nul"', cwd=ws, check=True)
    connect(ws).close()
    sid = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout.strip().split(",")[-1].strip('"')
    names = list(MODES)
    rows = []
    for r in range(a.rounds + 1):
        order = names[r % len(names):] + names[:r % len(names)]
        if r % 2:
            order.reverse()
        rec = {"warmup": r == 0}
        for m in order:
            subprocess.run("del /q out-*.txt 2>nul", cwd=ws, shell=True)
            p = None
            if MODES[m] is not None:
                env = dict(os.environ, **MODES[m])
                p = subprocess.Popen([str(EXE), "--root", str(ws), "--run-id", f"decomp-{m}", "--user-sid", sid,
                                      "--session", "whyfs-decomp", "--temp-root", os.environ["TEMP"]],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
                p.stdout.readline()
                time.sleep(1.5)
            t0 = time.perf_counter()
            subprocess.run(LOOP, cwd=ws, shell=True, check=True)
            dt = time.perf_counter() - t0
            if p:
                out_, _ = p.communicate("stop\n", timeout=120)
                rec[m + "_stats"] = json.loads(out_.strip().splitlines()[-1])
            else:
                time.sleep(1.5)
            rec[m] = dt
        rows.append(rec)
        print(f"round {r}: " + " ".join(f"{m}={rec[m]*1000:.0f}" for m in names), flush=True)
    meas = [x for x in rows if not x["warmup"]]
    res = {"rows": rows, "per_mode_ms": {m: summary([x[m] * 1000 for x in meas]) for m in names},
           "minus_A_ms": {m: summary([(x[m] - x["A"]) * 1000 for x in meas]) for m in names if m != "A"},
           "overhead_pct": {m: summary([(x[m] / x["A"] - 1) * 100 for x in meas]) for m in names if m != "A"}}
    for m in names[1:]:
        s, o = res["minus_A_ms"][m], res["overhead_pct"][m]
        print(f"{m:6} {s['median']:+7.1f} ms (CI90 {s['ci90'][0]:+.1f}..{s['ci90'][1]:+.1f})  {o['median']:+.2f}%")
    (out / "decomp.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
