#!/usr/bin/env python3
"""Counterbalanced paired benchmark of MSVC builds with and without whyfs (Windows).

AB/BA order per pair (alternating which condition goes first), a fixed 1 s idle before every
measured build, a warm-up build in both conditions, the collector started through the real
service (`whyfs daemon start/stop`).  For each workload: raw timings, cl/link phases, Defender
CPU, median paired delta with a bootstrap 90% CI, fast/slow split by condition (small
workload), and collector loss counters.

  python scripts\\win_msvc_paired.py --out DIR [--pairs 30]
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import win_gate as g  # noqa: E402
import win_msvc_characterize as ch  # noqa: E402


def boot_ci(xs, n=4000, seed=5):
    rnd = random.Random(seed)
    meds = sorted(statistics.median(rnd.choice(xs) for _ in xs) for _ in range(n))
    return [meds[int(n * .05)], meds[int(n * .95)]]


def build(d: Path, menv: dict, defender: list[int]) -> dict:
    subprocess.run(g.MSVC_CLEAN, cwd=d, env=menv, shell=True, capture_output=True)
    time.sleep(1.0)
    d0 = sum(ch.proc_cpu_s(p) or 0 for p in defender)
    cl = ch.run_in_job("cl /nologo /MP8 /O2 /c *.c >nul", d, menv)
    ln = ch.run_in_job("link /nologo *.obj /OUT:app.exe >nul", d, menv)
    return {"wall_s": cl["wall_s"] + ln["wall_s"], "cl_s": cl["wall_s"], "link_s": ln["wall_s"],
            "defender_cpu_s": sum(ch.proc_cpu_s(p) or 0 for p in defender) - d0, "ok": cl["rc"] == 0 and ln["rc"] == 0}


def measure(cond: str, ws: Path, d: Path, menv: dict, defender: list[int]) -> dict:
    subprocess.run(g.MSVC_CLEAN, cwd=d, env=menv, shell=True, capture_output=True)
    if cond == "off":
        build(d, menv, defender)                      # warm-up
        return build(d, menv, defender)
    with g.Daemon(ws) as dm:
        build(d, menv, defender)                      # warm-up
        r = build(d, menv, defender)
    st = dm.stats()
    r["lost"] = g.lost(st)
    r["stored_events"] = st.get("stored_events")
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pairs", type=int, default=30)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ws = Path(tempfile.gettempdir()) / "whyfs-msvc-paired"
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir()
    menv = g.msvc_env()
    g.write_c_project(ws / "small")
    g.write_c_project(ws / "heavy", g.PERF_UNITS, heavy=True)
    g.whyfs("init", str(ws), cwd=ws)
    defender = ch.pids_of("MsMpEng.exe")
    report = {}
    for w, d in (("small_36", ws / "small"), ("heavy_240", ws / "heavy")):
        pairs = []
        for i in range(a.pairs + 1):
            order = ("off", "on") if i % 2 == 0 else ("on", "off")
            res = {c: measure(c, ws, d, menv, defender) for c in order}
            pairs.append({"i": i, "warmup": i == 0, "order": order, **res})
            print(f"{w} pair {i:2} {order[0]}-first  off {res['off']['wall_s']:.3f}  on {res['on']['wall_s']:.3f}  "
                  f"(link off {res['off']['link_s']:.3f} on {res['on']['link_s']:.3f})  lost {res['on']['lost']}", flush=True)
        meas = [p for p in pairs if not p["warmup"]]
        deltas = [(p["on"]["wall_s"] / p["off"]["wall_s"] - 1) * 100 for p in meas]
        dms = [(p["on"]["wall_s"] - p["off"]["wall_s"]) * 1000 for p in meas]
        rep = {"pairs": pairs, "median_paired_pct": statistics.median(deltas), "median_paired_pct_ci90": boot_ci(deltas),
               "median_paired_ms": statistics.median(dms), "median_paired_ms_ci90": boot_ci(dms),
               "off_median_s": statistics.median(p["off"]["wall_s"] for p in meas),
               "on_median_s": statistics.median(p["on"]["wall_s"] for p in meas),
               "lost_total": sum(p["on"]["lost"] for p in meas)}
        if w == "small_36":
            for c in ("off", "on"):
                rep[f"fast_runs_{c}"] = sum(p[c]["wall_s"] < 0.3 for p in meas)
            rep["fast_threshold_s"] = 0.3
            # link-phase only (where the Defender-related bimodality lives) and cl-phase only
            rep["median_paired_cl_ms"] = statistics.median((p["on"]["cl_s"] - p["off"]["cl_s"]) * 1000 for p in meas)
            rep["median_paired_cl_ms_ci90"] = boot_ci([(p["on"]["cl_s"] - p["off"]["cl_s"]) * 1000 for p in meas])
        report[w] = rep
        print(f"== {w}: median paired {rep['median_paired_pct']:+.2f}% (CI90 {rep['median_paired_pct_ci90'][0]:+.2f}.."
              f"{rep['median_paired_pct_ci90'][1]:+.2f}), {rep['median_paired_ms']:+.1f} ms, lost {rep['lost_total']}"
              + (f"; fast runs off {rep['fast_runs_off']}/{len(meas)} on {rep['fast_runs_on']}/{len(meas)}" if w == "small_36" else ""))
    (out / "msvc_paired.json").write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
