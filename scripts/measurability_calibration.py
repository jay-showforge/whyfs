"""Calibration of the real-workload measurability rule (BENCHMARK.md, "Measurability").

Uses ONLY pre-existing machine_perf results (every hosted native run and every desktop campaign
in results/).  For each real workload (MSVC, Vite, make) and each measurement it reports:
  * the median paired overhead and its CI90 (machine_perf's own bootstrap: 4000 resamples of
    the median of the paired overheads, seed 1) and the CI90 width;
  * baseline (off) and monitored (on) dispersion: coefficient of variation, min..max spread;
  * the paired-delta distribution: IQR and outliers (beyond 1.5 IQR);
  * a bimodality coefficient of the baseline times (> 0.555 suggests a multimodal runner);
and, by resampling each measurement's own pairs, how the CI90 width shrinks with the number of
pairs N: the probability that a run of N pairs is precise enough (width <= the rule's limit).

  python scripts/measurability_calibration.py [--out FILE]
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import random
import statistics
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
REAL = ("msvc_240_units_mp8", "vite_build", "make_j8_36_units")
WIDTH_LIMIT = 5.0          # the rule: CI90 width <= 5 percentage points (half-width <= half the 5 % budget)
NS = (20, 30, 40, 50, 60, 80, 100, 120, 150)


def ci90(xs, n=4000, seed=1):  # identical to machine_perf.bootstrap_ci
    r = random.Random(seed)
    meds = sorted(statistics.median(r.choice(xs) for _ in xs) for _ in range(n))
    return meds[int(0.05 * n)], meds[int(0.95 * n) - 1]


def width(xs, n=1000, seed=1):
    lo, hi = ci90(xs, n, seed)
    return hi - lo


def bimodality(xs):
    n = len(xs)
    if n < 4:
        return None
    m = statistics.mean(xs)
    s = statistics.pstdev(xs)
    if s == 0:
        return 0.0
    g = sum((x - m) ** 3 for x in xs) / n / s ** 3
    k = sum((x - m) ** 4 for x in xs) / n / s ** 4 - 3
    return (g * g + 1) / (k + 3 * (n - 1) ** 2 / ((n - 2) * (n - 3)))


def cv(xs):
    return statistics.pstdev(xs) / statistics.mean(xs) * 100 if xs else None


def label(path: str) -> tuple[str, str]:
    p = path.replace("\\", "/")
    if "/native-ci/" in p or "/release-1.0.0" in p:
        run = p.split("results/")[1].split("/")[0 if "release" in p.split("results/")[1].split("/")[0] else 1]
        plat = next((x for x in ("windows-x64", "windows-arm64", "linux-ubuntu-24.04-arm", "linux-ubuntu-24.04") if f"/{x}/" in p), "?")
        return {"linux-ubuntu-24.04": "hosted linux-x86_64", "linux-ubuntu-24.04-arm": "hosted linux-aarch64"}.get(plat, "hosted " + plat), run
    return "desktop", p.split("results/")[1].split("/")[0]


def measurement(path: str, w: str, v: dict) -> dict:
    runs = [r for r in v["runs"] if not r["warmup"]]
    off = [r["seconds"] for r in runs if r["mode"] == "off"]
    on = [r["seconds"] for r in runs if r["mode"] == "on"]
    pairs = list(v["paired_overheads_percent"])
    lo, hi = ci90(pairs)
    q = statistics.quantiles(pairs, n=4)
    iqr = q[2] - q[0]
    out = [x for x in pairs if x < q[0] - 1.5 * iqr or x > q[2] + 1.5 * iqr]
    platform, run = label(path)
    return {"platform": platform, "run": run, "workload": w, "n_pairs": len(pairs),
            "median": round(statistics.median(pairs), 2), "ci90": [round(lo, 2), round(hi, 2)], "ci90_width": round(hi - lo, 2),
            "baseline_cv_percent": round(cv(off), 2), "monitored_cv_percent": round(cv(on), 2),
            "baseline_spread_percent": round((max(off) - min(off)) / statistics.median(off) * 100, 1),
            "pair_iqr": round(iqr, 2), "pair_outliers": len(out), "baseline_bimodality": round(bimodality(off), 3),
            "pairs": [round(x, 2) for x in pairs]}


def projection(pairs, sims=200, seed=7) -> dict:
    """P(CI90 width <= WIDTH_LIMIT) for a run of N pairs drawn like this run's pairs."""
    r = random.Random(seed)
    res = {}
    for n in NS:
        ok = 0
        for s in range(sims):
            sample = [r.choice(pairs) for _ in range(n)]
            ok += width(sample, n=400, seed=s) <= WIDTH_LIMIT
        res[n] = round(ok / sims, 2)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "results" / "measurability-calibration.json"))
    a = ap.parse_args()
    rows = []
    for f in sorted(glob.glob(str(REPO / "results" / "**" / "machine_perf.json"), recursive=True)):
        mp = json.loads(Path(f).read_text())
        for w in REAL:
            if w in mp.get("performance", {}):
                m = measurement(f, w, mp["performance"][w])
                m["p_measurable_by_n"] = projection(m["pairs"])
                rows.append(m)
    groups: dict = {}
    for m in rows:
        groups.setdefault((m["platform"], m["workload"]), []).append(m)
    summary = []
    for (plat, w), ms in sorted(groups.items()):
        summary.append({
            "platform": plat, "workload": w, "measurements": len(ms),
            "ci90_widths": [m["ci90_width"] for m in ms],
            "measurable_at_20": sum(m["ci90_width"] <= WIDTH_LIMIT for m in ms),
            "medians": [m["median"] for m in ms],
            "baseline_cv_percent": [m["baseline_cv_percent"] for m in ms],
            "baseline_bimodality": [m["baseline_bimodality"] for m in ms],
            "p_measurable_by_n_mean": {n: round(statistics.mean(m["p_measurable_by_n"][n] for m in ms), 2) for n in NS},
            "p_measurable_by_n_min": {n: min(m["p_measurable_by_n"][n] for m in ms) for n in NS},
        })
    report = {"width_limit_pp": WIDTH_LIMIT, "ns": NS, "summary": summary, "measurements": rows}
    Path(a.out).write_text(json.dumps(report, indent=1))
    for s in summary:
        print(f"{s['platform']:22s} {s['workload']:20s} n={s['measurements']:2d} widths {s['ci90_widths']}  measurable@20 {s['measurable_at_20']}/{s['measurements']}")
        print(f"{'':43s} medians {s['medians']}  baseCV {s['baseline_cv_percent']}  bimod {s['baseline_bimodality']}")
        print(f"{'':43s} P(measurable) mean {s['p_measurable_by_n_mean']}  min {s['p_measurable_by_n_min']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
