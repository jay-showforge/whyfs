"""The 1.0 performance contract, part A, over the UNCHANGED machine_perf campaign
(BENCHMARK.md, "WhyFS 1.0 performance contract", sections 6 and 8).

machine_perf.py is not modified: it measures every workload and applies its original checks,
including the historical pre-1.0 rule "process spawn x300 total overhead < 5 %".  This script
reads its result and applies the 1.0 release criteria:

  A. real development workloads (Windows: msvc_240_units_mp8, vite_build; Linux:
     make_j8_36_units, vite_build), each classified by the measurability rule frozen in
     scripts/real_workload_contract.json:
       PASS          CI90 upper < 5 %; or CI90 contains 5 %, width <= 5 pp, median < 5 %
       FAIL          CI90 lower >= 5 %; or CI90 contains 5 %, width <= 5 pp, median >= 5 %
       UNMEASURABLE  CI90 contains 5 % and width > 5 pp (never a PASS; reported with raw pairs)
       INVALID       fewer pairs than the contract requires
     plus idle collector CPU < 1 % of a core, zero event loss, why/label CLI median < 100 ms.

The spawn workload's total is carried through as the historical gate's result: always reported,
never hidden (part B, scripts/spawn_stress_gate.py, judges the spawn stress test).

Exit status: 0 when no workload FAILs or is INVALID and the other checks hold (an UNMEASURABLE
workload does not fail the step, and is listed in "unmeasurable" for the release decision).

  python scripts/perf_contract.py MACHINE_PERF_JSON [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPAWN = ("native_exe_x300", "static_binary_x300")


def bimodality(xs):
    n = len(xs)
    if n < 4:
        return None
    m, s = statistics.mean(xs), statistics.pstdev(xs)
    if s == 0:
        return 0.0
    g = sum((x - m) ** 3 for x in xs) / n / s ** 3
    k = sum((x - m) ** 4 for x in xs) / n / s ** 4 - 3
    return round((g * g + 1) / (k + 3 * (n - 1) ** 2 / ((n - 2) * (n - 3))), 3)


def classify(median: float, lo: float, hi: float, n: int, c: dict) -> str:
    t, wl = c["threshold_percent"], c["ci_width_limit_pp"]
    if n < c["pairs_required"]:
        return "INVALID"
    if hi < t:
        return "PASS"
    if lo >= t:
        return "FAIL"
    if hi - lo <= wl:
        return "PASS" if median < t else "FAIL"
    return "UNMEASURABLE"


def workload(v: dict, c: dict) -> dict:
    runs = [r for r in v["runs"] if not r["warmup"]]
    off = [r["seconds"] for r in runs if r["mode"] == "off"]
    on = [r["seconds"] for r in runs if r["mode"] == "on"]
    pairs = list(v["paired_overheads_percent"])
    lo, hi = v["median_paired_ci90"]
    med = v["median_paired_overhead_percent"]
    q = statistics.quantiles(pairs, n=4)
    iqr = q[2] - q[0]
    return {
        "status": classify(med, lo, hi, len(pairs), c),
        "median": round(med, 2), "ci90": [round(lo, 2), round(hi, 2)], "ci90_width": round(hi - lo, 2), "n_pairs": len(pairs),
        "baseline_median_s": round(statistics.median(off), 3), "baseline_cv_percent": round(statistics.pstdev(off) / statistics.mean(off) * 100, 2),
        "baseline_spread_percent": round((max(off) - min(off)) / statistics.median(off) * 100, 1),
        "baseline_bimodality": bimodality(off),
        "monitored_cv_percent": round(statistics.pstdev(on) / statistics.mean(on) * 100, 2),
        "pair_outliers": sum(x < q[0] - 1.5 * iqr or x > q[2] + 1.5 * iqr for x in pairs),
        "whyfs_collector_cpu_s_median": v.get("collector_cpu_s_median"),
        "pairs": [round(x, 2) for x in pairs],
    }


def evaluate(mp: dict, c: dict) -> dict:
    perf, checks = mp["performance"], {}
    real = {w: workload(perf[w], c) for w in c["workloads"] if w in perf}
    for w, r in real.items():
        checks[f"A.{w}.not_FAIL_or_INVALID"] = r["status"] in ("PASS", "UNMEASURABLE")
    checks["A.idle_cpu_below_1pct_of_a_core"] = mp["idle"]["cpu_percent_of_one_core"] < 1.0
    checks["A.zero_loss"] = mp["lost_total"] == 0
    checks["A.why_cli_median_lt_100ms"] = mp["query_latency_ms"]["why"]["median"] < 100
    checks["A.label_cli_median_lt_100ms"] = mp["query_latency_ms"]["label"]["median"] < 100
    hist = {}
    for w in SPAWN:
        if w in perf:
            v = perf[w]
            hist = {"workload": w, "median_total_overhead_percent": round(v["median_paired_overhead_percent"], 2),
                    "ci90": [round(x, 2) for x in v["median_paired_ci90"]], "n_pairs": len(v["paired_overheads_percent"]),
                    "pairs": [round(x, 2) for x in v["paired_overheads_percent"]],
                    "historical_rule": "total < 5 %", "historical_rule_met": v["median_paired_overhead_percent"] < 5}
    return {
        "real_workloads": real,
        "unmeasurable": [w for w, r in real.items() if r["status"] == "UNMEASURABLE"],
        "idle": mp["idle"], "query_latency_ms": mp["query_latency_ms"], "lost_total": mp["lost_total"],
        "historical_pre_1_0_spawn_gate": hist,
        "machine_perf_original_verdict": mp["verdict"],
        "contract": c,
        "checks": checks,
        "verdict": "PASS" if all(checks.values()) else "FAIL",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("machine_perf")
    ap.add_argument("--contract", default=str(HERE / "real_workload_contract.json"))
    ap.add_argument("--out")
    a = ap.parse_args()
    res = evaluate(json.loads(Path(a.machine_perf).read_text()), json.loads(Path(a.contract).read_text()))
    text = json.dumps(res, indent=1)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
