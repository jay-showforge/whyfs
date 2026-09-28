"""The 1.0 performance contract, part A, over the UNCHANGED machine_perf campaign
(BENCHMARK.md, "WhyFS 1.0 performance contract").

machine_perf.py is not modified: it measures every workload and applies its original checks,
including the historical pre-1.0 rule "process spawn x300 total overhead < 5 %".  This script
reads its result and applies the 1.0 release criteria:

  A. real development workloads: median paired total overhead < 5 %
       Windows: msvc_240_units_mp8, vite_build          Linux: make_j8_36_units, vite_build
     plus idle collector CPU < 1 % of a core, zero event loss, why/label CLI median < 100 ms.

The spawn workload's total is carried through as the historical gate's result: always reported,
never hidden, and no longer the sole release criterion for the spawn stress test (that is
part B: scripts/spawn_stress_gate.py, which separates the observation floor from WhyFS's own cost).

  python scripts/perf_contract.py MACHINE_PERF_JSON [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REAL = ("msvc_240_units_mp8", "vite_build", "make_j8_36_units")
SPAWN = ("native_exe_x300", "static_binary_x300")


def evaluate(mp: dict) -> dict:
    perf, checks = mp["performance"], {}
    for w in REAL:
        if w in perf:
            checks[f"A.{w}.median_total_overhead_lt_5pct"] = perf[w]["median_paired_overhead_percent"] < 5
    checks["A.idle_cpu_below_1pct_of_a_core"] = mp["idle"]["cpu_percent_of_one_core"] < 1.0
    checks["A.zero_loss"] = mp["lost_total"] == 0
    checks["A.why_cli_median_lt_100ms"] = mp["query_latency_ms"]["why"]["median"] < 100
    checks["A.label_cli_median_lt_100ms"] = mp["query_latency_ms"]["label"]["median"] < 100
    hist = {}
    for w in SPAWN:
        if w in perf:
            v = perf[w]
            hist = {"workload": w, "median_total_overhead_percent": round(v["median_paired_overhead_percent"], 2),
                    "ci90": [round(x, 2) for x in v["median_paired_ci90"]],
                    "pairs": [round(x, 2) for x in v["paired_overheads_percent"]],
                    "historical_rule": "total < 5 %", "historical_rule_met": v["median_paired_overhead_percent"] < 5}
    return {
        "real_workloads": {w: {"median": round(perf[w]["median_paired_overhead_percent"], 2),
                               "ci90": [round(x, 2) for x in perf[w]["median_paired_ci90"]]} for w in REAL if w in perf},
        "idle": mp["idle"], "query_latency_ms": mp["query_latency_ms"], "lost_total": mp["lost_total"],
        "historical_pre_1_0_spawn_gate": hist,
        "machine_perf_original_verdict": mp["verdict"],
        "checks": checks,
        "verdict": "PASS" if all(checks.values()) else "FAIL",
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("machine_perf")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = evaluate(json.loads(Path(a.machine_perf).read_text()))
    text = json.dumps(res, indent=1)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
