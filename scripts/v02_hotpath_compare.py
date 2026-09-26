#!/usr/bin/env python3
"""Before/after comparison of two v02_hotpath_profile.py results (identical protocol).

    python3 scripts/v02_hotpath_compare.py BEFORE_DIR[,BEFORE_X_DIR] AFTER_DIR [OUT.json]

Reads each run's raw hotpath.json and derived.json (run v02_hotpath_report.py first).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def load(dirs: str) -> dict:
    merged: dict = {}
    for d in dirs.split(","):
        raw = json.loads((Path(d) / "hotpath.json").read_text())
        der = json.loads((Path(d) / "derived.json").read_text())
        for k, v in raw.items():
            merged.setdefault(k, v)
        merged.setdefault("_derived", {}).update(der)
    return merged


def lstat_per_run(v: dict) -> float | None:
    txt = (v or {}).get("callback_cprofile_top", "")
    m = re.search(r"^\s*(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\{built-in method posix\.lstat\}", txt, re.M)
    reps = 5
    return int(m.group(1)) / reps if m else 0.0


def summarize(r: dict) -> dict:
    d = r["_derived"]
    T, U, V, X = r.get("phase_T"), r.get("phase_U"), r.get("phase_V"), r.get("phase_X")
    s = {}
    if T:
        s["T_median_paired_overhead_pct"] = T["summary"]["overhead_pct"]["median"]
        s["T_overhead_ci90_pct"] = T["summary"]["overhead_pct"]["median_ci90"]
        s["T_delta_ms"] = d["timing"]["delta_ms_median"]
        s["T_us_per_process"] = d["timing"]["delta_us_per_process"]
        s["T_events_received_per_run"] = d["timing"]["events_received_per_run"]
        s["T_collector_cpu_ms_per_run"] = d["timing"]["collector_cpu_s_per_run"] * 1000
        s["T_kernel_drops"] = d["timing"]["kernel_drops_total"]
        s["T_queue_drops"] = d["timing"]["queue_drops"]
        s["bpf_runtime_ms_per_run"] = d["bpf_runtime_ns_per_run"] / 1e6
        s["bpf_ns_per_call"] = {k: round(v["ns_per_call"]) for k, v in d["runtime_per_run"].items() if v["run_cnt"]}
        s["hook_calls_idle_adjusted"] = {k: v["calls"] for k, v in d["counts_per_run_idle_adjusted"].items() if v["calls"]}
        s["rb_records"] = {k: v["rb_records"] for k, v in d["counts_per_run_idle_adjusted"].items() if v["rb_records"]}
    for name, ph, keys in (("U", U, ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "full_minus_nostore_ms",
                                      "full_minus_kernel_ms", "full_minus_base_ms")),
                           ("V", V, ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "burn_minus_kernel_ms",
                                     "nostore_minus_burn_ms")),
                           ("X", X, ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "canon_only_minus_kernel_ms",
                                     "nostore_nocanon_minus_kernel_ms", "nostore_minus_nostore_nocanon_ms"))):
        if ph:
            for k in keys:
                s[f"{name}_{k}"] = {"median": ph[k]["median"], "ci90": ph[k]["median_ci90"]}
    if U:
        s["U_collector_cpu_ms"] = {m: v["median"] * 1000 for m, v in U["per_mode_collector_cpu_s"].items()}
    if V:
        s["W_callback_us_per_event"] = {k: round(v["us_per_event"], 1) for k, v in V["callback_time_per_event_type"].items()}
        s["W_callback_ms_per_run"] = round(sum(v["ms_per_run"] for v in V["callback_time_per_event_type"].values()), 1)
        s["W_lstat_per_run"] = lstat_per_run(V)
    return s


def main() -> int:
    before, after = summarize(load(sys.argv[1])), summarize(load(sys.argv[2]))
    out = {"before": sys.argv[1], "after": sys.argv[2], "before_summary": before, "after_summary": after}
    if len(sys.argv) > 3:
        Path(sys.argv[3]).write_text(json.dumps(out, indent=2))
    for k in sorted(set(before) | set(after)):
        print(f"{k}:\n  before {before.get(k)}\n  after  {after.get(k)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
