"""The 1.0 spawn-stress contract (BENCHMARK.md, "WhyFS 1.0 performance contract", part B).

Reads the output of scripts/diag_service_cost.py (Windows) or scripts/diag_service_cost_linux.py
(Linux): the unchanged machine_perf spawn workload, 20 counterbalanced pairs per variant, with
  normal   the product (every event source on, everything processed and stored)
  discard  the same event sources, records counted and dropped: the observation (kernel) floor
and evaluates it against the precommitted contract in scripts/spawn_stress_contract.json.

Reported, always (nothing here replaces reporting the total):
  total_overhead     normal vs baseline (median of the paired overheads, bootstrap CI90)
  kernel_floor       discard vs baseline
  whyfs_controlled   median(normal pairs) - median(discard pairs), bootstrap CI90 resampling
                     both sets of raw pairs independently (they are separate pair sets, not paired
                     with each other)
  whyfs_cpu_ms       WhyFS user-space CPU per measured run (collector + writer + service), mean
                     and median, during the run and the window after it
  loss               event loss over the normal variant's collector runs
  verify             the stress outputs' labels (when the diagnostic ran with --verify)

  python scripts/spawn_stress_gate.py DIAG_JSON --platform windows-x64 [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def boot_ci(xs, n=4000, seed=1):
    r = random.Random(seed)
    meds = sorted(statistics.median(r.choice(xs) for _ in xs) for _ in range(n))
    return [round(meds[int(0.05 * n)], 2), round(meds[int(0.95 * n) - 1], 2)]


def boot_diff_ci(a, b, n=4000, seed=2):
    r = random.Random(seed)
    ds = sorted(statistics.median(r.choice(a) for _ in a) - statistics.median(r.choice(b) for _ in b) for _ in range(n))
    return [round(ds[int(0.05 * n)], 2), round(ds[int(0.95 * n) - 1], 2)]


def whyfs_cpu(variant: dict) -> dict:
    """WhyFS user-space CPU per measured 'on' run: during it and in the window after it."""
    ons = [r for r in variant["runs"] if r["mode"] == "on" and not r["warmup"]]
    after_key = "after_7s" if ons and "after_7s" in ons[0] else "after"
    roles = ("collector", "serve", "svc") if after_key == "after_7s" else ("collector", "writer", "daemon", "store")
    per, parts = [], {r: [] for r in roles}
    for r in ons:
        tot = 0.0
        for role in roles:
            v = (r["proc"].get(role, {}).get("cpu_ms") or 0) + (r[after_key]["proc"].get(role, {}).get("cpu_ms") or 0)
            parts[role].append(v)
            tot += v
        per.append(tot)
    threads = {}
    for r in ons:
        for t, v in r.get("threads", {}).items():
            w = r[after_key].get("threads", {}).get(t, {})
            threads.setdefault(t, []).append((v.get("cpu_ms") or 0) + (w.get("cpu_ms") or 0))
    io = {}
    for k in ("write_ops", "write_bytes", "read_ops", "ctx"):
        vals = [(r["proc"].get(roles[0], {}).get(k) or 0) + (r[after_key]["proc"].get(roles[0], {}).get(k) or 0) for r in ons]
        if roles[1] == "writer":
            vals = [v + (r["proc"].get("writer", {}).get(k) or 0) + (r[after_key]["proc"].get("writer", {}).get(k) or 0)
                    for v, r in zip(vals, ons)]
        io[k] = round(statistics.median(vals), 1) if vals else None
    named = {t: round(statistics.mean(v), 2) for t, v in threads.items() if not t.startswith("tid") and t != "?"}
    return {"mean": round(statistics.mean(per), 2) if per else None, "median": round(statistics.median(per), 2) if per else None,
            "by_process_mean": {k: round(statistics.mean(v), 2) for k, v in parts.items() if v},
            "by_thread_mean": named, "collector_io_median": io, "runs": len(per)}


def evaluate(diag: dict, platform: str, contract: dict, cpu_diag: dict | None = None) -> dict:
    v = diag["variants"]
    for need in ("normal", "discard"):
        if need not in v:
            raise SystemExit(f"the diagnostic has no '{need}' variant")
    nrm, dsc = v["normal"]["summary"], v["discard"]["summary"]
    n_pairs, d_pairs = nrm["paired"], dsc["paired"]
    res = {
        "platform": platform,
        "total_overhead": {"median": nrm["median_paired_overhead_percent"], "ci90": boot_ci(n_pairs), "pairs": n_pairs,
                           "baseline_median_s": nrm["off_seconds_median"], "monitored_median_s": nrm["on_seconds_median"]},
        "kernel_floor": {"median": dsc["median_paired_overhead_percent"], "ci90": boot_ci(d_pairs), "pairs": d_pairs,
                         "baseline_median_s": dsc["off_seconds_median"]},
        "whyfs_controlled": {"median_difference": round(statistics.median(n_pairs) - statistics.median(d_pairs), 2),
                             "ci90": boot_diff_ci(n_pairs, d_pairs)},
        # CPU per iteration, from a session whose post-run window (7 s) outlasts the Windows reorder
        # window and the Linux batching, so each iteration's own processing is complete in it; the
        # machine_perf-timed session above undercounts (the work lands in the next iteration).
        "whyfs_cpu_ms_per_run": whyfs_cpu((cpu_diag or diag)["variants"]["normal"]),
        "whyfs_cpu_source": "cpu session (post-run window 7 s)" if cpu_diag else "machine_perf-timed session (undercounts)",
        "whyfs_cpu_ms_per_run_machine_perf_timing": whyfs_cpu(v["normal"]),
        "loss": nrm["lost"],
        "verify": v["normal"].get("verify"),
        "historical_total_lt_5pct": nrm["median_paired_overhead_percent"] < 5,
    }
    c = contract["platforms"].get(platform)
    checks = {"zero_loss": nrm["lost"] == 0 and dsc["lost"] == 0 and (cpu_diag is None or cpu_diag["variants"]["normal"]["summary"]["lost"] == 0)}
    checks["stress_outputs_labelled_correctly"] = bool(res["verify"] and res["verify"].get("ok"))
    if c:
        cpu = res["whyfs_cpu_ms_per_run"]["mean"]
        checks["whyfs_cpu_within_regression_ceiling"] = cpu is not None and cpu <= c["cpu_ms_per_run_ceiling"]
        # fail only on evidence: the lower CI90 bound of the WhyFS-controlled share above the ceiling
        checks["whyfs_controlled_not_above_ceiling"] = res["whyfs_controlled"]["ci90"][0] <= contract["whyfs_controlled_ceiling_pp"]
    else:
        checks["contract_has_this_platform"] = False
    res["contract"] = c
    res["checks"] = checks
    res["verdict"] = "PASS" if checks and all(checks.values()) else "FAIL"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("diag")
    ap.add_argument("--platform", required=True)
    ap.add_argument("--contract", default=str(HERE / "spawn_stress_contract.json"))
    ap.add_argument("--cpu-diag", help="the normal-only session with a 7 s post-run window (CPU per iteration)")
    ap.add_argument("--out")
    a = ap.parse_args()
    contract = json.loads(Path(a.contract).read_text()) if Path(a.contract).exists() else {"platforms": {}, "whyfs_controlled_ceiling_pp": None}
    cpu_diag = json.loads(Path(a.cpu_diag).read_text()) if a.cpu_diag else None
    res = evaluate(json.loads(Path(a.diag).read_text()), a.platform, contract, cpu_diag)
    text = json.dumps(res, indent=1)
    if a.out:
        Path(a.out).write_text(text)
    print(text)
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
