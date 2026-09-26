#!/usr/bin/env python3
"""Derive the Step-1 hot-path tables from a v02_hotpath_profile.py result.

    python3 scripts/v02_hotpath_report.py RESULT_DIR   -> RESULT_DIR/derived.json + HOTPATH_TABLES.md

All numbers are computed from the raw hotpath.json.  Per-run figures are
medians over repetitions of (workload window - equal-length idle window), so
background activity (other processes, the collector's own idle I/O) is removed.
Kernel run time and ns/call come from the production build (phase T), because
the WF_PROFILE counters themselves add run time; counts come from the
profiling build (phase P).
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

SHORT = {0: "security_file_open", 1: "security_file_permission", 2: "security_mmap_file",
         3: "do_renameat2 (entry)", 4: "do_renameat2 (return)", 5: "do_unlinkat (entry)",
         6: "do_unlinkat (return)", 7: "sys_enter_chdir", 8: "sys_exit_chdir", 9: "sys_enter_fchdir",
         10: "sys_exit_fchdir", 11: "sched_process_exec", 12: "sched_process_fork", 13: "sched_process_exit"}
METRICS = ["calls", "early_exits", "map_lookups", "map_updates", "map_deletes", "rb_records", "rb_bytes", "upid_walks"]
MAP_OPS = {
    0: {"map_deletes": "io_seen"},
    1: {"map_lookups": "io_seen", "map_updates": "io_seen"},
    2: {"map_lookups": "io_seen", "map_updates": "io_seen"},
    3: {"map_lookups": "scratch_rename", "map_updates": "pending_rename"},
    4: {"map_lookups": "pending_rename", "map_deletes": "pending_rename"},
    5: {"map_lookups": "scratch_unlink", "map_updates": "pending_unlink"},
    6: {"map_lookups": "pending_unlink", "map_deletes": "pending_unlink"},
    7: {"map_updates": "pending_chdir"}, 8: {"map_lookups": "pending_chdir", "map_deletes": "pending_chdir"},
    9: {"map_updates": "pending_fchdir"}, 10: {"map_lookups": "pending_fchdir", "map_deletes": "pending_fchdir"},
}
ABLATION_HOOK = {"security_file_open": 0, "security_file_permission": 1, "security_mmap_file": 2,
                 "sched_process_exec": 11, "sched_process_fork": 12, "sched_process_exit": 13}


def med(xs):
    xs = list(xs)
    return statistics.median(xs) if xs else 0.0


def net(rows, idle, get):
    """Median of per-rep (workload - matching idle window)."""
    return med(get(r) - get(i) for r, i in zip(rows, idle))


def main() -> int:
    d = Path(sys.argv[1])
    res = json.loads((d / "hotpath.json").read_text())
    procs = res["params"]["processes_per_run"]
    P, T, A = res["phase_P"], res["phase_T"], res.get("phase_A", {})
    k = lambda pid: str(pid)  # JSON keys are strings

    counts = {}
    for pid in list(SHORT) + [14]:
        counts[pid] = {m: net(P["reps"], P["idle"], lambda r, m=m: r["prof"][k(pid)][m]) for m in METRICS}
    runtime = {}
    for pid in SHORT:
        cnt = net(T["runtime_reps"], T["runtime_idle"], lambda r: r["prog"].get(k(pid), {}).get("run_cnt", 0))
        ns = net(T["runtime_reps"], T["runtime_idle"], lambda r: r["prog"].get(k(pid), {}).get("run_time_ns", 0))
        runtime[pid] = {"run_cnt": cnt, "run_time_ns": ns, "ns_per_call": ns / cnt if cnt else 0.0}
    total_bpf_ns = sum(v["run_time_ns"] for v in runtime.values())

    ts = T["summary"]
    wall_over_ms = (ts["on_s"]["median"] - ts["off_s"]["median"]) * 1000
    paired_ms = [(p["on"] - p["off"]) * 1000 for p in T["pairs"] if not p["warmup"]]
    abl = {}
    for label, a in A.items():
        nb, nn, xb = a["normal_minus_base_ms"], a["normal_minus_null_ms"], a["null_minus_base_ms"]
        pid = ABLATION_HOOK.get(label)
        calls = counts[pid]["calls"] if pid is not None else None
        abl[label] = {"normal_minus_base_ms": nb, "normal_minus_null_ms": nn, "null_minus_base_ms": xb,
                      "calls_per_run": calls,
                      "body_ns_per_call": (nn["median"] * 1e6 / calls) if calls else None,
                      "body_ns_per_call_ci90": ([nn["median_ci90"][0] * 1e6 / calls, nn["median_ci90"][1] * 1e6 / calls]
                                                if calls else None)}

    derived = {"processes_per_run": procs, "counts_per_run": counts, "runtime_per_run": runtime,
               "total_bpf_runtime_ns_per_run": total_bpf_ns,
               "timing": {"off_median_s": ts["off_s"]["median"], "on_median_s": ts["on_s"]["median"],
                          "median_paired_overhead_pct": ts["overhead_pct"]["median"],
                          "overhead_pct_ci90": ts["overhead_pct"]["median_ci90"],
                          "median_paired_delta_ms": med(paired_ms),
                          "per_process_us_median": ts["per_process_us"]["median"],
                          "first_build_after_load_s": T["first_build_after_load_s"]},
               "bpf_runtime_share_of_wall_overhead": (total_bpf_ns / 1e6) / med(paired_ms) if med(paired_ms) else None,
               "ablation": abl}
    (d / "derived.json").write_text(json.dumps(derived, indent=2))

    L = []
    L.append(f"## Timing (production build, {ts['overhead_pct']['n']} alternating pairs)\n")
    L.append("| | value |\n|---|---|")
    L.append(f"| baseline median | {ts['off_s']['median']*1000:.1f} ms |")
    L.append(f"| monitored median | {ts['on_s']['median']*1000:.1f} ms |")
    L.append(f"| median paired overhead | {ts['overhead_pct']['median']:.2f}% (90% CI {ts['overhead_pct']['median_ci90'][0]:.2f}..{ts['overhead_pct']['median_ci90'][1]:.2f}; IQR {ts['overhead_pct']['q1']:.2f}..{ts['overhead_pct']['q3']:.2f}) |")
    L.append(f"| median paired delta | {med(paired_ms):.2f} ms per run = {med(paired_ms)*1000/procs:.1f} µs per process |")
    L.append(f"| first build after load | {T['first_build_after_load_s']*1000:.1f} ms |")
    L.append(f"| measured BPF run time (sum of programs) | {total_bpf_ns/1e6:.2f} ms per run = {total_bpf_ns/1e3/procs:.2f} µs per process |")
    if derived["bpf_runtime_share_of_wall_overhead"]:
        L.append(f"| BPF run time / wall overhead | {derived['bpf_runtime_share_of_wall_overhead']*100:.0f}% |")
    L.append("")
    L.append("## Per-program cost (workload window minus idle window; per 300-process run)\n")
    L.append("| program | calls | early exits | ns/call (prod) | run time µs | % of BPF run time | upid walks | rb records | rb bytes |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for pid in sorted(SHORT, key=lambda p: -runtime[p]["run_time_ns"]):
        c, r = counts[pid], runtime[pid]
        if not (c["calls"] or r["run_cnt"]):
            continue
        L.append(f"| {SHORT[pid]} | {c['calls']:.0f} | {c['early_exits']:.0f} | {r['ns_per_call']:.0f} | "
                 f"{r['run_time_ns']/1e3:.1f} | {r['run_time_ns']/total_bpf_ns*100:.1f}% | {c['upid_walks']:.0f} | "
                 f"{c['rb_records']:.0f} | {c['rb_bytes']:.0f} |")
    L.append("")
    L.append("## Map operations per 300-process run (workload minus idle)\n")
    L.append("| program | map | lookups | updates | deletes | per process |")
    L.append("|---|---|---|---|---|---|")
    for pid, ops in MAP_OPS.items():
        c = counts[pid]
        tot = c["map_lookups"] + c["map_updates"] + c["map_deletes"]
        if tot:
            maps = ", ".join(sorted(set(ops.values())))
            L.append(f"| {SHORT[pid]} | {maps} | {c['map_lookups']:.0f} | {c['map_updates']:.0f} | {c['map_deletes']:.0f} | {tot/procs:.2f} |")
    L.append("| sched_process_fork / exec / exit | (none) | 0 | 0 | 0 | 0 |")
    L.append("")
    if abl:
        L.append("## Hook-body ablation (WF_NULL_MASK; rotated baseline/normal/nulled rounds)\n")
        L.append("| variant | normal − baseline ms | normal − nulled ms (90% CI) | nulled − baseline ms | calls/run | body ns/call (90% CI) |")
        L.append("|---|---|---|---|---|---|")
        for label, a in abl.items():
            nn = a["normal_minus_null_ms"]
            body = (f"{a['body_ns_per_call']:.0f} ({a['body_ns_per_call_ci90'][0]:.0f}..{a['body_ns_per_call_ci90'][1]:.0f})"
                    if a["body_ns_per_call"] is not None else "n/a")
            L.append(f"| {label} (n={nn['n']}) | {a['normal_minus_base_ms']['median']:+.2f} | "
                     f"{nn['median']:+.2f} ({nn['median_ci90'][0]:+.2f}..{nn['median_ci90'][1]:+.2f}) | "
                     f"{a['null_minus_base_ms']['median']:+.2f} | {a['calls_per_run'] if a['calls_per_run'] is not None else 'all'} | {body} |")
    (d / "HOTPATH_TABLES.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
