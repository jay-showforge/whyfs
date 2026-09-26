#!/usr/bin/env python3
"""Derive the Step-1 hot-path tables from a v02_hotpath_profile.py result.

    python3 scripts/v02_hotpath_report.py RESULT_DIR
        -> RESULT_DIR/derived.json, RESULT_DIR/tables/*.csv, RESULT_DIR/HOTPATH_TABLES.md

Every number is computed from the raw hotpath.json:
  * counts (phase P, WF_PROFILE build): per run, the workload window and the
    workload window minus an equal-length idle window (median over reps);
  * kernel run time and ns/call (phase T, production build, bpf_stats):
    the WF_PROFILE counters would inflate run time, so they are not used here;
  * section times (phase Q, WF_PROFILE_TIME build): approximate (each timer adds
    two bpf_ktime_get_ns calls), used for splitting a program's cost;
  * wall-clock (phases T/A/U/V): shell-timed loop, paired or rotated rounds,
    medians with bootstrap 90% CIs.
"""
from __future__ import annotations

import csv
import json
import statistics
import sys
from pathlib import Path

PROCS_DEFAULT = 300
SHORT = {0: "security_file_open", 1: "security_file_permission", 2: "security_mmap_file",
         3: "do_renameat2 (entry)", 4: "do_renameat2 (return)", 5: "do_unlinkat (entry)",
         6: "do_unlinkat (return)", 7: "sys_enter_chdir", 8: "sys_exit_chdir", 9: "sys_enter_fchdir",
         10: "sys_exit_fchdir", 11: "sched_process_exec", 12: "sched_process_fork", 13: "sched_process_exit"}
MAPS = {0: "io_seen (lru_hash): delete", 1: "io_seen (lru_hash): lookup + update", 2: "io_seen (lru_hash): lookup + update",
        3: "scratch_rename + pending_rename", 4: "pending_rename", 5: "scratch_unlink + pending_unlink",
        6: "pending_unlink", 7: "pending_chdir", 8: "pending_chdir", 9: "pending_fchdir", 10: "pending_fchdir",
        11: "(none)", 12: "(none)", 13: "(none)"}
ABL = {"security_file_open": 0, "security_file_permission": 1, "security_mmap_file": 2,
       "sched_process_exec": 11, "sched_process_fork": 12, "sched_process_exit": 13}


def med(xs):
    xs = list(xs)
    return statistics.median(xs) if xs else 0.0


def pget(r, pid, m):
    return r["prof"][str(pid)].get(m, 0)


def ci(s):
    return f"{s['median']:+.2f} (90% CI {s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})"


def main() -> int:
    d = Path(sys.argv[1])
    res = json.loads((d / "hotpath.json").read_text())
    procs = res["params"].get("processes_per_run", PROCS_DEFAULT)
    P, Q, T = res.get("phase_P"), res.get("phase_Q"), res.get("phase_T")
    if not (P and T):  # a follow-up run with only e.g. phase X
        X = res.get("phase_X") or {}
        lines = ["## realpath/lstat mechanism (phase X; rotated rounds, shell-timed)\n", "| comparison | ms per run |", "|---|---|"]
        for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "canon_only_minus_kernel_ms",
                  "nostore_nocanon_minus_kernel_ms", "nostore_minus_nostore_nocanon_ms"):
            if k in X:
                lines.append(f"| {k.replace('_ms', '').replace('_minus_', ' − ')} | {ci(X[k])} |")
        (d / "derived.json").write_text(json.dumps({"source": str(d), "git": res.get("git"),
                                                    "realpath_mechanism": {k: X[k] for k in X if k.endswith("_ms")},
                                                    "rounds": sum(1 for r in X.get("rounds", []) if not r["warmup"]),
                                                    "kernel_drops": X.get("kernel_drops_total"),
                                                    "queue_drops": X.get("queue_drops_total")}, indent=2))
        (d / "HOTPATH_TABLES.md").write_text("\n".join(lines) + "\n")
        print("\n".join(lines))
        return 0
    A, U, V = res.get("phase_A", {}), res.get("phase_U"), res.get("phase_V")
    tables = d / "tables"
    tables.mkdir(exist_ok=True)
    out: dict = {"source": str(d), "git": res.get("git"), "processes_per_run": procs, "checks": {}}

    # ---------------------------------------------------------------- counts (P)
    metrics = list(P["reps"][0]["prof"]["0"].keys())
    counts, raw_counts = {}, {}
    for pid in list(SHORT) + [14]:
        counts[pid] = {m: med(pget(r, pid, m) - pget(i, pid, m) for r, i in zip(P["reps"], P["idle"])) for m in metrics}
        raw_counts[pid] = {m: med(pget(r, pid, m) for r in P["reps"]) for m in metrics}
    out["counts_per_run_idle_adjusted"] = counts
    out["counts_per_run_workload_window"] = raw_counts

    # ---------------------------------------------------------------- runtime (T, production)
    rt = {}
    for pid in SHORT:
        g = lambda r, f: r["prog"].get(str(pid), {}).get(f, 0)
        cnt = med(g(r, "run_cnt") - g(i, "run_cnt") for r, i in zip(T["runtime_reps"], T["runtime_idle"]))
        ns = med(g(r, "run_time_ns") - g(i, "run_time_ns") for r, i in zip(T["runtime_reps"], T["runtime_idle"]))
        rt[pid] = {"run_cnt": cnt, "run_time_ns": ns, "ns_per_call": ns / cnt if cnt else 0.0}
    bpf_total = sum(v["run_time_ns"] for v in rt.values())
    out["runtime_per_run"] = rt
    out["bpf_runtime_ns_per_run"] = bpf_total

    # ---------------------------------------------------------------- section times (Q)
    sections = {}
    if Q:
        for pid in SHORT:
            qc = {m: med(pget(r, pid, m) - pget(i, pid, m) for r, i in zip(Q["reps"], Q["idle"])) for m in metrics}
            sections[pid] = qc
        # fast-path translation cost: programs whose translations never missed
        fast = [sections[p]["ns_translate_ns"] / sections[p]["calls"] for p in (13,) if sections[p]["calls"]]
        ns_fast = fast[0] if fast else 0.0
        out["section_counts_per_run"] = sections
        out["ns_fast_translation_estimate"] = ns_fast

    # ---------------------------------------------------------------- timing
    tm = {}
    if T:
        meas = [p for p in T["pairs"] if not p["warmup"]]
        dms = [(p["on"] - p["off"]) * 1000 for p in meas]
        tm = {"pairs": len(meas), "off_median_ms": med(p["off"] for p in meas) * 1000,
              "on_median_ms": med(p["on"] for p in meas) * 1000,
              "overhead_pct": T["summary"]["overhead_pct"], "delta_ms_median": med(dms),
              "delta_us_per_process": med(dms) * 1000 / procs,
              "first_build_after_load_ms": T["first_build_after_load_s"] * 1000,
              "outer_overhead_pct_median": med((p["on_outer"] / p["off_outer"] - 1) * 100 for p in meas if "on_outer" in p),
              "kernel_drops_total": T.get("kernel_drops_total"),
              "queue_drops": T["collector_final"].get("queue_drops"),
              "events_received_per_run": med(p["collector"]["received"] for p in meas),
              "events_filtered_per_run": med(p["collector"]["filtered"] for p in meas),
              "collector_cpu_s_per_run": med(p["collector_cpu_s"] for p in meas),
              "store_worker_cpu_s_per_run": med(p["store_worker_cpu_s"] for p in meas)}
        out["timing"] = tm

    # ---------------------------------------------------------------- foreign tasks (WSL init)
    if Q:
        fo = {}
        for pid in (0, 1):
            q = sections[pid]
            foreign = q["foreign_tasks"]
            translations = q["rb_records"] + foreign  # every emitted record and every foreign task was translated
            fast_calls = q["rb_records"]
            foreign_ns = max(0.0, q["ns_translate_ns"] - fast_calls * out["ns_fast_translation_estimate"])
            pre = 0.0
            if pid == 1 and q["map_lookups"]:
                pre = q["io_seen_map_ns"] / (q["map_lookups"] + q["map_updates"])  # perm looks io_seen up first
            fo[SHORT[pid]] = {"foreign_invocations_per_run": foreign, "upid_walks_per_run": q["upid_walks"],
                              "translation_ns_per_foreign_call": foreign_ns / foreign if foreign else 0.0,
                              "io_seen_lookup_ns_before_translation": pre,
                              "est_ns_per_foreign_call": (foreign_ns / foreign if foreign else 0) + pre,
                              "est_total_us_per_run": (foreign_ns + pre * foreign) / 1000,
                              "events_emitted": 0}
        tot = sum(v["est_total_us_per_run"] for v in fo.values())
        out["foreign_tasks"] = {"per_hook": fo, "est_total_us_per_run": tot,
                                "pct_of_bpf_runtime": tot * 1000 / bpf_total * 100 if bpf_total else None,
                                "pct_of_wall_overhead": (tot / 1000) / tm["delta_ms_median"] * 100 if tm.get("delta_ms_median") else None}

    # ---------------------------------------------------------------- ablation (A)
    abl = {}
    for label, a in A.items():
        pid = ABL.get(label)
        calls = counts[pid]["calls"] if pid is not None else None
        nn = a["normal_minus_null_ms"]
        abl[label] = {"normal_minus_base_ms": a["normal_minus_base_ms"], "normal_minus_null_ms": nn,
                      "null_minus_base_ms": a["null_minus_base_ms"], "calls_per_run": calls,
                      "body_ns_per_call": nn["median"] * 1e6 / calls if calls else None,
                      "body_ns_per_call_ci90": [x * 1e6 / calls for x in nn["median_ci90"]] if calls else None,
                      "conclusive": not (nn["median_ci90"][0] <= 0 <= nn["median_ci90"][1])}
    out["ablation"] = abl

    # ---------------------------------------------------------------- userspace (U, V, W)
    if U:
        out["userspace_split"] = {k: U[k] for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "full_minus_nostore_ms",
                                                    "full_minus_kernel_ms", "full_minus_base_ms", "full_overhead_pct",
                                                    "kernel_only_overhead_pct", "no_store_overhead_pct")}
        out["userspace_split"]["collector_cpu_s"] = {m: v["median"] for m, v in U["per_mode_collector_cpu_s"].items()}
    if V:
        out["mechanism"] = {k: V[k] for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "burn_minus_kernel_ms",
                                              "nostore_minus_burn_ms")}
        out["callback_time_per_event_type"] = V["callback_time_per_event_type"]

    # ---------------------------------------------------------------- consistency checks
    c0, c1, c2 = counts[0], counts[1], counts[2]
    chk = out["checks"]
    chk["open: records == deletes"] = abs(c0["rb_records"] - c0["map_deletes"]) <= 1
    chk["open: calls == early_exits + records"] = abs(c0["calls"] - c0["early_exits"] - c0["rb_records"]) <= 2
    chk["perm: updates == records"] = abs(c1["map_updates"] - c1["rb_records"]) <= 1
    chk["mmap: updates == records"] = abs(c2["map_updates"] - c2["rb_records"]) <= 1
    chk["fork/exec/exit ~ processes"] = all(abs(counts[p]["calls"] - procs) <= 10 for p in (11, 12, 13))
    chk["production timing built without WF_PROFILE"] = T is not None and not T.get("flags")
    chk["idle windows subtracted"] = len(P["idle"]) == len(P["reps"]) and len(T["runtime_idle"]) == len(T["runtime_reps"])
    chk["ablation rounds per variant"] = {k: sum(1 for r in a["rounds"] if not r["warmup"]) for k, a in A.items()}
    chk["timing pairs (excluding warm-up)"] = tm.get("pairs")
    chk["kernel drops"] = tm.get("kernel_drops_total")
    chk["queue drops"] = tm.get("queue_drops")

    (d / "derived.json").write_text(json.dumps(out, indent=2, default=str))

    # ---------------------------------------------------------------- CSV tables
    with (tables / "per_hook.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["hook", "calls_workload_window", "calls_idle_adjusted", "early_exits", "map_lookups", "map_updates",
                    "map_deletes", "rb_records", "rb_bytes", "upid_walks", "bpf_runtime_us_per_run", "ns_per_call",
                    "share_of_bpf_runtime_pct", "maps", "ablation_body_ms_median", "ablation_body_ms_ci90_lo",
                    "ablation_body_ms_ci90_hi"])
        for pid in SHORT:
            c, r = counts[pid], rt[pid]
            if not (raw_counts[pid]["calls"] or r["run_cnt"]):
                continue
            ab = next((v for k, v in abl.items() if ABL.get(k) == pid), None)
            w.writerow([SHORT[pid], raw_counts[pid]["calls"], c["calls"], c["early_exits"], c["map_lookups"], c["map_updates"],
                        c["map_deletes"], c["rb_records"], c["rb_bytes"], c["upid_walks"], r["run_time_ns"] / 1000,
                        r["ns_per_call"], r["run_time_ns"] / bpf_total * 100 if bpf_total else "", MAPS[pid],
                        ab["normal_minus_null_ms"]["median"] if ab else "", ab["normal_minus_null_ms"]["median_ci90"][0] if ab else "",
                        ab["normal_minus_null_ms"]["median_ci90"][1] if ab else ""])
    if Q:
        with (tables / "sections.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["hook", "section", "ns_per_run", "operations_per_run", "ns_per_operation"])
            ops = {"ns_translate_ns": lambda q: q["rb_records"] + q["foreign_tasks"] if q["calls"] else 0,
                   "d_path_ns": lambda q: q["rb_records"],
                   "io_seen_map_ns": lambda q: q["map_lookups"] + q["map_updates"] + q["map_deletes"],
                   "ringbuf_ns": lambda q: q["rb_records"], "exec_copy_ns": lambda q: q["rb_records"]}
            for pid in SHORT:
                q = sections[pid]
                for sec, f in ops.items():
                    if q.get(sec):
                        n = f(q)
                        w.writerow([SHORT[pid], sec, q[sec], n, q[sec] / n if n else ""])

    # ---------------------------------------------------------------- markdown
    L = []
    if tm:
        L += ["## Timing (production build, shell-timed loop)\n", "| | value |", "|---|---|",
              f"| alternating pairs | {tm['pairs']} (after {T['warmup_pairs']} warm-up pairs) |",
              f"| baseline / monitored median | {tm['off_median_ms']:.1f} ms / {tm['on_median_ms']:.1f} ms |",
              f"| median paired overhead | {tm['overhead_pct']['median']:.2f}% (90% CI {tm['overhead_pct']['median_ci90'][0]:.2f}..{tm['overhead_pct']['median_ci90'][1]:.2f}; IQR {tm['overhead_pct']['q1']:.2f}..{tm['overhead_pct']['q3']:.2f}) |",
              f"| median paired delta | {tm['delta_ms_median']:.2f} ms/run = {tm['delta_us_per_process']:.1f} µs/process |",
              f"| same pairs, Python-side timing | {tm['outer_overhead_pct_median']:.2f}% |",
              f"| first build after load | {tm['first_build_after_load_ms']:.1f} ms |",
              f"| events received / filtered per run | {tm['events_received_per_run']:.0f} / {tm['events_filtered_per_run']:.0f} |",
              f"| collector CPU / store-worker CPU per run | {tm['collector_cpu_s_per_run']*1000:.0f} ms / {tm['store_worker_cpu_s_per_run']*1000:.0f} ms |",
              f"| kernel drops / queue drops | {tm['kernel_drops_total']} / {tm['queue_drops']} |",
              f"| BPF run time (production, bpf_stats) | {bpf_total/1e6:.2f} ms/run = {bpf_total/1e3/procs:.2f} µs/process |", ""]
    L += ["## Per-hook (per 300-process run; counts from WF_PROFILE build, run time from production build)\n",
          "| hook | calls (window) | calls (idle-adj.) | early exits | lookups | updates | deletes | rb records | rb bytes | upid walks | BPF µs | ns/call | % BPF | ablation body ms (90% CI) |",
          "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for pid in sorted(SHORT, key=lambda p: -rt[p]["run_time_ns"]):
        c, r = counts[pid], rt[pid]
        if not (raw_counts[pid]["calls"] or r["run_cnt"]):
            continue
        ab = next((v for k, v in abl.items() if ABL.get(k) == pid), None)
        abs_ = ci(ab["normal_minus_null_ms"]) + ("" if ab["conclusive"] else " inconclusive") if ab else "—"
        L.append(f"| {SHORT[pid]} | {raw_counts[pid]['calls']:.0f} | {c['calls']:.0f} | {c['early_exits']:.0f} | {c['map_lookups']:.0f} | "
                 f"{c['map_updates']:.0f} | {c['map_deletes']:.0f} | {c['rb_records']:.0f} | {c['rb_bytes']:.0f} | {c['upid_walks']:.0f} | "
                 f"{r['run_time_ns']/1e3:.0f} | {r['ns_per_call']:.0f} | {r['run_time_ns']/bpf_total*100:.1f}% | {abs_} |")
    L.append("")
    if Q:
        L += ["## Section times inside programs (WF_PROFILE_TIME build; approximate, per run)\n",
              "| hook | namespace translation | bpf_d_path | io_seen map ops | ring buffer | exec copies |", "|---|---|---|---|---|---|"]
        for pid in (0, 1, 2, 11, 12, 13):
            q = sections[pid]
            def cell(sec, n):
                return f"{q[sec]/1e3:.0f} µs ({q[sec]/n:.0f} ns × {n:.0f})" if q.get(sec) and n else "—"
            L.append(f"| {SHORT[pid]} | {cell('ns_translate_ns', q['rb_records'] + q['foreign_tasks'])} | {cell('d_path_ns', q['rb_records'])} | "
                     f"{cell('io_seen_map_ns', q['map_lookups'] + q['map_updates'] + q['map_deletes'])} | {cell('ringbuf_ns', q['rb_records'])} | "
                     f"{cell('exec_copy_ns', q['rb_records'])} |")
        L.append("")
    if "foreign_tasks" in out:
        f = out["foreign_tasks"]
        L += ["## Foreign-task (out-of-namespace) invocations\n", "| hook | invocations/run | upid walks/run | est. ns/call | est. µs/run | events emitted |", "|---|---|---|---|---|---|"]
        for k, v in f["per_hook"].items():
            L.append(f"| {k} | {v['foreign_invocations_per_run']:.0f} | {v['upid_walks_per_run']:.0f} | {v['est_ns_per_foreign_call']:.0f} | {v['est_total_us_per_run']:.0f} | 0 |")
        L.append(f"\nTotal ≈ {f['est_total_us_per_run']:.0f} µs/run = {f['pct_of_bpf_runtime']:.1f}% of BPF run time, "
                 f"{f['pct_of_wall_overhead']:.1f}% of the measured wall overhead.\n")
    if abl:
        L += ["## Hook-body ablation (WF_NULL_MASK; rotated baseline/normal/nulled rounds, shell-timed)\n",
              "| variant | normal − base ms | normal − nulled ms | nulled − base ms | calls/run | body ns/call (90% CI) | conclusive |", "|---|---|---|---|---|---|---|"]
        for k, v in abl.items():
            body = f"{v['body_ns_per_call']:.0f} ({v['body_ns_per_call_ci90'][0]:.0f}..{v['body_ns_per_call_ci90'][1]:.0f})" if v["body_ns_per_call"] is not None else "n/a"
            L.append(f"| {k} (n={v['normal_minus_null_ms']['n']}) | {ci(v['normal_minus_base_ms'])} | {ci(v['normal_minus_null_ms'])} | "
                     f"{ci(v['null_minus_base_ms'])} | {v['calls_per_run'] if v['calls_per_run'] is not None else 'all'} | {body} | {'yes' if v['conclusive'] else 'no'} |")
        L.append("")
    if U:
        us = out["userspace_split"]
        L += ["## Userspace split (phase U; rotated rounds, shell-timed)\n", "| comparison | ms per run |", "|---|---|"]
        for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "full_minus_nostore_ms", "full_minus_kernel_ms", "full_minus_base_ms"):
            L.append(f"| {k.replace('_ms', '').replace('_minus_', ' − ')} | {ci(us[k])} |")
        L.append(f"| collector CPU per run (base/kernel/no_store/full) | " + " / ".join(f"{v*1000:.0f} ms" for v in us["collector_cpu_s"].values()) + " |\n")
    if V:
        mv = out["mechanism"]
        L += ["## Mechanism (phase V; burn = callback discards, a Python thread spins during the run)\n", "| comparison | ms per run |", "|---|---|"]
        for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "burn_minus_kernel_ms", "nostore_minus_burn_ms"):
            L.append(f"| {k.replace('_ms', '').replace('_minus_', ' − ')} | {ci(mv[k])} |")
        L += ["", "Callback time per event type (no_store mode):\n", "| event | per run | µs/event | ms/run |", "|---|---|---|---|"]
        for k, v in sorted(out["callback_time_per_event_type"].items(), key=lambda kv: -kv[1]["ms_per_run"]):
            L.append(f"| {k} | {v['events_per_run']:.0f} | {v['us_per_event']:.1f} | {v['ms_per_run']:.2f} |")
        L.append("")
    X = res.get("phase_X")
    if X:
        out["realpath_mechanism"] = {k: X[k] for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms",
                                                       "canon_only_minus_kernel_ms", "nostore_nocanon_minus_kernel_ms",
                                                       "nostore_minus_nostore_nocanon_ms")}
        (d / "derived.json").write_text(json.dumps(out, indent=2, default=str))
        L += ["## realpath/lstat mechanism (phase X; rotated rounds, shell-timed)\n", "| comparison | ms per run |", "|---|---|"]
        for k, v in out["realpath_mechanism"].items():
            L.append(f"| {k.replace('_ms', '').replace('_minus_', ' − ')} | {ci(v)} |")
        L.append("")
    L += ["## Consistency checks\n", "| check | result |", "|---|---|"] + [f"| {k} | {v} |" for k, v in chk.items()]
    (d / "HOTPATH_TABLES.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
