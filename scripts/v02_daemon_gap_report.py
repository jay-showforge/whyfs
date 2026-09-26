#!/usr/bin/env python3
"""Tables for a v02_daemon_gap.py result.

    python3 scripts/v02_daemon_gap_report.py RESULT_DIR  -> RESULT_DIR/derived.json, RESULT_DIR/tables/*.csv, GAP_TABLES.md
"""
from __future__ import annotations

import csv
import json
import statistics as st
import sys
from pathlib import Path

MODES = ["A", "B", "C", "D", "E"]
NAMES = {"A": "baseline", "B": "kernel only (separate agent, callback discards)", "C": "in-process full collector",
         "D": "separate process, processing, no SQLite", "E": "separate process, production path (processing + SQLite)"}


def med(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else None


def ci(s):
    return f"{s['median']:+.2f} ({s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})"


def cpu(d):
    return (d.get("utime_s", 0) or 0) + (d.get("stime_s", 0) or 0)


def main() -> int:
    d = Path(sys.argv[1])
    r = json.loads((d / "gap.json").read_text())
    tables = d / "tables"
    tables.mkdir(exist_ok=True)
    out: dict = {"source": str(d), "git": r["git"]}
    L = []

    R = r["R"]
    meas = [x for x in R["rows"] if not x["warmup"]]
    # per-mode OS metrics
    per_mode = {}
    for m in MODES:
        rows = [x[m] for x in meas]
        pm = {"wall_ms": med(x["s"] * 1000 for x in rows),
              "wl_vol_ctx": med(x.get("wl_vol_ctx") for x in rows), "wl_invol_ctx": med(x.get("wl_invol_ctx") for x in rows),
              "wl_minflt": med(x.get("wl_minflt") for x in rows), "wl_majflt": med(x.get("wl_majflt") for x in rows),
              "loop_shell_migrations": med(x.get("loop_shell_migrations") for x in rows)}
        if m != "A":
            col = [x.get("collector", {}) for x in rows]
            pm.update({
                "collector_user_s": med(c.get("self", {}).get("utime_s") for c in col),
                "collector_sys_s": med(c.get("self", {}).get("stime_s") for c in col),
                "collector_vol_ctx": med(c.get("self", {}).get("vol_ctx") for c in col),
                "collector_invol_ctx": med(c.get("self", {}).get("invol_ctx") for c in col),
                "collector_minflt": med(c.get("self", {}).get("minflt") for c in col),
                "collector_majflt": med(c.get("self", {}).get("majflt") for c in col),
                "collector_migrations": med(c.get("self", {}).get("migrations") for c in col),
                "store_cpu_s": med(cpu(c.get("store", {})) for c in col),
                "store_write_bytes": med(c.get("store", {}).get("write_bytes") for c in col),
                "events_received": med(c.get("stats", {}).get("received") for c in col),
                "records_submitted": med(c.get("stats", {}).get("submitted") for c in col),
                "kernel_drops": sum((c.get("kernel_drops") or 0) for c in col),
                "queue_drops": sum((c.get("stats", {}).get("queue_drops") or 0) for c in col),
                "sqlite_ingest_ms": med((c.get("counters", {}).get("ingest_ns") or 0) / 1e6 for c in col) if m in "BDE" else None,
                "sqlite_rows": med(c.get("counters", {}).get("ingest_rows") for c in col) if m in "BDE" else None,
                "resolve_calls": med(c.get("counters", {}).get("resolve_calls") for c in col) if m in "BDE" else None,
                "canon_calls": med(c.get("counters", {}).get("canon_calls") for c in col) if m in "BDE" else None,
            })
        per_mode[m] = pm
    out["R_per_mode"] = per_mode
    out["R_deltas_ms"] = {k: R[k] for k in ("B_minus_A", "D_minus_B", "E_minus_D", "E_minus_A", "C_minus_A", "E_minus_C", "D_minus_A")}
    out["R_overhead_pct"] = R["overhead_pct"]
    with (tables / "R_per_mode.csv").open("w", newline="") as fh:
        keys = sorted({k for v in per_mode.values() for k in v})
        w = csv.writer(fh)
        w.writerow(["mode", "description"] + keys)
        for m in MODES:
            w.writerow([m, NAMES[m]] + [per_mode[m].get(k) for k in keys])
    with (tables / "R_rounds.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["round", "warmup", "order"] + [f"{m}_ms" for m in MODES])
        for i, x in enumerate(R["rows"]):
            w.writerow([i, x["warmup"], "".join(x["order"])] + [x[m]["s"] * 1000 for m in MODES])

    # reconciliation
    comp = {k: R[k]["median"] for k in ("B_minus_A", "D_minus_B", "E_minus_D")}
    total = R["E_minus_A"]["median"]
    out["reconciliation_R"] = {"components_ms": comp, "sum_components_ms": sum(comp.values()), "measured_E_minus_A_ms": total,
                               "unexplained_ms": total - sum(comp.values())}

    # S
    out["S_bpf_ms_per_run"] = r["S"]["bpf_ms_per_run"]

    # F time series
    for tag in ("F1", "F2"):
        F = r[tag]
        series = F["series"]
        with (tables / f"{tag}_series.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["run", "wall_ms", "overhead_pct_vs_baseline_median", "daemon_cpu_s", "daemon_minflt", "daemon_vol_ctx",
                        "daemon_invol_ctx", "daemon_migrations", "store_cpu_s", "store_minflt", "store_write_bytes", "db_events",
                        "bpf_run_time_ms", "wl_vol_ctx", "wl_invol_ctx", "wl_minflt", "loop_shell_migrations"])
            for x in series:
                dd = x["daemon"]
                w.writerow([x["index"], x["s"] * 1000, x["overhead_pct_vs_baseline_median"], cpu(dd["self"]), dd["self"].get("minflt"),
                            dd["self"].get("vol_ctx"), dd["self"].get("invol_ctx"), dd["self"].get("migrations"), cpu(dd["store"]),
                            dd["store"].get("minflt"), dd["store"].get("write_bytes"), dd.get("db_events"),
                            dd["bpf"]["run_time_ns"] / 1e6 if tag == "F2" else "", x.get("wl_vol_ctx"), x.get("wl_invol_ctx"),
                            x.get("wl_minflt"), x.get("loop_shell_migrations")])
        ov = [x["overhead_pct_vs_baseline_median"] for x in series]
        out[tag] = {"baseline_median_ms": F["baseline_median_s"] * 1000,
                    "baseline_before_ms": F["baseline_before_median_s"] * 1000, "baseline_after_ms": F["baseline_after_median_s"] * 1000,
                    "startup_s": F["startup_s"], "overhead_pct_series": ov,
                    "median_overhead_pct_all": med(ov), "median_runs_1_5": med(ov[:5]), "median_runs_6_15": med(ov[5:15]),
                    "median_runs_16_25": med(ov[15:]),
                    "median_delta_ms": med(x["s"] * 1000 - F["baseline_median_s"] * 1000 for x in series),
                    "daemon_minflt_series": [x["daemon"]["self"].get("minflt") for x in series],
                    "bpf_ms_series": [x["daemon"]["bpf"]["run_time_ns"] / 1e6 for x in series] if tag == "F2" else None,
                    "final_stats": F["daemon_final_stats"]}

    # G / K
    for tag in ("G", "K"):
        X = r[tag]
        out[tag] = {"overhead_pct": X["overhead_pct"], "first_overhead_pct": X["first_overhead_pct"], "delta_ms": X["delta_ms"],
                    "first_delta_ms": X["first_delta_ms"],
                    "pairs_pct": [x["overhead_pct"] for x in X["rows"] if not x["warmup"]]}
        with (tables / f"{tag}_pairs.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["pair", "warmup", "off_ms", "first_ms", "on_ms", "overhead_pct", "first_overhead_pct", "start_s"])
            for i, x in enumerate(X["rows"]):
                w.writerow([i, x["warmup"], x["off"]["s"] * 1000, x["first"]["s"] * 1000, x["on"]["s"] * 1000,
                            x["overhead_pct"], x["first_overhead_pct"], x.get("start_s")])
    out["cal"] = r["cal"]["perf_minus_plain_ms"]
    (d / "derived.json").write_text(json.dumps(out, indent=2, default=str))

    # markdown
    L += ["## R: steady-state topology split (40 rotated rounds; per 300-process run)\n",
          "| mode | configuration | wall ms | overhead % vs A (90% CI) |", "|---|---|---|---|"]
    for m in MODES:
        ov = "—" if m == "A" else ci(R["overhead_pct"][m])
        L.append(f"| {m} | {NAMES[m]} | {per_mode[m]['wall_ms']:.1f} | {ov} |")
    L += ["", "| difference | ms per run (90% CI) |", "|---|---|"]
    for k in ("B_minus_A", "D_minus_B", "E_minus_D", "E_minus_A", "C_minus_A", "E_minus_C"):
        L.append(f"| {k.replace('_minus_', ' − ')} | {ci(R[k])} |")
    rc = out["reconciliation_R"]
    L += ["", f"Reconciliation: (B−A) + (D−B) + (E−D) = {rc['sum_components_ms']:.2f} ms vs measured E−A {rc['measured_E_minus_A_ms']:.2f} ms "
          f"→ unexplained {rc['unexplained_ms']:+.2f} ms (medians of paired differences are not additive; each CI is ±1–2 ms).", ""]
    L += ["### OS-level metrics per run (medians)\n", "| metric | " + " | ".join(MODES) + " |", "|---|" + "---|" * len(MODES)]
    for k in ("wl_vol_ctx", "wl_invol_ctx", "wl_minflt", "loop_shell_migrations", "collector_user_s", "collector_sys_s",
              "collector_vol_ctx", "collector_invol_ctx", "collector_minflt", "collector_migrations", "store_cpu_s",
              "store_write_bytes", "events_received", "records_submitted", "sqlite_ingest_ms", "sqlite_rows",
              "resolve_calls", "canon_calls", "kernel_drops", "queue_drops"):
        vals = []
        for m in MODES:
            v = per_mode[m].get(k)
            vals.append("—" if v is None else (f"{v:.3f}" if isinstance(v, float) and v < 10 else f"{v:,.0f}" if isinstance(v, (int, float)) else str(v)))
        L.append(f"| {k} | " + " | ".join(vals) + " |")
    L += ["", f"BPF run time (phase S, agent, idle-subtracted): {ci(r['S']['bpf_ms_per_run'])} ms per run.", ""]
    for tag in ("F1", "F2"):
        f = out[tag]
        L += [f"## {tag}: persistent real daemon, 25 consecutive runs, no restart ({'bpf_stats on' if tag == 'F2' else 'bpf_stats off'})\n",
              f"Baseline median {f['baseline_median_ms']:.1f} ms (before {f['baseline_before_ms']:.1f}, after {f['baseline_after_ms']:.1f}); "
              f"daemon start {f['startup_s']:.2f} s.\n",
              "| run | " + " | ".join(str(i + 1) for i in range(len(f["overhead_pct_series"]))) + " |",
              "|---|" + "---|" * len(f["overhead_pct_series"]),
              "| overhead % | " + " | ".join(f"{v:+.1f}" for v in f["overhead_pct_series"]) + " |",
              "| daemon minflt | " + " | ".join(str(v) for v in f["daemon_minflt_series"]) + " |"]
        if f["bpf_ms_series"]:
            L.append("| BPF ms | " + " | ".join(f"{v:.2f}" for v in f["bpf_ms_series"]) + " |")
        L += ["", f"Median overhead: runs 1–5 {f['median_runs_1_5']:+.2f}%, runs 6–15 {f['median_runs_6_15']:+.2f}%, "
              f"runs 16–25 {f['median_runs_16_25']:+.2f}%, all {f['median_overhead_pct_all']:+.2f}% "
              f"({f['median_delta_ms']:+.2f} ms). Drops: kernel {f['final_stats'].get('kernel_drops')}, queue {f['final_stats'].get('queue_drops')}.", ""]
    for tag, title in (("G", "harness pattern: fresh daemon per measured build"), ("K", "lifecycle control: daemon stopped before the measured build")):
        g = out[tag]
        L += [f"## {tag}: {title} (20 alternating pairs)\n",
              f"Measured build: {ci(g['overhead_pct'])} % ({ci(g['delta_ms'])} ms). First build after start: {ci(g['first_overhead_pct'])} %.\n",
              "Pairs (%): " + ", ".join(f"{v:+.1f}" for v in g["pairs_pct"]), ""]
    L += [f"perf stat -a calibration: {ci(out['cal'])} ms on the baseline loop → disabled for all phases.", ""]
    (d / "GAP_TABLES.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
