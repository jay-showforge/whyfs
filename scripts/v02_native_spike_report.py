#!/usr/bin/env python3
"""Phase 2 table (Python collector vs native spike) from native-spike.json. Usage: report.py DIR"""
import json, statistics, sys
from pathlib import Path

d = Path(sys.argv[1])
r = json.loads((d / "native-spike.json").read_text())["rounds"]
rows = [x for x in r["rows"] if not x["warmup"]]
med = statistics.median


def py(m, f):
    return med([f(x[m]) for x in rows])


def cpu(c):
    return sum(c.get(p, {}).get(k, 0) for p in ("self", "store") for k in ("utime_s", "stime_s")) * 1000


def ctx(c):
    return sum(c.get(p, {}).get(k, 0) for p in ("self", "store") for k in ("vol_ctx", "invol_ctx"))


t = []
t.append(("workload wall time (ms)", f"{r['per_mode_ms']['E']['median']:.2f}", f"{r['per_mode_ms']['N1']['median']:.2f}"))
t.append(("added overhead vs A (ms, CI90)", "{:+.2f} ({:+.2f}..{:+.2f})".format(r["E_minus_A"]["median"], *r["E_minus_A"]["median_ci90"]),
          "{:+.2f} ({:+.2f}..{:+.2f})".format(r["N1_minus_A"]["median"], *r["N1_minus_A"]["median_ci90"])))
t.append(("added overhead vs A (%)", f"{r['overhead_pct']['E']['median']:+.2f}", f"{r['overhead_pct']['N1']['median']:+.2f}"))
t.append(("collector CPU (ms/run)", f"{py('E', lambda x: cpu(x['collector'])):.1f}",
          f"{py('N1', lambda x: (x['native']['user_s'] + x['native']['sys_s']) * 1000):.1f}"))
t.append(("collector context switches/run", f"{py('E', lambda x: ctx(x['collector'])):.0f}",
          f"{py('N1', lambda x: x['native']['vol_ctx'] + x['native']['invol_ctx']):.0f}"))
t.append(("events received/run", f"{py('E', lambda x: x['collector']['stats']['received']):.0f}", f"{py('N1', lambda x: x['native']['received']):.0f}"))
t.append(("events persisted/run", f"{py('E', lambda x: x['collector']['counters']['ingest_rows']):.0f}",
          f"{py('N1', lambda x: x['native']['stored']):.0f} (lower bound: open/io/exec only)"))
t.append(("kernel drops (sum)", str(sum(x["E"]["collector"].get("kernel_drops", 0) for x in rows)),
          str(sum(x["N1"]["collector"].get("kernel_drops", 0) for x in rows))))
t.append(("userspace drops (sum)", str(sum(x["E"]["collector"]["stats"].get("queue_drops", 0) for x in rows)), "0 (no userspace queue)"))
t.append(("store/ingest time (ms/run)", f"{py('E', lambda x: x['collector']['counters']['ingest_ns'] / 1e6):.2f}",
          f"{py('N1', lambda x: x['native']['commit_ms']):.2f} (commit only)"))
t.append(("query-visible records/run", f"{py('E', lambda x: x['collector']['counters']['ingest_rows']):.0f}", f"{py('N1', lambda x: x['native']['stored']):.0f}"))
out = ["| Metric | Python collector (E) | Native spike (N1) |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in t]
out += ["", "Paired differences (median ms, CI90):"]
for k in ("B_minus_A", "N0_minus_A", "E_minus_B", "N1_minus_N0", "N0_minus_B", "E_minus_N1"):
    s = r[k]
    out.append(f"- {k}: {s['median']:+.2f} ({s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
(d / "table.md").write_text("\n".join(out) + "\n")
print("\n".join(out))
