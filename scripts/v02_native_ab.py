#!/usr/bin/env python3
"""Phase 2 A/B: Python collector vs the integrated native collector (diagnostic harness).

Two persistent collector agents, each in its production topology and each with its
own copy of the production BPF programs (attached one at a time, per run):

  py      BCCCollector + privilege-separated Store (the Python daemon path)
  native  BPF loaded by Python, one persistent whyfs-collect consuming the ring and
          writing the store through its privilege-dropped writer (the native daemon path)

Rotated rounds on the graduation harness's static x300:
  A   baseline (nothing attached)
  B   py agent, ring callback discards (kernel evidence + Python consumption)
  E   py agent, full production path
  NF  native agent, full production path

Workload time is shell-internal (date +%s%N).  After each monitored run the driver
counts the run's query-visible rows in SQLite.

Usage: sudo python3 scripts/v02_native_ab.py --user USER --out DIR [--rounds 40]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from v02_graduation import Ctx, environment  # noqa: E402
from v02_hotpath_profile import CMD, Log, summary, git_info  # noqa: E402
from v02_daemon_gap import Agent, GapWorkload, delta  # noqa: E402
from whyfs.daemon import ensure_kernel_headers  # noqa: E402

MODES = ["A", "B", "E", "NF"]
PAIRS = [("B", "A"), ("E", "A"), ("NF", "A"), ("E", "B"), ("NF", "B"), ("E", "NF")]
# --decompose: add the native kernel floor (K: persistent native consumer, discard) and
# native processing without persistence (NP), all persistent, same session.
DECOMP_MODES = ["A", "B", "E", "K", "NP", "NF", "NI"]
DECOMP_PAIRS = PAIRS + [("K", "A"), ("NP", "K"), ("NF", "NP"), ("NF", "K"), ("B", "K"), ("NI", "A"), ("NI", "NP"),
                        ("NI", "NF")]
AGENT_RUN = {"B": "ab-py", "E": "ab-py", "K": "ab-native-k", "NP": "ab-native-np", "NF": "ab-native",
             "NI": "ab-native-imm"}


def visible(db: Path, run_id: str) -> int:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    try:
        return sum(con.execute(f"SELECT COUNT(*) FROM {t} WHERE run_id=?", (run_id,)).fetchone()[0]
                   for t in ("events", "processes"))
    finally:
        con.close()


def cpu_ms(d: dict, parts) -> float:
    return sum(d.get(p, {}).get(k, 0) for p in parts for k in ("utime_s", "stime_s")) * 1000


def ctx(d: dict, parts) -> float:
    return sum(d.get(p, {}).get(k, 0) for p in parts for k in ("vol_ctx", "invol_ctx"))


def rounds(wl: GapWorkload, log: Log, n: int, agents: dict) -> dict:
    orders = [MODES[i:] + MODES[:i] for i in range(len(MODES))]
    orders += [list(reversed(o)) for o in orders]
    db = wl.ws / ".whyfs" / "whyfs.db"
    rows = []
    for r in range(n + 1):
        rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
        for m in orders[r % len(orders)]:
            ag = agents.get(m)
            rid = AGENT_RUN.get(m)
            if m != "A":
                if m in ("B", "E"):
                    ag.cmd("mode " + ("kernel_only" if m == "B" else "full"))
                s0 = ag.cmd("snap")
                v0 = visible(db, rid)
                ag.cmd("attach")
            wl.prep()
            run = wl.run_measured()
            if m != "A":
                ag.cmd("detach")
                time.sleep(0.4)  # let userspace finish this run's records
                run["collector"] = delta(s0, ag.cmd("snap"))
                time.sleep(0.2)
                run["visible"] = visible(db, rid) - v0
            else:
                time.sleep(0.4)
            rec[m] = run
        rows.append(rec)
        if r % 5 == 0:
            log(f"  round {r}: " + " ".join(f"{m}={rec[m]['s']*1000:.1f}" for m in MODES))
    meas = [x for x in rows if not x["warmup"]]
    out = {"rows": rows, "per_mode_ms": {m: summary([x[m]["s"] * 1000 for x in meas]) for m in MODES},
           "overhead_pct": {m: summary([(x[m]["s"] / x["A"]["s"] - 1) * 100 for x in meas]) for m in MODES if m != "A"}}
    for a, z in PAIRS:
        s = out[f"{a}_minus_{z}"] = summary([(x[a]["s"] - x[z]["s"]) * 1000 for x in meas])
        log(f"  {a}-{z}: {s['median']:+.2f} ms (CI90 {s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
    for m in MODES[1:]:
        s = out["overhead_pct"][m]
        log(f"  overhead {m}: {s['median']:+.2f}% (CI90 {s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
    return out


def table(res: dict) -> str:
    r = res["rounds"]
    meas = [x for x in r["rows"] if not x["warmup"]]
    med = statistics.median
    E = [x["E"] for x in meas]
    N = [x["NF"] for x in meas]
    py_parts, nat_parts = ("self", "store"), ("self", "store", "native", "native_writer")
    t = [
        ("workload wall time (ms, median)", f"{r['per_mode_ms']['E']['median']:.2f}", f"{r['per_mode_ms']['NF']['median']:.2f}"),
        ("added overhead vs A (ms, CI90)", "{:+.2f} ({:+.2f}..{:+.2f})".format(r["E_minus_A"]["median"], *r["E_minus_A"]["median_ci90"]),
         "{:+.2f} ({:+.2f}..{:+.2f})".format(r["NF_minus_A"]["median"], *r["NF_minus_A"]["median_ci90"])),
        ("added overhead vs A (%)", f"{r['overhead_pct']['E']['median']:+.2f}", f"{r['overhead_pct']['NF']['median']:+.2f}"),
        ("collector CPU (ms/run, all collector processes)", f"{med([cpu_ms(x['collector'], py_parts) for x in E]):.1f}",
         f"{med([cpu_ms(x['collector'], nat_parts) for x in N]):.1f}"),
        ("collector context switches/run", f"{med([ctx(x['collector'], py_parts) for x in E]):.0f}",
         f"{med([ctx(x['collector'], nat_parts) for x in N]):.0f}"),
        ("events received/run", f"{med([x['collector']['stats']['received'] for x in E]):.0f}",
         f"{med([x['collector']['stats']['received'] for x in N]):.0f}"),
        ("events persisted/run", f"{med([x['collector']['counters']['ingest_rows'] for x in E]):.0f}",
         f"{med([x['collector']['stats']['submitted'] for x in N]):.0f}"),
        ("kernel drops (sum over runs)", str(sum(x["collector"].get("kernel_drops", 0) for x in E)),
         str(sum(x["collector"].get("kernel_drops", 0) for x in N))),
        ("userspace drops (sum over runs)", str(sum(x["collector"]["stats"].get("queue_drops", 0) for x in E)),
         str(sum(x["collector"]["stats"].get("queue_drops", 0) for x in N))),
        ("store/ingest time (ms/run)", f"{med([x['collector']['counters']['ingest_ns'] / 1e6 for x in E]):.2f} (ingest calls)",
         f"{med([cpu_ms(x['collector'], ('native_writer',)) for x in N]):.1f} (writer CPU)"),
        ("query-visible records/run", f"{med([x['visible'] for x in E]):.0f}", f"{med([x['visible'] for x in N]):.0f}"),
    ]
    out = ["| Metric | Python collector (E) | Native collector (NF) |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in t]
    out += ["", "Paired differences (median ms, CI90):"]
    for a, z in PAIRS:
        s = r[f"{a}_minus_{z}"]
        out.append(f"- {a}-{z}: {s['median']:+.2f} ({s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-native-ab-ws")
    ap.add_argument("--rounds", type=int, default=40)
    ap.add_argument("--decompose", action="store_true",
                    help="also K (native discard), NP (native, no store), NI (native, immediate persistence)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        return 2
    out = Path(a.out)
    if out.exists():
        print(f"{out} exists; refusing to overwrite", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    log = Log(out / "console.log")
    ensure_kernel_headers()
    base = Path(a.base.format(user=a.user))
    if base.exists():
        shutil.rmtree(base)
    (out / "harness-ctx").mkdir()
    ctx_ = Ctx(a.user, out / "harness-ctx")
    params = dict(vars(a), workload_cmd=CMD, timing="shell (date +%s%N) inside the workload; never a collecting process")
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out), "environment": environment()}
    log(f"tree {res['git']['head'][:7]} (dirty {len(res['git']['dirty_files'])})")
    wl = GapWorkload(ctx_, base, log)
    global MODES, PAIRS
    if a.decompose:
        MODES, PAIRS = DECOMP_MODES, DECOMP_PAIRS
    py = Agent(wl.ws, "ab-py", log)
    agents = {"B": py, "E": py, "NF": Agent(wl.ws, "ab-native", log, native=True)}
    if a.decompose:
        agents["K"] = Agent(wl.ws, "ab-native-k", log, native=True, native_diag="discard")
        agents["NP"] = Agent(wl.ws, "ab-native-np", log, native=True, native_diag="no-store")
        agents["NI"] = Agent(wl.ws, "ab-native-imm", log, native=True, native_diag="flush-immediate")
    try:
        wl.prep()
        wl.run_measured()
        log("rotated rounds " + " / ".join(MODES))
        res["rounds"] = rounds(wl, log, a.rounds, agents)
    finally:
        for k, ag in agents.items():
            if k != "B":
                res[f"final_{k}"] = ag.quit()
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "native-ab.json").write_text(json.dumps(res, indent=1, default=str))
    tbl = table(res)
    (out / "table.md").write_text(tbl)
    log("\n" + tbl)
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
