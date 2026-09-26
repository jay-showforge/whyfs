#!/usr/bin/env python3
"""io_seen reset variants, before/after on the graduation harness's workloads (diagnostic).

Separate collector processes run the production path (BCCCollector + privilege-separated
Store) from the current tree; they differ only in the compile-time WF_IOSEEN_MODE:

  M0  current production: delete the key on every open
  M1  lockless lookup, delete only if a stale entry exists; skip directories
  M2  no reset at all (UNSAFE diagnostic upper bound: may suppress first-I/O events)

Per workload (static x300, make -j8, Vite): rotated rounds A (baseline) / M0 / M1 / M2 with
shell-internal timing, per-run records received/submitted and drops, then production
bpf_stats run time per variant (idle-subtracted).

Usage: sudo python3 scripts/v02_ioseen_exp.py --user USER --out DIR
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from v02_graduation import Ctx, environment  # noqa: E402
from v02_hotpath_profile import Log, summary, git_info, WORKLOADS  # noqa: E402
from v02_daemon_gap import Agent, GapWorkload, delta  # noqa: E402
from whyfs.daemon import ensure_kernel_headers  # noqa: E402

VARIANTS = {"M0": "-DWF_IOSEEN_MODE=0", "M1": "-DWF_IOSEEN_MODE=1", "M2": "-DWF_IOSEEN_MODE=2"}
MODES = ["A", "M0", "M1", "M2"]


class Wl(GapWorkload):
    def __init__(self, ctx, base, log, kind):
        super(GapWorkload, self).__init__(ctx, base, log, kind)


def rounds(wl, log, n, agents) -> dict:
    orders = [MODES[i:] + MODES[:i] for i in range(4)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    for r in range(n + 1):
        rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
        for m in orders[r % len(orders)]:
            if m != "A":
                ag = agents[m]
                s0 = ag.cmd("snap")
                ag.cmd("attach")
            wl.prep()
            run = wl.run_measured()
            if m != "A":
                ag.cmd("detach")
                time.sleep(0.4)
                run["collector"] = delta(s0, ag.cmd("snap"))
            else:
                time.sleep(0.4)
            rec[m] = run
        rows.append(rec)
        if r % 5 == 0:
            log(f"    round {r}: " + " ".join(f"{m}={rec[m]['s']*1000:.1f}" for m in MODES))
    meas = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a]["s"] - x[z]["s"]) * 1000 for x in meas])

    out = {"rows": rows, "per_mode_ms": {m: summary([x[m]["s"] * 1000 for x in meas]) for m in MODES},
           "overhead_pct": {m: summary([(x[m]["s"] / x["A"]["s"] - 1) * 100 for x in meas]) for m in MODES if m != "A"},
           "added_ms": {m: d(m, "A") for m in MODES if m != "A"},
           "M0_minus_M1": d("M0", "M1"), "M0_minus_M2": d("M0", "M2")}
    for m in ("M0", "M1", "M2"):
        col = [x[m]["collector"] for x in meas]
        out.setdefault("records", {})[m] = {
            "received_median": statistics.median(c["stats"]["received"] for c in col),
            "submitted_median": statistics.median(c["stats"]["submitted"] for c in col),
            "received_total": sum(c["stats"]["received"] for c in col),
            "submitted_total": sum(c["stats"]["submitted"] for c in col),
            "kernel_drops": sum(c["kernel_drops"] for c in col), "queue_drops": sum(c["stats"]["queue_drops"] for c in col)}
    log(f"    added ms: " + "  ".join(f"{m} {out['added_ms'][m]['median']:+.2f}" for m in ("M0", "M1", "M2")) +
        f"  | M0-M1 {out['M0_minus_M1']['median']:+.2f} (CI90 {out['M0_minus_M1']['median_ci90'][0]:+.2f}..{out['M0_minus_M1']['median_ci90'][1]:+.2f})"
        f"  | M0-M2 {out['M0_minus_M2']['median']:+.2f} (CI90 {out['M0_minus_M2']['median_ci90'][0]:+.2f}..{out['M0_minus_M2']['median_ci90'][1]:+.2f})")
    log(f"    records received/submitted per run: " + "  ".join(
        f"{m} {out['records'][m]['received_median']:.0f}/{out['records'][m]['submitted_median']:.0f}" for m in ("M0", "M1", "M2")))
    return out


def bpf_runtime(wl, log, agents, reps) -> dict:
    out = {}
    agents["M0"].cmd("bpfstats on")
    try:
        for m in ("M0", "M1", "M2"):
            ag = agents[m]
            ag.cmd("attach")
            rows = []
            for _ in range(reps):
                wl.prep()
                time.sleep(0.3)
                a0 = ag.cmd("progstats")
                run = wl.run_measured()
                a1 = ag.cmd("progstats")
                i0 = ag.cmd("progstats")
                time.sleep(run["s"])
                i1 = ag.cmd("progstats")
                per = {k: (a1[k]["run_time_ns"] - a0[k]["run_time_ns"]) - (i1[k]["run_time_ns"] - i0[k]["run_time_ns"]) for k in a1}
                cnt = {k: (a1[k]["run_cnt"] - a0[k]["run_cnt"]) - (i1[k]["run_cnt"] - i0[k]["run_cnt"]) for k in a1}
                rows.append({"total_ns": sum(per.values()), "per_prog_ns": per, "per_prog_cnt": cnt})
            ag.cmd("detach")
            time.sleep(0.3)
            out[m] = {"rows": rows, "total_ms": summary([x["total_ns"] / 1e6 for x in rows]),
                      "per_prog_ns_median": {k: statistics.median(x["per_prog_ns"][k] for x in rows) for k in rows[0]["per_prog_ns"]},
                      "per_prog_cnt_median": {k: statistics.median(x["per_prog_cnt"][k] for x in rows) for k in rows[0]["per_prog_cnt"]}}
            log(f"    BPF run time {m}: {out[m]['total_ms']['median']:.3f} ms/run "
                f"(open {out[m]['per_prog_ns_median'].get('0', 0)/1e3:.0f} us, perm {out[m]['per_prog_ns_median'].get('1', 0)/1e3:.0f} us)")
    finally:
        agents["M0"].cmd("bpfstats off")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-ioseen-ws")
    ap.add_argument("--workloads", default="static,make,vite")
    ap.add_argument("--rounds", default="static=40,make=30,vite=30")
    ap.add_argument("--bpf-reps", type=int, default=8)
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
    (out / "harness-ctx").mkdir()
    ctx = Ctx(a.user, out / "harness-ctx")
    nrounds = dict(kv.split("=") for kv in a.rounds.split(","))
    params = dict(vars(a), variants=VARIANTS, workloads_def={k: WORKLOADS[k][:2] for k in WORKLOADS},
                  timing="shell (date +%s%N) inside the workload; never a collecting process")
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out), "environment": environment(),
           "workloads": {}}
    log(f"git HEAD {res['git']['head'][:7]} dirty={len(res['git']['dirty_files'])}")
    try:
        for kind in a.workloads.split(","):
            log(f"== workload {kind}")
            base = Path(a.base.format(user=a.user)) / kind
            if base.exists():
                shutil.rmtree(base)
            wl = Wl(ctx, base, log, kind)
            agents = {m: Agent(wl.ws, f"ioseen-{kind}-{m}", log, cflags=VARIANTS[m]) for m in ("M0", "M1", "M2")}
            try:
                wl.prep()
                wl.run_measured()
                r = rounds(wl, log, int(nrounds[kind]), agents)
                r["bpf"] = bpf_runtime(wl, log, agents, a.bpf_reps)
                res["workloads"][kind] = r
            finally:
                for m, ag in agents.items():
                    res["workloads"].setdefault(kind, {}).setdefault("agent_final", {})[m] = ag.quit()
    finally:
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "ioseen.json").write_text(json.dumps(res, indent=1, default=str))
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
