#!/usr/bin/env python3
"""Native ingestion feasibility spike vs the Python collector (diagnostic harness).

One separate collector agent (production BCCCollector + privilege-separated Store) loads
the production BPF programs once.  For the native modes the agent pauses its Python ring
consumer and hands the SAME ring map fd to native/spike/spike_ingest.  Rotated rounds on
the graduation harness's static x300:

  A   baseline (no whyfs attached)
  B   Python consumer, callback discards (kernel evidence + Python ring consumption)
  E   Python collector, full production path (processing + privsep SQLite)
  N0  native consumer, discard (kernel evidence + native ring consumption)
  N1  native lower bound: decode, file map, workspace filter, batched SQLite

Workload time is shell-internal (date +%s%N).  Nothing collecting times the workload.

Usage: sudo python3 scripts/v02_native_spike_exp.py --user USER --out DIR
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
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

MODES = ["A", "B", "E", "N0", "N1"]
PAIRS = [("B", "A"), ("E", "A"), ("N0", "A"), ("N1", "A"), ("E", "B"), ("N1", "N0"), ("N0", "B"), ("E", "N1")]


def rounds(wl: GapWorkload, log: Log, n: int, ag: Agent, native_db: Path) -> dict:
    orders = [MODES[i:] + MODES[:i] for i in range(len(MODES))]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    for r in range(n + 1):
        rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
        for m in orders[r % len(orders)]:
            if m in ("B", "E"):
                ag.cmd("mode " + ("kernel_only" if m == "B" else "full"))
                s0 = ag.cmd("snap")
                ag.cmd("attach")
            elif m in ("N0", "N1"):
                s0 = ag.cmd("snap")
                ag.cmd(f"native start {'discard' if m == 'N0' else 'min'} {native_db}")
                ag.cmd("attach")
            wl.prep()
            run = wl.run_measured()
            if m != "A":
                ag.cmd("detach")
                time.sleep(0.4)  # let userspace finish this run's records
                if m.startswith("N"):
                    nat = ag.cmd("native stop")
                    run["native"] = nat["native"]
                    run["kernel_drops_total"] = nat["kernel_drops"]
                run["collector"] = delta(s0, ag.cmd("snap"))
            else:
                time.sleep(0.4)
            rec[m] = run
        rows.append(rec)
        if r % 5 == 0:
            log(f"  round {r}: " + " ".join(f"{m}={rec[m]['s']*1000:.1f}" for m in MODES))
    meas = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a]["s"] - x[z]["s"]) * 1000 for x in meas])

    out = {"rows": rows, "per_mode_ms": {m: summary([x[m]["s"] * 1000 for x in meas]) for m in MODES},
           "overhead_pct": {m: summary([(x[m]["s"] / x["A"]["s"] - 1) * 100 for x in meas]) for m in MODES if m != "A"}}
    for a, z in PAIRS:
        out[f"{a}_minus_{z}"] = d(a, z)
        s = out[f"{a}_minus_{z}"]
        log(f"  {a}-{z}: {s['median']:+.2f} ms (CI90 {s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
    for m in MODES[1:]:
        s = out["overhead_pct"][m]
        log(f"  overhead {m}: {s['median']:+.2f}% (CI90 {s['median_ci90'][0]:+.2f}..{s['median_ci90'][1]:+.2f})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-native-ws")
    ap.add_argument("--rounds", type=int, default=30)
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
    ctx = Ctx(a.user, out / "harness-ctx")
    spike = REPO / "native" / "spike" / "spike_ingest"
    subprocess.run(["gcc", "-O2", "-Wall", "-o", str(spike), str(spike) + ".c",
                    *subprocess.run(["pkg-config", "--cflags", "--libs", "libbpf", "sqlite3"], capture_output=True,
                                    text=True, check=True).stdout.split()], check=True)
    params = dict(vars(a), workload_cmd=CMD, spike_sha256=subprocess.run(["sha256sum", str(spike) + ".c"], capture_output=True,
                                                                          text=True).stdout.split()[0],
                  timing="shell (date +%s%N) inside the workload; never a collecting process")
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out), "environment": environment()}
    wl = GapWorkload(ctx, base, log)
    native_db = base / "native-spike.db"
    ag = Agent(wl.ws, "native-spike", log)
    try:
        wl.prep()
        wl.run_measured()
        log("rotated rounds " + " / ".join(MODES))
        res["rounds"] = rounds(wl, log, a.rounds, ag, native_db)
    finally:
        res["agent_final"] = ag.quit()
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        if native_db.exists():
            con = sqlite3.connect(native_db)
            res["native_db"] = {"events": con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                                "processes": con.execute("SELECT COUNT(*) FROM processes").fetchone()[0]}
            con.close()
        (out / "native-spike.json").write_text(json.dumps(res, indent=1, default=str))
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
