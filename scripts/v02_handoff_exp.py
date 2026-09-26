#!/usr/bin/env python3
"""Before/after: per-record writer handoff vs batched handoff (diagnostic harness).

Two separate collector processes, the production path wired exactly as the daemon wires
it (BCCCollector + privilege-separated Store), one importing the BEFORE tree's src
(per-record handoff) and one the AFTER tree's src (batched handoff).  Identical BPF
programs; attached one at a time.  Rotated rounds over:

  A   baseline (no whyfs attached)
  B   kernel only (BEFORE agent, ring callback discards)
  Eb  BEFORE: full production path
  Ea  AFTER:  full production path

Then visibility latency (event -> row queryable in SQLite) for both, idle and during a
running static x300 build.  Workload timing is shell-internal; nothing is timed from a
process that takes part in collection.

Usage: sudo python3 scripts/v02_handoff_exp.py --user USER --out DIR --before-src PATH
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

MODES = ["A", "B", "Eb", "Ea"]


def rounds(wl: GapWorkload, log: Log, n: int, before: Agent, after: Agent) -> dict:
    orders = [MODES[i:] + MODES[:i] for i in range(4)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    for r in range(n + 1):
        rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
        for m in orders[r % len(orders)]:
            ag = after if m == "Ea" else before
            if m != "A":
                ag.cmd("mode " + ("kernel_only" if m == "B" else "full"))
                s0 = ag.cmd("snap")
                ag.cmd("attach")
            wl.prep()
            run = wl.run_measured()
            if m != "A":
                ag.cmd("detach")
                time.sleep(0.4)  # let userspace finish this run's records
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
           "overhead_pct": {m: summary([(x[m]["s"] / x["A"]["s"] - 1) * 100 for x in meas]) for m in MODES if m != "A"},
           "B_minus_A": d("B", "A"), "Eb_minus_A": d("Eb", "A"), "Ea_minus_A": d("Ea", "A"),
           "Eb_minus_B": d("Eb", "B"), "Ea_minus_B": d("Ea", "B"), "Eb_minus_Ea": d("Eb", "Ea")}
    for k in ("B_minus_A", "Eb_minus_A", "Ea_minus_A", "Eb_minus_B", "Ea_minus_B", "Eb_minus_Ea"):
        log(f"  {k}: {out[k]['median']:+.2f} ms (CI90 {out[k]['median_ci90'][0]:+.2f}..{out[k]['median_ci90'][1]:+.2f})")
    return out


def user_argv(ctx: Ctx, cmd: str) -> list[str]:
    return ["runuser", "-u", ctx.user, "--", "env", "-i", *[f"{k}={v}" for k, v in ctx.env().items()], "bash", "-c", cmd]


def latency(wl: GapWorkload, ctx: Ctx, log: Log, agents: dict, samples: int) -> dict:
    """Seconds from a marker write's kernel timestamp to its row being queryable."""
    db = wl.ws / ".whyfs" / "whyfs.db"
    out = {}
    for tag, ag in agents.items():
        ag.cmd("mode full")
    rows = {tag: {"idle": [], "load": []} for tag in agents}
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    for i in range(samples):
        for loaded in (False, True):
            for tag, ag in (list(agents.items()) if i % 2 == 0 else list(reversed(agents.items()))):
                ag.cmd("attach")
                wl.prep()
                bg = None
                if loaded:
                    bg = subprocess.Popen(user_argv(ctx, CMD), cwd=wl.ws, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(0.05)  # mid-build
                name = f"lat-{tag}-{'load' if loaded else 'idle'}-{i:03d}.txt"
                path = str(wl.ws / name)
                subprocess.run(user_argv(ctx, f"echo x > {name}"), cwd=wl.ws, check=True)
                seen = None
                deadline = time.time() + 5
                while time.time() < deadline:
                    r = con.execute("SELECT MIN(ts_ns) FROM events WHERE path=? AND is_write=1", (path,)).fetchone()
                    if r and r[0]:
                        seen = (time.time_ns() - r[0]) / 1e6
                        break
                    time.sleep(0.002)
                if bg:
                    bg.wait()
                ag.cmd("detach")
                time.sleep(0.3)
                rows[tag]["load" if loaded else "idle"].append(seen)
    con.close()
    for tag, v in rows.items():
        out[tag] = {}
        for k, xs in v.items():
            got = sorted(x for x in xs if x is not None)
            out[tag][k] = {"samples_ms": xs, "missing": sum(1 for x in xs if x is None),
                           "median_ms": got[len(got) // 2] if got else None,
                           "p95_ms": got[min(len(got) - 1, int(round(0.95 * (len(got) - 1))))] if got else None,
                           "max_ms": got[-1] if got else None}
        log(f"  latency {tag}: idle median {out[tag]['idle']['median_ms']:.1f} ms p95 {out[tag]['idle']['p95_ms']:.1f} "
            f"max {out[tag]['idle']['max_ms']:.1f}; under load median {out[tag]['load']['median_ms']:.1f} "
            f"p95 {out[tag]['load']['p95_ms']:.1f} max {out[tag]['load']['max_ms']:.1f}; missing "
            f"{out[tag]['idle']['missing']}/{out[tag]['load']['missing']}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--before-src", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-handoff-ws")
    ap.add_argument("--rounds", type=int, default=40)
    ap.add_argument("--latency-samples", type=int, default=20)
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
    before_head = subprocess.run(["git", "-c", f"safe.directory={Path(a.before_src).parent}", "-C", str(Path(a.before_src).parent),
                                  "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    params = dict(vars(a), before_tree_head=before_head, workload_cmd=CMD,
                  timing="shell (date +%s%N) inside the workload; never a collecting process")
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out), "environment": environment()}
    log(f"after tree {res['git']['head'][:7]} (dirty {len(res['git']['dirty_files'])}); before tree {before_head[:7]}")
    wl = GapWorkload(ctx, base, log)
    before = Agent(wl.ws, "handoff-before", log, src=a.before_src)
    after = Agent(wl.ws, "handoff-after", log, src=str(REPO / "src"))
    res["agents"] = {"before": {"src": before.src, "batched": before.batched}, "after": {"src": after.src, "batched": after.batched}}
    if before.batched or not after.batched:
        raise SystemExit("before must be per-record and after must be batched")
    try:
        wl.prep()
        wl.run_measured()
        log("rotated rounds A / B / Eb / Ea")
        res["rounds"] = rounds(wl, log, a.rounds, before, after)
        log("visibility latency")
        res["latency"] = latency(wl, ctx, log, {"before": before, "after": after}, a.latency_samples)
    finally:
        res["before_final"] = before.quit()
        res["after_final"] = after.quit()
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "handoff.json").write_text(json.dumps(res, indent=1, default=str))
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
