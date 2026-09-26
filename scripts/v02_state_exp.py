#!/usr/bin/env python3
"""Four-state experiment: database state vs daemon runtime state (diagnostic only).

Separates what the daemon-gap experiment could not: its fresh-daemon phase (G)
ran last, against the largest database, so lifecycle and DB size were confounded.

  S1 fresh daemon per measured build (graduation-harness pattern) + EMPTY DB
  S2 fresh daemon per measured build                               + PRE-POPULATED DB
  S3 persistent daemon                                             + DB empty at start
  S4 persistent daemon                                             + PRE-POPULATED DB

S1/S2 are interleaved with baseline runs in rotated rounds (no time confound).
S3/S4 are persistent blocks in ABBA order with baseline blocks between them.
Two workspaces with equal-length paths; the pre-populated DB is a copy of an existing
whyfs.db made while no daemon runs.  Timing is shell-internal (never a collector's
process).  Production code is used unmodified via `whyfs daemon start/stop`.

Usage: sudo python3 scripts/v02_state_exp.py --user USER --out DIR --big-db PATH
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
from v02_hotpath_profile import Log, summary, git_info  # noqa: E402
from v02_daemon_gap import GapWorkload, RealDaemon, delta  # noqa: E402
from whyfs.daemon import ensure_kernel_headers  # noqa: E402


def db_files(ws: Path) -> list[Path]:
    d = ws / ".whyfs"
    return [d / "whyfs.db", d / "whyfs.db-wal", d / "whyfs.db-shm", d / "whyfs.db-journal"]


def db_bytes(ws: Path) -> int:
    return sum(p.stat().st_size for p in db_files(ws) if p.exists())


def table_counts(ws: Path) -> dict:
    try:
        con = sqlite3.connect(f"file:{ws}/.whyfs/whyfs.db?mode=ro", uri=True, timeout=5)
        out = {t: con.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("events", "processes", "runs", "collector_stats")}
        con.close()
        return out
    except sqlite3.Error:
        return {}


def reset_db(ws: Path, big_db: Path | None) -> None:
    """Only called while no daemon runs."""
    for p in db_files(ws):
        if p.exists():
            p.unlink()
    if big_db:
        shutil.copy2(big_db, ws / ".whyfs" / "whyfs.db")
        st = os.stat(ws)
        os.chown(ws / ".whyfs" / "whyfs.db", st.st_uid, st.st_gid)


def fresh_session(wl: GapWorkload, ctx: Ctx) -> dict:
    """Exactly the graduation harness's monitored row, with per-build daemon metrics."""
    rec = {}
    wl.prep()
    d = RealDaemon(ctx, wl.ws)
    t0 = time.time()
    d.start()
    time.sleep(0.3)
    rec["start_s"] = time.time() - t0
    rec["db_bytes_at_start"] = db_bytes(wl.ws)
    m0 = d.metrics()
    rec["first"] = wl.run_measured()
    wl.prep()
    time.sleep(0.0)
    m1 = d.metrics()
    rec["on"] = wl.run_measured()
    time.sleep(0.3)
    m2 = d.metrics()
    rec["first_daemon"] = delta(m0, m1)   # first build + prep
    rec["on_daemon"] = delta(m1, m2)      # measured build (+0.3 s settle)
    rec["db_bytes_before_stop"] = db_bytes(wl.ws)
    d.stop()
    rec["daemon_final"] = d.final_stats()
    rec["db_bytes_after_stop"] = db_bytes(wl.ws)
    return rec


def persistent_block(wl: GapWorkload, ctx: Ctx, log: Log, big_db: Path | None, warm: int, runs: int, tag: str) -> dict:
    reset_db(wl.ws, big_db)
    d = RealDaemon(ctx, wl.ws)
    d.start()
    time.sleep(0.3)
    series = []
    m0 = d.metrics()
    try:
        for i in range(warm + runs):
            wl.prep()
            b0 = db_bytes(wl.ws)
            r = wl.run_measured()
            time.sleep(0.4)
            m1 = d.metrics()
            r["daemon"] = delta(m0, m1)
            r["db_growth_bytes"] = db_bytes(wl.ws) - b0
            r["warmup"] = i < warm
            r["index"] = i + 1
            series.append(r)
            m0 = m1
    finally:
        d.stop()
    log(f"  {tag}: " + " ".join(f"{x['s']*1000:.1f}" for x in series))
    return {"series": series, "final": d.final_stats(), "tables_after": table_counts(wl.ws)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--big-db", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-state-ws")
    ap.add_argument("--rounds", type=int, default=16)
    ap.add_argument("--warm", type=int, default=3)
    ap.add_argument("--block-runs", type=int, default=12)
    ap.add_argument("--base-runs", type=int, default=6)
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
    big_src = Path(a.big_db)
    big = out / "prepopulated.db.src"  # private copy so the source can't change underneath
    shutil.copy2(big_src, big)
    con = sqlite3.connect(f"file:{big}?mode=ro", uri=True)
    big_info = {"bytes": big.stat().st_size, "events": con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "processes": con.execute("SELECT COUNT(*) FROM processes").fetchone()[0]}
    con.close()
    params = dict(vars(a), big_db_info=big_info)
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out), "environment": environment()}
    log(f"git HEAD {res['git']['head']}; pre-populated DB {big_info}")
    wl_e = GapWorkload(ctx, base / "ws_e", log)  # equal-length workspace paths
    wl_b = GapWorkload(ctx, base / "ws_b", log)
    try:
        # ---- fresh-daemon states, interleaved: base / S1 (empty DB) / S2 (big DB)
        log("fresh-daemon states S1 (empty DB) / S2 (pre-populated DB), rotated rounds")
        orders = [["base", "S1", "S2"], ["S1", "S2", "base"], ["S2", "base", "S1"],
                  ["base", "S2", "S1"], ["S2", "S1", "base"], ["S1", "base", "S2"]]
        rows = []
        for r in range(a.rounds + 1):
            rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
            for m in orders[r % len(orders)]:
                if m == "base":
                    wl_e.prep()
                    rec["base"] = wl_e.run_measured()
                elif m == "S1":
                    reset_db(wl_e.ws, None)
                    rec["S1"] = fresh_session(wl_e, ctx)
                else:
                    reset_db(wl_b.ws, big)
                    rec["S2"] = fresh_session(wl_b, ctx)
            rows.append(rec)
            log(f"  round {r}: base {rec['base']['s']*1000:.1f}  S1 on {rec['S1']['on']['s']*1000:.1f}  S2 on {rec['S2']['on']['s']*1000:.1f}")
        meas = [x for x in rows if not x["warmup"]]
        res["fresh"] = {
            "rows": rows,
            "S1_overhead_pct": summary([(x["S1"]["on"]["s"] / x["base"]["s"] - 1) * 100 for x in meas]),
            "S2_overhead_pct": summary([(x["S2"]["on"]["s"] / x["base"]["s"] - 1) * 100 for x in meas]),
            "S1_delta_ms": summary([(x["S1"]["on"]["s"] - x["base"]["s"]) * 1000 for x in meas]),
            "S2_delta_ms": summary([(x["S2"]["on"]["s"] - x["base"]["s"]) * 1000 for x in meas]),
            "S2_minus_S1_ms": summary([(x["S2"]["on"]["s"] - x["S1"]["on"]["s"]) * 1000 for x in meas]),
            "S1_first_overhead_pct": summary([(x["S1"]["first"]["s"] / x["base"]["s"] - 1) * 100 for x in meas]),
            "S2_first_overhead_pct": summary([(x["S2"]["first"]["s"] / x["base"]["s"] - 1) * 100 for x in meas]),
        }
        f = res["fresh"]
        log(f"  S1 {f['S1_overhead_pct']['median']:.2f}%  S2 {f['S2_overhead_pct']['median']:.2f}%  "
            f"S2-S1 {f['S2_minus_S1_ms']['median']:+.2f} ms (CI90 {f['S2_minus_S1_ms']['median_ci90'][0]:+.2f}..{f['S2_minus_S1_ms']['median_ci90'][1]:+.2f})")

        # ---- persistent states, ABBA with baseline blocks
        log("persistent-daemon states S3 (empty DB) / S4 (pre-populated DB), ABBA blocks")
        blocks = []
        for tag in ("S3", "S4", "S4", "S3"):
            basel = []
            for _ in range(a.base_runs):
                wl_e.prep()
                basel.append(wl_e.run_measured())
            blk = persistent_block(wl_e if tag == "S3" else wl_b, ctx, log, None if tag == "S3" else big,
                                   a.warm, a.block_runs, tag)
            blk["tag"] = tag
            blk["baseline_before"] = basel
            blocks.append(blk)
        tail = []
        for _ in range(a.base_runs):
            wl_e.prep()
            tail.append(wl_e.run_measured())
        res["persistent"] = {"blocks": blocks, "baseline_tail": tail}
        # per block overhead vs the mean of its surrounding baseline blocks
        bases = [b["baseline_before"] for b in blocks] + [tail]
        for i, b in enumerate(blocks):
            ref = statistics.median([x["s"] for x in bases[i] + bases[i + 1]])
            b["baseline_ref_s"] = ref
            b["overhead_pct"] = [(x["s"] / ref - 1) * 100 for x in b["series"] if not x["warmup"]]
            b["median_overhead_pct"] = statistics.median(b["overhead_pct"])
            b["median_delta_ms"] = statistics.median((x["s"] - ref) * 1000 for x in b["series"] if not x["warmup"])
            log(f"  block {b['tag']}: median {b['median_overhead_pct']:+.2f}% ({b['median_delta_ms']:+.2f} ms)")
    finally:
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "state.json").write_text(json.dumps(res, indent=1, default=str))
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
