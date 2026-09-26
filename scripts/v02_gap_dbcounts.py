#!/usr/bin/env python3
"""Per-run, per-phase work counts from a daemon-gap experiment's whyfs.db (read-only).

    python3 scripts/v02_gap_dbcounts.py WHYFS_DB GAP_RESULT_DIR OUT.json

Runs are labelled from their start order, which v02_daemon_gap.py fixes:
gap-agent (phases R/S), gap-inproc (phase C), then daemon runs F1, F2, G x (pairs+warmups),
K x (pairs+warmups).  Counts are what the production store actually persisted.
"""
from __future__ import annotations

import json
import sqlite3
import statistics as st
import sys
from pathlib import Path

REC_BYTES = {"open": 592, "io": 80, "exec": 1104, "unlink": 592, "rename": 1104}  # kernel record sizes (hdr 80 + paths)


def main() -> int:
    db, gapdir, outp = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    gap = json.loads((gapdir / "gap.json").read_text())
    n_g = len(gap["G"]["rows"])
    n_k = len(gap["K"]["rows"])
    f_runs = len(gap["F1"]["series"])
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    runs = con.execute("SELECT id, started_ns, ended_ns FROM runs ORDER BY started_ns").fetchall()
    daemon = [r for r in runs if r[0].startswith("daemon-")]
    labels = {}
    for r in runs:
        if r[0] == "gap-agent":
            labels[r[0]] = "agent(R,S)"
        elif r[0] == "gap-inproc":
            labels[r[0]] = "inproc(C)"
    order = ["F1", "F2"] + ["G"] * n_g + ["K"] * n_k
    if len(daemon) != len(order):
        raise SystemExit(f"expected {len(order)} daemon runs, found {len(daemon)}")
    for r, lab in zip(daemon, order):
        labels[r[0]] = lab
    per_run = []
    cum = 0
    for rid, s, e in runs:
        kinds = dict(con.execute("SELECT kind, COUNT(*) FROM events WHERE run_id=? GROUP BY kind", (rid,)).fetchall())
        ev = sum(kinds.values())
        pr = con.execute("SELECT COUNT(*) FROM processes WHERE run_id=?", (rid,)).fetchone()[0]
        stats = dict(con.execute("SELECT key, value FROM collector_stats WHERE run_id=?", (rid,)).fetchall())
        per_run.append({"run_id": rid, "phase": labels.get(rid, "?"), "db_events_before": cum, "events": ev, "by_kind": kinds,
                        "process_rows": pr, "stats": stats, "duration_s": (e - s) / 1e9 if e else None})
        cum += ev
    con.close()

    def agg(phase, builds_per_unit):
        rows = [r for r in per_run if r["phase"] == phase]
        if not rows:
            return None
        kinds = sorted({k for r in rows for k in r["by_kind"]})
        return {"units": len(rows), "builds_per_unit": builds_per_unit,
                "db_events_before_range": [rows[0]["db_events_before"], rows[-1]["db_events_before"]],
                "events_per_unit": st.median(r["events"] for r in rows),
                "by_kind_per_unit": {k: st.median(r["by_kind"].get(k, 0) for r in rows) for k in kinds},
                "process_rows_per_unit": st.median(r["process_rows"] for r in rows),
                "received_per_unit": st.median(r["stats"].get("received", 0) for r in rows),
                "submitted_per_unit": st.median(r["stats"].get("submitted", 0) for r in rows),
                "filtered_per_unit": st.median(r["stats"].get("filtered", 0) for r in rows),
                "writer_batches_per_unit": st.median(r["stats"].get("writer_batches", 0) for r in rows),
                "proc_fallbacks_per_unit": st.median(r["stats"].get("proc_fallbacks", 0) for r in rows),
                "kernel_drops": sum(r["stats"].get("kernel_drops", 0) for r in rows),
                "queue_drops": sum(r["stats"].get("queue_drops", 0) for r in rows),
                "stored_record_bytes_per_unit": st.median(sum(REC_BYTES.get(k, 80) * v for k, v in r["by_kind"].items()) for r in rows)}

    # One F unit = the whole 25-run series; one G unit = first build + prep + measured build;
    # one K unit = first build only (daemon stopped before prep and the measured build).
    phases = {"F1": agg("F1", f_runs), "F2": agg("F2", f_runs), "G": agg("G", 2), "K": agg("K", 1)}
    # Solve per-build and per-prep work from F (build + prep per run) and G (2 builds + 1 prep).
    f, g = phases["F1"], phases["G"]
    solve = {}
    for key in ("received_per_unit", "submitted_per_unit", "events_per_unit", "process_rows_per_unit"):
        fr = f[key] / f_runs            # = build + prep
        build = g[key] - fr             # 2*build + prep - (build + prep)
        solve[key.replace("_per_unit", "")] = {"persistent_per_run(build+prep)": fr, "fresh_session(2 builds+prep)": g[key],
                                                "implied_build": build, "implied_prep": fr - build,
                                                "fresh_first_build_only(K)": phases["K"][key]}
    out = {"db": str(db), "runs": per_run, "phases": phases, "per_build_solution": solve,
           "note": "F units are 25-run series; G units are sessions of first build + prep + measured build; "
                   "K units are sessions with only a first build. Stored record bytes use kernel record sizes."}
    outp.write_text(json.dumps(out, indent=2))
    print(json.dumps({"phases": phases, "per_build_solution": solve}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
