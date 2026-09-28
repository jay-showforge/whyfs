"""Where `whyfs label` spends its time, per SQL statement, as a file's history grows.

Runs the real server-side label (whyfs.label.explain_file, the function the API, the window and
the CLI all use) against a store, timing every SQL statement including its fetches, and counting
SQLite virtual-machine instructions per statement (a proxy for rows visited: the progress handler
fires every 100 instructions).  The text rendering is timed separately.

  python scripts/profile_label.py --db STORE.db FILE [FILE ...] [--runs 5] [--out JSON]
  python scripts/profile_label.py --snapshot LIVE.db --db COPY.db ...   (copies a live store first)
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

STATS: dict = {}
VM = [0]


def _norm(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip()[:160]


class TimedCursor(sqlite3.Cursor):
    def _t(self, fn, *a):
        t0 = time.perf_counter(); v0 = VM[0]
        try:
            return fn(*a)
        finally:
            s = STATS.setdefault(self._sql, {"n": 0, "ms": 0.0, "vm": 0})
            s["ms"] += (time.perf_counter() - t0) * 1000
            s["vm"] += (VM[0] - v0) * 100

    def execute(self, sql, params=()):
        self._sql = _norm(sql)
        STATS.setdefault(self._sql, {"n": 0, "ms": 0.0, "vm": 0})["n"] += 1
        return self._t(super().execute, sql, params)

    def fetchone(self):
        return self._t(super().fetchone)

    def fetchall(self):
        return self._t(super().fetchall)


class TimedConnection(sqlite3.Connection):
    def cursor(self, factory=TimedCursor):
        return super().cursor(factory)

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)


def open_db(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, factory=TimedConnection)
    con.row_factory = sqlite3.Row

    def tick():
        VM[0] += 1
        return 0
    con.set_progress_handler(tick, 100)
    return con


def profile(con, path: str, runs: int) -> dict:
    from whyfs.label import explain_file, render_label
    explain_file(con, path)  # warm the page cache
    totals, renders = [], []
    STATS.clear()
    for _ in range(runs):
        t0 = time.perf_counter()
        lb = explain_file(con, path)
        totals.append((time.perf_counter() - t0) * 1000)
        t1 = time.perf_counter()
        render_label(lb)
        renders.append((time.perf_counter() - t1) * 1000)
    per = sorted(({"sql": k, "calls": v["n"] // runs, "ms": round(v["ms"] / runs, 2), "vm_ops": v["vm"] // runs}
                  for k, v in STATS.items()), key=lambda x: -x["ms"])
    gens = con.execute("SELECT COUNT(*) FROM events WHERE path=? AND is_write=1", (lb["path"],)).fetchone()[0]
    return {"path": path, "status": lb.get("status"), "write_events_at_path": gens,
            "label_ms_median": round(statistics.median(totals), 2), "render_ms_median": round(statistics.median(renders), 2),
            "sql_statements_per_label": sum(p["calls"] for p in per), "sql_ms": round(sum(p["ms"] for p in per), 2),
            "statements": per}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--db", required=True)
    ap.add_argument("--snapshot", help="copy this live store to --db first (SQLite online backup)")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.snapshot:
        t0 = time.perf_counter()
        src = sqlite3.connect(f"file:{a.snapshot}?mode=ro", uri=True)
        dst = sqlite3.connect(a.db)
        src.backup(dst)
        dst.close(); src.close()
        print(f"snapshot {a.snapshot} -> {a.db} in {time.perf_counter() - t0:.1f} s", flush=True)
    con = open_db(a.db)
    res = [profile(con, f, a.runs) for f in a.files]
    for r in res:
        print(f"\n{r['path']}: {r['write_events_at_path']} writes  label {r['label_ms_median']} ms  render {r['render_ms_median']} ms  "
              f"{r['sql_statements_per_label']} statements, {r['sql_ms']} ms in SQL")
        for p in r["statements"][:8]:
            print(f"   {p['ms']:8.2f} ms  {p['calls']:3d}x  vm {p['vm_ops']:>10d}  {p['sql'][:110]}")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
