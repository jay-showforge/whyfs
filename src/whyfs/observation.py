"""Observation integrity: when whyfs was recording, and what it may have missed.

The guarantee (docs/MACHINE_MODE.md): if the observer was active and healthy, a label reflects
what it observed; if the observer was unavailable or evidence was lost, the label says so.

* Every machine collector run records a heartbeat (``collector_stats.heartbeat_ns``) every
  HEARTBEAT_EVERY_S seconds.  A run that ends cleanly records its end; a run that crashed (killed,
  power loss) never does, so the next run closes it at its last heartbeat and marks it unclean
  (``collector_stats.unclean_end = 1``).  The time between that and the next start is a gap.
* A label's ``observation`` separates the file's **origin** (was whyfs recording, without loss,
  when the file was created?) from **later gaps** (downtime or loss since then, which can hide
  later history and dependents).  A file that appeared during a gap has no observed origin and
  is never given a creator; when its own timestamps fall in a recorded gap, the label says so.
"""
from __future__ import annotations

import datetime as _dt
import os
import sqlite3
import time

HEARTBEAT_KEY = "heartbeat_ns"
UNCLEAN_KEY = "unclean_end"
HEARTBEAT_EVERY_S = 10
HEARTBEAT_STALE_NS = 45 * 10**9       # a current run whose heartbeat is older is not recording now
GAP_MIN_NS = 5 * 10**9                # shorter pauses are not reported
WEAK_RETENTION_DAYS = 30              # pure reads are kept this long by default (retention.py)
LOSS_KEYS = ("kernel_drops", "queue_drops", "lost_file", "lost_sys", "buffers_lost_file", "buffers_lost_sys",
             "late_records", "user_unresolved")


def iso(ns: int | None) -> str | None:
    if not ns:
        return None
    return _dt.datetime.fromtimestamp(ns / 1e9).astimezone().isoformat(timespec="seconds")


def heartbeat(con: sqlite3.Connection, run_id: str) -> None:
    con.execute("INSERT INTO collector_stats(run_id,key,value) VALUES(?,?,?) "
                "ON CONFLICT(run_id,key) DO UPDATE SET value=excluded.value", (run_id, HEARTBEAT_KEY, time.time_ns()))
    con.commit()


def close_unclean_runs(con: sqlite3.Connection, keep: str | None = None) -> list[str]:
    """Runs that never recorded an end (the observer crashed or the machine lost power) end at
    their last heartbeat, else their last recorded event, else their start; marked unclean."""
    closed = []
    for r in con.execute("SELECT id, started_ns FROM runs WHERE ended_ns IS NULL AND id IS NOT ?", (keep,)).fetchall():
        hb = con.execute("SELECT value FROM collector_stats WHERE run_id=? AND key=?", (r[0], HEARTBEAT_KEY)).fetchone()
        last = con.execute("SELECT MAX(ts_ns) FROM events WHERE run_id=?", (r[0],)).fetchone()
        end = max(x for x in (hb[0] if hb else None, last[0] if last else None, r[1]) if x is not None)
        con.execute("UPDATE runs SET ended_ns=?, exit_code=COALESCE(exit_code, -1) WHERE id=?", (end, r[0]))
        con.execute("INSERT INTO collector_stats(run_id,key,value) VALUES(?,?,1) "
                    "ON CONFLICT(run_id,key) DO UPDATE SET value=1", (r[0], UNCLEAN_KEY))
        closed.append(r[0])
    con.commit()
    return closed


def intervals(con: sqlite3.Connection, now: int | None = None) -> list[dict]:
    """Recorded intervals, oldest first: {run_id, start, end, unclean, current}."""
    now = now or time.time_ns()
    rows = con.execute("SELECT id, started_ns, ended_ns FROM runs ORDER BY started_ns").fetchall()
    stats: dict[str, dict] = {}
    for rid, key, value in con.execute("SELECT run_id, key, value FROM collector_stats WHERE key IN (?,?)",
                                       (HEARTBEAT_KEY, UNCLEAN_KEY)):
        stats.setdefault(rid, {})[key] = value
    out = []
    for i, (rid, start, end) in enumerate(rows):
        st = stats.get(rid, {})
        current = end is None
        if end is None:
            hb = st.get(HEARTBEAT_KEY)
            later = rows[i + 1][1] if i + 1 < len(rows) else None
            if later is not None:           # superseded without an end: crashed, not yet closed
                end = max(x for x in (hb, start) if x is not None)
            elif hb is not None and now - hb > HEARTBEAT_STALE_NS:
                end = hb                    # the current run stopped beating: not recording now
            else:
                end = now
        out.append({"run_id": rid, "start": start, "end": end, "current": current and end == now,
                    "unclean": bool(st.get(UNCLEAN_KEY)) or (current and end != now)})
    return out


def gaps(ivs: list[dict], since: int, now: int | None = None) -> list[dict]:
    """Uncovered spans after ``since`` (longer than GAP_MIN_NS): {from, to (None = now), after_crash}."""
    now = now or time.time_ns()
    out, covered, prev_unclean = [], since, False
    for iv in ivs:
        if iv["end"] < since:
            prev_unclean = iv["unclean"]
            continue
        if iv["start"] - covered > GAP_MIN_NS:
            out.append({"from": covered, "to": iv["start"], "after_crash": prev_unclean})
        covered = max(covered, iv["end"])
        prev_unclean = iv["unclean"]
    if now - covered > GAP_MIN_NS:
        out.append({"from": covered, "to": None, "after_crash": prev_unclean})
    return out


def _loss(con: sqlite3.Connection, run_ids: list[str]) -> int:
    lost = 0
    for i in range(0, len(run_ids), 500):
        chunk = run_ids[i:i + 500]
        lost += con.execute(f"SELECT COALESCE(SUM(value),0) FROM collector_stats WHERE run_id IN "
                            f"({','.join('?' * len(chunk))}) AND key IN ({','.join('?' * len(LOSS_KEYS))})",
                            [*chunk, *LOSS_KEYS]).fetchone()[0]
    return lost


def _gap_text(g: dict) -> str:
    why = " (the observer stopped unexpectedly)" if g["after_crash"] else ""
    if g["to"] is None:
        return f"whyfs is not recording now (last recorded {iso(g['from'])}){why}"
    return f"whyfs was not recording from {iso(g['from'])} to {iso(g['to'])}{why}"


def file_times(path: str) -> tuple[int | None, int | None]:
    """(birth, modified) of the file now at ``path``, in ns (birth where the OS reports it)."""
    try:
        st = os.stat(path)
    except OSError:
        return None, None
    birth = getattr(st, "st_birthtime_ns", None)
    if birth is None and os.name == "nt":
        birth = st.st_ctime_ns  # creation time on Windows before Python 3.12
    return birth, st.st_mtime_ns


def for_label(con: sqlite3.Connection, created_ns: int | None, *, path: str | None = None,
              chain: list[dict] | None = None, identity: str | None = None, status: str = "labelled") -> dict:
    """The label's ``observation`` section."""
    now = time.time_ns()
    ivs = intervals(con, now)
    first = ivs[0]["start"] if ivs else None
    origin: list[str] = []
    later: list[str] = []
    in_gap = None
    if status != "labelled":
        origin.append("this file's origin was not observed")
        if path:  # when did the file now at this path appear, and was whyfs recording then?
            birth, mtime = file_times(path)
            for label, t in (("created", birth), ("last modified", mtime)):
                if not t:
                    continue
                if first is not None and t < first:
                    in_gap = {"time": iso(t), "which": label, "gap_from": None, "gap_to": iso(first)}
                    origin.append(f"the file was {label} at {iso(t)}, before whyfs started recording ({iso(first)})")
                    break
                for g in gaps(ivs, first or t, now):
                    if g["from"] <= t <= (g["to"] or now):
                        in_gap = {"time": iso(t), "which": label, "gap_from": iso(g["from"]), "gap_to": iso(g["to"]),
                                  "after_crash": g["after_crash"]}
                        origin.append(f"the file was {label} at {iso(t)}, while whyfs was not recording "
                                      f"({_gap_text(g).split('whyfs ', 1)[1]})")
                        break
                if in_gap:
                    break
    if status == "labelled" and created_ns:
        runs_then = [iv for iv in ivs if iv["start"] <= created_ns <= iv["end"]]
        if not runs_then:
            origin.append("whyfs has no recording session covering the file's creation time")
        else:
            lost = _loss(con, [iv["run_id"] for iv in runs_then])
            if lost:
                origin.append(f"the collector reported {lost} lost or unattributed events in the recording session "
                              "in which this file was created")
        for g in gaps(ivs, created_ns, now):
            later.append(_gap_text(g))
        after = [iv["run_id"] for iv in ivs if iv["end"] >= created_ns and iv not in runs_then]
        lost_after = _loss(con, after) if after else 0
        if lost_after:
            later.append(f"the collector reported {lost_after} lost or unattributed events since then")
        if now - created_ns > WEAK_RETENTION_DAYS * 86400e9:
            later.append(f"reads older than {WEAK_RETENTION_DAYS} days are pruned: older uses of this file are no longer known")
    notes: list[str] = []
    if chain and chain[0].get("exe") is None:
        # Informational: every process tree reaches ancestors that exited before whyfs started
        # (boot and logon processes).  The writer, its inputs and the file itself were observed.
        notes.append("the process chain begins where whyfs started observing: earlier ancestors had already exited")
    if identity == "unknown":
        origin.append("the file's identity could not be compared with the recorded one")
    return {"complete": not origin, "gaps": origin, "later_gaps": later, "file_time_in_gap": in_gap,
            "notes": notes, "observing_since": iso(first) if first else None}


def recording_gaps(con: sqlite3.Connection, limit: int = 20) -> list[dict]:
    """Recent gaps in recording, newest first (for `status`)."""
    now = time.time_ns()
    ivs = intervals(con, now)
    if not ivs:
        return []
    out = [{"from": iso(g["from"]), "to": iso(g["to"]), "seconds": round(((g["to"] or now) - g["from"]) / 1e9, 1),
            "after_crash": g["after_crash"]} for g in gaps(ivs, ivs[0]["start"], now)]
    return out[::-1][:limit]
