"""Retention of the machine store (docs/MACHINE_MODE.md "Retention").

strong: writes, moves, deletes, the creating process chains, the inputs of processes that
        wrote files, agent sessions                         -> ``retention_days``
weak:   reads by processes that never wrote an in-scope file (pure consumers)
                                                            -> ``weak_retention_days``
cap:    past ``max_db_mb``, weak records go oldest first, then strong records oldest first.
Processes with no remaining evidence and not an ancestor of a process with evidence go too.
"""
from __future__ import annotations

import sqlite3
import time

DAY = 86_400 * 1_000_000_000
DEFAULTS = {"retention_days": 365, "weak_retention_days": 30, "max_db_mb": 2048}

_PURE_READ = ("kind='io' AND is_write=0 AND NOT EXISTS (SELECT 1 FROM events w WHERE w.run_id=events.run_id "
              "AND w.pid=events.pid AND w.is_write=1)")


def db_bytes(con: sqlite3.Connection) -> int:
    pc = con.execute("PRAGMA page_count").fetchone()[0]
    fl = con.execute("PRAGMA freelist_count").fetchone()[0]
    ps = con.execute("PRAGMA page_size").fetchone()[0]
    return (pc - fl) * ps


def _orphans(con: sqlite3.Connection, before_ns: int) -> int:
    cur = con.execute(
        """WITH RECURSIVE keep(run_id, pid) AS (
               SELECT DISTINCT run_id, pid FROM events
               UNION SELECT p.run_id, p.parent_key FROM processes p JOIN keep k ON p.run_id=k.run_id AND p.pid=k.pid
               WHERE p.parent_key IS NOT NULL)
           DELETE FROM processes WHERE first_seen_ns < ? AND (run_id, pid) NOT IN (SELECT run_id, pid FROM keep)""",
        (before_ns,))
    return cur.rowcount


def prune(con: sqlite3.Connection, policy: dict | None = None, now_ns: int | None = None) -> dict:
    pol = {**DEFAULTS, **(policy or {})}
    now = now_ns or time.time_ns()
    weak_cut = now - int(pol["weak_retention_days"] * DAY)
    strong_cut = now - int(pol["retention_days"] * DAY)
    out = {"weak_events": 0, "strong_events": 0, "exec_events": 0, "processes": 0, "sessions": 0, "cap_rounds": 0}
    out["weak_events"] = con.execute(f"DELETE FROM events WHERE ts_ns < ? AND {_PURE_READ}", (weak_cut,)).rowcount
    out["strong_events"] = con.execute("DELETE FROM events WHERE ts_ns < ?", (strong_cut,)).rowcount
    # exec boundaries of processes whose other evidence is gone
    out["exec_events"] = con.execute(
        "DELETE FROM events WHERE kind='exec' AND ts_ns < ? AND NOT EXISTS (SELECT 1 FROM events o WHERE "
        "o.run_id=events.run_id AND o.pid=events.pid AND o.kind!='exec')", (weak_cut,)).rowcount
    out["sessions"] = con.execute("DELETE FROM agent_sessions WHERE ended_ns IS NOT NULL AND ended_ns < ?",
                                  (strong_cut,)).rowcount
    con.commit()
    cap = int(pol["max_db_mb"]) * 1024 * 1024
    while cap and db_bytes(con) > cap and out["cap_rounds"] < 50:
        out["cap_rounds"] += 1
        n = con.execute(f"SELECT COUNT(*) FROM events WHERE {_PURE_READ}").fetchone()[0]
        if n:
            out["weak_events"] += con.execute(
                f"DELETE FROM events WHERE id IN (SELECT id FROM events WHERE {_PURE_READ} ORDER BY ts_ns LIMIT ?)",
                (max(1000, n // 10),)).rowcount
        else:
            total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if not total:
                break
            out["strong_events"] += con.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts_ns LIMIT ?)", (max(1000, total // 10),)
            ).rowcount
        con.commit()
    out["processes"] = _orphans(con, now if out["cap_rounds"] else weak_cut)
    con.commit()
    con.execute("PRAGMA incremental_vacuum")
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass
    con.commit()
    out["db_bytes"] = db_bytes(con)
    return out


def forget(con: sqlite3.Connection, *, path: str | None = None, user: str | None = None, everything: bool = False) -> dict:
    """Delete records on request.  ``user``: restricted to that user's processes."""
    from .store import normalize
    who = "" if user is None else " AND (run_id, pid) IN (SELECT run_id, pid FROM main.processes WHERE user=?)"
    args: tuple = () if user is None else (user,)
    if path:
        import os
        p = normalize(path)
        esc = p.rstrip(os.sep).replace("!", "!!").replace("%", "!%").replace("_", "!_")
        n = con.execute(f"DELETE FROM main.events WHERE (path=? OR path2=? OR path LIKE ? ESCAPE '!'){who}",
                        (p, p, esc + os.sep + "%") + args).rowcount
    elif everything:
        n = con.execute(f"DELETE FROM main.events WHERE 1=1{who}", args).rowcount
        s = "DELETE FROM main.agent_sessions" + ("" if user is None else " WHERE user=?")
        con.execute(s, args)
    else:
        raise ValueError("forget needs a path or everything=True")
    removed = _orphans(con, time.time_ns() + DAY)
    con.commit()
    con.execute("PRAGMA incremental_vacuum")
    con.commit()
    return {"events": n, "processes": removed}
