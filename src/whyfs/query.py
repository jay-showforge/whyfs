from __future__ import annotations

import os
import sqlite3
from .store import normalize

# Human-view noise only. Raw evidence remains in SQLite and is available with
# --all/JSON. We never delete an observed edge because a heuristic dislikes it.
NOISE_PREFIXES = (
    "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/", "/usr/share/",
    "/etc/ld.so", "/proc/", "/sys/", "/dev/", "/run/ld-so-cache/",
)
NOISE_BASENAMES = {
    ".DS_Store", "ld.so.cache",
}


def _is_noise(path: str, workspace: str) -> bool:
    if path.startswith(workspace.rstrip(os.sep) + os.sep) or path == workspace:
        return False
    if os.path.basename(path) in NOISE_BASENAMES:
        return True
    return path.startswith(NOISE_PREFIXES)


def last_writer(con: sqlite3.Connection, path: str):
    p = normalize(path)
    return con.execute(
        """
      SELECT e.*, r.command AS run_command, r.cwd AS run_cwd, r.workspace, r.collector,
             pr.exe, pr.cwd AS process_cwd, pr.command AS process_command, pr.source AS process_source
      FROM events e JOIN runs r ON r.id=e.run_id
      LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
      WHERE ((e.path=? AND e.is_write=1) OR (e.kind='rename' AND e.path2=?))
      ORDER BY e.ts_ns DESC LIMIT 1
    """,
        (p, p),
    ).fetchone()


def _input_rows(con: sqlite3.Connection, run_id: str, pid: int, before_ns: int):
    return con.execute(
        """
      SELECT path, MIN(ts_ns) AS first_ns FROM events
      WHERE run_id=? AND pid=? AND is_read=1 AND path IS NOT NULL AND ts_ns<=?
      GROUP BY path ORDER BY first_ns
    """,
        (run_id, pid, before_ns),
    ).fetchall()


def process_inputs(con: sqlite3.Connection, run_id: str, pid: int, before_ns: int, workspace: str, include_noise=False):
    rows = _input_rows(con, run_id, pid, before_ns)
    visible: list[str] = []
    hidden = 0
    for r in rows:
        p = r["path"]
        if include_noise or not _is_noise(p, workspace):
            visible.append(p)
        else:
            hidden += 1
    return visible, hidden


def process_outputs(con: sqlite3.Connection, run_id: str, pid: int, workspace: str, include_noise=False):
    rows = con.execute(
        """
      SELECT DISTINCT CASE WHEN kind='rename' THEN path2 ELSE path END AS out_path
      FROM events WHERE run_id=? AND pid=? AND (is_write=1 OR kind='rename')
    """,
        (run_id, pid),
    ).fetchall()
    out = []
    for r in rows:
        p = r["out_path"]
        if p and (include_noise or not _is_noise(p, workspace)):
            out.append(p)
    return out


def why(con: sqlite3.Connection, path: str, include_noise=False):
    w = last_writer(con, path)
    if not w:
        return None
    inputs, hidden = process_inputs(con, w["run_id"], w["pid"], w["ts_ns"], w["workspace"], include_noise)
    target = normalize(path)
    # O_RDWR output files can appear as both read and write.  A file is not its
    # own upstream cause, so suppress the self-edge from the human view while
    # preserving the raw event in SQLite.
    inputs = [p for p in inputs if p != target]
    return {
        "path": target,
        "run_id": w["run_id"],
        "ts_ns": w["ts_ns"],
        "pid": w["pid"],
        "exe": w["exe"] or "?",
        "process_cwd": w["process_cwd"] or w["run_cwd"],
        "command": w["process_command"] or w["run_command"],
        "collector": w["collector"] or w["process_source"] or "unknown",
        "inputs": inputs,
        "hidden_input_count": hidden,
        "outputs": process_outputs(con, w["run_id"], w["pid"], w["workspace"], include_noise),
    }


def history(con: sqlite3.Connection, path: str, limit=20):
    p = normalize(path)
    return con.execute(
        """
      SELECT e.ts_ns,e.run_id,e.pid,e.kind,e.path,e.path2,
             COALESCE(pr.command,r.command) AS command,pr.exe,r.collector,e.source
      FROM events e JOIN runs r ON r.id=e.run_id
      LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
      WHERE ((e.path=? AND e.is_write=1) OR (e.kind='rename' AND (e.path=? OR e.path2=?)))
      ORDER BY e.ts_ns DESC LIMIT ?
    """,
        (p, p, p, limit),
    ).fetchall()


def impact(con: sqlite3.Connection, path: str, max_depth=5, include_noise=False):
    start = normalize(path)
    seen_files = {start}
    frontier = [start]
    edges = []
    for _depth in range(max_depth):
        nxt = []
        for f in frontier:
            readers = con.execute(
                """
              SELECT DISTINCT e.run_id,e.pid,r.workspace,pr.exe FROM events e
              JOIN runs r ON r.id=e.run_id LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
              WHERE e.path=? AND e.is_read=1
            """,
                (f,),
            ).fetchall()
            for rr in readers:
                outs = process_outputs(con, rr["run_id"], rr["pid"], rr["workspace"], include_noise)
                for o in outs:
                    if o == f:
                        continue
                    edges.append((f, o, rr["exe"] or "?", rr["run_id"]))
                    if o not in seen_files:
                        seen_files.add(o)
                        nxt.append(o)
        frontier = nxt
        if not frontier:
            break
    return edges
