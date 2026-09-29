from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Iterable

# Path equality is a platform property: POSIX paths are case-sensitive; Windows paths
# are compared case-insensitively (NTFS semantics; SQLite NOCASE folds ASCII only).
PATH_COLLATE = " COLLATE NOCASE" if os.name == "nt" else ""

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY,
  started_ns INTEGER NOT NULL,
  ended_ns INTEGER,
  cwd TEXT NOT NULL,
  command TEXT NOT NULL,
  exit_code INTEGER,
  workspace TEXT NOT NULL,
  collector TEXT DEFAULT 'preload'
);
CREATE TABLE IF NOT EXISTS processes(
  run_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  ppid INTEGER,
  exe TEXT{C},
  cwd TEXT,
  command TEXT,
  source TEXT,
  first_seen_ns INTEGER NOT NULL,
  PRIMARY KEY(run_id,pid)
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL,
  ts_ns INTEGER NOT NULL,
  pid INTEGER NOT NULL,
  ppid INTEGER,
  kind TEXT NOT NULL,
  path TEXT{C},
  path2 TEXT{C},
  is_read INTEGER DEFAULT 0,
  is_write INTEGER DEFAULT 0,
  flags INTEGER,
  api TEXT,
  source TEXT
);
CREATE TABLE IF NOT EXISTS collector_stats(
  run_id TEXT NOT NULL,
  key TEXT NOT NULL,
  value INTEGER NOT NULL,
  PRIMARY KEY(run_id,key)
);
CREATE INDEX IF NOT EXISTS events_path ON events(path, ts_ns);
CREATE INDEX IF NOT EXISTS events_path2 ON events(path2, ts_ns);
CREATE INDEX IF NOT EXISTS events_pid ON events(run_id,pid,ts_ns);
CREATE INDEX IF NOT EXISTS processes_exe ON processes(exe);
CREATE TABLE IF NOT EXISTS agent_sessions(
  session_id TEXT PRIMARY KEY,
  agent_name TEXT NOT NULL,
  agent_version TEXT,
  user TEXT,
  root_os_pid INTEGER,
  root_start_ns INTEGER,
  workspace TEXT,
  task TEXT,
  started_ns INTEGER NOT NULL,
  ended_ns INTEGER,
  source TEXT NOT NULL,
  confidence TEXT NOT NULL,
  evidence TEXT
);
CREATE INDEX IF NOT EXISTS agent_sessions_root ON agent_sessions(root_os_pid);
"""


def _ensure_column(con: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
    cols = {r["name"] if isinstance(r, sqlite3.Row) else r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


STATE_DIR = ".whyfs"
DB_NAME = "whyfs.db"


def _check_state_paths(root: Path) -> Path:
    """Refuse a symlinked state directory or database file.  Raw evidence
    stays private: the directory is created 0700 and the database 0600."""
    d = root / STATE_DIR
    if d.is_symlink():
        raise PermissionError(f"refusing symlinked whyfs state directory {d}")
    if not d.exists():
        root.mkdir(parents=True, exist_ok=True)
        os.mkdir(d, 0o700)
    if not d.is_dir():
        raise PermissionError(f"whyfs state path {d} is not a directory")
    for name in (DB_NAME, DB_NAME + "-wal", DB_NAME + "-shm", DB_NAME + "-journal"):
        if (d / name).is_symlink():
            raise PermissionError(f"refusing symlinked whyfs database file {d / name}")
    return d


def connect(root: Path, *, check_same_thread: bool = True) -> sqlite3.Connection:
    d = _check_state_paths(root)
    db = d / DB_NAME
    fresh = not db.exists()
    con = sqlite3.connect(db, timeout=30, check_same_thread=check_same_thread)
    if fresh:
        try:
            os.chmod(db, 0o600)  # -wal/-shm inherit the database file's mode
        except OSError:
            pass
    con.row_factory = sqlite3.Row
    if fresh:
        con.execute("PRAGMA auto_vacuum=INCREMENTAL")  # retention can return space (retention.prune)
    con.executescript(SCHEMA.replace("{C}", PATH_COLLATE))
    # v0.1 -> v0.2 in-place migration. SQLite lacks ADD COLUMN IF NOT EXISTS.
    _ensure_column(con, "runs", "collector", "TEXT DEFAULT 'preload'")
    _ensure_column(con, "processes", "command", "TEXT")
    _ensure_column(con, "processes", "source", "TEXT")
    _ensure_column(con, "events", "source", "TEXT")
    # v0.2 eBPF: `pid` is a per-run process-instance key (unique even when the OS
    # re-uses a PID); `os_pid` is the real kernel pid; `parent_key` links the
    # process tree by instance rather than by re-usable pid.
    _ensure_column(con, "events", "os_pid", "INTEGER")
    _ensure_column(con, "processes", "os_pid", "INTEGER")
    _ensure_column(con, "processes", "parent_key", "INTEGER")
    # machine-wide labels (docs/MACHINE_MODE.md): the process's user ("uid:N" / a Windows
    # SID) and the file's native identity at I/O time ("lnx:MAJ:MIN:INO:GEN" / "win:VOL:FILEID")
    _ensure_column(con, "processes", "user", "TEXT")
    _ensure_column(con, "events", "file_id", "TEXT")
    con.execute("CREATE INDEX IF NOT EXISTS events_file_id ON events(file_id) WHERE file_id IS NOT NULL")
    con.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts_ns)")
    con.execute("CREATE INDEX IF NOT EXISTS processes_parent ON processes(run_id, parent_key)")
    con.execute("CREATE INDEX IF NOT EXISTS processes_os_pid ON processes(os_pid)")
    con.commit()
    return con


def normalize(path: str | os.PathLike[str]) -> str:
    p = os.path.normpath(os.path.abspath(os.fspath(path)))
    if sys.platform == "darwin":  # the form the collector records: links resolved, stored case
        from .macos import true_path
        return true_path(p)
    return _long_name(p) if os.name == "nt" and "~" in p else p


def _long_name(p: str) -> str:
    """Windows: expand 8.3 short components (C:\\Users\\LONGUS~1\\...) to the long names the
    collectors record.  A path that does not exist yet keeps its missing tail as given."""
    import ctypes
    buf = ctypes.create_unicode_buffer(32768)
    get_long = ctypes.windll.kernel32.GetLongPathNameW
    head, tail = p, []
    while True:
        n = get_long(head, buf, len(buf))
        if 0 < n < len(buf):
            return os.path.join(buf.value, *reversed(tail)) if tail else buf.value
        parent, leaf = os.path.split(head)
        if not leaf or parent == head:
            return p
        tail.append(leaf)
        head = parent


def ingest_events(con: sqlite3.Connection, events: Iterable[dict]) -> int:
    """Import already-normalized collector events in one transaction.

    This is shared by the v0.1 JSONL importer and the v0.2 daemon writer.  It
    deliberately stores *observed evidence* without relevance pruning; query.py
    is responsible for the human view.
    """
    n = 0
    process_rows: list[tuple] = []
    event_rows: list[tuple] = []
    for e in events:
        run = e.get("run_id", "")
        pid = int(e.get("pid", 0))
        ppid = e.get("ppid")
        ts = int(e.get("ts_ns", time.time_ns()))
        kind = e.get("kind", "")
        if kind == "process":
            process_rows.append((
                run,
                pid,
                ppid,
                e.get("exe"),
                e.get("cwd"),
                e.get("command"),
                e.get("source"),
                ts,
                e.get("os_pid", pid),
                e.get("parent_key"),
                e.get("user"),
            ))
        else:
            p = normalize(e["path"]) if e.get("path") else None
            p2 = normalize(e["path2"]) if e.get("path2") else None
            event_rows.append((
                run,
                ts,
                pid,
                ppid,
                kind,
                p,
                p2,
                int(bool(e.get("read"))),
                int(bool(e.get("write"))),
                e.get("flags"),
                e.get("api"),
                e.get("source"),
                e.get("os_pid", pid),
                e.get("file_id"),
            ))
        n += 1

    if process_rows:
        con.executemany(
            """INSERT INTO processes(run_id,pid,ppid,exe,cwd,command,source,first_seen_ns,os_pid,parent_key,user)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(run_id,pid) DO UPDATE SET
                 user=COALESCE(excluded.user,processes.user),
                 ppid=COALESCE(excluded.ppid,processes.ppid),
                 os_pid=COALESCE(excluded.os_pid,processes.os_pid),
                 parent_key=COALESCE(excluded.parent_key,processes.parent_key),
                 exe=COALESCE(excluded.exe,processes.exe),
                 cwd=COALESCE(excluded.cwd,processes.cwd),
                 command=COALESCE(excluded.command,processes.command),
                 source=COALESCE(excluded.source,processes.source)""",
            process_rows,
        )
    if event_rows:
        con.executemany(
            """INSERT INTO events(run_id,ts_ns,pid,ppid,kind,path,path2,is_read,is_write,flags,api,source,os_pid,file_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            event_rows,
        )
    con.commit()
    return n


def import_log(con: sqlite3.Connection, log: Path) -> int:
    if not log.exists():
        return 0
    batch: list[dict] = []
    total = 0
    with log.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            e.setdefault("source", "preload")
            batch.append(e)
            if len(batch) >= 1000:
                total += ingest_events(con, batch)
                batch.clear()
    if batch:
        total += ingest_events(con, batch)
    return total


def set_collector_stat(con: sqlite3.Connection, run_id: str, key: str, value: int) -> None:
    con.execute(
        """INSERT INTO collector_stats(run_id,key,value) VALUES(?,?,?)
           ON CONFLICT(run_id,key) DO UPDATE SET value=excluded.value""",
        (run_id, key, int(value)),
    )
    con.commit()
