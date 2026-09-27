"""Per-user visibility over the machine store.

The machine store holds every user's evidence and is readable only by the whyfs service.
The service opens it for a requester with ``open_for``: an administrator (root, or an
elevated Windows administrator) sees everything; anyone else sees exactly the evidence of
their own processes.  The restriction is enforced by TEMP views that shadow the tables
(SQLite resolves unqualified names to the temp schema first), so every query in query.py,
label.py and agents.py runs unchanged under it.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from .store import connect


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def restrict(con: sqlite3.Connection, user: str) -> sqlite3.Connection:
    u = _q(user)
    con.executescript(f"""
        CREATE TEMP VIEW processes AS SELECT * FROM main.processes WHERE user = {u};
        CREATE TEMP VIEW events AS SELECT e.* FROM main.events e
            JOIN main.processes p ON p.run_id = e.run_id AND p.pid = e.pid WHERE p.user = {u};
        CREATE TEMP VIEW agent_sessions AS SELECT * FROM main.agent_sessions WHERE user = {u};
    """)
    return con


def open_for(root: Path, user: str | None, admin: bool) -> sqlite3.Connection:
    con = connect(root, check_same_thread=False)
    if not admin:
        if not user:
            raise PermissionError("unknown requester")
        restrict(con, user)
    return con
