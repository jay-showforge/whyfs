"""Agent/session attribution: which AI agent session, if any, caused a process.

Two sources, both stored beside (never instead of) the OS-observed process chain:

* registered: an agent told the local whyfs service who it is (docs/AGENT_PROTOCOL.md);
  the service verified that the caller's user owns the session's root process.
* detected:   an ancestor process whose program image path AND command line match a known
  agent's installed layout.  A file name alone never qualifies (anyone can name a program
  `claude`).

Attribution is computed at query time from the stored ancestry: the nearest ancestor of the
creating process that is a session root.  Intent ("the task") is only ever the text a
registered session supplied.
"""
from __future__ import annotations

import os
import re
import sqlite3

# (agent id, display name, image-path test, command-line test, version extractor)
# Paths are compared with forward slashes, lower-cased.


def _norm(p: str | None) -> str:
    return (p or "").replace("\\", "/").lower()


def _base(p: str) -> str:
    return p.rsplit("/", 1)[-1]


_VERSION = re.compile(r"/(?:claude-code|versions)/(\d+\.\d+\.\d+[^/]*)/")


def _claude_code(exe: str, cmd: str) -> tuple[bool, str | None, str]:
    """Claude Code: the native build (claude[.exe] inside a claude-code/<version> or
    claude/versions/<version> directory), or node running @anthropic-ai/claude-code."""
    b = _base(exe)
    if b in ("claude", "claude.exe") and ("/claude-code/" in exe or "/claude/versions/" in exe
                                          or "/@anthropic-ai/claude-code/" in exe):
        m = _VERSION.search(exe)
        return True, m.group(1) if m else None, "image path in a Claude Code install layout"
    if b in ("node", "node.exe") and "@anthropic-ai/claude-code/cli" in cmd:
        m = re.search(r"@anthropic-ai/claude-code@?(\d+\.\d+\.\d+)", cmd)
        return True, m.group(1) if m else None, "node running @anthropic-ai/claude-code/cli.js"
    return False, None, ""


def _codex(exe: str, cmd: str) -> tuple[bool, str | None, str]:
    """OpenAI Codex CLI: node running @openai/codex, or its vendored native binary."""
    b = _base(exe)
    if b in ("node", "node.exe") and "/@openai/codex/" in cmd:
        return True, None, "node running @openai/codex"
    if b.startswith("codex") and "/@openai/codex/" in exe:
        return True, None, "image path in the @openai/codex package"
    return False, None, ""


def _gemini(exe: str, cmd: str) -> tuple[bool, str | None, str]:
    b = _base(exe)
    if b in ("node", "node.exe") and "/@google/gemini-cli/" in cmd:
        return True, None, "node running @google/gemini-cli"
    return False, None, ""


SIGNATURES = (
    ("claude-code", "Claude Code", _claude_code),
    ("codex-cli", "Codex CLI", _codex),
    ("gemini-cli", "Gemini CLI", _gemini),
)


def detect(exe: str | None, command: str | None) -> dict | None:
    """Agent identity of a process from its image path and command line, or None."""
    e, c = _norm(exe), _norm(command)
    if not e:
        return None
    for aid, name, test in SIGNATURES:
        ok, version, why = test(e, c)
        if ok:
            return {"agent_id": aid, "agent_name": name, "agent_version": version, "evidence": why}
    return None


# ---------------------------------------------------------------- ancestry
def ancestry(con: sqlite3.Connection, run_id: str, key: int, max_hops: int = 64) -> list[sqlite3.Row]:
    """Process rows from the given process up to the oldest stored ancestor."""
    out, seen = [], set()
    while key is not None and len(out) < max_hops and key not in seen:
        seen.add(key)
        row = con.execute("SELECT * FROM processes WHERE run_id=? AND pid=?", (run_id, key)).fetchone()
        if not row:
            break
        out.append(row)
        key = row["parent_key"] if row["parent_key"] is not None else None
    return out


def _starts_match(row: sqlite3.Row, root_start_ns: int | None) -> bool:
    """A registered root PID names this process instance, not a later reuse of the PID: the
    process row starts when the root process started.  first_seen_ns is the observed start
    (fork / process start) or, for a process that predates the collector, its OS start time."""
    if not root_start_ns:
        return True
    return abs(row["first_seen_ns"] - root_start_ns) <= 2_000_000_000


def session_for(con: sqlite3.Connection, run_id: str, key: int, at_ns: int) -> dict | None:
    """The agent session behind a process: the nearest ancestor (or the process itself)
    that is a registered session root active at ``at_ns``, else a detected agent root."""
    chain = ancestry(con, run_id, key)
    for row in chain:  # registered sessions first: explicit, verified context
        if row["os_pid"] is None:
            continue
        for s in con.execute(
                "SELECT * FROM agent_sessions WHERE root_os_pid=? AND started_ns<=? AND (ended_ns IS NULL OR ended_ns>=?)"
                " ORDER BY started_ns DESC", (row["os_pid"], at_ns + 2_000_000_000, at_ns)):
            if (s["user"] is None or row["user"] is None or s["user"] == row["user"]) and _starts_match(row, s["root_start_ns"]):
                d = dict(s)
                d["root_process"] = {"pid": row["os_pid"], "exe": row["exe"], "process_key": row["pid"], "run_id": run_id}
                d["depth"] = chain.index(row)
                return d
    for row in chain:
        a = detect(row["exe"], row["command"])
        if a:
            return {
                "session_id": f"detected:{a['agent_id']}:{run_id}:{row['pid']}",
                "agent_name": a["agent_name"], "agent_version": a["agent_version"], "user": row["user"],
                "root_os_pid": row["os_pid"], "root_start_ns": row["first_seen_ns"], "workspace": row["cwd"],
                "task": None, "started_ns": row["first_seen_ns"], "ended_ns": None, "source": "detected",
                "confidence": "high: " + a["evidence"], "evidence": a["evidence"],
                "root_process": {"pid": row["os_pid"], "exe": row["exe"], "process_key": row["pid"], "run_id": run_id},
                "depth": chain.index(row),
            }
    return None


def session_roots(con: sqlite3.Connection, session_id: str) -> list[tuple[str, int, int, int | None]]:
    """(run_id, process key, start, end) of the root process(es) of a session."""
    if session_id.startswith("detected:"):
        parts = session_id.split(":")
        if len(parts) >= 4:
            run_id, key = ":".join(parts[2:-1]), int(parts[-1])
            row = con.execute("SELECT first_seen_ns FROM processes WHERE run_id=? AND pid=?", (run_id, key)).fetchone()
            if row:
                return [(run_id, key, row["first_seen_ns"], None)]
        return []
    s = con.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not s or s["root_os_pid"] is None:
        return []
    out = []
    for row in con.execute("SELECT * FROM processes WHERE os_pid=? AND first_seen_ns<=?",
                           (s["root_os_pid"], (s["ended_ns"] or 1 << 62))):
        if (s["user"] is None or row["user"] in (None, s["user"])) and _starts_match(row, s["root_start_ns"]):
            out.append((row["run_id"], row["pid"], s["started_ns"], s["ended_ns"]))
    return out


def descendants(con: sqlite3.Connection, run_id: str, key: int) -> list[int]:
    rows = con.execute(
        """WITH RECURSIVE d(pid) AS (SELECT ? UNION SELECT p.pid FROM processes p JOIN d ON p.parent_key=d.pid
                                     WHERE p.run_id=?)
           SELECT pid FROM d""", (key, run_id)).fetchall()
    return [r[0] for r in rows]


def is_detected_agent_process(exe: str | None, command: str | None) -> bool:
    return detect(exe, command) is not None


def proc_start_ns(pid: int) -> int | None:
    """Wall-clock start of a live process (Linux /proc; Windows via GetProcessTimes)."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            ft = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(h, *[ctypes.byref(f) for f in ft]):
                return None
            v = (ft[0].dwHighDateTime << 32) | ft[0].dwLowDateTime
            return (v - 116444736000000000) * 100
        finally:
            k32.CloseHandle(h)
    try:
        fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        ticks = int(fields[19])
        hz = os.sysconf("SC_CLK_TCK")
        btime = next(int(line.split()[1]) for line in open("/proc/stat") if line.startswith("btime"))
        return btime * 1_000_000_000 + ticks * 1_000_000_000 // hz
    except (OSError, ValueError, IndexError, StopIteration):
        return None
