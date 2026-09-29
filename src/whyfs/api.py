"""whyfs-api/1: the local provenance service (docs/AGENT_PROTOCOL.md).

Transport: Linux Unix socket /run/whyfs/api.sock (requester from SO_PEERCRED); Windows named
pipe \\\\.\\pipe\\whyfs-api (requester from the client's token).  One JSON object per line:
    request  {"v": 1, "op": "<operation>", "params": {...}}
    reply    {"v": 1, "ok": true, "result": ...}  |  {"v": 1, "ok": false, "error": "..."}
No network listener exists; there is no account, cloud or telemetry.

Operations (all answers are what the requester may see: their own processes' evidence;
administrators see everything):
    get_file_provenance {path}           the full label (dict)
    explain_file {path}                  {"label": dict, "text": human-readable label}
    get_file_history {path, limit?}
    get_file_inputs {path}
    get_file_dependents {path, depth?}
    get_recent_changes {since_ns?, limit?, path_prefix?}
    get_agent_session {session_id}
    get_files_by_agent {session_id, limit?}
    session_start {agent_name, agent_version?, session_id?, root_pid?, workspace?, task?}
    session_end {session_id}
    status {}
    forget {path?} | {everything: true}
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path

from . import agents, label, retention
from .access import open_for
from .query import impact_details, pkey
from .query import why as qwhy
from .store import normalize
from .client import PIPE_NAME, PROTOCOL, SOCKET_PATH, ServiceUnavailable, call, dumps  # noqa: F401

MAX_REQUEST = 1 << 20
_SESSION_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")


class ApiError(Exception):
    pass


# ---------------------------------------------------------------- operations
def _path(params: dict) -> str:
    p = params.get("path")
    if not isinstance(p, str) or not p:
        raise ApiError("path required")
    if not os.path.isabs(p):
        raise ApiError("path must be absolute (clients resolve it against their own working directory)")
    return normalize(p)


def _session_view(con, s: dict | sqlite3.Row) -> dict:
    d = dict(s)
    d["started"] = label.iso(d.get("started_ns"))
    d["ended"] = label.iso(d.get("ended_ns"))
    d["user_name"] = label.user_name(d.get("user"))
    return d


def op_get_file_provenance(ctx, con, params):
    return label.explain_file(con, _path(params), include_noise=bool(params.get("include_noise")))


def op_explain_file(ctx, con, params):
    lb = label.explain_file(con, _path(params), include_noise=bool(params.get("include_noise")))
    return {"label": lb, "text": label.render_label(lb)}


def op_get_file_history(ctx, con, params):
    return label.file_history(con, _path(params), limit=int(params.get("limit", 50)))


def op_get_file_inputs(ctx, con, params):
    w = qwhy(con, _path(params), include_noise=bool(params.get("include_noise")))
    if not w:
        return None
    return {"creator": {"exe": w["exe"], "pid": w["pid"], "command": w.get("command")}, "inputs": w["inputs"],
            "inputs_via_temporaries": w.get("inputs_via_temporaries") or [], "hidden_input_count": w["hidden_input_count"],
            "shared_by_outputs": w.get("shared_by_outputs", 0)}


def op_get_file_dependents(ctx, con, params):
    return impact_details(con, _path(params), max_depth=int(params.get("depth", 5)),
                          include_noise=bool(params.get("include_noise")))


def op_get_recent_changes(ctx, con, params):
    since = int(params.get("since_ns") or (time.time_ns() - 24 * 3600 * 10**9))
    limit = min(int(params.get("limit", 100)), 1000)
    prefix = params.get("path_prefix")
    q = ("SELECT e.*, pr.exe, pr.command, pr.user FROM events e LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid "
         "WHERE e.ts_ns>=? AND (e.is_write=1 OR e.kind IN ('rename','unlink')) AND e.api NOT LIKE '%derived-temp'")
    args: list = [since]
    if prefix:
        q += " AND (e.path LIKE ? ESCAPE '!' OR e.path2 LIKE ? ESCAPE '!')"
        esc = normalize(prefix).replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        args += [esc, esc]
    q += " ORDER BY e.ts_ns DESC LIMIT ?"
    args.append(limit * 5)
    out, seen = [], set()
    for r in con.execute(q, args):
        target = r["path2"] if r["kind"] == "rename" else r["path"]
        if not target or pkey(target) in seen:
            continue
        seen.add(pkey(target))
        s = agents.session_for(con, r["run_id"], r["pid"], r["ts_ns"])
        out.append({"path": target, "action": {"io": "written", "rename": "moved here", "unlink": "deleted"}[r["kind"]],
                    "ts_ns": r["ts_ns"], "at": label.iso(r["ts_ns"]), "exe": r["exe"], "pid": r["os_pid"],
                    "user": r["user"], "agent": ({"agent_name": s["agent_name"], "session_id": s["session_id"],
                                                  "source": s["source"]} if s else None)})
        if len(out) >= limit:
            break
    return out


def _like(text: str) -> str:
    return "%" + str(text).replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"


def _ns(v) -> int | None:
    if v in (None, ""):
        return None
    return int(v)


def _users_matching(con, text: str) -> list[str]:
    """Stored user ids (uid:N / SIDs) whose id or resolved name contains ``text``."""
    t = text.lower()
    out = []
    for (u,) in con.execute("SELECT DISTINCT user FROM processes WHERE user IS NOT NULL"):
        name = label.user_name(u) or ""
        if t in u.lower() or t in name.lower():
            out.append(u)
    return out


def _session_process_sets(con, session_ids: list[str]) -> dict[str, tuple[set, int, int]]:
    """run_id -> (process keys, start, end) of the given sessions' process trees."""
    out: dict[str, tuple[set, int, int]] = {}
    for sid in session_ids:
        for run_id, key, start, end in agents.session_roots(con, sid):
            keys, s0, e0 = out.get(run_id, (set(), 1 << 62, 0))
            keys.update(agents.descendants(con, run_id, key))
            out[run_id] = (keys, min(s0, (start or 0) - 2 * 10**9), max(e0, end or (1 << 62)))
    return out


def op_list_agent_sessions(ctx, con, params):
    """Registered sessions and detected agent process trees, newest first."""
    since = _ns(params.get("since_ns")) or 0
    name = (params.get("agent") or "").lower()
    limit = min(int(params.get("limit", 200)), 2000)
    out = []
    for s in con.execute("SELECT * FROM agent_sessions WHERE started_ns>=? ORDER BY started_ns DESC LIMIT ?", (since, limit)):
        if name and name not in s["agent_name"].lower():
            continue
        d = _session_view(con, s)
        d.pop("root_start_ns", None)
        out.append(d)
    # detected agents: root processes whose image/command line is a known agent and whose parent is not
    rows = con.execute("SELECT p.*, pp.exe AS pexe, pp.command AS pcommand FROM processes p "
                       "LEFT JOIN processes pp ON pp.run_id=p.run_id AND pp.pid=p.parent_key "
                       "WHERE p.first_seen_ns>=? AND (p.exe LIKE '%claude%' OR p.exe LIKE '%node%' OR p.exe LIKE '%codex%') "
                       "ORDER BY p.first_seen_ns DESC LIMIT 20000", (since,)).fetchall()
    seen = set()
    for r in reversed(rows):  # oldest first: a process instance is named by its first collector run
        a = agents.detect(r["exe"], r["command"])
        if not a or agents.detect(r["pexe"], r["pcommand"]):
            continue
        inst = (r["os_pid"], r["first_seen_ns"] // 2_000_000_000)
        if inst in seen:  # the same process, seen again by a later collector run
            continue
        seen.add(inst)
        if name and name not in a["agent_name"].lower():
            continue
        out.append({"session_id": f"detected:{a['agent_id']}:{r['run_id']}:{r['pid']}", "agent_name": a["agent_name"],
                    "agent_version": a["agent_version"], "user": r["user"], "user_name": label.user_name(r["user"]),
                    "root_os_pid": r["os_pid"], "workspace": r["cwd"], "task": None, "started_ns": r["first_seen_ns"],
                    "started": label.iso(r["first_seen_ns"]), "ended_ns": None, "ended": None, "source": "detected",
                    "confidence": "high: " + a["evidence"], "evidence": a["evidence"]})
    out.sort(key=lambda d: -(d.get("started_ns") or 0))
    return out[:limit]


def op_search_files(ctx, con, params):
    """Files whose observed history matches every given filter (docs/AGENT_PROTOCOL.md):
    name (part of the file name), path (part of the full path), creator (part of the writing
    program's path), user (id or name), agent (agent name), session_id, since_ns/until_ns,
    action (created | changed | deleted | any).  One row per file, newest activity first."""
    limit = min(int(params.get("limit", 100)), 1000)
    since, until = _ns(params.get("since_ns")), _ns(params.get("until_ns"))
    action = params.get("action") or "any"
    if action not in ("any", "created", "changed", "deleted"):
        raise ApiError("action must be any, created, changed or deleted")
    where = ["(e.is_write=1 OR e.kind IN ('rename','unlink'))", "e.api NOT LIKE '%derived-temp'"]
    args: list = []
    target = "CASE WHEN e.kind='rename' THEN e.path2 ELSE e.path END"
    if since is not None:
        where.append("e.ts_ns>=?")
        args.append(since)
    if until is not None:
        where.append("e.ts_ns<=?")
        args.append(until)
    for key, expr in (("path", target), ("creator", "pr.exe")):
        if params.get(key):
            where.append(f"{expr} LIKE ? ESCAPE '!'")
            args.append(_like(params[key]))
    if params.get("name"):  # the file name: the part after the last separator
        where.append(f"{target} LIKE ? ESCAPE '!'")
        args.append(_like(params["name"]))
    if action == "deleted":
        where.append("e.kind='unlink'")
    elif action in ("created", "changed"):
        where.append("e.kind!='unlink'")
    if params.get("user"):
        users = _users_matching(con, str(params["user"]))
        if not users:
            return []
        where.append(f"pr.user IN ({','.join('?' * len(users))})")
        args += users
    sessions = None
    if params.get("session_id") or params.get("agent"):
        sids = [str(params["session_id"])] if params.get("session_id") else [
            d["session_id"] for d in op_list_agent_sessions(ctx, con, {"agent": params["agent"], "limit": 2000})]
        sessions = _session_process_sets(con, sids)
        if not sessions:
            return []
        where.append(f"e.run_id IN ({','.join('?' * len(sessions))})")
        args += list(sessions)
    q = (f"SELECT {target} AS target, e.kind, e.ts_ns, e.run_id, e.pid, pr.exe, pr.os_pid, pr.user FROM events e "
         f"LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid WHERE {' AND '.join(where)} "
         f"ORDER BY e.ts_ns DESC LIMIT ?")
    args.append(limit * 50)
    name = str(params.get("name") or "").lower()
    files: dict[str, dict] = {}
    for r in con.execute(q, args):
        t = r["target"]
        if not t:
            continue
        if name and name not in os.path.basename(t).lower():
            continue
        if sessions is not None:
            ks = sessions.get(r["run_id"])
            if not ks or r["pid"] not in ks[0] or not (ks[1] <= r["ts_ns"] <= ks[2]):
                continue
        k = pkey(t)
        if k in files:
            continue
        files[k] = {"path": t, "last_action": {"io": "written", "rename": "moved here", "unlink": "deleted"}[r["kind"]],
                    "ts_ns": r["ts_ns"], "at": label.iso(r["ts_ns"]), "exe": r["exe"], "pid": r["os_pid"],
                    "user": r["user"], "user_name": label.user_name(r["user"]), "run_id": r["run_id"], "process_key": r["pid"]}
        if len(files) >= limit * 3:
            break
    out = []
    for f in files.values():
        first = con.execute("SELECT MIN(ts_ns) FROM (SELECT ts_ns FROM events WHERE path=? AND is_write=1 "
                            "UNION ALL SELECT ts_ns FROM events WHERE path2=? AND kind='rename')",
                            (f["path"], f["path"])).fetchone()[0]
        f["first_observed_ns"] = first
        f["first_observed"] = label.iso(first)
        f["created_in_range"] = bool(first is not None and (since is None or first >= since) and (until is None or first <= until))
        if action == "created" and not f["created_in_range"]:
            continue
        s = agents.session_for(con, f["run_id"], f["process_key"], f["ts_ns"])
        f["agent"] = {"agent_name": s["agent_name"], "session_id": s["session_id"], "source": s["source"]} if s else None
        f["exists"] = os.path.exists(f["path"])
        del f["run_id"], f["process_key"]
        out.append(f)
        if len(out) >= limit:
            break
    return out


def op_get_agent_session(ctx, con, params):
    sid = str(params.get("session_id") or "")
    roots = agents.session_roots(con, sid)
    s = con.execute("SELECT * FROM agent_sessions WHERE session_id=?", (sid,)).fetchone()
    if s:
        d = _session_view(con, s)
    elif sid.startswith("detected:") and roots:
        run_id, key, start, _ = roots[0]
        row = con.execute("SELECT * FROM processes WHERE run_id=? AND pid=?", (run_id, key)).fetchone()
        a = agents.detect(row["exe"], row["command"]) or {}
        d = _session_view(con, {"session_id": sid, "agent_name": a.get("agent_name"), "agent_version": a.get("agent_version"),
                                "user": row["user"], "root_os_pid": row["os_pid"], "started_ns": start, "ended_ns": None,
                                "task": None, "source": "detected", "confidence": "high: " + a.get("evidence", ""),
                                "evidence": a.get("evidence"), "workspace": row["cwd"]})
    else:
        return None
    d["root_processes"] = [{"run_id": r, "process_key": k} for r, k, _s, _e in roots]
    return d


def op_get_files_by_agent(ctx, con, params):
    sid = str(params.get("session_id") or "")
    limit = min(int(params.get("limit", 500)), 5000)
    files: dict[str, dict] = {}
    for run_id, key, start, end in agents.session_roots(con, sid):
        pids = agents.descendants(con, run_id, key)
        for i in range(0, len(pids), 500):
            chunk = pids[i:i + 500]
            q = (f"SELECT e.*, pr.exe FROM events e LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid "
                 f"WHERE e.run_id=? AND e.pid IN ({','.join('?' * len(chunk))}) AND e.ts_ns>=? AND e.ts_ns<=? "
                 f"AND (e.is_write=1 OR e.kind IN ('rename','unlink')) AND e.api NOT LIKE '%derived-temp'")
            for r in con.execute(q, [run_id, *chunk, (start or 0) - 2 * 10**9, end or (1 << 62)]):
                target = r["path2"] if r["kind"] == "rename" else r["path"]
                if not target:
                    continue
                cur = files.get(pkey(target))
                if not cur or r["ts_ns"] > cur["ts_ns"]:
                    files[pkey(target)] = {"path": target, "ts_ns": r["ts_ns"], "at": label.iso(r["ts_ns"]),
                                           "action": {"io": "written", "rename": "moved here", "unlink": "deleted"}[r["kind"]],
                                           "exe": r["exe"], "pid": r["os_pid"]}
    return sorted(files.values(), key=lambda f: -f["ts_ns"])[:limit]


def op_why(ctx, con, params):
    """query.why, as `whyfs why --json` prints it (for tools written against the CLI)."""
    from .query import raw_process_events
    r = qwhy(con, _path(params), include_noise=bool(params.get("include_noise")))
    if r and params.get("raw") and r.get("run_id"):
        r["raw_events"] = [dict(x) for x in raw_process_events(con, r["run_id"], r["process_key"])]
    return r


def op_history(ctx, con, params):
    from .query import history as qhistory
    return [dict(r) for r in qhistory(con, _path(params), int(params.get("limit", 20)))]


def op_impact(ctx, con, params):
    return impact_details(con, _path(params), max_depth=int(params.get("depth", 5)),
                          include_noise=bool(params.get("include_noise")))


def _process_user(pid: int) -> str | None:
    if os.name == "nt":
        from .winsecurity import process_sid
        return process_sid(pid)
    if sys.platform == "darwin":
        from .macos import process_user
        return process_user(pid)
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("Uid:"):
                return f"uid:{int(line.split()[2])}"
    except (OSError, ValueError, IndexError):
        return None
    return None


def op_session_start(ctx, con, params):
    name = params.get("agent_name")
    if not isinstance(name, str) or not (1 <= len(name) <= 100):
        raise ApiError("agent_name required (1-100 characters)")
    sid = params.get("session_id") or f"{uuid.uuid4()}"
    if not isinstance(sid, str) or not _SESSION_ID.match(sid) or sid.startswith("detected:"):
        raise ApiError("session_id: 1-128 of [A-Za-z0-9._:-], not starting with 'detected:'")
    root = params.get("root_pid", ctx.get("pid"))
    try:
        root = int(root) if root is not None else None
    except (TypeError, ValueError):
        raise ApiError("root_pid must be an integer")
    if root is not None:
        owner = _process_user(root)
        if owner is None:
            raise ApiError(f"root process {root} does not exist")
        if owner != ctx["user"] and not ctx["admin"]:
            raise ApiError(f"root process {root} belongs to another user")
    task = params.get("task")
    if task is not None and (not isinstance(task, str) or len(task) > 4000):
        raise ApiError("task: text up to 4000 characters")
    task = redact_task(task)
    main = con.execute("SELECT * FROM main.agent_sessions WHERE session_id=?", (sid,)).fetchone()
    if main and main["user"] != ctx["user"]:
        raise ApiError("session_id already registered by another user")
    now = time.time_ns()
    con.execute(
        "INSERT INTO main.agent_sessions(session_id,agent_name,agent_version,user,root_os_pid,root_start_ns,workspace,task,"
        "started_ns,ended_ns,source,confidence,evidence) VALUES(?,?,?,?,?,?,?,?,?,NULL,'registered',?,?) "
        "ON CONFLICT(session_id) DO UPDATE SET agent_name=excluded.agent_name, agent_version=excluded.agent_version, "
        "root_os_pid=excluded.root_os_pid, root_start_ns=excluded.root_start_ns, workspace=excluded.workspace, "
        "task=excluded.task, ended_ns=NULL",
        (sid, name, params.get("agent_version"), ctx["user"], root, agents.proc_start_ns(root) if root else None,
         params.get("workspace"), task, now,
         "registered: the local service verified that the requester owns the root process",
         f"registered by {ctx['user']} (caller pid {ctx.get('pid')}) for root pid {root}"))
    con.commit()
    return {"session_id": sid, "started_ns": now, "root_pid": root}


def redact_task(task: str | None) -> str | None:
    """Task text is supplied context; secrets in it are redacted like command lines."""
    if not task:
        return task
    from .redact import redact_text
    return redact_text(task)


def op_session_end(ctx, con, params):
    sid = str(params.get("session_id") or "")
    s = con.execute("SELECT user FROM main.agent_sessions WHERE session_id=?", (sid,)).fetchone()
    if not s:
        raise ApiError("unknown session")
    if s["user"] != ctx["user"] and not ctx["admin"]:
        raise ApiError("session belongs to another user")
    now = time.time_ns()
    con.execute("UPDATE main.agent_sessions SET ended_ns=? WHERE session_id=?", (now, sid))
    con.commit()
    return {"session_id": sid, "ended_ns": now}


def op_status(ctx, con, params):
    from . import machine
    run = con.execute("SELECT * FROM runs ORDER BY started_ns DESC LIMIT 1").fetchone()
    stats = {r["key"]: r["value"] for r in con.execute("SELECT key, value FROM collector_stats WHERE run_id=?",
                                                        (run["id"],))} if run else {}
    visible = {
        "events": con.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "processes": con.execute("SELECT COUNT(*) FROM processes").fetchone()[0],
        "agent_sessions": con.execute("SELECT COUNT(*) FROM agent_sessions").fetchone()[0],
        "labelled_files": con.execute("SELECT COUNT(DISTINCT path) FROM events WHERE is_write=1").fetchone()[0],
    }
    return {
        "protocol": PROTOCOL, "requester": ctx["user"], "requester_name": label.user_name(ctx["user"]),
        "admin_view": ctx["admin"], "visible": visible,
        "store_bytes": retention.db_bytes(con), "policy": machine.load_config(),
        "collector": dict(run) if run else None, "collector_running": bool(run and run["ended_ns"] is None),
        "collector_ready": machine.collector_ready(),
        "collector_stats": stats,
        "lost": sum(int(stats.get(k, 0)) for k in ("kernel_drops", "queue_drops", "user_unresolved", "late_records",
                                                    "lost_file", "lost_sys", "bridge_evicted")),
        "scope_rules": machine.effective_scope_text(),
        "heartbeat_age_s": (round((time.time_ns() - stats["heartbeat_ns"]) / 1e9, 1) if stats.get("heartbeat_ns") else None),
        "recording_gaps": _recording_gaps(con),
        **({"endpoint_security": _endpoint_security()} if sys.platform == "darwin" else {}),
    }


def _endpoint_security():
    from .macos import endpoint_security_state
    return endpoint_security_state()


def _recording_gaps(con):
    from .observation import recording_gaps
    return recording_gaps(con)


def op_forget(ctx, con, params):
    user = None if ctx["admin"] else ctx["user"]
    if params.get("everything"):
        return retention.forget(con, user=user, everything=True)
    return retention.forget(con, path=_path(params), user=user)


OPS = {k[3:]: v for k, v in globals().items() if k.startswith("op_")}


def handle(ctx: dict, root: Path, request: dict) -> dict:
    """Serve one request for an authenticated requester ``ctx`` = {user, admin, pid}."""
    try:
        if not isinstance(request, dict) or request.get("v", 1) != PROTOCOL:
            raise ApiError(f"unsupported protocol version (this service speaks {PROTOCOL})")
        fn = OPS.get(request.get("op"))
        if fn is None:
            raise ApiError(f"unknown op {request.get('op')!r}; ops: {sorted(OPS)}")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise ApiError("params must be an object")
        con = open_for(root, ctx["user"], ctx["admin"])
        try:
            return {"v": PROTOCOL, "ok": True, "result": fn(ctx, con, params)}
        finally:
            con.close()
    except ApiError as exc:
        return {"v": PROTOCOL, "ok": False, "error": str(exc)}
    except (PermissionError, sqlite3.Error, OSError, ValueError, TypeError, KeyError) as exc:
        return {"v": PROTOCOL, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


_dumps = dumps


# ---------------------------------------------------------------- Linux server
def serve_unix(root: Path, path: str = SOCKET_PATH, stop: threading.Event | None = None) -> threading.Thread:
    import socket
    import socketserver
    import struct

    d = os.path.dirname(path)
    os.makedirs(d, mode=0o755, exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            if sys.platform == "darwin":  # LOCAL_PEERCRED / LOCAL_PEERPID: the kernel's view of the peer
                from .macos import peer_credentials
                pid, uid = peer_credentials(self.request)
            else:
                pid, uid, _gid = struct.unpack("3i", self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                                             struct.calcsize("3i")))
            ctx = {"user": f"uid:{uid}", "admin": uid == 0, "pid": pid}
            while True:
                line = self.rfile.readline(MAX_REQUEST)
                if not line:
                    return
                try:
                    req = json.loads(line)
                except ValueError:
                    self.wfile.write(_dumps({"v": PROTOCOL, "ok": False, "error": "request is not JSON"}))
                    continue
                self.wfile.write(_dumps(handle(ctx, root, req)))

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    srv = Server(path, Handler)
    os.chmod(path, 0o666)  # every local user may ask; each sees only their own evidence
    t = threading.Thread(target=srv.serve_forever, name="whyfs-api", daemon=True)
    t.start()
    if stop is not None:
        threading.Thread(target=lambda: (stop.wait(), srv.shutdown()), daemon=True).start()
    return t


# ---------------------------------------------------------------- Windows server
def serve_pipe(root: Path, stop: threading.Event | None = None) -> threading.Thread:
    from . import winsecurity as ws

    def one(h):
        try:
            data = b""
            while not data.endswith(b"\n") and len(data) < MAX_REQUEST:
                chunk = ws.pipe_read(h)
                if not chunk:
                    break
                data += chunk
            ctx = ws.pipe_client_context(h)  # impersonates after the first read, as Windows requires
            for line in data.splitlines():
                if not line.strip():
                    continue
                try:
                    reply = handle(ctx, root, json.loads(line))
                except ValueError:
                    reply = {"v": PROTOCOL, "ok": False, "error": "request is not JSON"}
                ws.pipe_write(h, _dumps(reply))
        except Exception as exc:  # one client never stops the service
            try:
                ws.pipe_write(h, _dumps({"v": PROTOCOL, "ok": False, "error": f"{type(exc).__name__}: {exc}"}))
            except OSError:
                pass
        finally:
            ws.pipe_close(h)

    def loop():
        first = True
        while stop is None or not stop.is_set():
            h = ws.pipe_create(PIPE_NAME, first=first)
            first = False
            if not ws.pipe_accept(h):
                ws.pipe_close(h)
                continue
            threading.Thread(target=one, args=(h,), daemon=True).start()

    t = threading.Thread(target=loop, name="whyfs-api", daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------- client (whyfs.client)


def main(argv: list[str] | None = None) -> int:  # `whyfs api OP [JSON-PARAMS]`
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    try:
        params = json.loads(argv[1]) if len(argv) > 1 else {}
    except ValueError as exc:
        raise SystemExit(f"whyfs api: the parameters are not valid JSON ({exc}); backslashes in paths must be doubled")
    if "path" in params and isinstance(params["path"], str):
        params["path"] = os.path.abspath(params["path"])
    print(json.dumps(call(argv[0], params), indent=2, default=str))
    return 0
