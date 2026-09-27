"""The provenance label of a file: the canonical answer to "where did this come from?".

explain_file() combines OS-observed evidence (query.why / history / impact), the file's
native identity (a path is not identity), and agent/session context (agents.py), keeping
them distinguishable:

* causal why  -- derived from observed activity: "X wrote it after reading A and B";
* intent why  -- only the task text a registered agent session supplied, labelled as such;
                 never inferred.

render_label() is the human form; the dict is the structured (JSON) form.
"""
from __future__ import annotations

import datetime as _dt
import os
import sqlite3

from . import agents
from .query import impact_details, pkey
from .query import why as qwhy
from .store import normalize


# ---------------------------------------------------------------- identity
def current_file_id(path: str) -> str | None:
    """Native identity of the file now at ``path`` (same format the collectors record)."""
    if os.name == "nt":
        return _win_file_id(path)
    try:
        st = os.stat(path)
    except OSError:
        return None
    gen = None
    try:
        import fcntl
        import struct
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        try:
            buf = fcntl.ioctl(fd, 0x80087601, b"\0" * 8)  # FS_IOC_GETVERSION: inode generation
            gen = struct.unpack("<I", buf[:4])[0]
        finally:
            os.close(fd)
    except (OSError, ImportError):
        pass
    return f"lnx:{os.major(st.st_dev)}:{os.minor(st.st_dev)}:{st.st_ino}:{'' if gen is None else gen}"


def _win_file_id(path: str) -> str | None:
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    h = k32.CreateFileW(path, 0x80, 7, None, 3, 0x02000000, None)  # FILE_READ_ATTRIBUTES, share all, backup semantics
    if h in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        class FILE_ID_INFO(ctypes.Structure):
            _fields_ = [("VolumeSerialNumber", ctypes.c_ulonglong), ("FileId", ctypes.c_ubyte * 16)]
        info = FILE_ID_INFO()
        if not k32.GetFileInformationByHandleEx(h, 18, ctypes.byref(info), ctypes.sizeof(info)):  # FileIdInfo
            return None
        return f"win:{info.VolumeSerialNumber:016x}:{bytes(info.FileId)[::-1].hex()}"
    finally:
        k32.CloseHandle(h)


def compare_ids(recorded: str | None, current: str | None) -> str:
    """match | mismatch | unknown.  Linux: a different device is 'unknown' (an overlay or
    bind mount can show another device number for the same inode); only a different inode
    or generation on the same device proves a different file."""
    if not recorded or not current:
        return "unknown"
    if recorded.startswith("lnx:") and current.startswith("lnx:"):
        r, c = recorded.split(":"), current.split(":")
        if len(r) < 5 or len(c) < 5 or r[1:3] != c[1:3]:
            return "unknown"
        if r[3] != c[3]:
            return "mismatch"
        if r[4] and c[4] and r[4] != c[4]:
            return "mismatch"
        return "match"
    return "match" if recorded.lower() == current.lower() else "mismatch"


def _stale(con: sqlite3.Connection, path: str, since_ns: int) -> sqlite3.Row | None:
    """The content observed at ``path`` was removed after ``since_ns`` (deleted or moved
    away) and nothing observed put content back: the file there now is not that one."""
    p = normalize(path)  # each query on one indexed column (path / path2, ts_ns)
    gone = con.execute("SELECT * FROM events WHERE path=? AND ts_ns>? AND kind IN ('unlink','rename')"
                       " ORDER BY ts_ns DESC LIMIT 1", (p, since_ns)).fetchone()
    if not gone:
        return None
    back = con.execute("SELECT 1 FROM events WHERE path=? AND ts_ns>? AND is_write=1 LIMIT 1", (p, gone["ts_ns"])).fetchone()         or con.execute("SELECT 1 FROM events WHERE path2=? AND ts_ns>? AND kind='rename' LIMIT 1", (p, gone["ts_ns"])).fetchone()
    return None if back else gone


# ---------------------------------------------------------------- users
def user_name(user: str | None) -> str | None:
    if not user:
        return None
    try:
        if user.startswith("uid:"):
            import pwd
            return pwd.getpwuid(int(user[4:])).pw_name
        if user.startswith("S-1-") and os.name == "nt":
            import ctypes
            from ctypes import wintypes
            sid = ctypes.c_void_p()
            if not ctypes.windll.advapi32.ConvertStringSidToSidW(user, ctypes.byref(sid)):
                return None
            try:
                name, dom = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
                n1, n2, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
                if ctypes.windll.advapi32.LookupAccountSidW(None, sid, name, ctypes.byref(n1), dom, ctypes.byref(n2),
                                                            ctypes.byref(use)):
                    return f"{dom.value}\\{name.value}" if dom.value else name.value
            finally:
                ctypes.windll.kernel32.LocalFree(sid)
    except Exception:
        return None
    return None


def iso(ns: int | None) -> str | None:
    if not ns:
        return None
    return _dt.datetime.fromtimestamp(ns / 1e9).astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------- history
def file_history(con: sqlite3.Connection, path: str, limit: int = 50) -> list[dict]:
    """What happened to the file, newest first: writes, moves in and out, deletes, and the
    first read by each other process (its consumers)."""
    p = normalize(path)
    rows = con.execute(
        """SELECT e.ts_ns, e.kind, e.path, e.path2, e.is_read, e.is_write, e.api, e.run_id, e.pid AS process_key,
                  COALESCE(e.os_pid, e.pid) AS pid, pr.exe, pr.command, pr.user
           FROM events e LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid
           WHERE e.id IN (SELECT id FROM events WHERE path=? AND (is_write=1 OR is_read=1 OR kind IN ('unlink','rename'))
                          UNION ALL SELECT id FROM events WHERE path2=? AND kind='rename')
           ORDER BY e.ts_ns DESC LIMIT ?""", (p, p, limit * 4)).fetchall()
    out, readers = [], set()
    for r in rows:
        if r["kind"] == "rename":
            action = "moved here" if pkey(r["path2"] or "") == pkey(p) else "moved away"
        elif r["kind"] == "unlink":
            action = "deleted"
        elif r["is_write"]:
            action = "written"
        else:
            if (r["run_id"], r["process_key"]) in readers:
                continue
            readers.add((r["run_id"], r["process_key"]))
            action = "read"
        out.append({"ts_ns": r["ts_ns"], "at": iso(r["ts_ns"]), "action": action, "exe": r["exe"], "pid": r["pid"],
                    "command": r["command"], "user": r["user"], "path": r["path"], "path2": r["path2"],
                    "evidence": r["api"]})
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- the label
def _chain(con, run_id, key) -> list[dict]:
    rows = agents.ancestry(con, run_id, key)
    return [{"exe": r["exe"], "pid": r["os_pid"], "command": r["command"], "user": r["user"]} for r in reversed(rows)]


def _find_by_identity(con: sqlite3.Connection, fid: str | None) -> sqlite3.Row | None:
    if not fid:
        return None
    return con.execute("SELECT * FROM events WHERE file_id=? AND is_write=1 ORDER BY ts_ns DESC LIMIT 1", (fid,)).fetchone()


def explain_file(con: sqlite3.Connection, path: str, *, include_noise: bool = False, history_limit: int = 20,
                 dependents_limit: int = 50) -> dict:
    target = normalize(path)
    exists = os.path.exists(target)
    cur_id = current_file_id(target) if exists else None
    w = qwhy(con, target, include_noise=include_noise)
    note = None
    via_identity = None
    if not w and cur_id:  # a hard link, or a move whyfs did not see: find the file by identity
        ev = _find_by_identity(con, cur_id)
        if ev:
            w2 = qwhy(con, ev["path"], include_noise=include_noise)
            if w2 and w2.get("run_id") == ev["run_id"]:
                w, via_identity = w2, ev["path"]
    label: dict = {"schema": "whyfs-label/1", "path": target, "exists": exists}
    label["history"] = file_history(con, target, limit=history_limit)
    if not w:
        label.update(status="no-record", note="whyfs has no observed origin for this file (created before whyfs "
                     "was running, excluded by the scope policy, or not visible to you)")
        return label
    # the creator's write, under whatever name the file had then (it may have moved since)
    rec = con.execute("SELECT file_id FROM events WHERE run_id=? AND pid=? AND ts_ns=? AND is_write=1 "
                      "ORDER BY file_id IS NULL LIMIT 1",
                      (w.get("run_id"), w.get("process_key"), w.get("ts_ns"))).fetchone() if w.get("run_id") else None
    rec_id = rec["file_id"] if rec else None
    if not via_identity:  # a later move into this path may carry the identity (Windows records it there)
        mv = con.execute("SELECT file_id FROM events WHERE kind='rename' AND path2=? AND ts_ns>=? AND file_id IS NOT NULL "
                         "ORDER BY ts_ns DESC LIMIT 1", (target, w["ts_ns"])).fetchone()
        if mv and (rec_id is None or w.get("renamed_from")):
            rec_id = mv["file_id"]
    idcheck = compare_ids(rec_id, cur_id)
    stale = _stale(con, target, w["ts_ns"]) if not via_identity else None
    label["identity"] = {"current": cur_id, "recorded": rec_id, "check": idcheck}
    if exists and (idcheck == "mismatch" or (idcheck != "match" and stale is not None)):
        why_not = ("the file now at this path has a different identity than the file whyfs observed"
                   if idcheck == "mismatch" else
                   f"the observed file was {'deleted' if stale['kind'] == 'unlink' else 'moved away'} at "
                   f"{iso(stale['ts_ns'])} and the file now here was not observed being written")
        label.update(status="not-observed", note=f"this file's origin was not observed: {why_not}",
                     previous_file_at_path={"written_by": w["exe"], "at": iso(w["ts_ns"]), "command": w.get("command")})
        return label
    if via_identity:
        note = f"found by file identity: the observed writes were to {via_identity} (a hard link or an unobserved move)"
    key, run_id = w.get("process_key"), w.get("run_id")
    creator_row = con.execute("SELECT * FROM processes WHERE run_id=? AND pid=?", (run_id, key)).fetchone() if run_id else None
    user = creator_row["user"] if creator_row else None
    session = agents.session_for(con, run_id, key, w["ts_ns"]) if run_id else None
    first = con.execute("SELECT MIN(ts_ns) FROM events WHERE path=? AND (is_write=1 OR kind='rename')", (target,)).fetchone()[0]
    deps = impact_details(con, target, include_noise=include_noise)[:dependents_limit]
    inputs = list(w.get("inputs") or [])
    label.update({
        "status": "labelled",
        "note": note,
        "created_ns": min(x for x in (first, w["ts_ns"]) if x),
        "created": iso(min(x for x in (first, w["ts_ns"]) if x)),
        "last_written_ns": w["ts_ns"], "last_written": iso(w["ts_ns"]),
        "user": user, "user_name": user_name(user),
        "created_by": {"exe": w["exe"], "pid": w["pid"], "command": w.get("command"), "cwd": w.get("process_cwd"),
                       "process_key": key, "run_id": run_id},
        "process_chain": _chain(con, run_id, key) if run_id else [],
        "inputs": inputs,
        "inputs_hidden": w.get("hidden_input_count", 0),
        "inputs_via_temporaries": w.get("inputs_via_temporaries") or [],
        "shared_by_outputs": w.get("shared_by_outputs", 0),
        "renamed_from": w.get("renamed_from") or [],
        "dependents": deps,
        "agent": None, "intent": None,
    })
    if session:
        label["agent"] = {k: session.get(k) for k in ("agent_name", "agent_version", "session_id", "source", "confidence",
                                                     "evidence", "workspace", "root_process", "started_ns", "ended_ns")}
        label["agent"]["started"] = iso(session.get("started_ns"))
        if session.get("task"):
            label["intent"] = {"task": session["task"], "source": f"supplied by the agent session {session['session_id']} "
                               "when it registered (not verified by whyfs)"}
    if not label["intent"]:
        label["intent"] = {"task": None, "note": "no intent context was provided; whyfs does not infer intent"}
    label["causal_why"] = _causal_sentence(label)
    label["evidence"] = "OS-observed" + ("" if not session else
                                         " + registered agent context" if session["source"] == "registered" else
                                         " + detected agent (process image and command line)")
    return label


def _short(p: str) -> str:
    return os.path.basename(p) or p


def _causal_sentence(lb: dict) -> str:
    exe = _short(lb["created_by"]["exe"] or "?")
    ins = lb["inputs"]
    s = f"{_short(lb['path'])} exists because {exe} wrote it"
    if ins:
        s += " after reading " + ", ".join(_short(p) for p in ins[:4]) + (f" and {len(ins) - 4} more" if len(ins) > 4 else "")
    elif not lb.get("renamed_from"):
        s += " (no input files were observed)"
    if lb.get("renamed_from"):
        s += f"; it was moved here from {lb['renamed_from'][0]['from']}"
    if lb.get("shared_by_outputs"):
        s += f"; the inputs are shared with {lb['shared_by_outputs']} other outputs of the same process"
    return s + "."


def render_label(lb: dict) -> str:
    L = [f"File:     {lb['path']}"]
    if lb["status"] != "labelled":
        L.append(f"Status:   {lb['status']}: {lb.get('note')}")
        if lb.get("previous_file_at_path"):
            pv = lb["previous_file_at_path"]
            L.append(f"Previous file at this path: written by {pv['written_by']} at {pv['at']}")
        return "\n".join(L)
    L.append(f"Created:  {lb['created']}" + ("" if lb["created"] == lb["last_written"] else f"   (last written {lb['last_written']})"))
    L.append(f"User:     {lb.get('user_name') or lb.get('user') or 'unknown'}")
    L.append(f"Created by: {lb['created_by']['exe']}  (pid {lb['created_by']['pid']})")
    if lb["created_by"].get("command"):
        L.append(f"  command: {lb['created_by']['command']}")
    chain = [_short(c["exe"] or "?") for c in lb["process_chain"]]
    while chain and chain[0] == "?":  # ancestors that exited before whyfs started: image unknown
        chain.pop(0)
    if chain:
        L.append("Process chain: " + " → ".join(chain))
    a = lb.get("agent")
    if a:
        L.append(f"Agent:    {a['agent_name']}" + (f" {a['agent_version']}" if a.get("agent_version") else "") +
                 f"   ({a['source']}: {a['evidence'] or a['confidence']})")
        L.append(f"Session:  {a['session_id']}")
    else:
        L.append("Agent:    none observed")
    it = lb["intent"]
    L.append(f"Task:     {it['task']}   [{it['source']}]" if it.get("task") else f"Task:     — ({it['note']})")
    L.append("Why:      " + lb["causal_why"])
    if lb["inputs"]:
        L.append("Inputs:")
        L.extend(f"  {p}" for p in lb["inputs"][:20])
        if len(lb["inputs"]) > 20:
            L.append(f"  … {len(lb['inputs']) - 20} more")
    if lb.get("inputs_hidden"):
        L.append(f"  ({lb['inputs_hidden']} system/library inputs hidden; --all shows them)")
    if lb["history"]:
        L.append("History:")
        for h in lb["history"][:12]:
            extra = (f"  (from {h['path']})" if h["action"] == "moved here" else
                     f"  (to {h['path2']})" if h["action"] == "moved away" else "")
            L.append(f"  {h['at']}  {h['action']:<10} by {_short(h.get('exe') or '?')}{extra}")
    if lb["dependents"]:
        L.append("Used by:")
        for d in lb["dependents"][:10]:
            L.append(f"  {d.get('to')}  (via {_short(d.get('exe') or '?')})")
    if lb.get("note"):
        L.append(f"Note:     {lb['note']}")
    L.append(f"Evidence: {lb['evidence']}; identity {lb['identity']['check']}")
    return "\n".join(L)
