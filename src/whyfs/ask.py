"""`whyfs ask`: one provenance question, one small JSON answer (docs/AGENT_PROTOCOL.md, "Questions").

For AI agents and scripts.  Each question is a compact projection over the same evidence and the
same rules as the label, `why`, `impact` and the session queries: nothing here decides provenance
differently, and every qualifier that could change a decision is kept (observed or not, complete
or not, registered or detected agent, supplied task or none, observed dependents are not proof of
safety).  Lists are bounded with counts; full detail stays in `whyfs label FILE --json`,
`whyfs impact`, `whyfs history` and the API.

Questions
  origin FILE       who or what wrote it, and whether attribution is justified (and why not)
  sources FILE      what to edit: the observed generation chain down to its source inputs
  dependents FILE   observed downstream outputs (never proof that nothing else depends on it)
  session           files written by the sessions whose supplied task, id or agent matches
  changes [DIR]     recent changes under DIR, grouped by the command that made them
"""
from __future__ import annotations

import os
import sqlite3
import time

from . import agents, label
from .query import impact_details, pkey
from .query import why as qwhy
from .store import normalize

VERSION = 1
LIST_MAX = 20           # files per list; the rest are counted
CHAIN_MAX = 8           # generation steps shown by `sources`
CMD_MAX = 160           # command lines are cut to this many characters
VCS_DIRS = {".git", ".hg", ".svn"}
SHELLS = {"sh", "bash", "dash", "zsh", "fish", "ksh", "cmd.exe", "powershell.exe", "pwsh", "pwsh.exe"}

INDEX = """whyfs ask QUESTION ...   one provenance question, one small JSON answer (for AI agents and scripts)
  origin FILE        who or what wrote it; whether its origin was observed (attributable, or why not)
  sources FILE       what to edit: the observed generation chain down to its source inputs
  dependents FILE    observed downstream outputs (observed only: never proof that removal is safe)
  session --task TEXT | --session ID | --agent NAME [--under DIR]   files an agent session wrote
  changes [DIR] [--since 2h]    recent changes under DIR, grouped by the command that made them
Paths under the current directory are relative to it.  Full evidence: whyfs label FILE --json.
Tool definitions (JSON): whyfs ask --schema"""

SCHEMA = {
    "name": "whyfs_ask", "version": VERSION,
    "description": "Local file provenance (WhyFS): one question, one small JSON answer.",
    "questions": {
        "origin": {"description": "Who or what wrote FILE, and whether attribution is justified (attributable=false "
                                  "with a reason when the origin was not observed).",
                   "params": {"path": "file"}},
        "sources": {"description": "What to edit: FILE's observed generation chain and the source inputs at its end.",
                    "params": {"path": "file"}},
        "dependents": {"description": "Observed downstream outputs of FILE.  Observed only: an empty list is never "
                                      "proof that removing or changing FILE is safe.",
                       "params": {"path": "file"}},
        "session": {"description": "Files written by the agent sessions whose supplied task, id or agent matches.",
                    "params": {"task": "text in the task the session supplied", "session": "session id",
                               "agent": "agent name", "under": "directory (optional)", "since": "e.g. 2h (optional)"}},
        "changes": {"description": "Recent changes under a directory, grouped by the command that made them.",
                    "params": {"under": "directory (default: current)", "since": "e.g. 2h (default 24h)"}},
    },
}


class ApiError(Exception):
    pass


# ---------------------------------------------------------------- projection helpers
class _P:
    """Paths under ``base`` shown relative to it; others absolute."""

    def __init__(self, base: str | None):
        self.base = normalize(base) if base else None

    def __call__(self, p: str | None) -> str | None:
        if not p or not self.base:
            return p
        b = self.base.rstrip(os.sep) + os.sep
        if pkey(p).startswith(pkey(b)):
            return p[len(b):]
        return "." if pkey(p) == pkey(self.base) else p


def _cmd(c: str | None) -> str | None:
    if not c:
        return None
    c = " ".join(c.split())
    return c if len(c) <= CMD_MAX else c[:CMD_MAX - 1] + "…"


def _prog(exe: str | None) -> str | None:
    return os.path.basename(exe) if exe else None


def _vcs(p: str) -> bool:
    return any(part in VCS_DIRS for part in p.replace("\\", "/").split("/"))


def _bounded(items: list, key: str, out: dict) -> None:
    out[key] = items[:LIST_MAX]
    if len(items) > LIST_MAX:
        out[key + "_more"] = len(items) - LIST_MAX


def _agent(a: dict | None) -> dict | None:
    """The label's agent, compact: registered (the agent said so) or detected (its program was
    recognised); a task only when the session supplied one (never inferred)."""
    if not a:
        return None
    return {"name": a.get("agent_name"), "session": a.get("session_id"), "source": a.get("source")}


# ---------------------------------------------------------------- origin
def origin(con: sqlite3.Connection, path: str, P: _P, lb: dict | None = None) -> dict:
    lb = lb or label.explain_file(con, path)
    out: dict = {"q": "origin", "path": P(lb["path"])}
    if not lb["exists"]:
        out["exists"] = False
    obs = lb.get("observation") or {}
    st = lb["status"]
    if st == "labelled":
        cb = lb["created_by"]
        out.update(status="observed", attributable=True,
                   written_by={"cmd": _cmd(cb.get("command")), "program": _prog(cb.get("exe")), "at": lb["last_written"]})
        if lb.get("created") and lb["created"] != lb["last_written"]:
            out["created"] = lb["created"]
        if lb.get("user_name") or lb.get("user"):
            out["user"] = lb.get("user_name") or lb.get("user")
        moved = [P(r["from"]) for r in lb.get("renamed_from") or []]
        if moved:
            out["moved_from"] = moved[:LIST_MAX]
        ag = _agent(lb.get("agent"))
        if ag:
            task = (lb.get("intent") or {}).get("task")
            if task:
                ag["task"] = task            # as supplied by the session, not verified
            out["agent"] = ag
        else:
            out["agent"] = None
        ident = (lb.get("identity") or {}).get("check")
        if ident and ident != "match":
            out["identity"] = ident
        out["complete"] = bool(obs.get("complete"))
        if obs.get("gaps"):
            out["gaps"] = obs["gaps"][:3]
        if obs.get("later_gaps"):
            out["later_gaps"] = obs["later_gaps"][:3]
        if lb.get("note"):   # e.g. found by file identity (a hard link, or an unobserved move)
            out["note"] = lb["note"]
        return out
    out["attributable"] = False
    out["complete"] = False
    if st == "not-observed":
        ident = (lb.get("identity") or {}).get("check")
        out["status"] = "replaced"
        out["reason"] = "identity_mismatch" if ident == "mismatch" else "removed_then_unobserved"
        prev = lb.get("previous_file_at_path") or {}
        out["previous_file"] = {"cmd": _cmd(prev.get("command")), "program": _prog(prev.get("written_by")), "at": prev.get("at")}
        out["note"] = lb.get("note")
        return out
    # no record of this file's origin
    out["status"] = "unknown"
    g = dict(obs.get("file_time_in_gap") or {}) or None
    if g:
        g["which"] = str(g.get("which") or "time").replace(" ", "_")   # created | last_modified
    if not lb["exists"]:
        out["reason"] = "no_record"
    elif g and g.get("gap_from") is None:
        out["reason"] = "before_recording"
        out["file_time"] = {g.get("which"): g.get("time")}
        out["recording_since"] = g.get("gap_to")
    elif g:
        out["reason"] = "observation_gap"
        out["file_time"] = {g.get("which"): g.get("time")}
        out["gap"] = {"from": g.get("gap_from"), "to": g.get("gap_to"), "after_crash": bool(g.get("after_crash"))}
    else:
        out["reason"] = "no_observed_write"
        out["possible"] = ["created before whyfs recorded it", "outside the recording scope",
                           "written by a process you cannot see"]
    if obs.get("observing_since"):
        out.setdefault("recording_since", obs["observing_since"])
    return out


# ---------------------------------------------------------------- sources
def _generated(w: dict | None) -> bool:
    """A file is generated (rebuild it, edit its sources) when an observed process wrote it after
    reading inputs, and the process did not write so many outputs that which input produced which
    output is unknowable (label.AMBIGUOUS_SHARED, the label's rule)."""
    return bool(w and w.get("run_id") and (w.get("inputs") or w.get("inputs_via_temporaries"))
                and (w.get("shared_by_outputs") or 0) <= label.AMBIGUOUS_SHARED)


def sources(con: sqlite3.Connection, path: str, P: _P) -> dict:
    target = normalize(path)
    o = origin(con, target, P)
    out: dict = {"q": "sources", "path": o["path"], "status": o["status"], "attributable": o["attributable"]}
    if o["status"] != "observed":
        out.update({k: v for k, v in o.items() if k in ("reason", "gap", "file_time", "recording_since", "possible",
                                                        "previous_file", "note", "exists")})
        out["edit"] = None
        return out
    w0 = qwhy(con, target)
    out["generated"] = _generated(w0)
    chain, edit, seen = [], [], {pkey(target)}
    frontier = [target]
    hidden = 0
    while frontier and len(chain) < CHAIN_MAX:
        nxt = []
        for f in frontier:
            w = w0 if f == target else qwhy(con, f)
            if f != target and not _generated(w):
                edit.append(P(f))
                continue
            if f == target and not out["generated"]:
                edit.append(P(f))
                if w and (w.get("shared_by_outputs") or 0) > label.AMBIGUOUS_SHARED:
                    out["ambiguous"] = {"outputs_of_writer": w["shared_by_outputs"] + 1,
                                        "note": "its writer wrote many files: which input produced this one is not observable"}
                continue
            ins = list(dict.fromkeys((w.get("inputs") or []) + (w.get("inputs_via_temporaries") or [])))
            step = {"file": P(f), "by": _cmd(w.get("command"))}
            _bounded([P(i) for i in ins], "inputs", step)
            if w.get("renamed_from"):
                step["moved_from"] = [P(r["from"]) for r in w["renamed_from"]][:5]
            if w.get("shared_by_outputs"):
                step["shared_with_outputs"] = w["shared_by_outputs"]
            hidden += w.get("hidden_input_count") or 0
            chain.append(step)
            for i in ins:
                if pkey(i) not in seen:
                    seen.add(pkey(i))
                    nxt.append(i)
            if len(chain) >= CHAIN_MAX:
                break
        frontier = nxt
    if frontier:
        out["chain_truncated"] = True
    out["chain"] = chain
    _bounded(list(dict.fromkeys(edit)), "edit", out)
    if hidden:
        out["hidden_inputs"] = hidden   # system/runtime/dependency reads (whyfs why --all shows them)
    if not o.get("complete"):
        out["complete"] = False
        if o.get("gaps"):
            out["gaps"] = o["gaps"]
    return out


# ---------------------------------------------------------------- dependents
def _reader_command(con: sqlite3.Connection, run_id: str, src: str, dst: str) -> str | None:
    r = con.execute(
        "SELECT pr.command, pr.exe FROM events e JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid "
        "WHERE e.run_id=? AND e.path=? AND (e.is_read=1 OR e.kind='rename') AND e.pid IN "
        "(SELECT pid FROM events WHERE run_id=? AND ((path=? AND is_write=1) OR (path2=? AND kind='rename'))) LIMIT 1",
        (run_id, src, run_id, dst, dst)).fetchone()
    return (_cmd(r["command"]) or _prog(r["exe"])) if r else None


def dependents(con: sqlite3.Connection, path: str, P: _P) -> dict:
    target = normalize(path)
    edges = impact_details(con, target)
    out: dict = {"q": "dependents", "path": P(target)}
    rows, vcs, seen = [], set(), set()
    # A reader that wrote more files after reading this one than the label's ambiguity limit (an
    # agent or an IDE writing its own state, an indexer) is summarised: the evidence says each of
    # those outputs is only "one of N", so they are counted per program, and so is everything
    # reached through them, instead of listed.
    broad: dict = {}
    through_broad: set = set()
    for e in edges:
        to = e["to"]
        if pkey(e["from"]) in through_broad or (e.get("shared") or 0) > label.AMBIGUOUS_SHARED:
            if pkey(to) not in through_broad and not _vcs(to):
                key = "through a broad reader's outputs" if pkey(e["from"]) in through_broad else \
                    (_reader_command(con, e["run_id"], e["from"], to) or _prog(e.get("exe")))
                broad[key] = broad.get(key, 0) + 1
            through_broad.add(pkey(to))
            continue
        if _vcs(to):
            vcs.add(pkey(to))
            continue
        if pkey(to) in seen:
            continue
        seen.add(pkey(to))
        rename = str(e.get("exe") or "").endswith(" (rename)")
        row = {"file": P(to)}
        if pkey(e["from"]) != pkey(target):
            row["from"] = P(e["from"])
        row["via"] = ("moved by " + _prog(e["exe"][:-9]) if rename else
                      _reader_command(con, e["run_id"], e["from"], to) or _prog(e.get("exe")))
        if e.get("shared"):
            row["one_of"] = e["shared"]   # the reader wrote this many outputs after reading: which used it is unknown
        rows.append(row)
    _bounded(rows, "observed", out)
    out["count"] = len(rows)
    if broad:
        items = sorted(broad.items(), key=lambda kv: -kv[1])
        out["broad_readers"] = [{"via": k, "wrote": n} for k, n in items[:5]]
        if len(items) > 5:
            out["broad_readers_more"] = len(items) - 5
        out["broad_readers_note"] = ("these programs wrote many files after reading it; whether any of those files "
                                     "used it is not observable (whyfs impact FILE lists them)")
    if vcs:
        out["vcs_metadata"] = len(vcs)   # version-control bookkeeping written after reading it (e.g. git status)
    out["observed_only"] = True
    out["not_proof_of_safety"] = True    # no observed dependent never means it is safe to remove or change
    w = qwhy(con, target)
    obs = label.observation(con, w["ts_ns"] if w and w.get("run_id") else None, path=target,
                            status="labelled" if w and w.get("run_id") else "no-record")
    later = obs.get("later_gaps") if w and w.get("run_id") else obs.get("gaps")
    if later:
        out["gaps_since_written"] = later[:3]
    return out


# ---------------------------------------------------------------- session
def _registered_sessions(con, task: str | None, sid: str | None, agent: str | None, since: int) -> list[dict]:
    q, args = "SELECT * FROM agent_sessions WHERE started_ns>=?", [since]
    if sid:
        q += " AND session_id=?"
        args.append(sid)
    if task:
        q += " AND task IS NOT NULL AND lower(task) LIKE ? ESCAPE '!'"
        args.append("%" + task.lower().replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%")
    if agent:
        q += " AND lower(agent_name) LIKE ? ESCAPE '!'"
        args.append("%" + agent.lower().replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%")
    return [dict(r) for r in con.execute(q + " ORDER BY started_ns DESC LIMIT 50", args)]


def session(con: sqlite3.Connection, params: dict, P: _P, ctx: dict | None = None) -> dict:
    from . import api
    task, sid, agent = params.get("task"), params.get("session"), params.get("agent")
    if not (task or sid or agent):
        raise ApiError("session: give task, session or agent")
    under = normalize(params["under"]) if params.get("under") else None
    since = int(params.get("since_ns") or 0)
    found = _registered_sessions(con, task, sid, agent, since)
    if not task and (agent or (sid and sid.startswith("detected:"))):  # detected sessions have no task
        for d in api.op_list_agent_sessions(ctx or {}, con, {"agent": agent, "since_ns": since, "limit": 200}):
            if d["source"] == "detected" and (not sid or d["session_id"] == sid):
                found.append(d)
    out: dict = {"q": "session"}
    per: list = []   # (session, its files) for the sessions considered
    mine: set = set()
    for s in found[:20]:
        fl = []
        for f in api.op_get_files_by_agent(ctx or {}, con, {"session_id": s["session_id"], "limit": 5000}):
            p = f["path"]
            if (under and not pkey(p).startswith(pkey(under.rstrip(os.sep) + os.sep))) or _vcs(p) or pkey(p) in mine:
                continue
            mine.add(pkey(p))
            fl.append({"path": P(p), "action": f["action"]})
        per.append((s, fl))
    if under:  # sessions that wrote nothing there are counted, not listed
        elsewhere = [x for x in per if not x[1]]
        per = [x for x in per if x[1]]
        if elsewhere or len(found) > 20:
            out["matched_elsewhere"] = len(elsewhere) + max(0, len(found) - 20)
    matched, files = [], []
    for i, (s, fl) in enumerate(per[:5]):
        m = {"session": s["session_id"], "agent": s.get("agent_name"), "source": s.get("source"),
             "started": label.iso(s.get("started_ns"))}
        if s.get("task"):
            m["task"] = s["task"]            # as supplied by the session (whyfs never infers a task)
        matched.append(m)
        for row in fl:
            if len(per) > 1:
                row["session"] = i
            files.append(row)
    out["matched"] = matched
    if len(per) > 5:
        out["matched_more"] = len(per) - 5
    _bounded(files, "files", out)
    if under:
        others = []
        for r in api.op_get_recent_changes(ctx or {}, con, {"path_prefix": under, "since_ns": since or 1, "limit": 200}):
            if pkey(r["path"]) in mine or _vcs(r["path"]):
                continue
            ag = r.get("agent") or {}
            if ag.get("session_id") in {s["session_id"] for s in found}:
                continue
            others.append({"path": P(r["path"]), "by": _prog(r.get("exe")), "agent": ag.get("agent_name")})
        _bounded(others, "other_writers_under", out)
    if not matched:
        out["note"] = ("no session matches" + (" with files there" if under and found else "") +
                       "; a task is known only when an agent session supplied one (whyfs agent start --task) "
                       "and whyfs never infers one")
    return out


# ---------------------------------------------------------------- changes
def _image_at(con: sqlite3.Connection, run_id: str, key: int, at_ns: int | None) -> str | None:
    """A process's program image at a time: its latest recorded exec up to then (a shell that
    later executes its last command in place keeps its own image before that)."""
    if at_ns is None:
        return None
    r = con.execute("SELECT path FROM events WHERE run_id=? AND pid=? AND kind='exec' AND ts_ns<=? "
                    "ORDER BY ts_ns DESC LIMIT 1", (run_id, key, at_ns)).fetchone()
    return r[0] if r else None



def changes(con: sqlite3.Connection, params: dict, P: _P) -> dict:
    under = normalize(params.get("under") or os.getcwd())
    since = int(params.get("since_ns") or (time.time_ns() - 24 * 3600 * 10**9))
    prefix = under.rstrip(os.sep) + os.sep
    esc = prefix.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
    rows = con.execute(
        "SELECT e.run_id, e.pid, e.kind, e.path, e.path2, e.ts_ns, pr.parent_key FROM events e "
        "LEFT JOIN processes pr ON pr.run_id=e.run_id AND pr.pid=e.pid "
        "WHERE e.ts_ns>=? AND (e.is_write=1 OR e.kind IN ('rename','unlink')) AND e.api NOT LIKE '%derived-temp' "
        "AND (e.path LIKE ? ESCAPE '!' OR e.path2 LIKE ? ESCAPE '!') ORDER BY e.ts_ns DESC LIMIT 5000",
        (since, esc, esc)).fetchall()
    proc: dict = {}

    def pinfo(run_id, key):
        k = (run_id, key)
        if k not in proc:
            r = con.execute("SELECT exe, command, parent_key FROM processes WHERE run_id=? AND pid=?", k).fetchone()
            proc[k] = dict(r) if r else {"exe": None, "command": None, "parent_key": None}
        return proc[k]

    fs: dict = {}

    def first_seen(run_id, key):
        k = (run_id, key)
        if k not in fs:
            r = con.execute("SELECT first_seen_ns FROM processes WHERE run_id=? AND pid=?", k).fetchone()
            fs[k] = r[0] if r else None
        return fs[k]

    groups: dict = {}
    order: list = []
    vcs, seen = set(), set()
    for r in rows:
        target = r["path2"] if r["kind"] == "rename" else r["path"]
        if not target or not pkey(target).startswith(pkey(prefix)):
            continue
        if _vcs(target):
            vcs.add(pkey(target))
            continue
        if pkey(target) in seen:     # newest action per file
            continue
        seen.add(pkey(target))
        # a build driver's children join its group (make -> cc; build.py -> stage scripts); a shell
        # or an agent is not a build driver
        key = r["pid"]
        par = r["parent_key"]
        if par is not None:
            pi = pinfo(r["run_id"], par)
            img = _image_at(con, r["run_id"], par, first_seen(r["run_id"], r["pid"])) or pi["exe"]
            if img and _prog(img).lower() not in SHELLS and not agents.detect(img, pi["command"]) \
                    and img == pi["exe"]:  # the parent was this build driver when it started the writer
                key = par
        gk = (r["run_id"], key)
        if gk not in groups:
            g = pinfo(*gk)
            s = agents.session_for(con, r["run_id"], key, r["ts_ns"])
            groups[gk] = {"by": _cmd(g["command"]) or _prog(g["exe"]), "at": label.iso(r["ts_ns"]),
                          "agent": ({"name": s["agent_name"], "source": s["source"]} | ({"task": s["task"]} if s.get("task") else {}))
                          if s else None, "_files": {}}
            order.append(gk)
        act = {"io": "written", "rename": "moved_here", "unlink": "deleted"}[r["kind"]]
        groups[gk]["_files"].setdefault(act, []).append(P(target))
    out: dict = {"q": "changes", "under": P(under) or ".", "since": label.iso(since)}
    shown = []
    for gk in order[:5]:
        g = groups[gk]
        fl = g.pop("_files")
        for act, lst in fl.items():
            g[act] = lst[:LIST_MAX]
            if len(lst) > LIST_MAX:
                g[act + "_more"] = len(lst) - LIST_MAX
        shown.append(g)
    out["groups"] = shown
    if len(order) > 5:
        out["more_groups"] = len(order) - 5
    if vcs:
        out["vcs_metadata"] = len(vcs)
    from .observation import gaps as _gaps, intervals
    gl = _gaps(intervals(con), since)
    if gl:
        out["recording_gaps"] = [{"from": label.iso(g["from"]), "to": label.iso(g["to"]) if g["to"] else None,
                                  "after_crash": g["after_crash"]} for g in gl[:3]]
    return out


# ---------------------------------------------------------------- entry point
def ask(con: sqlite3.Connection, question: str, params: dict, ctx: dict | None = None) -> dict:
    P = _P(params.get("base"))
    if question in ("origin", "sources", "dependents"):
        p = params.get("path")
        if not isinstance(p, str) or not p:
            raise ApiError(f"{question}: path required")
        p = normalize(p)
        return {"origin": lambda: origin(con, p, P), "sources": lambda: sources(con, p, P),
                "dependents": lambda: dependents(con, p, P)}[question]()
    if question == "session":
        return session(con, params, P, ctx)
    if question == "changes":
        return changes(con, params, P)
    raise ApiError(f"unknown question {question!r}; questions: origin, sources, dependents, session, changes")
