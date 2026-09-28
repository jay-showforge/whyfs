"""The human form of a provenance label (whyfs-label/1).  Import-light: `whyfs label` prints
it in a fresh process, whose start-up time is most of the command's latency."""
from __future__ import annotations

import os


def _short(p: str) -> str:
    return os.path.basename(p) or p


def render_label(lb: dict) -> str:
    L = [f"File:     {lb['path']}"]
    if lb["status"] != "labelled":
        L.append(f"Status:   {lb['status']}: {lb.get('note')}")
        if lb.get("previous_file_at_path"):
            pv = lb["previous_file_at_path"]
            L.append(f"Previous file at this path: written by {pv['written_by']} at {pv['at']}")
        L.extend(_render_impact_tail(lb))
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
    L.extend(_render_impact_tail(lb))
    if lb.get("note"):
        L.append(f"Note:     {lb['note']}")
    L.append(f"Evidence: {lb['evidence']}; identity {lb['identity']['check']}")
    return "\n".join(L)


def _render_impact_tail(lb: dict) -> list[str]:
    L = []
    im = lb.get("impact")
    if im:
        L.append("If removed or changed: " + im["summary"])
    obs = lb.get("observation")
    if obs:
        L.append("Provenance: " + ("complete: whyfs was recording, without loss, when this file was created"
                                   if obs["complete"] else "incomplete — " + "; ".join(obs["gaps"])))
        if obs.get("later_gaps"):
            L.append("Since then: " + "; ".join(obs["later_gaps"]) + " (later history and dependents may be missing)")
    if lb.get("scope", {}).get("recent_only"):
        L.append("Long history: readers and dependents above come from the most recent activity; "
                 "`whyfs history FILE --limit 0` and `whyfs impact FILE` show all of it.")
    return L
