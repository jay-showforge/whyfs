"""Profile the frozen agent-efficiency pilot (read-only): every WhyFS invocation in the treatment
transcripts, the command-output bytes it returned, and repeated / discovery calls."""
import json
import re
import sys
from collections import Counter
from pathlib import Path

B = Path(r"C:\Users\ftmon\Downloads\githubtestwhyfs\results\agent-efficiency-pilot")
OPS = ("why", "history", "impact", "recent", "status", "label", "search", "api", "--help", "agent", "stats", "doctor")


def whyfs_ops(cmd: str) -> list[str]:
    out = []
    for m in re.finditer(r"whyfs(?:\s+(--help|-h|[a-z_-]+))?(?:\s+([a-z_]+))?", cmd):
        op = m.group(1) or "(bare)"
        if op == "-h":
            op = "--help"
        if op == "api" and m.group(2):
            op = f"api:{m.group(2)}"
        out.append(op)
    return out


rows = []
for t in sorted((B / "transcripts").glob("*-whyfs.jsonl")):
    case = t.stem.split("-")[1]
    calls = []
    for line in t.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue  # the client's own non-JSON lines
        it = e.get("item") or {}
        if e.get("type") != "item.completed" or it.get("type") != "command_execution":
            continue
        cmd, outp = it.get("command", ""), it.get("aggregated_output") or ""
        if "whyfs" not in cmd:
            continue
        ops = whyfs_ops(cmd)
        calls.append({"ops": ops, "bytes": len(outp.encode()), "cmd": cmd[:300], "out_head": outp[:200]})
    rows.append({"case": case, "commands": len(calls), "ops": Counter(o for c in calls for o in c["ops"]),
                 "whyfs_bytes": sum(c["bytes"] for c in calls), "calls": calls})

json.dump(rows, open(sys.argv[1], "w"), indent=1, default=str)
for r in rows:
    print(f"{r['case']}: {r['commands']} whyfs commands, {sum(r['ops'].values())} ops, {r['whyfs_bytes']} bytes: {dict(r['ops'])}")
    for c in r["calls"]:
        print(f"    {c['bytes']:6d} B  {' '.join(c['ops'])}")
