"""Interface-size comparison on the agent-efficiency pilot's own fixtures (NOT an agent benchmark).

  sudo python3 scripts/agent_interface_size.py --pilot DIR --calls results/agent-interface-v2/benchmark-whyfs-calls.json \
      --user uid:1001 --out results/agent-interface-v2

For each of the ten task classes, on one read-only copy of the machine store (so old and new see
the same evidence), with the benchmark user's view:
  old: the existing JSON answers an agent needs for that question (`whyfs label/why/impact/recent
       --json`, `whyfs api list_agent_sessions`), as those commands print them;
  new: the `whyfs ask` answer(s), as `whyfs ask` prints them;
and, for reference, the WhyFS calls and bytes the pilot's treatment transcripts actually show.
Bytes are UTF-8 bytes of command output: an interface-size measure, not token usage.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from whyfs import api, ask, label  # noqa: E402
from whyfs.access import restrict  # noqa: E402
from whyfs.query import impact_details  # noqa: E402
from whyfs.query import why as qwhy  # noqa: E402
from whyfs.store import connect  # noqa: E402

MACHINE_DB = Path("/var/lib/whyfs/machine/.whyfs/whyfs.db")

# per task class: the question(s) the task asks, old-interface calls and new `whyfs ask` calls
CASES = {
    "case01": ("generated-artifact", [("label", "dist/banner.txt"), ("why", "dist/banner.txt")],
               [("sources", {"path": "dist/banner.txt"})]),
    "case02": ("generated-intermediate", [("why", "dist/release.txt"), ("why", ".build/release.json"),
                                          ("label", "dist/release.txt")],
               [("sources", {"path": "dist/release.txt"})]),
    "case03": ("dependency-impact", [("impact", "src/colors.json")], [("dependents", {"path": "src/colors.json"})]),
    "case04": ("stale-output", [("why", "dist/mobile.json"), ("why", "dist/web.json"), ("label", "dist/mobile.json")],
               [("sources", {"path": "dist/mobile.json"}), ("sources", {"path": "dist/web.json"})]),
    "case05": ("agent-produced-files", [("sessions", None), ("recent", "work")],
               [("session", {"task": "Dependency audit for checkout", "under": "work"})]),
    "case06": ("rename-lineage", [("why", "dist/summary.txt"), ("label", "dist/summary.txt")],
               [("sources", {"path": "dist/summary.txt"})]),
    "case07": ("observation-gap", [("why", "vendor/cache/module.dat"), ("label", "vendor/cache/module.dat")],
               [("origin", {"path": "vendor/cache/module.dat"})]),
    "case08": ("multiple-generators", [("why", "dist/package.json"), ("label", "dist/package.json")],
               [("origin", {"path": "dist/package.json"})]),
    "case09": ("downstream-safety", [("impact", "cache/schema.idx"), ("label", "cache/schema.idx")],
               [("dependents", {"path": "cache/schema.idx"})]),
    "case10": ("recent-build", [("recent", ".")], [("changes", {"under": "."})]),
}


def cli_json(obj, indent=2) -> int:  # as the existing commands print JSON
    return len((json.dumps(obj, indent=indent, default=str) + "\n").encode())


def ask_json(obj) -> int:  # as `whyfs ask` prints it
    return len((json.dumps(obj, ensure_ascii=False, separators=(", ", ": ")) + "\n").encode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", required=True, help="the pilot's scenario root (…/cases/caseNN-whyfs below it)")
    ap.add_argument("--calls", required=True)
    ap.add_argument("--user", default="uid:1001")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    observed = {r["case"]: r for r in json.loads(Path(a.calls).read_text())}
    with tempfile.TemporaryDirectory() as t:
        root = Path(t)
        (root / ".whyfs").mkdir()
        src = sqlite3.connect(f"file:{MACHINE_DB}?mode=ro", uri=True)
        dst = sqlite3.connect(root / ".whyfs" / "whyfs.db")
        src.backup(dst)
        src.close()
        dst.close()
        con = connect(root)
        restrict(con, a.user)
        ctx = {"user": a.user, "admin": False, "pid": 0}
        rows = []
        for case, (name, old_calls, new_calls) in CASES.items():
            d = Path(a.pilot) / "cases" / f"{case}-whyfs"
            old_b, old_detail = 0, []
            for op, rel in old_calls:
                p = str(d / rel) if rel else None
                if op == "label":
                    n = cli_json(label.explain_file(con, p))
                elif op == "why":
                    n = cli_json(qwhy(con, p))
                elif op == "impact":
                    n = cli_json(impact_details(con, p))
                elif op == "recent":
                    n = cli_json(api.op_get_recent_changes(ctx, con, {"path_prefix": p, "limit": 50,
                                                                      "since_ns": 1}))
                elif op == "sessions":
                    n = cli_json({"v": 1, "ok": True, "result": api.op_list_agent_sessions(ctx, con, {})})
                old_b += n
                old_detail.append({"call": f"{op} {rel or ''}".strip(), "bytes": n})
            new_b, new_detail, answers = 0, [], []
            for q, params in new_calls:
                pr = {"base": str(d), **{k: (str(d / v) if k in ("path", "under") else v) for k, v in params.items()}}
                ans = ask.ask(con, q, pr, ctx)
                n = ask_json(ans)
                new_b += n
                new_detail.append({"call": f"ask {q} " + " ".join(f"{k}={v}" for k, v in params.items()), "bytes": n})
                answers.append(ans)
            ob = observed.get(case, {})
            rows.append({"case": case, "task_class": name,
                         "pilot_observed": {"whyfs_commands": ob.get("commands", 0),
                                            "whyfs_operations": sum(ob.get("ops", {}).values()) if ob else 0,
                                            "bytes": ob.get("whyfs_bytes", 0)},
                         "old_equivalent": {"calls": len(old_calls), "bytes": old_b, "detail": old_detail},
                         "new": {"calls": len(new_calls), "bytes": new_b, "detail": new_detail, "answers": answers},
                         "reduction_vs_old_equivalent_percent": round((1 - new_b / old_b) * 100, 1) if old_b else None,
                         "reduction_vs_pilot_observed_percent": round((1 - new_b / ob["whyfs_bytes"]) * 100, 1)
                         if ob.get("whyfs_bytes") else None})
        con.close()
    from whyfs.cli import parser
    import contextlib
    import io
    helps = {}
    for argv in (["--help"], ["ask"]):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
            if argv == ["ask"]:
                print(ask.INDEX)
            else:
                parser().parse_args(argv)
        helps[" ".join(argv)] = len(buf.getvalue().encode())
    report = {"measure": "UTF-8 bytes of command output (interface size), not tokens", "store_copy_of": str(MACHINE_DB),
              "view": a.user, "cases": rows, "discovery_bytes": helps}
    out = Path(a.out)
    (out / "interface-size.json").write_text(json.dumps(report, indent=1, default=str) + "\n")
    lines = ["| case | task class | pilot: WhyFS commands / bytes | old equivalent: calls / bytes | new `whyfs ask`: calls / bytes "
             "| reduction vs old equivalent | reduction vs pilot bytes |", "|---|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        po, oe, nw = r["pilot_observed"], r["old_equivalent"], r["new"]
        lines.append(f"| {r['case']} | {r['task_class']} | {po['whyfs_commands']} / {po['bytes']:,} | {oe['calls']} / "
                     f"{oe['bytes']:,} | {nw['calls']} / {nw['bytes']:,} | {r['reduction_vs_old_equivalent_percent']} % | "
                     f"{r['reduction_vs_pilot_observed_percent'] if r['reduction_vs_pilot_observed_percent'] is not None else 'n/a'}"
                     f"{' %' if r['reduction_vs_pilot_observed_percent'] is not None else ''} |")
    tot_o = sum(r["old_equivalent"]["bytes"] for r in rows)
    tot_n = sum(r["new"]["bytes"] for r in rows)
    tot_p = sum(r["pilot_observed"]["bytes"] for r in rows)
    lines.append(f"| **total** | | {tot_p:,} | {tot_o:,} | {tot_n:,} | {round((1 - tot_n / tot_o) * 100, 1)} % | "
                 f"{round((1 - tot_n / tot_p) * 100, 1)} % |")
    (out / "interface-size-table.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print("discovery:", helps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
