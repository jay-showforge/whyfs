"""Correctness under spawn stress: after one monitored run of the ×300 workload, every output
must be labelled with the program that wrote it, observed completely, with a matching identity.
Used by scripts/diag_service_cost.py and diag_service_cost_linux.py (--verify)."""
from __future__ import annotations

import os
import time
from pathlib import Path


def verify(run, prep, cmd, cwd: Path, env, creator: str, n: int = 300, wait_s: float = 12.0) -> dict:
    from whyfs.client import call
    run(prep, cwd, env=env, check=False)
    run(cmd, cwd, env=env)
    time.sleep(wait_s)  # reorder window + group commit (Windows), ring drain + batch (Linux)
    res = {"checked": 0, "labelled": 0, "creator_ok": 0, "complete": 0, "identity_match": 0, "failures": []}
    for k in range(1, n + 1):
        p = str(Path(cwd) / f"out-{k}.txt")
        reply = call("get_file_provenance", {"path": p, "include_noise": False})
        lb = reply.get("result") or {}
        res["checked"] += 1
        ok_l = lb.get("status") == "labelled"
        ok_c = ok_l and os.path.basename((lb.get("created_by") or {}).get("exe") or "").lower() == creator.lower()
        ok_o = ok_l and (lb.get("observation") or {}).get("complete") is True
        ok_i = ok_l and (lb.get("identity") or {}).get("check") == "match"
        res["labelled"] += ok_l; res["creator_ok"] += ok_c; res["complete"] += ok_o; res["identity_match"] += ok_i
        if not (ok_l and ok_c and ok_o and ok_i) and len(res["failures"]) < 5:
            res["failures"].append({"path": p, "status": lb.get("status"), "exe": (lb.get("created_by") or {}).get("exe"),
                                    "observation": (lb.get("observation") or {}).get("complete"),
                                    "identity": (lb.get("identity") or {}).get("check"), "error": reply.get("error")})
    res["ok"] = res["checked"] == n and res["labelled"] == res["creator_ok"] == res["complete"] == res["identity_match"] == n
    return res
