"""Long-history label gate, against the INSTALLED product and its service.

Builds real histories through the running machine collector: for each depth N, one file in the
user's home recreated N times -- the loop shell deletes it, a fresh short-lived process writes
each generation, another fresh process reads it (the shape of a rebuilt build output that is
consumed).  Then, for every depth, the `whyfs why FILE --json` and `whyfs label FILE --json`
CLI latency (median and p95 of 15 runs after 3 warm-ups) and the label's correctness:
Every depth is timed in the same round-robin rounds (25 after 3 warm-ups), so drift does not
favour one depth.
  * status labelled, creator = the process that wrote the LATEST generation (its command line
    carries the generation number), observation complete, identity match where recorded;
  * `whyfs history FILE --limit 0` returns every generation's write (the complete history).
Checks: label and why medians < 100 ms at every depth; near-flat: the label median at the
deepest history is within 20 ms of the 1-generation file.

  python scripts/label_latency_gate.py --out DIR [--user USER] [--depths 1,100,300,600,1000,5000]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NT = os.name == "nt"
WHYFS = [os.path.join(os.environ.get("ProgramFiles", ""), "whyfs", "whyfs.exe")] if NT else ["/usr/bin/whyfs"]


def as_user(argv: list[str], user: str | None) -> list[str]:
    if not NT and user and os.geteuid() == 0:
        return ["runuser", "-u", user, "--", *argv]
    return argv


def build(f: Path, n: int, user: str | None) -> float:
    t0 = time.perf_counter()
    if NT:
        script = f.parent / f"make-{n}.cmd"
        script.write_text(
            "@echo off\r\n"
            f"for /L %%i in (1,1,{n}) do (\r\n"
            f"  del /q \"{f}\" 2>nul\r\n"
            # redirect first: "echo generation 5> f" would redirect handle 5 and write nothing
            f"  cmd /d /c \">\"{f}\" echo generation %%i\"\r\n"
            f"  cmd /d /c \"type \"{f}\" >nul\"\r\n"
            ")\r\n")
        subprocess.run(["cmd", "/d", "/c", str(script)], check=True)
        script.unlink()
    else:
        script = (f"for i in $(seq 1 {n}); do rm -f '{f}'; sh -c \"echo generation $i > '{f}'\"; "
                  f"sh -c \"cat '{f}' >/dev/null\"; done")
        subprocess.run(as_user(["sh", "-c", script], user), check=True)
    return time.perf_counter() - t0


def cli(args: list[str], user: str | None) -> tuple[float, str]:
    t0 = time.perf_counter()
    p = subprocess.run(as_user([*WHYFS, *args], user), capture_output=True)
    return (time.perf_counter() - t0) * 1000, p.stdout.decode("utf-8", "replace")


def settled(f: Path, n: int, user: str | None, timeout_s: float = 120) -> dict:
    """Wait until the label shows the latest generation (reorder window, batching)."""
    deadline, lb = time.time() + timeout_s, {}
    while time.time() < deadline:
        try:
            lb = json.loads(cli(["label", str(f), "--json"], user)[1])
            if f"generation {n}" in ((lb.get("created_by") or {}).get("command") or ""):
                return lb
        except ValueError:
            pass
        time.sleep(1)
    return lb


def measure_all(files: list[Path], user: str | None, runs: int = 25) -> list[dict]:
    """Every depth measured in the same rounds (round-robin), so a machine's drift during the
    measurement affects every depth alike; 3 warm-up rounds are discarded."""
    times = [{"why": [], "label": []} for _ in files]
    for rnd in range(runs + 3):
        for i, f in enumerate(files):
            for op in ("why", "label"):
                ms = cli([op, str(f), "--json"], user)[0]
                if rnd >= 3:
                    times[i][op].append(ms)
    out = []
    for t in times:
        o = {}
        for op, v in t.items():
            v = sorted(v)
            o[op] = {"median": round(statistics.median(v), 1), "p95": round(v[int(0.95 * len(v)) - 1], 1),
                     "runs": [round(x, 1) for x in v]}
        out.append(o)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--depths", default="1,100,300,600,1000,5000")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    home = os.path.expanduser("~") if NT else f"/home/{a.user}"
    base = Path(tempfile.mkdtemp(prefix="whyfs-labelgate-", dir=home))  # in scope
    if not NT:
        os.chmod(base, 0o777)
    rows, checks = [], {}
    try:
        depths = [int(x) for x in a.depths.split(",")]
        built = {}
        for n in depths:
            f = base / f"gen-{n}.txt"
            built[n] = (f, build(f, n, a.user))
            print(f"built {n} generations in {built[n][1]:.0f} s", flush=True)
        labels = {n: settled(built[n][0], n, a.user) for n in depths}
        lats = dict(zip(depths, measure_all([built[n][0] for n in depths], a.user)))
        for n in depths:
            f, secs = built[n]
            lb, lat = labels[n], lats[n]
            hist = json.loads(cli(["history", str(f), "--limit", "0", "--json"], a.user)[1] or "[]")
            writes = [h for h in hist if h.get("kind") == "io"]
            row = {"generations": n, "build_s": round(secs, 1), "why_ms": lat["why"], "label_ms": lat["label"],
                   "status": lb.get("status"), "creator_command": (lb.get("created_by") or {}).get("command"),
                   "observation_complete": (lb.get("observation") or {}).get("complete"),
                   "identity": (lb.get("identity") or {}).get("check"), "scope": lb.get("scope"),
                   "history_writes": len(writes)}
            rows.append(row)
            checks[f"{n}.label_median_lt_100ms"] = lat["label"]["median"] < 100
            checks[f"{n}.why_median_lt_100ms"] = lat["why"]["median"] < 100
            checks[f"{n}.labelled_with_the_latest_generation"] = (lb.get("status") == "labelled"
                                                                  and f"generation {n}" in (row["creator_command"] or ""))
            checks[f"{n}.observation_complete"] = row["observation_complete"] is True
            checks[f"{n}.identity_not_mismatched"] = row["identity"] in ("match", "unknown", None)
            checks[f"{n}.complete_history_has_every_generation"] = len(writes) >= n
            print(f"{n:5d} generations (built in {secs:.0f} s): why {lat['why']['median']} ms (p95 {lat['why']['p95']}), "
                  f"label {lat['label']['median']} ms (p95 {lat['label']['p95']}), history writes {len(writes)}, "
                  f"creator '{row['creator_command']}', scope {'recent' if lb.get('scope') else 'complete'}", flush=True)
        if len(rows) > 1:
            checks["label_near_flat_deepest_within_20ms_of_1_generation"] = \
                rows[-1]["label_ms"]["median"] - rows[0]["label_ms"]["median"] <= 20
    finally:
        shutil.rmtree(base, ignore_errors=True)
    report = {"platform": sys.platform, "rows": rows, "checks": checks,
              "verdict": "PASS" if checks and all(checks.values()) else "FAIL"}
    (out / "label_latency.json").write_text(json.dumps(report, indent=1))
    for k, v in checks.items():
        if not v:
            print("FAIL", k)
    print("verdict", report["verdict"])
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
