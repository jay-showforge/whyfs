"""macOS collector cost and loss diagnostics (run as root on a CI Mac with the package installed).

  sudo python3 scripts/macos_es_diag.py --user USER --out DIR [--idle-s 300] [--generations 1000]

1. idle: a second Endpoint Security client with the service's own scope rules (so the same
   kernel muting) records what the service still receives while the machine is idle; the
   messages are counted by type, by process image and by path prefix (the raw capture is
   deleted after counting: it holds every program's arguments).
2. burst: the long-history gate's workload (a fresh `sh -c` per generation, then a `cat`), run as
   the user; then the service's loss counters for that period and the exact observation text of
   the last file's label.
Diagnostics only: nothing here is a gate.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import signal
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

COLLECTOR = "/Library/WhyFS/WhyFSCollector.app/Contents/MacOS/whyfs-collect"
STORE = Path("/Library/Application Support/WhyFS/machine/.whyfs/whyfs.db")
SCOPE = "/Library/WhyFS/scope-default.conf"


def prefix(p: str | None, depth: int = 3) -> str:
    if not p:
        return "-"
    parts = p.split("/")
    return "/".join(parts[:depth + 1])


def idle(seconds: int) -> dict:
    d = Path(tempfile.mkdtemp(prefix="whyfs-diag-"))
    cap = d / "cap.jsonl"
    p = subprocess.Popen([COLLECTOR, "--es", "--machine", "--scope", SCOPE, "--root", str(d), "--run-id", "diag",
                          "--emit", "--es-record", str(cap)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    hello = json.loads(p.stdout.readline() or "{}")
    import threading  # --emit writes every record to stdout: drain it, or the collector blocks on a full pipe
    threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
    threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
    time.sleep(seconds)
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=120)
    by_type, by_exe, by_path = collections.Counter(), collections.Counter(), collections.Counter()
    n = 0
    for line in cap.read_text().splitlines():
        m = json.loads(line)
        n += 1
        by_type[m["type"]] += 1
        by_exe[(m.get("proc") or {}).get("exe")] += 1
        by_path[(m["type"], prefix((m.get("f1") or {}).get("path")))] += 1
    import shutil
    shutil.rmtree(d, ignore_errors=True)
    return {"seconds": seconds, "ready": hello, "messages": n, "per_minute": round(n / seconds * 60, 1),
            "by_type": dict(by_type.most_common()), "top_processes": by_exe.most_common(15),
            "top_type_and_path_prefix": [[f"{t} {pp}", c] for (t, pp), c in by_path.most_common(25)]}


def stats_since(t0: int) -> dict:
    con = sqlite3.connect(f"file:{STORE}?mode=ro", uri=True, timeout=30)
    rows = con.execute("SELECT s.run_id, s.key, s.value FROM collector_stats s JOIN runs r ON r.id=s.run_id "
                       "WHERE r.ended_ns IS NULL OR r.ended_ns>=?", (t0,)).fetchall()
    con.close()
    out: dict = {}
    for run, k, v in rows:
        out.setdefault(run, {})[k] = v
    return out


def burst(user: str, n: int) -> dict:
    home = Path(f"/Users/{user}")
    base = Path(tempfile.mkdtemp(prefix="whyfs-diag-burst-", dir=home))
    os.chown(base, int(subprocess.check_output(["id", "-u", user])), -1)
    f = base / "gen.txt"
    t0 = time.time_ns()
    subprocess.run(["sudo", "-u", user, "sh", "-c",
                    f"for i in $(seq 1 {n}); do rm -f '{f}'; sh -c \"echo generation $i > '{f}'\"; "
                    f"sh -c \"cat '{f}' >/dev/null\"; done"], check=True)
    took = (time.time_ns() - t0) / 1e9
    subprocess.run(["sudo", "-u", user, "/usr/local/bin/whyfs", "status", "--json"], capture_output=True)
    time.sleep(70)  # the supervisor asks the collector for its counters every 60 s
    lb = json.loads(subprocess.run(["sudo", "-u", user, "/usr/local/bin/whyfs", "label", str(f), "--json"],
                                   capture_output=True, text=True).stdout or "{}")
    return {"generations": n, "seconds": round(took, 1), "label_status": lb.get("status"),
            "observation": lb.get("observation"), "collector_stats": stats_since(t0)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--idle-s", type=int, default=300)
    ap.add_argument("--generations", type=int, default=1000)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rep = {"idle": idle(a.idle_s), "burst": burst(a.user, a.generations)}
    (out / "es_diag.json").write_text(json.dumps(rep, indent=1, default=str))
    print(json.dumps(rep, indent=1, default=str)[:6000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
