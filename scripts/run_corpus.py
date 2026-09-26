#!/usr/bin/env python3
"""Run the shared cross-platform behavioural corpus (tests/corpus) on this platform.

Linux:   sudo python3 scripts/run_corpus.py --user USER --out DIR   (eBPF daemon; workload as USER)
Windows: python scripts\\run_corpus.py --out DIR                    (whyfs service; workload as you)

Same scenarios, same expected answers everywhere; only collector start/stop differs.
Writes DIR/corpus.json (every check, the collector's counters, environment) and exits 0
only if every check passes and nothing was lost.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "corpus"))
import scenarios  # noqa: E402
from whyfs.query import history, impact, why  # noqa: E402
from whyfs.store import connect  # noqa: E402

LINUX = sys.platform.startswith("linux")
ENV = dict(os.environ, PYTHONPATH=str(REPO / "src"))


def whyfs(*args, cwd, check=True):
    p = subprocess.run([sys.executable, "-m", "whyfs", *args], cwd=cwd, env=ENV, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise SystemExit(f"whyfs {' '.join(args)} failed: {p.stdout}{p.stderr}")
    return p


def run_step(step, cwd, user):
    argv = [scenarios.env_python(), scenarios.tool_path(), *step]
    if LINUX and user:
        argv = ["runuser", "-u", user, "--", *argv]
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"step {step} failed in {cwd}: {p.stderr}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="whyfs-corpus-", dir=f"/home/{a.user}" if LINUX and a.user else None)).resolve()
    if LINUX:
        if os.geteuid() != 0:
            raise SystemExit("run as root on Linux (the eBPF daemon needs it); the workload runs as --user")
        os.chmod(base, 0o755)
    scenarios.prepare(base)
    if LINUX and a.user:
        subprocess.run(["chown", "-R", f"{a.user}:", str(base)], check=True)
    whyfs("init", ".", cwd=base)
    whyfs("daemon", "start", "--workspace", str(base), cwd=base)
    time.sleep(1.0)
    t0 = time.time()
    for sc in scenarios.SCENARIOS:
        for step in sc["steps"]:
            run_step(step, base / sc["dir"], a.user)
    workload_s = time.time() - t0
    time.sleep(0.5)
    whyfs("daemon", "stop", "--workspace", str(base), cwd=base)
    con = connect(base)
    results = scenarios.evaluate(con, base, why, impact, history)
    stats = {k: v for k, v in con.execute("SELECT key, SUM(value) FROM collector_stats GROUP BY key")}
    collector = con.execute("SELECT collector FROM runs ORDER BY started_ns DESC LIMIT 1").fetchone()[0]
    con.close()
    lost = sum(int(stats.get(k, 0) or 0) for k in ("kernel_drops", "queue_drops", "user_unresolved", "late_records"))
    failed = [r for r in results if not r["ok"]]
    report = {"platform": platform.platform(), "machine": platform.machine(), "collector": collector,
              "checks": len(results), "failed": len(failed), "lost": lost, "workload_s": round(workload_s, 3),
              "results": results, "collector_stats": stats, "workspace": str(base),
              "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (out / "corpus.json").write_text(json.dumps(report, indent=1))
    by = {}
    for r in results:
        by.setdefault(r["scenario"], []).append(r["ok"])
    for sc in scenarios.SCENARIOS:
        oks = by.get(sc["id"], [])
        print(f"  {sc['id']} {sc['title']:<44} {sum(oks)}/{len(oks)}")
    for r in failed:
        print(f"  FAIL {r['scenario']} {r['check']}: got {r['got']!r}, want {r['want']!r}")
    print(f"corpus on {platform.system()} {platform.machine()} ({collector}): {len(results) - len(failed)}/{len(results)} "
          f"checks, lost {lost}")
    shutil.rmtree(base, ignore_errors=True) if not failed else None
    return 0 if not failed and lost == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
