#!/usr/bin/env python3
"""Run the shared cross-platform behavioural corpus (tests/corpus) on this platform.

Linux:   sudo python3 scripts/run_corpus.py --user USER --out DIR   (eBPF daemon; workload as USER)
macOS:   sudo python3 scripts/run_corpus.py --installed --machine --user USER --out DIR   (the launchd service)
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
INSTALLED = "--installed" in sys.argv  # exercise an installed package: `whyfs` on PATH, no source tree
if not INSTALLED:
    sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests" / "corpus"))
import scenarios  # noqa: E402
from whyfs.query import history, impact, why  # noqa: E402
from whyfs.store import connect  # noqa: E402

LINUX = sys.platform.startswith("linux")
MAC = sys.platform == "darwin"
ENV = dict(os.environ) if INSTALLED else dict(os.environ, PYTHONPATH=str(REPO / "src"))
WHYFS = [("/usr/local/bin/whyfs" if MAC else shutil.which("whyfs") or "whyfs")] if INSTALLED else [sys.executable, "-m", "whyfs"]


def whyfs(*args, cwd, check=True):
    p = subprocess.run([*WHYFS, *args], cwd=cwd, env=ENV, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if check and p.returncode != 0:
        raise SystemExit(f"whyfs {' '.join(args)} failed: {p.stdout}{p.stderr}")
    return p


def run_step(step, cwd, user):
    argv = [scenarios.env_python(), scenarios.tool_path(), *step]
    if MAC and user:
        argv = ["sudo", "-u", user, "--", *argv]
    elif LINUX and user:
        argv = ["runuser", "-u", user, "--", *argv]
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(f"step {step} failed in {cwd}: {p.stderr}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--installed", action="store_true", help="use the installed whyfs (PATH), not this source tree")
    ap.add_argument("--machine", action="store_true",
                    help="no workspace: rely on the running machine service and read its store (as root / elevated admin)")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    home = f"/Users/{a.user}" if MAC and a.user else f"/home/{a.user}" if LINUX and a.user else (os.path.expanduser("~") if a.machine else None)  # in scope, not a temp root
    base = Path(tempfile.mkdtemp(prefix="whyfs-corpus-", dir=home)).resolve()
    if LINUX or MAC:
        if os.geteuid() != 0:
            raise SystemExit("run as root (the machine store is root's); the workload runs as --user")
        os.chmod(base, 0o755)
    scenarios.prepare(base)
    if (LINUX or MAC) and a.user:
        subprocess.run(["chown", "-R", a.user if MAC else f"{a.user}:", str(base)], check=True)
    if a.machine:  # the service may still be (re)starting its collector, e.g. right after another gate
        deadline = time.time() + 120
        while True:
            try:
                ready = json.loads(whyfs("status", "--json", cwd=base, check=False).stdout).get("collector_ready")
            except ValueError:
                ready = False
            if ready:
                break
            if time.time() > deadline:
                raise SystemExit("the machine collector is not ready after 120 s")
            time.sleep(1.0)
    else:
        whyfs("init", ".", cwd=base)
        whyfs("daemon", "start", "--workspace", str(base), cwd=base)
        time.sleep(1.0)
    t_start = time.time_ns()
    t0 = time.time()
    for sc in scenarios.SCENARIOS:
        for step in sc["steps"]:
            run_step(step, base / sc["dir"], a.user)
    workload_s = time.time() - t0
    if a.machine:
        time.sleep(3.0 if LINUX or MAC else 10.0)  # ETW reorder window / ring drain, then the writer's batch
        from whyfs.machine import paths
        con = connect(paths()["root"])
    else:
        time.sleep(0.5)
        whyfs("daemon", "stop", "--workspace", str(base), cwd=base)
        con = connect(base)
    results = scenarios.evaluate(con, base, why, impact, history)
    if a.machine:  # the live counters of the machine collector run(s) covering this workload
        stats = {k: v for k, v in con.execute(
            "SELECT s.key, SUM(s.value) FROM collector_stats s JOIN runs r ON r.id=s.run_id "
            "WHERE r.ended_ns IS NULL OR r.ended_ns>=? GROUP BY s.key", (t_start,))}
    else:
        stats = {k: v for k, v in con.execute("SELECT key, SUM(value) FROM collector_stats GROUP BY key")}
    collector = con.execute("SELECT collector FROM runs ORDER BY started_ns DESC LIMIT 1").fetchone()[0]
    con.close()
    lost = sum(int(stats.get(k, 0) or 0) for k in ("kernel_drops", "queue_drops", "user_unresolved", "late_records"))
    failed = [r for r in results if not r["ok"]]
    import whyfs as _w
    report = {"installed": INSTALLED, "machine": a.machine, "whyfs_module": _w.__file__, "platform": platform.platform(), "machine": platform.machine(), "collector": collector,
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
