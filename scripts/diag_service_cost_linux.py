"""Diagnostic (not validation): where the Linux machine service's cost goes on static_binary_x300.

The Linux counterpart of scripts/diag_service_cost.py.  It runs the unchanged machine_perf
workload (300 x a static binary) with the same pairing and pauses, against the INSTALLED
service, and snapshots counters around every measured run:
  * total busy CPU from /proc/stat;
  * per process (the native collector, its store-writer child, the `whyfs machine run` daemon):
    CPU time from /proc/PID/schedstat (nanoseconds), context switches, write syscalls and bytes.
Service variants (systemctl set-environment WHYFS_DIAG_NATIVE_ARGS; see daemon.py):
  normal    the product
  no_store  the full event model, nothing persisted (--diag-no-store)
  discard   ring records counted and dropped: the kernel + ring cost alone (--diag-discard)

  sudo python3 scripts/diag_service_cost_linux.py --user USER --out DIR [--pairs 20] [--variants normal,discard] [--after-s 0.2]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import machine_perf as mp  # noqa: E402

VARIANTS = {"normal": "", "no_store": "--diag-no-store", "discard": "--diag-discard"}
HZ = os.sysconf("SC_CLK_TCK")


def cpu_busy_jiffies() -> tuple[int, int]:
    f = open("/proc/stat").readline().split()[1:]
    v = [int(x) for x in f]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v[:8]) - idle, idle


def roles() -> dict[str, int]:
    r = {}
    out = subprocess.run(["ps", "-eo", "pid=,ppid=,args="], capture_output=True, text=True).stdout
    procs = []
    for ln in out.splitlines():
        parts = ln.split(None, 2)
        if len(parts) == 3:
            procs.append((int(parts[0]), int(parts[1]), parts[2]))
    for pid, ppid, args in procs:
        if "whyfs machine run" in args and "python" in args:
            r["daemon"] = pid
    for pid, ppid, args in procs:
        if "whyfs-collect" in args.split()[0]:
            if ppid == r.get("daemon"):
                r["collector"] = pid
    for pid, ppid, args in procs:
        if "whyfs-collect" in args.split()[0] and ppid == r.get("collector"):
            r["writer"] = pid
    return r


def proc_counters(pid: int) -> dict | None:
    try:
        ns = int(open(f"/proc/{pid}/schedstat").read().split()[0])
        st = {k: v for k, v in (ln.split(":", 1) for ln in open(f"/proc/{pid}/status") if ":" in ln)}
        io = {k: int(v) for k, v in (ln.split(": ") for ln in open(f"/proc/{pid}/io").read().splitlines())}
        cs = int(st["voluntary_ctxt_switches"]) + int(st["nonvoluntary_ctxt_switches"])
        # a process's schedstat is its main thread; add the other threads
        for t in os.listdir(f"/proc/{pid}/task"):
            if int(t) != pid:
                ns += int(open(f"/proc/{pid}/task/{t}/schedstat").read().split()[0])
        return {"cpu_ns": ns, "ctx": cs, "write_ops": io.get("syscw", 0), "write_bytes": io.get("write_bytes", 0),
                "read_ops": io.get("syscr", 0)}
    except (OSError, ValueError, KeyError):
        return None


def snapshot(rl: dict[str, int]) -> dict:
    busy, idle = cpu_busy_jiffies()
    s = {"t": time.perf_counter(), "busy": busy, "idle": idle, "proc": {}}
    for role, pid in rl.items():
        c = proc_counters(pid)
        if c:
            s["proc"][role] = c
    return s


def delta(a: dict, b: dict) -> dict:
    d = {"wall_ms": round((b["t"] - a["t"]) * 1000, 1), "busy_ms": round((b["busy"] - a["busy"]) * 1000 / HZ, 1), "proc": {}}
    for role in b["proc"]:
        if role in a["proc"]:
            x, y = a["proc"][role], b["proc"][role]
            d["proc"][role] = {"cpu_ms": round((y["cpu_ns"] - x["cpu_ns"]) / 1e6, 2), "ctx": y["ctx"] - x["ctx"],
                               "write_ops": y["write_ops"] - x["write_ops"], "write_bytes": y["write_bytes"] - x["write_bytes"],
                               "read_ops": y["read_ops"] - x["read_ops"]}
    return d


def set_variant(args: str) -> None:
    if args:
        subprocess.run(["systemctl", "set-environment", f"WHYFS_DIAG_NATIVE_ARGS={args}"], check=True)
    else:
        subprocess.run(["systemctl", "unset-environment", "WHYFS_DIAG_NATIVE_ARGS"], check=True)


def med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 2) if xs else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--pairs", type=int, default=20)
    ap.add_argument("--warmups", type=int, default=1)
    ap.add_argument("--variants", default="normal,discard")
    ap.add_argument("--after-s", type=float, default=0.2)
    ap.add_argument("--verify", action="store_true", help="after the normal variant: every stress output's label checked")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="whyfs-dsc-", dir=f"/home/{a.user}"))  # in scope, as machine_perf
    os.chmod(base, 0o755)
    ws, run, wl, _ = mp.workloads(base, a.user)
    prep, cmd, cwd, env = wl["static_binary_x300"]
    report = {"cpus": os.cpu_count(), "machine": os.uname().machine, "kernel": os.uname().release, "variants": {}}
    try:
        for vname in a.variants.split(","):
            set_variant(VARIANTS[vname])
            mp.service(False)
            state = {"on": False}
            t_var = time.time_ns()
            rows = []
            order = ["off", "on"] * a.warmups + [m for i in range(a.pairs) for m in (("off", "on") if i % 2 == 0 else ("on", "off"))]
            for idx, mode in enumerate(order):
                if state["on"] is not (mode == "on"):
                    mp.service(mode == "on")
                    state["on"] = mode == "on"
                rl = roles() if mode == "on" else {}
                run(prep, cwd, env=env, check=False)
                run(cmd, cwd, env=env)  # the same warm first run as machine_perf
                run(prep, cwd, env=env, check=False)
                time.sleep(mp.PAUSE_S)
                s0 = snapshot(rl)
                secs = run(cmd, cwd, env=env)
                s1 = snapshot(rl)
                row = {"mode": mode, "warmup": idx < 2 * a.warmups, "seconds": secs, **delta(s0, s1)}
                time.sleep(a.after_s)
                row["after"] = delta(s1, snapshot(rl))
                rows.append(row)
                mp.note(f"{vname} {mode}{' warmup' if row['warmup'] else ''}: {secs:.3f}s collector "
                        f"{row['proc'].get('collector', {}).get('cpu_ms')} ms writer {row['proc'].get('writer', {}).get('cpu_ms')} ms")
            verify = None
            if a.verify and vname == "normal":  # correctness under the same stress, the product configuration
                if not state["on"]:
                    mp.service(True)
                import stress_verify
                verify = stress_verify.verify(run, prep, cmd, cwd, env, "static_copy")
                mp.note(f"verify: {verify}")
            mp.service(False)
            meas = [r for r in rows if not r["warmup"]]
            offs = [r for r in meas if r["mode"] == "off"]
            ons = [r for r in meas if r["mode"] == "on"]
            paired = [(ons[i]["seconds"] / offs[i]["seconds"] - 1) * 100 for i in range(min(len(ons), len(offs)))]
            lost, per = mp.loss_since(t_var)

            def tot(r, role, k):
                v = r["proc"].get(role, {}).get(k)
                w = r["after"]["proc"].get(role, {}).get(k)
                return None if v is None else v + (w or 0)
            summary = {
                "median_paired_overhead_percent": med(paired), "paired": [round(p, 2) for p in paired],
                "ci90": mp.bootstrap_ci(paired) if len(paired) > 2 else None,
                "off_seconds_median": med([r["seconds"] for r in offs]), "on_seconds_median": med([r["seconds"] for r in ons]),
                "per_on_run": {role: {k: med([tot(r, role, k) for r in ons]) for k in ("cpu_ms", "ctx", "write_ops", "write_bytes", "read_ops")}
                               for role in ("collector", "writer", "daemon")},
                "lost": lost, "collector_stats": per,
            }
            report["variants"][vname] = {"summary": summary, "runs": rows, "verify": verify}
            mp.note(f"{vname}: median paired overhead {summary['median_paired_overhead_percent']}%  {json.dumps(summary['per_on_run'])}")
            (out / "diag_service_cost.json").write_text(json.dumps(report, indent=1, default=str))
    finally:
        set_variant("")
        mp.service(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
