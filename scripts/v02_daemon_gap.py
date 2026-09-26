#!/usr/bin/env python3
"""Why does the real separate daemon measure more static-x300 overhead than the
in-process profiler?  Topology matrix + persistent-daemon time series.

Workload: exactly the graduation harness's static x300 (via v02_hotpath_profile.Workload,
which asserts the prep/loop strings against scripts/v02_graduation.py).  All workload
timing is measured INSIDE the workload's own shell (date +%s%N), never by a Python
process that participates in collection.

Phases
  cal  perf-stat calibration: baseline with vs without `perf stat -a` running.
  R    rotated rounds over A baseline / B kernel only (separate agent, callback discards) /
       C in-process full collector (profiler topology) / D separate process, full
       processing, no SQLite / E separate process, full production path (processing +
       privilege-separated SQLite).  One persistent agent, one in-driver collector,
       attach/detach per run.
  S    BPF run time per run (agent, full mode, bpf_stats on, idle-subtracted).
  F1   persistent REAL daemon (`whyfs daemon start`): 10 baselines, start, 25 consecutive
       monitored runs recorded individually, stop, 10 baselines.  bpf_stats off.
  F2   as F1 with bpf_stats on (per-run BPF run time from the daemon's prog fds).
  G    graduation-harness pattern: fresh daemon per monitored run (start, sleep .3,
       first build, prep, measured build, stop), alternating with baseline runs.
  K    lifecycle control: like G but the daemon is stopped before prep + measured build,
       so the measured build runs with no whyfs present.

Usage: sudo python3 scripts/v02_daemon_gap.py --user USER --out DIR
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from v02_graduation import Ctx, environment, LINUX_PATH  # noqa: E402
from v02_hotpath_profile import CMD, Log, Poller, Workload, set_attached, summary, git_info  # noqa: E402
from v02_gap_agent import proc_metrics  # noqa: E402
from whyfs.daemon import ensure_kernel_headers  # noqa: E402
from whyfs.ebpf_bcc import BCCCollector  # noqa: E402
from whyfs.privsep import Store  # noqa: E402

PERF = next(iter(sorted(Path("/usr/lib/linux-tools").glob("*/perf"))), None) if Path("/usr/lib/linux-tools").exists() else None


# ---------------------------------------------------------------- measured workload run
class GapWorkload(Workload):
    """Harness workload, shell-timed, plus zero-cost rusage (/usr/bin/time, from wait4)
    and the loop shell's own migrations; optional system-wide perf software counters."""

    use_perf = False

    def run_measured(self) -> dict:
        inner = (f"s=$(date +%s%N); {CMD}; e=$(date +%s%N); echo WFTIME=$((e-s)); "
                 "echo WFMIG=$(awk -F: '/se.nr_migrations/{gsub(/ /,\"\",$2);print $2}' /proc/$$/sched)")
        cmd = f"/usr/bin/time -f 'WFRU %e %U %S %F %R %w %c' bash -c {shlex.quote(inner)}"
        perf = None
        if self.use_perf and PERF:
            perf = subprocess.Popen([str(PERF), "stat", "-a", "-x,", "-e",
                                     "task-clock,context-switches,cpu-migrations,page-faults"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            time.sleep(0.05)
        outer, p = self.ctx.run_user(cmd, self.ws)
        rec = {"outer_s": outer}
        if perf:
            perf.send_signal(signal.SIGINT)
            err = perf.communicate(timeout=10)[1]
            for line in err.splitlines():
                parts = line.split(",")
                if len(parts) > 2 and parts[2] in ("task-clock", "context-switches", "cpu-migrations", "page-faults"):
                    try:
                        rec["perf_" + parts[2].replace("-", "_")] = float(parts[0])
                    except ValueError:
                        pass
        for line in (p.stdout + "\n" + p.stderr).splitlines():
            if line.startswith("WFTIME="):
                rec["s"] = int(line.split("=", 1)[1]) / 1e9
            elif line.startswith("WFMIG="):
                try:
                    rec["loop_shell_migrations"] = int(line.split("=", 1)[1])
                except ValueError:
                    pass
            elif line.startswith("WFRU "):
                f = line.split()
                rec.update(wl_elapsed=float(f[1]), wl_user_s=float(f[2]), wl_sys_s=float(f[3]),
                           wl_majflt=int(f[4]), wl_minflt=int(f[5]), wl_vol_ctx=int(f[6]), wl_invol_ctx=int(f[7]))
        if "s" not in rec:
            raise RuntimeError("workload did not report WFTIME")
        return rec


def delta(a: dict, b: dict) -> dict:
    out = {}
    for k, v in b.items():
        if isinstance(v, dict):
            out[k] = delta(a.get(k, {}), v)
        elif isinstance(v, (int, float)) and isinstance(a.get(k), (int, float)):
            out[k] = v - a[k]
    return out


# ---------------------------------------------------------------- agent (separate process)
class Agent:
    def __init__(self, ws: Path, run_id: str, log: Log):
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PATH=LINUX_PATH)
        self.p = subprocess.Popen([sys.executable, "-W", "ignore", str(REPO / "scripts" / "v02_gap_agent.py"),
                                   "--workspace", str(ws), "--run-id", run_id],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=open(ws.parent / f"{run_id}.agent.log", "w"),
                                  text=True, env=env)
        hello = self._read()
        self.pid, self.store_pid = hello["pid"], hello["store_pid"]
        log(f"  agent pid {self.pid} store worker {self.store_pid}")

    def _read(self) -> dict:
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("agent exited")
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    def cmd(self, c: str) -> dict:
        self.p.stdin.write(c + "\n")
        self.p.stdin.flush()
        r = self._read()
        if "error" in r:
            raise RuntimeError(f"agent: {r['error']}")
        return r

    def quit(self) -> dict:
        self.p.stdin.write("quit\n")
        self.p.stdin.flush()
        r = self._read()
        self.p.wait(timeout=60)
        return r


# ---------------------------------------------------------------- in-process collector (topology C)
class InProc:
    def __init__(self, ws: Path, run_id: str):
        self.store = Store(ws).start()
        self.store.call("begin_run", run_id, time.time_ns(), str(ws))
        self.run_id = run_id
        self.c = BCCCollector(ws, run_id, store=self.store)
        self.c.start()
        self.poller = Poller(lambda: self.c.poll(50))
        set_attached(self.c.bpf, False)

    def snap(self) -> dict:
        return {"stats": {k: int(v) for k, v in vars(self.c.stats).items()}, "kernel_drops": self.c.kernel_drop_count(),
                "self": proc_metrics(os.getpid()), "store": proc_metrics(self.store.pid)}

    def close(self) -> dict:
        self.poller.close()
        st = self.c.stop()
        self.store.call("end_run", self.run_id, time.time_ns(), 0, {k: int(v) for k, v in vars(st).items()})
        self.store.close()
        self.c.bpf.cleanup()
        return {k: int(v) for k, v in vars(st).items()}


# ---------------------------------------------------------------- real daemon (CLI)
class RealDaemon:
    def __init__(self, ctx: Ctx, ws: Path):
        self.ctx, self.ws = ctx, ws

    def start(self):
        self.ctx.whyfs("daemon", "start", "--workspace", str(self.ws), cwd=self.ws)
        st = json.loads((self.ws / ".whyfs" / "daemon.json").read_text())
        self.pid, self.run_id = int(st["pid"]), st["run_id"]
        self.store_pid = None
        for t in Path(f"/proc/{self.pid}/task").iterdir():
            kids = (t / "children").read_text().split()
            if kids:
                self.store_pid = int(kids[0])
        return self

    def stop(self):
        self.ctx.whyfs("daemon", "stop", "--workspace", str(self.ws), cwd=self.ws)

    def metrics(self) -> dict:
        return {"self": proc_metrics(self.pid), "store": proc_metrics(self.store_pid), "db_events": self.db_events(),
                "bpf": self.prog_totals()}

    def db_events(self) -> int | None:
        try:
            con = sqlite3.connect(f"file:{self.ws}/.whyfs/whyfs.db?mode=ro", uri=True, timeout=5)
            n = con.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (self.run_id,)).fetchone()[0]
            con.close()
            return n
        except sqlite3.Error:
            return None

    def prog_totals(self) -> dict:
        cnt = ns = 0
        try:
            for fd in Path(f"/proc/{self.pid}/fd").iterdir():
                try:
                    if os.readlink(fd) != "anon_inode:bpf-prog":
                        continue
                    kv = dict(l.split(":", 1) for l in Path(f"/proc/{self.pid}/fdinfo/{fd.name}").read_text().splitlines() if ":" in l)
                    cnt += int(kv.get("run_cnt", "0").strip())
                    ns += int(kv.get("run_time_ns", "0").strip())
                except OSError:
                    pass
        except OSError:
            pass
        return {"run_cnt": cnt, "run_time_ns": ns}

    def final_stats(self) -> dict:
        con = sqlite3.connect(f"file:{self.ws}/.whyfs/whyfs.db?mode=ro", uri=True, timeout=5)
        d = {r[0]: r[1] for r in con.execute("SELECT key,value FROM collector_stats WHERE run_id=?", (self.run_id,))}
        con.close()
        return d


def bpf_stats(on: bool) -> None:
    Path("/proc/sys/kernel/bpf_stats_enabled").write_text("1" if on else "0")


# ---------------------------------------------------------------- phases
def phase_cal(wl: GapWorkload, log: Log, pairs: int) -> dict:
    log("phase cal: perf stat -a overhead on the baseline workload")
    rows = []
    for i in range(pairs + 1):
        rec = {"warmup": i == 0}
        for m in (("plain", "perf") if i % 2 == 0 else ("perf", "plain")):
            wl.use_perf = m == "perf"
            wl.prep()
            rec[m] = wl.run_measured()
        wl.use_perf = False
        rows.append(rec)
    meas = [r for r in rows if not r["warmup"]]
    d = summary([(r["perf"]["s"] - r["plain"]["s"]) * 1000 for r in meas])
    log(f"  cal perf - plain: {d['median']:+.2f} ms (CI90 {d['median_ci90'][0]:+.2f}..{d['median_ci90'][1]:+.2f})")
    return {"rows": rows, "perf_minus_plain_ms": d}


MODES = ["A", "B", "C", "D", "E"]


def phase_R(wl: GapWorkload, log: Log, rounds: int, agent: Agent, inproc: InProc) -> dict:
    log("phase R: rotated A/B/C/D/E rounds")
    orders = [MODES[i:] + MODES[:i] for i in range(5)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    for r in range(rounds + 1):
        rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
        for m in orders[r % len(orders)]:
            if m in ("B", "D", "E"):
                agent.cmd("mode " + {"B": "kernel_only", "D": "no_store", "E": "full"}[m])
                s0 = agent.cmd("snap")
                agent.cmd("attach")
            elif m == "C":
                s0 = inproc.snap()
                set_attached(inproc.c.bpf, True)
            wl.prep()
            run = wl.run_measured()
            if m in ("B", "D", "E"):
                agent.cmd("detach")
                time.sleep(0.4)
                run["collector"] = delta(s0, agent.cmd("snap"))
            elif m == "C":
                set_attached(inproc.c.bpf, False)
                time.sleep(0.4)
                run["collector"] = delta(s0, inproc.snap())
            else:
                time.sleep(0.4)
            rec[m] = run
        rows.append(rec)
        if r % 5 == 0:
            log(f"  R round {r}: " + " ".join(f"{m}={rec[m]['s']*1000:.1f}" for m in MODES))
    meas = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a]["s"] - x[z]["s"]) * 1000 for x in meas])

    out = {"rows": rows, "per_mode_ms": {m: summary([x[m]["s"] * 1000 for x in meas]) for m in MODES},
           "overhead_pct": {m: summary([(x[m]["s"] / x["A"]["s"] - 1) * 100 for x in meas]) for m in MODES if m != "A"},
           "B_minus_A": d("B", "A"), "D_minus_B": d("D", "B"), "E_minus_D": d("E", "D"), "E_minus_A": d("E", "A"),
           "C_minus_A": d("C", "A"), "E_minus_C": d("E", "C"), "D_minus_A": d("D", "A")}
    for k in ("B_minus_A", "D_minus_B", "E_minus_D", "E_minus_A", "C_minus_A", "E_minus_C"):
        log(f"  R {k}: {out[k]['median']:+.2f} ms (CI90 {out[k]['median_ci90'][0]:+.2f}..{out[k]['median_ci90'][1]:+.2f})")
    return out


def phase_S(wl: GapWorkload, log: Log, reps: int, agent: Agent) -> dict:
    log("phase S: BPF run time per run (agent, full mode, bpf_stats on)")
    agent.cmd("mode full")
    agent.cmd("attach")
    agent.cmd("bpfstats on")
    rows = []
    try:
        for _ in range(reps):
            wl.prep()
            time.sleep(0.3)
            a0 = agent.cmd("progstats")
            run = wl.run_measured()
            a1 = agent.cmd("progstats")
            i0 = agent.cmd("progstats")
            time.sleep(run["s"])
            i1 = agent.cmd("progstats")
            tot = lambda x, y: sum(y[k]["run_time_ns"] - x[k]["run_time_ns"] for k in y)
            cnt = lambda x, y: sum(y[k]["run_cnt"] - x[k]["run_cnt"] for k in y)
            rows.append({"s": run["s"], "bpf_ns": tot(a0, a1), "bpf_cnt": cnt(a0, a1),
                         "idle_ns": tot(i0, i1), "idle_cnt": cnt(i0, i1)})
    finally:
        agent.cmd("bpfstats off")
        agent.cmd("detach")
    net = [r["bpf_ns"] - r["idle_ns"] for r in rows]
    log(f"  S BPF run time: {statistics.median(net)/1e6:.2f} ms/run (idle-subtracted)")
    return {"rows": rows, "bpf_ms_per_run": summary([x / 1e6 for x in net])}


def phase_F(wl: GapWorkload, ctx: Ctx, log: Log, runs: int, base_runs: int, stats_on: bool, tag: str) -> dict:
    log(f"phase {tag}: persistent real daemon, {runs} consecutive runs (bpf_stats {'on' if stats_on else 'off'})")
    before, after, series = [], [], []
    for _ in range(base_runs):
        wl.prep()
        before.append(wl.run_measured())
    d = RealDaemon(ctx, wl.ws)
    if stats_on:
        bpf_stats(True)
    t_start = time.time()
    d.start()
    time.sleep(0.3)  # as the graduation harness
    startup_s = time.time() - t_start
    try:
        m0 = d.metrics()
        for i in range(runs):
            wl.prep()
            run = wl.run_measured()
            time.sleep(0.4)
            m1 = d.metrics()
            run["daemon"] = delta(m0, m1)
            run["index"] = i + 1
            series.append(run)
            m0 = m1
            log(f"  {tag} run {i+1:2d}: {run['s']*1000:.1f} ms  events+{run['daemon'].get('db_events')}  "
                f"daemon cpu {run['daemon']['self'].get('utime_s', 0) + run['daemon']['self'].get('stime_s', 0):.3f}s "
                f"minflt {run['daemon']['self'].get('minflt')}" + (f"  bpf {run['daemon']['bpf']['run_time_ns']/1e6:.2f} ms" if stats_on else ""))
    finally:
        d.stop()
        if stats_on:
            bpf_stats(False)
    final = d.final_stats()
    for _ in range(base_runs):
        wl.prep()
        after.append(wl.run_measured())
    base = statistics.median([r["s"] for r in before + after])
    for r in series:
        r["overhead_pct_vs_baseline_median"] = (r["s"] / base - 1) * 100
    return {"baseline_before": before, "baseline_after": after, "baseline_median_s": base,
            "baseline_before_median_s": statistics.median(r["s"] for r in before),
            "baseline_after_median_s": statistics.median(r["s"] for r in after),
            "startup_s": startup_s, "series": series, "daemon_final_stats": final}


def phase_GK(wl: GapWorkload, ctx: Ctx, log: Log, pairs: int, warmups: int, control: bool, tag: str) -> dict:
    log(f"phase {tag}: {'lifecycle control (daemon stopped before measured build)' if control else 'harness pattern (fresh daemon per measured build)'}")
    order = [("off", "on")] * warmups + [("off", "on") if i % 2 == 0 else ("on", "off") for i in range(pairs)]
    rows = []
    for i, modes in enumerate(order):
        rec = {"warmup": i < warmups}
        for m in modes:
            if m == "off":
                wl.prep()
                rec["off"] = wl.run_measured()
                continue
            # Exactly the graduation harness's monitored row: prep, start, sleep .3,
            # first build, prep, measured build, sleep .3, stop.
            wl.prep()
            d = RealDaemon(ctx, wl.ws)
            t0 = time.time()
            d.start()
            time.sleep(0.3)
            rec["start_s"] = time.time() - t0
            rec["first"] = wl.run_measured()
            if control:
                d.stop()
            wl.prep()
            rec["on"] = wl.run_measured()
            if not control:
                time.sleep(0.3)
                d.stop()
                rec["daemon_final"] = d.final_stats()
        rec["overhead_pct"] = (rec["on"]["s"] / rec["off"]["s"] - 1) * 100
        rec["first_overhead_pct"] = (rec["first"]["s"] / rec["off"]["s"] - 1) * 100
        rows.append(rec)
        log(f"  {tag} pair {i}{' (warm-up)' if rec['warmup'] else ''}: off {rec['off']['s']*1000:.1f} "
            f"first {rec['first']['s']*1000:.1f} on {rec['on']['s']*1000:.1f} -> {rec['overhead_pct']:+.2f}%")
    meas = [r for r in rows if not r["warmup"]]
    out = {"rows": rows, "overhead_pct": summary([r["overhead_pct"] for r in meas]),
           "first_overhead_pct": summary([r["first_overhead_pct"] for r in meas]),
           "delta_ms": summary([(r["on"]["s"] - r["off"]["s"]) * 1000 for r in meas]),
           "first_delta_ms": summary([(r["first"]["s"] - r["off"]["s"]) * 1000 for r in meas])}
    log(f"  {tag} median paired overhead {out['overhead_pct']['median']:.2f}% "
        f"(CI90 {out['overhead_pct']['median_ci90'][0]:.2f}..{out['overhead_pct']['median_ci90'][1]:.2f}); "
        f"delta {out['delta_ms']['median']:+.2f} ms")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-gap-ws")
    ap.add_argument("--cal-pairs", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=40)
    ap.add_argument("--s-reps", type=int, default=10)
    ap.add_argument("--f-runs", type=int, default=25)
    ap.add_argument("--f-base", type=int, default=10)
    ap.add_argument("--pairs", type=int, default=20)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--phases", default="cal,R,S,F1,F2,G,K")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        return 2
    out = Path(a.out)
    if out.exists():
        print(f"{out} exists; refusing to overwrite", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    log = Log(out / "console.log")
    ensure_kernel_headers()
    base = Path(a.base.format(user=a.user))
    if base.exists():
        shutil.rmtree(base)
    (out / "harness-ctx").mkdir()
    ctx = Ctx(a.user, out / "harness-ctx")
    phases = a.phases.split(",")
    params = {k: v for k, v in vars(a).items()}
    params.update(workload_cmd=CMD, timing="shell (date +%s%N) inside the workload; never the collector's process",
                  perf=str(PERF) if PERF else None)
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out),
           "environment": environment()}
    log(f"git HEAD {res['git']['head']} dirty={len(res['git']['dirty_files'])}")
    wl = GapWorkload(ctx, base, log)
    bpf_stats(False)
    try:
        if "cal" in phases:
            res["cal"] = phase_cal(wl, log, a.cal_pairs)
            cal = res["cal"]["perf_minus_plain_ms"]
            wl.use_perf = abs(cal["median"]) < 0.5 and cal["median_ci90"][0] < 0.5
            log(f"  perf stat -a {'ENABLED' if wl.use_perf else 'DISABLED'} for the remaining phases")
            res["perf_enabled"] = wl.use_perf
        if "R" in phases or "S" in phases:
            agent = Agent(wl.ws, "gap-agent", log)
            inproc = InProc(wl.ws, "gap-inproc")
            try:
                wl.prep()
                wl.run_measured()  # prime (not recorded)
                if "R" in phases:
                    res["R"] = phase_R(wl, log, a.rounds, agent, inproc)
                if "S" in phases:
                    res["S"] = phase_S(wl, log, a.s_reps, agent)
            finally:
                res["agent_final"] = agent.quit()
                res["inproc_final"] = inproc.close()
        if "F1" in phases:
            res["F1"] = phase_F(wl, ctx, log, a.f_runs, a.f_base, False, "F1")
        if "F2" in phases:
            res["F2"] = phase_F(wl, ctx, log, a.f_runs, a.f_base, True, "F2")
        if "G" in phases:
            res["G"] = phase_GK(wl, ctx, log, a.pairs, a.warmups, False, "G")
        if "K" in phases:
            res["K"] = phase_GK(wl, ctx, log, a.pairs, a.warmups, True, "K")
    finally:
        bpf_stats(False)
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "gap.json").write_text(json.dumps(res, indent=1, default=str))
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
