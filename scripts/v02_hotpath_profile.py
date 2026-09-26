#!/usr/bin/env python3
"""whyfs v0.2 Step-1 hot-path profiler for the exec-heavy graduation workload.

Measures where the per-process eBPF cost goes on the exact static-binary x300
workload of scripts/v02_graduation.py (same C source, same build, same user
runner, same prep and loop commands, asserted against the harness source).

Phases (run as root; the workload runs as --user):

  P  counts     WF_PROFILE build under the real collector + privilege-separated
                store: per-program calls, early exits, map lookups/updates/
                deletes, ring-buffer records/bytes, upid-walk fallbacks; plus
                kernel run time per program (kernel.bpf_stats_enabled).  Idle
                windows of equal length measure background activity.
  T  timing     production build (no diagnostic flags) under the real collector:
                alternating baseline/monitored pairs (programs detached/attached
                on one loaded object), then separate bpf_stats run-time reps
                (stats accounting itself costs time, so it is off while timing).
  A  ablation   per hot hook: a normal object and one with that hook's body
                nulled (WF_NULL_MASK) are both loaded; each round times
                baseline / normal / nulled in rotated order.  A null-all variant
                isolates pure hook-dispatch cost.  Userspace is a no-op ring
                consumer in this phase, so only kernel-side cost differs.

Nothing here changes production behaviour: the diagnostic flags are compile-time
and only this script passes them.

Usage:  sudo python3 scripts/v02_hotpath_profile.py --user USER --out DIR
"""
from __future__ import annotations

import argparse
import csv
import ctypes as ct
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from v02_graduation import STATIC_C, VITE, Ctx, environment, write_c_project, write_vite_project  # noqa: E402  (workload source of truth)
from whyfs.daemon import ensure_kernel_headers  # noqa: E402
from whyfs.ebpf_bcc import BCCCollector, BPF_SOURCE, pid_namespace_identity, pid_namespace_kdev  # noqa: E402
from whyfs.privsep import Store  # noqa: E402

# Exactly the harness's static workload (asserted against its source below).
PREP = "rm -f out-*.txt"
CMD = "for i in $(seq 1 300); do ./static_copy raw.txt out-$i.txt; done"
PROCESSES_PER_RUN = 300

# (profile id, program function, attach kind, attach target)
PROGRAMS = [
    (0, "kfunc__vmlinux__security_file_open", "kfunc", None),
    (1, "kfunc__vmlinux__security_file_permission", "kfunc", None),
    (2, "kfunc__vmlinux__security_mmap_file", "kfunc", None),
    (3, "kfunc__vmlinux__do_renameat2", "kfunc", None),
    (4, "kretfunc__vmlinux__do_renameat2", "kretfunc", None),
    (5, "kfunc__vmlinux__do_unlinkat", "kfunc", None),
    (6, "kretfunc__vmlinux__do_unlinkat", "kretfunc", None),
    (7, "tracepoint__syscalls__sys_enter_chdir", "tp", "syscalls:sys_enter_chdir"),
    (8, "tracepoint__syscalls__sys_exit_chdir", "tp", "syscalls:sys_exit_chdir"),
    (9, "tracepoint__syscalls__sys_enter_fchdir", "tp", "syscalls:sys_enter_fchdir"),
    (10, "tracepoint__syscalls__sys_exit_fchdir", "tp", "syscalls:sys_exit_fchdir"),
    (11, "tracepoint__sched__sched_process_exec", "tp", "sched:sched_process_exec"),
    (12, "raw_tracepoint__sched_process_fork", "rawtp", "sched_process_fork"),
    (13, "tracepoint__sched__sched_process_exit", "tp", "sched:sched_process_exit"),
]
SHORT = {0: "security_file_open", 1: "security_file_permission", 2: "security_mmap_file",
         3: "do_renameat2 (entry)", 4: "do_renameat2 (return)", 5: "do_unlinkat (entry)",
         6: "do_unlinkat (return)", 7: "sys_enter_chdir", 8: "sys_exit_chdir", 9: "sys_enter_fchdir",
         10: "sys_exit_fchdir", 11: "sched_process_exec", 12: "sched_process_fork", 13: "sched_process_exit"}
METRICS = ["calls", "early_exits", "map_lookups", "map_updates", "map_deletes", "rb_records", "rb_bytes", "upid_walks",
           "ns_translate_ns", "ns_fastpath_misses", "foreign_tasks", "d_path_ns", "io_seen_map_ns", "ringbuf_ns",
           "exec_copy_ns", "io_seen_update_ns"]
STRIDE = 16
P_NSWALK = 14
# Which map each program's counted operations touch (from the BPF source).
MAP_OPS = {
    0: {"map_deletes": "io_seen (lru_hash)"},
    1: {"map_lookups": "io_seen (lru_hash)", "map_updates": "io_seen (lru_hash)"},
    2: {"map_lookups": "io_seen (lru_hash)", "map_updates": "io_seen (lru_hash)"},
    3: {"map_lookups": "scratch_rename (percpu_array)", "map_updates": "pending_rename (hash)"},
    4: {"map_lookups": "pending_rename (hash)", "map_deletes": "pending_rename (hash)"},
    5: {"map_lookups": "scratch_unlink (percpu_array)", "map_updates": "pending_unlink (hash)"},
    6: {"map_lookups": "pending_unlink (hash)", "map_deletes": "pending_unlink (hash)"},
    7: {"map_updates": "pending_chdir (hash)"},
    8: {"map_lookups": "pending_chdir (hash)", "map_deletes": "pending_chdir (hash)"},
    9: {"map_updates": "pending_fchdir (hash)"},
    10: {"map_lookups": "pending_fchdir (hash)", "map_deletes": "pending_fchdir (hash)"},
}
HOT_ABLATIONS = [("security_file_open", 1 << 0), ("security_file_permission", 1 << 1),
                 ("security_mmap_file", 1 << 2), ("sched_process_exec", 1 << 11),
                 ("sched_process_fork", 1 << 12), ("sched_process_exit", 1 << 13)]
NULL_ALL = (1 << 14) - 1


class Log:
    def __init__(self, path: Path):
        self.f = path.open("a", encoding="utf-8")

    def __call__(self, msg: str) -> None:
        line = time.strftime("%H:%M:%S ") + msg
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()


# ---------------------------------------------------------------- BPF helpers
def ns_cflags() -> list[str]:
    _level, inum = pid_namespace_identity()
    return [f"-DNS_INUM={inum}U", f"-DNS_DEV={pid_namespace_kdev()}ULL"]


def set_attached(b, on: bool) -> None:
    for _pid, fn, kind, target in PROGRAMS:
        if kind == "kfunc":
            (b.attach_kfunc if on else b.detach_kfunc)(fn_name=fn)
        elif kind == "kretfunc":
            (b.attach_kretfunc if on else b.detach_kretfunc)(fn_name=fn)
        elif kind == "tp":
            b.attach_tracepoint(tp=target, fn_name=fn) if on else b.detach_tracepoint(tp=target)
        else:
            b.attach_raw_tracepoint(tp=target, fn_name=fn) if on else b.detach_raw_tracepoint(tp=target)


def prog_stats(b) -> dict:
    """run_cnt / run_time_ns per program from /proc/self/fdinfo (needs bpf_stats)."""
    out = {}
    for pid, fn, _kind, _t in PROGRAMS:
        f = b.funcs.get(fn.encode())
        if f is None:
            continue
        kv = {}
        for line in Path(f"/proc/self/fdinfo/{f.fd}").read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                kv[k.strip()] = v.strip()
        out[pid] = {"run_cnt": int(kv.get("run_cnt", 0)), "run_time_ns": int(kv.get("run_time_ns", 0)),
                    "verified_insns": int(kv["verified_insns"]) if "verified_insns" in kv else None}
    return out


def prof_counters(b) -> dict:
    t = b["wf_prof"]
    vals = {}
    for pid in list(SHORT) + [P_NSWALK]:
        vals[pid] = {m: int(t.sum(t.Key(pid * STRIDE + i)).value) for i, m in enumerate(METRICS)}
    return vals


def diff_nested(a: dict, b: dict) -> dict:
    return {k: ({kk: b[k][kk] - a[k].get(kk, 0) for kk in b[k] if isinstance(b[k][kk], int)} if isinstance(b[k], dict)
                else b[k] - a[k]) for k in b}


def bpf_stats(on: bool) -> None:
    Path("/proc/sys/kernel/bpf_stats_enabled").write_text("1" if on else "0")


class Poller:
    def __init__(self, fn):
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._loop, args=(fn,), daemon=True)
        self.t.start()

    def _loop(self, fn):
        while not self.stop.is_set():
            fn()

    def close(self):
        self.stop.set()
        self.t.join(timeout=5)


def child_cpu_s(pid: int | None) -> float:
    if not pid:
        return 0.0
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        return 0.0


# ---------------------------------------------------------------- statistics
def summary(xs: list[float]) -> dict:
    xs = sorted(xs)
    if not xs:
        return {}
    q = statistics.quantiles(xs, n=4) if len(xs) >= 2 else [xs[0]] * 3
    rng = random.Random(12345)
    meds = sorted(statistics.median(rng.choices(xs, k=len(xs))) for _ in range(2000))
    return {"n": len(xs), "median": statistics.median(xs), "mean": statistics.fmean(xs),
            "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0, "q1": q[0], "q3": q[2],
            "min": xs[0], "max": xs[-1], "median_ci90": [meds[100], meds[1899]]}


# ---------------------------------------------------------------- workload
# The graduation harness's three performance workloads: (prep, command, subdirectory).
WORKLOADS = {
    "static": (PREP, CMD, ""),
    "make": ("make -s clean >/dev/null; true", "make -s -j8", "cproj"),
    "vite": ("true", VITE, "web"),
}


class Workload:
    def __init__(self, ctx: Ctx, base: Path, log: Log, kind: str = "static", vite_template: Path | None = None):
        self.ctx, self.log, self.kind = ctx, log, kind
        self.prep_cmd, self.cmd, sub = WORKLOADS[kind]
        src = (REPO / "scripts" / "v02_graduation.py").read_text()
        assert f'"{self.prep_cmd}"' in src and (f'"{self.cmd}"' in src or self.cmd == VITE),             "workload differs from the graduation harness"
        self.ws = base / "perf"
        self.ws.mkdir(parents=True)
        self.cwd = self.ws / sub if sub else self.ws
        if kind == "static":
            (self.ws / "static_copy.c").write_text(STATIC_C)
            (self.ws / "raw.txt").write_text("x" * 4096)
        elif kind == "make":
            write_c_project(self.cwd)
        else:
            write_vite_project(self.cwd, vite_template or Path(f"/home/{ctx.user}/vite-template"))
        ctx.chown(self.ws)
        if kind == "static":
            ctx.run_user("gcc -static -O2 static_copy.c -o static_copy", self.ws)
        ctx.whyfs("init", str(self.ws), cwd=self.ws)

    def prep(self) -> None:
        self.ctx.run_user(self.prep_cmd, self.cwd, check=False)

    def run(self) -> float:
        """Seconds for the harness loop, timed inside the workload's own shell.

        The collector runs in this Python process in most phases; a busy
        collector thread holds the GIL, which delays this process noticing the
        child's exit and draining its pipes (up to the 5 ms switch interval per
        wake-up).  That inflates a Python-side timing without slowing the
        workload, so the loop is timed by the shell around the unchanged
        harness command.  The Python-side time is kept as ``last_outer``."""
        wrapped = f"s=$(date +%s%N); {self.cmd}; e=$(date +%s%N); echo WFTIME=$((e-s))"
        outer, p = self.ctx.run_user(wrapped, self.cwd)
        self.last_outer = outer
        for line in p.stdout.splitlines():
            if line.startswith("WFTIME="):
                return int(line.split("=", 1)[1]) / 1e9
        raise RuntimeError("workload did not report WFTIME")


# ---------------------------------------------------------------- phases
def start_collector(wl: Workload, run_id: str, flags: list[str]):
    store = Store(wl.ws).start()
    store.call("begin_run", run_id, time.time_ns(), str(wl.ws))
    c = BCCCollector(wl.ws, run_id, store=store, extra_cflags=flags)
    c.start()
    return c, store, Poller(lambda: c.poll(50))


def stop_collector(c, store, poller, run_id: str) -> dict:
    poller.close()
    stats = c.stop()
    final = {k: int(v) for k, v in vars(stats).items()}
    final.update(writer_rows=c.writer.written, writer_batches=c.writer.batches, writer_max_batch=c.writer.max_batch)
    store.call("end_run", run_id, time.time_ns(), 0, final)
    store.close()
    c.bpf.cleanup()
    return final


def phase_counts(wl: Workload, log: Log, reps: int, flags: list[str] | None = None, tag: str = "P") -> dict:
    flags = flags or ["-DWF_PROFILE"]
    log(f"phase {tag}: {' '.join(flags)} build, per-program counters + bpf_stats run time")
    c, store, poller = start_collector(wl, f"hotpath-{tag}", flags)
    child = store.pid
    b = c.bpf
    bpf_stats(True)
    try:
        for _ in range(2):  # warm-up, recorded
            wl.prep()
            log(f"  {tag} warm-up: {wl.run():.3f}s")
        rows, idle = [], []
        for i in range(reps):
            wl.prep()
            time.sleep(0.2)  # let prep's own events drain out of the window
            time.sleep(0.12)  # the poller thread consumes; ring-buffer consume is not thread-safe
            s0 = (prof_counters(b), prog_stats(b), dict(vars(c.stats)), time.process_time(), child_cpu_s(child))
            dt = wl.run()
            time.sleep(0.12)
            time.sleep(0.12)  # the poller thread consumes; ring-buffer consume is not thread-safe
            s1 = (prof_counters(b), prog_stats(b), dict(vars(c.stats)), time.process_time(), child_cpu_s(child))
            rows.append({"seconds": dt, "prof": diff_nested(s0[0], s1[0]), "prog": diff_nested(s0[1], s1[1]),
                         "collector": {k: s1[2][k] - s0[2][k] for k in s1[2]},
                         "collector_cpu_s": s1[3] - s0[3], "store_worker_cpu_s": s1[4] - s0[4],
                         "kernel_drops_total": c.kernel_drop_count()})
            log(f"  {tag} rep {i}: {dt:.3f}s  opens={rows[-1]['prof'][0]['calls']} perms={rows[-1]['prof'][1]['calls']}")
            # idle window of the same length: background activity
            a0 = (prof_counters(b), prog_stats(b))
            time.sleep(dt)
            a1 = (prof_counters(b), prog_stats(b))
            idle.append({"seconds": dt, "prof": diff_nested(a0[0], a1[0]), "prog": diff_nested(a0[1], a1[1])})
    finally:
        bpf_stats(False)
        final = stop_collector(c, store, poller, f"hotpath-{tag}")
    return {"flags": flags, "reps": rows, "idle": idle, "collector_final": final}


def phase_userspace(wl: Workload, log: Log, rounds: int) -> dict:
    """Controlled split of the monitored cost: one production program, one real
    collector; per round, rotated: detached baseline / kernel only (ring callback
    discards) / no store (full Python processing, SQLite ingest discarded) /
    full collector + privilege-separated store."""
    log("phase U: userspace split (base / kernel_only / no_store / full), rotated rounds")
    mode = {"discard": False, "nostore": False}
    store = Store(wl.ws).start()
    store.call("begin_run", "hotpath-U", time.time_ns(), str(wl.ws))
    c = BCCCollector(wl.ws, "hotpath-U", store=store)
    orig_cb = c._process_event
    c._process_event = lambda ctx, data, size: None if mode["discard"] else orig_cb(ctx, data, size)
    orig_ingest = store.ingest
    store.ingest = lambda events: len(events) if mode["nostore"] else orig_ingest(events)
    c.start()
    poller = Poller(lambda: c.poll(50))
    b = c.bpf
    child = store.pid
    modes = ["base", "kernel_only", "no_store", "full"]
    orders = [modes[i:] + modes[:i] for i in range(4)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    first = None
    stats = None
    try:
        wl.prep()
        first = wl.run()
        log(f"  U first build after load: {first:.3f}s")
        set_attached(b, False)
        time.sleep(0.3)
        for r in range(rounds + 1):  # round 0 is warm-up
            rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
            for m in orders[r % len(orders)]:
                mode["discard"], mode["nostore"] = (m == "kernel_only"), (m == "no_store")
                if m != "base":
                    set_attached(b, True)
                wl.prep()
                st0, cpu0, ch0 = dict(vars(c.stats)), time.process_time(), child_cpu_s(child)
                rec[m] = wl.run()
                rec[m + "_outer"] = wl.last_outer
                if m != "base":
                    set_attached(b, False)
                time.sleep(0.3)  # let userspace finish this run's events before the next run
                rec[m + "_collector_cpu_s"] = time.process_time() - cpu0
                rec[m + "_store_cpu_s"] = child_cpu_s(child) - ch0
                rec[m + "_received"] = vars(c.stats)["received"] - st0["received"]
            mode["discard"] = mode["nostore"] = False
            rows.append(rec)
            if r % 5 == 0:
                log(f"  U round {r}: " + " ".join(f"{m}={rec[m]:.4f}" for m in modes))
    finally:
        mode["discard"] = mode["nostore"] = False
        poller.close()
        stats = c.stop()
        store.call("end_run", "hotpath-U", time.time_ns(), 0, {k: int(v) for k, v in vars(stats).items()})
        store.close()
        b.cleanup()
    m = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a] - x[z]) * 1000 for x in m])

    out = {"first_build_after_load_s": first, "rounds": rows, "kernel_drops_total": c.kernel_drop_count(),
           "queue_drops_total": stats.queue_drops, "collector_final": {k: int(v) for k, v in vars(stats).items()},
           "kernel_minus_base_ms": d("kernel_only", "base"), "nostore_minus_base_ms": d("no_store", "base"),
           "full_minus_base_ms": d("full", "base"), "nostore_minus_kernel_ms": d("no_store", "kernel_only"),
           "full_minus_nostore_ms": d("full", "no_store"), "full_minus_kernel_ms": d("full", "kernel_only"),
           "per_mode_s": {k: summary([x[k] for x in m]) for k in modes},
           "per_mode_collector_cpu_s": {k: summary([x[k + "_collector_cpu_s"] for x in m]) for k in modes},
           "per_mode_store_cpu_s": {k: summary([x[k + "_store_cpu_s"] for x in m]) for k in modes},
           "full_overhead_pct": summary([(x["full"] / x["base"] - 1) * 100 for x in m]),
           "kernel_only_overhead_pct": summary([(x["kernel_only"] / x["base"] - 1) * 100 for x in m]),
           "no_store_overhead_pct": summary([(x["no_store"] / x["base"] - 1) * 100 for x in m])}
    for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "full_minus_nostore_ms", "full_minus_base_ms"):
        log(f"  U {k}: median {out[k]['median']:+.2f} ms (CI90 {out[k]['median_ci90'][0]:+.2f}..{out[k]['median_ci90'][1]:+.2f})")
    return out


def phase_timing(wl: Workload, log: Log, pairs: int, warmups: int, runtime_reps: int) -> dict:
    log("phase T: production build, alternating detached/attached pairs")
    c, store, poller = start_collector(wl, "hotpath-timing", [])
    child = store.pid
    b = c.bpf
    out: dict = {"flags": [], "pairs": [], "warmup_pairs": warmups}
    try:
        wl.prep()
        out["first_build_after_load_s"] = wl.run()
        log(f"  T first build after load: {out['first_build_after_load_s']:.3f}s")
        set_attached(b, False)
        order = [("off", "on")] * warmups + [("off", "on") if i % 2 == 0 else ("on", "off") for i in range(pairs)]
        for i, modes in enumerate(order):
            rec = {"warmup": i < warmups}
            for mode in modes:
                if mode == "on":
                    set_attached(b, True)
                wl.prep()
                time.sleep(0.12)  # the poller thread consumes; ring-buffer consume is not thread-safe
                st0, cpu0, ch0 = dict(vars(c.stats)), time.process_time(), child_cpu_s(child)
                dt = wl.run()
                if mode == "on":
                    time.sleep(0.12)
                    time.sleep(0.12)  # the poller thread consumes; ring-buffer consume is not thread-safe
                    rec["collector"] = {k: vars(c.stats)[k] - st0[k] for k in st0}
                    rec["collector_cpu_s"] = time.process_time() - cpu0
                    rec["store_worker_cpu_s"] = child_cpu_s(child) - ch0
                    set_attached(b, False)
                rec[mode] = dt
                rec[mode + "_outer"] = wl.last_outer
            rec["overhead_pct"] = (rec["on"] / rec["off"] - 1) * 100
            out["pairs"].append(rec)
            log(f"  T pair {i}{' (warm-up)' if rec['warmup'] else ''}: off {rec['off']:.4f}s on {rec['on']:.4f}s "
                f"-> {rec['overhead_pct']:+.2f}%")
        log("  T run-time reps (bpf_stats on)")
        set_attached(b, True)
        bpf_stats(True)
        rt, idle = [], []
        for i in range(runtime_reps):
            wl.prep()
            time.sleep(0.2)
            s0 = prog_stats(b)
            dt = wl.run()
            s1 = prog_stats(b)
            rt.append({"seconds": dt, "prog": diff_nested(s0, s1)})
            a0 = prog_stats(b)
            time.sleep(dt)
            idle.append({"seconds": dt, "prog": diff_nested(a0, prog_stats(b))})
        out["runtime_reps"], out["runtime_idle"] = rt, idle
        out["kernel_drops_total"] = c.kernel_drop_count()
    finally:
        bpf_stats(False)
        out["collector_final"] = stop_collector(c, store, poller, "hotpath-timing")
    meas = [p for p in out["pairs"] if not p["warmup"]]
    out["summary"] = {"overhead_pct": summary([p["overhead_pct"] for p in meas]),
                      "off_s": summary([p["off"] for p in meas]), "on_s": summary([p["on"] for p in meas]),
                      "per_process_us": summary([(p["on"] - p["off"]) / PROCESSES_PER_RUN * 1e6 for p in meas])}
    return out


def load_plain(mask: int):
    """A BPF object of the production program (optionally with nulled bodies)
    and a no-op ring consumer; attached at load, detached here."""
    from bcc import BPF  # type: ignore
    flags = ns_cflags() + ([f"-DWF_NULL_MASK={mask}U"] if mask else [])
    b = BPF(text=BPF_SOURCE, cflags=flags)
    b["events"].open_ring_buffer(lambda *a: None)
    poller = Poller(lambda: (b.ring_buffer_poll(50), b.ring_buffer_consume()))
    set_attached(b, False)
    return b, poller


def phase_ablation(wl: Workload, log: Log, rounds: int) -> dict:
    log("phase A: hook-body ablation (WF_NULL_MASK), rotated baseline/normal/nulled rounds")
    perms = [("base", "normal", "null"), ("normal", "null", "base"), ("null", "base", "normal"),
             ("base", "null", "normal"), ("null", "normal", "base"), ("normal", "base", "null")]
    result = {}
    for label, mask in [("null_all", NULL_ALL)] + HOT_ABLATIONS:
        normal, pn = load_plain(0)
        nulled, px = load_plain(mask)
        objs = {"normal": normal, "null": nulled}
        rows = []
        try:
            for r in range(rounds + 1):  # round 0 is warm-up
                rec = {"warmup": r == 0}
                for mode in perms[r % len(perms)]:
                    if mode != "base":
                        set_attached(objs[mode], True)
                    wl.prep()
                    rec[mode] = wl.run()
                    rec[mode + "_outer"] = wl.last_outer
                    if mode != "base":
                        set_attached(objs[mode], False)
                rows.append(rec)
        finally:
            for o, p in ((normal, pn), (nulled, px)):
                p.close()
                o.cleanup()
        m = [x for x in rows if not x["warmup"]]
        result[label] = {
            "mask": mask, "rounds": rows,
            "normal_minus_base_ms": summary([(x["normal"] - x["base"]) * 1000 for x in m]),
            "normal_minus_null_ms": summary([(x["normal"] - x["null"]) * 1000 for x in m]),
            "null_minus_base_ms": summary([(x["null"] - x["base"]) * 1000 for x in m]),
            "base_s": summary([x["base"] for x in m]), "normal_s": summary([x["normal"] for x in m]),
            "null_s": summary([x["null"] for x in m]),
        }
        s = result[label]
        log(f"  A {label}: normal-base {s['normal_minus_base_ms']['median']:+.2f} ms, "
            f"normal-null {s['normal_minus_null_ms']['median']:+.2f} ms "
            f"(CI90 {s['normal_minus_null_ms']['median_ci90'][0]:+.2f}..{s['normal_minus_null_ms']['median_ci90'][1]:+.2f})")
    return result


EVENT_NAMES = {1: "open", 2: "read", 3: "write", 4: "rename", 5: "unlink", 6: "exec", 7: "fork", 8: "exit",
               9: "mmap_read", 13: "chdir", 14: "fchdir", 15: "mmap_write"}
TYPE_OFFSET = 36  # struct hdr_t: ts_ns, file, file2 (8 each), tgid, tid, aux_pid (4 each), type


def phase_mechanism(wl: Workload, log: Log, rounds: int, cprofile_reps: int) -> dict:
    """V: is the userspace cost generic CPU interference or specific to event
    processing?  Rotated rounds of base / kernel_only / no_store / burn, where
    burn discards events at once but spins a Python thread for the whole run.
    W: per-event-type callback time (no_store runs) and a cProfile of the
    callback."""
    import cProfile
    import io
    import pstats
    log("phase V: mechanism (base / kernel_only / no_store / burn), rotated rounds")
    mode = {"discard": False, "nostore": False, "time": False, "prof": None}
    per_type_ns: dict[int, int] = {}
    per_type_n: dict[int, int] = {}
    store = Store(wl.ws).start()
    store.call("begin_run", "hotpath-V", time.time_ns(), str(wl.ws))
    c = BCCCollector(wl.ws, "hotpath-V", store=store)
    orig_cb = c._process_event

    def cb(ctx, data, size):
        if mode["discard"]:
            return None
        if mode["prof"] is not None:
            mode["prof"].enable()
            try:
                return orig_cb(ctx, data, size)
            finally:
                mode["prof"].disable()
        if mode["time"]:
            typ = ct.c_uint32.from_address(data + TYPE_OFFSET).value
            t0 = time.perf_counter_ns()
            try:
                return orig_cb(ctx, data, size)
            finally:
                per_type_ns[typ] = per_type_ns.get(typ, 0) + time.perf_counter_ns() - t0
                per_type_n[typ] = per_type_n.get(typ, 0) + 1
        return orig_cb(ctx, data, size)

    c._process_event = cb
    orig_ingest = store.ingest
    store.ingest = lambda events: len(events) if mode["nostore"] else orig_ingest(events)
    c.start()
    poller = Poller(lambda: c.poll(50))
    b = c.bpf
    burn_stop = threading.Event()

    def burner():
        x = 0
        while not burn_stop.is_set():
            x += 1

    modes = ["base", "kernel_only", "no_store", "burn"]
    orders = [modes[i:] + modes[:i] for i in range(4)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    stats = None
    try:
        wl.prep()
        wl.run()
        set_attached(b, False)
        time.sleep(0.3)
        for r in range(rounds + 1):
            rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
            for m in orders[r % len(orders)]:
                mode["discard"] = m in ("kernel_only", "burn")
                mode["nostore"] = m == "no_store"
                if m != "base":
                    set_attached(b, True)
                wl.prep()
                cpu0 = time.process_time()
                th = None
                if m == "burn":
                    burn_stop.clear()
                    th = threading.Thread(target=burner, daemon=True)
                    th.start()
                rec[m] = wl.run()
                rec[m + "_outer"] = wl.last_outer
                if th:
                    burn_stop.set()
                    th.join()
                if m != "base":
                    set_attached(b, False)
                time.sleep(0.3)
                rec[m + "_process_cpu_s"] = time.process_time() - cpu0
            mode["discard"] = mode["nostore"] = False
            rows.append(rec)
            if r % 5 == 0:
                log(f"  V round {r}: " + " ".join(f"{m}={rec[m]:.4f}" for m in modes))
        log("phase W: per-event-type callback time and cProfile (no_store mode)")
        mode["nostore"] = True
        set_attached(b, True)
        mode["time"] = True
        for _ in range(cprofile_reps):
            wl.prep()
            wl.run()
            time.sleep(0.3)
        mode["time"] = False
        prof = cProfile.Profile()
        mode["prof"] = prof
        for _ in range(cprofile_reps):
            wl.prep()
            wl.run()
            time.sleep(0.3)
        mode["prof"] = None
        set_attached(b, False)
        time.sleep(0.3)
    finally:
        mode["discard"] = mode["nostore"] = mode["time"] = False
        mode["prof"] = None
        poller.close()
        stats = c.stop()
        store.call("end_run", "hotpath-V", time.time_ns(), 0, {k: int(v) for k, v in vars(stats).items()})
        store.close()
        b.cleanup()
    m = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a] - x[z]) * 1000 for x in m])

    buf = io.StringIO()
    pstats.Stats(prof, stream=buf).sort_stats("tottime").print_stats(25)
    per_type = {EVENT_NAMES.get(t, str(t)): {"events_per_run": per_type_n[t] / cprofile_reps,
                                             "us_per_event": per_type_ns[t] / per_type_n[t] / 1000,
                                             "ms_per_run": per_type_ns[t] / cprofile_reps / 1e6}
                for t in per_type_n}
    out = {"rounds": rows, "per_mode_s": {k: summary([x[k] for x in m]) for k in modes},
           "per_mode_process_cpu_s": {k: summary([x[k + "_process_cpu_s"] for x in m]) for k in modes},
           "kernel_minus_base_ms": d("kernel_only", "base"), "nostore_minus_kernel_ms": d("no_store", "kernel_only"),
           "burn_minus_kernel_ms": d("burn", "kernel_only"), "nostore_minus_burn_ms": d("no_store", "burn"),
           "callback_time_per_event_type": per_type, "callback_cprofile_top": buf.getvalue(),
           "kernel_drops_total": c.kernel_drop_count(), "queue_drops_total": stats.queue_drops}
    for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "burn_minus_kernel_ms", "nostore_minus_burn_ms"):
        log(f"  V {k}: median {out[k]['median']:+.2f} ms (CI90 {out[k]['median_ci90'][0]:+.2f}..{out[k]['median_ci90'][1]:+.2f})")
    log("  W callback time per event type: " + json.dumps({k: round(v["us_per_event"], 1) for k, v in per_type.items()}))
    return out


def phase_canon(wl: Workload, log: Log, rounds: int) -> dict:
    """X: is the userspace interference the realpath() lstat traffic?
    Rotated rounds of base / kernel_only / no_store / canon_only / no_store_nocanon.
      canon_only        callback discards, but performs the realpath() calls that
                        processing makes for exec and unlink names
      no_store_nocanon  full processing with realpath replaced by normpath
                        (diagnostic only: realpath is needed for symlinked paths)"""
    import whyfs.ebpf_bcc as eb
    log("phase X: realpath/lstat mechanism, rotated rounds")
    mode = {"discard": False, "nostore": False, "nocanon": False, "canon_only": False}
    orig_canon = eb._canon
    eb._canon = lambda p: os.path.normpath(p) if mode["nocanon"] else orig_canon(p)
    store = Store(wl.ws).start()
    store.call("begin_run", "hotpath-X", time.time_ns(), str(wl.ws))
    c = BCCCollector(wl.ws, "hotpath-X", store=store)
    orig_cb = c._process_event
    ws = str(wl.ws)

    def cb(ctx, data, size):
        if mode["canon_only"]:
            typ = ct.c_uint32.from_address(data + TYPE_OFFSET).value
            if typ in (5, 6):  # unlink, exec: the events whose names go through realpath
                raw = ct.string_at(data + eb.OFF_PATH).decode("utf-8", "replace")
                if raw:
                    orig_canon(raw if raw.startswith("/") else os.path.join(ws, raw))
            return None
        if mode["discard"]:
            return None
        return orig_cb(ctx, data, size)

    c._process_event = cb
    orig_ingest = store.ingest
    store.ingest = lambda events: len(events) if mode["nostore"] else orig_ingest(events)
    c.start()
    poller = Poller(lambda: c.poll(50))
    b = c.bpf
    modes = ["base", "kernel_only", "no_store", "canon_only", "no_store_nocanon"]
    orders = [modes[i:] + modes[:i] for i in range(5)]
    orders += [list(reversed(o)) for o in orders]
    rows = []
    stats = None
    try:
        wl.prep()
        wl.run()
        set_attached(b, False)
        time.sleep(0.3)
        for r in range(rounds + 1):
            rec = {"warmup": r == 0, "order": orders[r % len(orders)]}
            for m in orders[r % len(orders)]:
                mode["discard"] = m == "kernel_only"
                mode["canon_only"] = m == "canon_only"
                mode["nostore"] = m in ("no_store", "no_store_nocanon")
                mode["nocanon"] = m == "no_store_nocanon"
                if m != "base":
                    set_attached(b, True)
                wl.prep()
                cpu0 = time.process_time()
                rec[m] = wl.run()
                rec[m + "_outer"] = wl.last_outer
                if m != "base":
                    set_attached(b, False)
                time.sleep(0.3)
                rec[m + "_process_cpu_s"] = time.process_time() - cpu0
            for k in mode:
                mode[k] = False
            rows.append(rec)
            if r % 5 == 0:
                log(f"  X round {r}: " + " ".join(f"{m}={rec[m]:.4f}" for m in modes))
    finally:
        for k in mode:
            mode[k] = False
        eb._canon = orig_canon
        poller.close()
        stats = c.stop()
        store.call("end_run", "hotpath-X", time.time_ns(), 0, {k: int(v) for k, v in vars(stats).items()})
        store.close()
        b.cleanup()
    m = [x for x in rows if not x["warmup"]]

    def d(a, z):
        return summary([(x[a] - x[z]) * 1000 for x in m])

    out = {"rounds": rows, "per_mode_s": {k: summary([x[k] for x in m]) for k in modes},
           "per_mode_process_cpu_s": {k: summary([x[k + "_process_cpu_s"] for x in m]) for k in modes},
           "kernel_minus_base_ms": d("kernel_only", "base"), "nostore_minus_kernel_ms": d("no_store", "kernel_only"),
           "canon_only_minus_kernel_ms": d("canon_only", "kernel_only"),
           "nostore_nocanon_minus_kernel_ms": d("no_store_nocanon", "kernel_only"),
           "nostore_minus_nostore_nocanon_ms": d("no_store", "no_store_nocanon"),
           "kernel_drops_total": c.kernel_drop_count(), "queue_drops_total": stats.queue_drops}
    for k in ("kernel_minus_base_ms", "nostore_minus_kernel_ms", "canon_only_minus_kernel_ms",
              "nostore_nocanon_minus_kernel_ms", "nostore_minus_nostore_nocanon_ms"):
        log(f"  X {k}: median {out[k]['median']:+.2f} ms (CI90 {out[k]['median_ci90'][0]:+.2f}..{out[k]['median_ci90'][1]:+.2f})")
    return out


# ---------------------------------------------------------------- tables
def write_tables(out: Path, res: dict) -> None:
    P = res["phase_P"]
    with (out / "counts_per_program.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["program", "hook", "window"] + METRICS + ["run_cnt", "run_time_ns"])
        for kind, rows in (("workload", P["reps"]), ("idle", P["idle"])):
            for pid in list(SHORT) + [P_NSWALK]:
                med = {m: statistics.median(r["prof"][pid][m] for r in rows) for m in METRICS}
                rc = statistics.median(r["prog"].get(pid, {}).get("run_cnt", 0) for r in rows)
                rtn = statistics.median(r["prog"].get(pid, {}).get("run_time_ns", 0) for r in rows)
                w.writerow([pid, SHORT.get(pid, "upid_walk (any program)"), kind] + [med[m] for m in METRICS] + [rc, rtn])
    T = res["phase_T"]
    with (out / "timing_pairs.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["pair", "warmup", "off_s", "on_s", "overhead_pct", "received", "submitted", "filtered",
                    "queue_drops", "collector_cpu_s", "store_worker_cpu_s"])
        for i, p in enumerate(T["pairs"]):
            col = p.get("collector", {})
            w.writerow([i, p["warmup"], p["off"], p["on"], p["overhead_pct"], col.get("received"), col.get("submitted"),
                        col.get("filtered"), col.get("queue_drops"), p.get("collector_cpu_s"), p.get("store_worker_cpu_s")])
    with (out / "ablation_rounds.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["variant", "round", "warmup", "base_s", "normal_s", "null_s"])
        for label, a in res["phase_A"].items():
            for i, r in enumerate(a["rounds"]):
                w.writerow([label, i, r["warmup"], r["base"], r["normal"], r["null"]])


def git_info(out: Path) -> dict:
    g = ["git", "-c", f"safe.directory={REPO}", "-C", str(REPO)]
    head = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    diff = subprocess.run(g + ["diff", "HEAD"], capture_output=True, text=True).stdout
    status = subprocess.run(g + ["status", "--short"], capture_output=True, text=True).stdout
    (out / "git.diff").write_text(diff)
    (out / "git-status.txt").write_text(f"HEAD {head}\n{status}")
    return {"head": head, "dirty_files": status.splitlines(), "diff_bytes": len(diff)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--base", default="/home/{user}/whyfs-hotpath-ws")
    ap.add_argument("--profile-reps", type=int, default=10)
    ap.add_argument("--pairs", type=int, default=20)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--runtime-reps", type=int, default=10)
    ap.add_argument("--ablation-rounds", type=int, default=20)
    ap.add_argument("--userspace-rounds", type=int, default=40)
    ap.add_argument("--cprofile-reps", type=int, default=5)
    ap.add_argument("--phases", default="P,T,A", help="comma list of P,T,A (Step 1) and Q,U,V,X (follow-up)")
    ap.add_argument("--workload", default="static", choices=sorted(WORKLOADS))
    ap.add_argument("--extra-cflags", default="", help="extra BPF cflags for phases P/Q (e.g. -DWF_IOSEEN_MODE=1)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        return 2
    out = Path(a.out)
    if out.exists():
        print(f"{out} exists; refusing to overwrite earlier results", file=sys.stderr)
        return 2
    out.mkdir(parents=True)
    log = Log(out / "console.log")
    ensure_kernel_headers()
    base = Path(a.base.format(user=a.user))
    if base.exists():
        shutil.rmtree(base)
    (out / "harness-ctx").mkdir()
    ctx = Ctx(a.user, out / "harness-ctx")
    params = {"workload": a.workload, "workload_prep": WORKLOADS[a.workload][0], "workload_cmd": WORKLOADS[a.workload][1],
              "extra_cflags": a.extra_cflags, "processes_per_run": PROCESSES_PER_RUN,
              "timing": "shell-timed loop (date +%s%N around the unchanged harness command); "
                        "Python-side subprocess time kept as *_outer",
              "static_c_source": "scripts/v02_graduation.py:STATIC_C", "user": a.user, "workspace_base": str(base),
              "profile_reps": a.profile_reps, "pairs": a.pairs, "warmups": a.warmups,
              "runtime_reps": a.runtime_reps, "ablation_rounds": a.ablation_rounds,
              "profiling_build_flags": ["-DWF_PROFILE"], "production_build_flags": ns_cflags(),
              "ablation_masks": {label: mask for label, mask in [("null_all", NULL_ALL)] + HOT_ABLATIONS}}
    (out / "params.json").write_text(json.dumps(params, indent=2))
    res = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "params": params, "git": git_info(out),
           "environment": environment()}
    (out / "environment.json").write_text(json.dumps(res["environment"], indent=2))
    log(f"git HEAD {res['git']['head']} dirty={len(res['git']['dirty_files'])}")
    wl = Workload(ctx, base, log, a.workload)
    phases = set(a.phases.split(","))
    params["phases"] = sorted(phases)
    params["userspace_rounds"] = a.userspace_rounds
    (out / "params.json").write_text(json.dumps(params, indent=2))
    try:
        if "P" in phases:
            res["phase_P"] = phase_counts(wl, log, a.profile_reps)
        extra = a.extra_cflags.split() if a.extra_cflags else []
        if "Q" in phases:
            res["phase_Q"] = phase_counts(wl, log, a.profile_reps, ["-DWF_PROFILE", "-DWF_PROFILE_TIME", *extra], "Q")
        if "T" in phases:
            res["phase_T"] = phase_timing(wl, log, a.pairs, a.warmups, a.runtime_reps)
        if "A" in phases:
            res["phase_A"] = phase_ablation(wl, log, a.ablation_rounds) if a.ablation_rounds > 0 else {}
        if "U" in phases:
            res["phase_U"] = phase_userspace(wl, log, a.userspace_rounds)
        if "V" in phases:
            res["phase_V"] = phase_mechanism(wl, log, a.userspace_rounds, a.cprofile_reps)
        if "X" in phases:
            res["phase_X"] = phase_canon(wl, log, a.userspace_rounds)
    finally:
        res["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        (out / "hotpath.json").write_text(json.dumps(res, indent=1, default=str))
    if "phase_P" in res and "phase_T" in res and "phase_A" in res:
        write_tables(out, res)
    log(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
