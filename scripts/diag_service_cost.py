"""Diagnostic only (not validation): where the machine service's cost goes on native_exe_x300.

Runs the unchanged machine_perf workload (300 x copy.exe) with the same pairing and pauses,
with the INSTALLED service, and snapshots precise OS counters around every measured run:
  * total busy CPU: elapsed cycles minus idle-processor cycles (QueryIdleProcessorCycleTime);
    this includes the kernel's event generation inside the workload's own processes;
  * per process (collector, `whyfs machine serve`, whyfs-svc, System): cycle time, context
    switches, I/O operations and bytes (NtQuerySystemInformation);
  * per collector thread (named by the collector): cycle time (QueryThreadCycleTime).
Service variants (the collector reads them from the service's environment):
  normal    the product
  no_write  everything except the SQLite writes (WHYFS_DIAG_NO_WRITE)
  discard   events delivered and counted, nothing processed (WHYFS_DIAG_DISCARD)
  discard_no_vamap / discard_no_kfile / discard_no_sys   the same, without one event source

  python scripts\\diag_service_cost.py --out DIR [--pairs 10] [--variants normal,no_write,discard]
Needs an elevated shell, the MSI installed, and WHYFS_VCVARS for the workload build.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import sqlite3
import statistics
import struct
import sys
import tempfile
import time
import winreg
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import machine_perf as mp  # noqa: E402

ntdll, k32 = ctypes.windll.ntdll, ctypes.windll.kernel32
k32.OpenThread.restype = wintypes.HANDLE
k32.OpenProcess.restype = wintypes.HANDLE
SVC_KEY = r"SYSTEM\CurrentControlSet\Services\whyfs"
VARIANTS = {"normal": [], "no_write": ["WHYFS_DIAG_NO_WRITE=1"], "discard": ["WHYFS_DIAG_DISCARD=1"],
            # kernel-side cost of each event source (nothing processed in user space)
            "discard_no_vamap": ["WHYFS_DIAG_DISCARD=1", "WHYFS_DIAG_NO_VAMAP=1"],
            "discard_no_kfile": ["WHYFS_DIAG_DISCARD=1", "WHYFS_DIAG_NO_KFILE=1"],
            "discard_no_sys": ["WHYFS_DIAG_DISCARD=1", "WHYFS_DIAG_NO_SYS=1"]}


# ---------------------------------------------------------------- counters
def idle_cycles() -> int:
    n = wintypes.ULONG(0)
    k32.QueryIdleProcessorCycleTime(ctypes.byref(n), None)
    buf = (ctypes.c_ulonglong * (n.value // 8))()
    k32.QueryIdleProcessorCycleTime(ctypes.byref(n), buf)
    return sum(buf)


def processes() -> dict[int, dict]:
    """NtQuerySystemInformation(SystemProcessInformation): per-process counters and thread ids."""
    size = 1 << 20
    while True:
        buf = ctypes.create_string_buffer(size)
        ret = wintypes.ULONG(0)
        st = ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(ret)) & 0xFFFFFFFF
        if st == 0xC0000004:  # STATUS_INFO_LENGTH_MISMATCH
            size = max(size * 2, ret.value + 65536)
            continue
        if st:
            raise OSError(f"NtQuerySystemInformation {st:#x}")
        break
    raw, out, off = buf.raw, {}, 0
    while True:
        nxt, nthreads = struct.unpack_from("<II", raw, off)
        cycles, = struct.unpack_from("<Q", raw, off + 24)
        user, kern = struct.unpack_from("<qq", raw, off + 40)
        name_len, = struct.unpack_from("<H", raw, off + 56)
        name_ptr, = struct.unpack_from("<Q", raw, off + 64)
        pid, = struct.unpack_from("<Q", raw, off + 80)
        rops, wops, oops, rbytes, wbytes, obytes = struct.unpack_from("<6q", raw, off + 208)
        name = ctypes.wstring_at(name_ptr, name_len // 2) if name_ptr and name_len else ""
        threads, cs = [], 0
        for t in range(nthreads):
            to = off + 256 + 80 * t
            tid, = struct.unpack_from("<Q", raw, to + 48)
            ctx, = struct.unpack_from("<I", raw, to + 64)
            threads.append((tid, ctx))
            cs += ctx
        out[pid] = {"name": name, "cycles": cycles, "cpu_100ns": user + kern, "ctx": cs, "read_ops": rops,
                    "write_ops": wops, "read_bytes": rbytes, "write_bytes": wbytes, "threads": threads}
        if not nxt:
            return out
        off += nxt


def thread_info(tid: int) -> tuple[str, int]:
    h = k32.OpenThread(0x0800, False, tid)  # THREAD_QUERY_LIMITED_INFORMATION
    if not h:
        return "?", 0
    try:
        c = ctypes.c_ulonglong(0)
        k32.QueryThreadCycleTime(wintypes.HANDLE(h), ctypes.byref(c))
        name = ""
        p = ctypes.c_void_p()
        f = getattr(k32, "GetThreadDescription", None)
        if f:
            f.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
            f.restype = ctypes.c_long  # HRESULT: success is >= 0
            if f(wintypes.HANDLE(h), ctypes.byref(p)) >= 0 and p.value:
                name = ctypes.wstring_at(p.value)
                k32.LocalFree.argtypes = [ctypes.c_void_p]
                k32.LocalFree(p)
        return name, c.value
    finally:
        k32.CloseHandle(wintypes.HANDLE(h))


def roles() -> dict[str, int]:
    """pid of each service component (python machine serve found through machine_perf)."""
    procs = processes()
    r = {}
    for pid, p in procs.items():
        n = p["name"].lower()
        if n == "whyfs-collect-win.exe":
            r["collector"] = pid
        elif n == "whyfs-svc.exe":
            r["svc"] = pid
    for pid in mp.collector_pids():
        if procs.get(pid, {}).get("name", "").lower() in ("python.exe", "pythonw.exe"):
            r["serve"] = pid
    r["system"] = 4
    return r


def snapshot(rl: dict[str, int]) -> dict:
    procs = processes()
    snap = {"t": time.perf_counter(), "idle": idle_cycles(), "all_cycles": sum(p["cycles"] for p in procs.values()),
            "all_ctx": sum(p["ctx"] for p in procs.values()), "proc": {}, "threads": {}}
    for role, pid in rl.items():
        p = procs.get(pid)
        if p:
            snap["proc"][role] = {k: p[k] for k in ("cycles", "cpu_100ns", "ctx", "read_ops", "write_ops", "read_bytes", "write_bytes")}
            if role == "collector":
                for tid, ctx in p["threads"]:
                    name, cyc = thread_info(tid)
                    snap["threads"][name or f"tid{tid}"] = {"cycles": cyc, "ctx": ctx}
    return snap


def delta(a: dict, b: dict, rate: float) -> dict:
    ms = lambda cyc: round(cyc / rate * 1000, 2)  # noqa: E731
    wall = b["t"] - a["t"]
    d = {"wall_ms": round(wall * 1000, 1), "busy_ms": ms(wall * rate * (os.cpu_count() or 1) - (b["idle"] - a["idle"])),
         "ctx_live_procs": b["all_ctx"] - a["all_ctx"], "proc": {}, "threads": {}}
    for role in b["proc"]:
        if role in a["proc"]:
            x, y = a["proc"][role], b["proc"][role]
            d["proc"][role] = {"cpu_ms": ms(y["cycles"] - x["cycles"]), "ctx": y["ctx"] - x["ctx"],
                               "write_ops": y["write_ops"] - x["write_ops"], "write_bytes": y["write_bytes"] - x["write_bytes"],
                               "read_ops": y["read_ops"] - x["read_ops"]}
    for t in b["threads"]:
        if t in a["threads"]:
            d["threads"][t] = {"cpu_ms": ms(b["threads"][t]["cycles"] - a["threads"][t]["cycles"]),
                               "ctx": b["threads"][t]["ctx"] - a["threads"][t]["ctx"]}
    return d


def cycle_rate() -> float:
    """cycles per second of one processor, from all processes' cycles plus idle over 3 s."""
    n = os.cpu_count() or 1
    a_i, a_p, t0 = idle_cycles(), sum(p["cycles"] for p in processes().values()), time.perf_counter()
    time.sleep(3)
    b_i, b_p, t1 = idle_cycles(), sum(p["cycles"] for p in processes().values()), time.perf_counter()
    return ((b_i - a_i) + (b_p - a_p)) / (t1 - t0) / n


# ---------------------------------------------------------------- service variants
def set_variant(env: list[str]) -> None:
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SVC_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if env:
            winreg.SetValueEx(k, "Environment", 0, winreg.REG_MULTI_SZ, env)
        else:
            try:
                winreg.DeleteValue(k, "Environment")
            except FileNotFoundError:
                pass


def store_counts(t0_ns: int) -> dict:
    con = sqlite3.connect(f"file:{mp.STORE}?mode=ro", uri=True, timeout=30)
    try:
        runs = [r[0] for r in con.execute("SELECT id FROM runs WHERE started_ns>=?", (t0_ns,))]
        q = ",".join("?" * len(runs)) or "''"
        return {"processes": con.execute(f"SELECT COUNT(*) FROM processes WHERE run_id IN ({q})", runs).fetchone()[0],
                "events": con.execute(f"SELECT COUNT(*) FROM events WHERE run_id IN ({q})", runs).fetchone()[0],
                "events_by_kind": dict(con.execute(f"SELECT kind, COUNT(*) FROM events WHERE run_id IN ({q}) GROUP BY kind", runs).fetchall())}
    finally:
        con.close()


def med(xs):
    xs = [x for x in xs if x is not None]
    return round(statistics.median(xs), 2) if xs else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pairs", type=int, default=10)
    ap.add_argument("--warmups", type=int, default=1)
    ap.add_argument("--variants", default="normal,no_write,discard")
    ap.add_argument("--after-s", type=float, default=7.0,
                    help="wait after each measured run, counted as 'after_7s' (0.2 = machine_perf's own timing, where "
                         "the previous run's processing overlaps the next measured run)")
    ap.add_argument("--verify", action="store_true", help="after the normal variant: every stress output's label checked")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    base = Path(tempfile.mkdtemp(prefix="whyfs-dsc-", dir=os.path.expanduser("~")))  # in scope, as machine_perf
    ws, run, wl, _ = mp.workloads(base, None)
    prep, cmd, cwd, env = wl["native_exe_x300"]
    rate = cycle_rate()
    report = {"cpu_count": os.cpu_count(), "cycles_per_s": rate, "variants": {}}
    mp.note(f"cycle rate {rate / 1e9:.3f} GHz per processor, {os.cpu_count()} processor(s)")
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
                rl = roles() if mode == "on" else {"system": 4}
                run(prep, cwd, env=env, check=False)
                run(cmd, cwd, env=env)  # the same warm first build as machine_perf
                run(prep, cwd, env=env, check=False)
                time.sleep(mp.PAUSE_S)
                s0 = snapshot(rl)
                secs = run(cmd, cwd, env=env)
                s1 = snapshot(rl)
                row = {"mode": mode, "warmup": idx < 2 * a.warmups, "seconds": secs, **delta(s0, s1, rate)}
                # the 5 s reorder window moves a run's processing into the following seconds: count it too
                time.sleep(a.after_s)
                s2 = snapshot(rl)
                row["after_7s"] = delta(s1, s2, rate)
                rows.append(row)
                mp.note(f"{vname} {mode}{' warmup' if row['warmup'] else ''}: {secs:.3f}s busy {row['busy_ms']} ms "
                        f"collector {row['proc'].get('collector', {}).get('cpu_ms')} ms (+{row['after_7s']['proc'].get('collector', {}).get('cpu_ms')} after)")
            verify = None
            if a.verify and vname == "normal":  # correctness under the same stress, the product configuration
                if not state["on"]:
                    mp.service(True)
                import stress_verify
                verify = stress_verify.verify(run, prep, cmd, cwd, env, "copy.exe")
                mp.note(f"verify: {verify}")
            mp.service(False)  # final collector stats are written at exit
            meas = [r for r in rows if not r["warmup"]]
            offs = [r for r in meas if r["mode"] == "off"]
            ons = [r for r in meas if r["mode"] == "on"]
            paired = [(ons[i]["seconds"] / offs[i]["seconds"] - 1) * 100 for i in range(min(len(ons), len(offs)))]
            lost, per = mp.loss_since(t_var)

            def during_and_after(r, *path):
                v, w = r, r["after_7s"]
                for p in path:
                    v = v.get(p, {}) if isinstance(v, dict) else {}
                    w = w.get(p, {}) if isinstance(w, dict) else {}
                return (v or 0) + (w or 0) if isinstance(v, (int, float)) and isinstance(w, (int, float)) else None
            thread_names = sorted({t for r in ons for t in r["threads"]})
            summary = {
                "median_paired_overhead_percent": med(paired), "paired": [round(p, 2) for p in paired],
                "ci90": mp.bootstrap_ci(paired) if len(paired) > 2 else None,
                "off_seconds_median": med([r["seconds"] for r in offs]), "on_seconds_median": med([r["seconds"] for r in ons]),
                "busy_ms_during": {"off": med([r["busy_ms"] for r in offs]), "on": med([r["busy_ms"] for r in ons])},
                "busy_ms_during_plus_7s": {"off": med([r["busy_ms"] + r["after_7s"]["busy_ms"] for r in offs]),
                                           "on": med([r["busy_ms"] + r["after_7s"]["busy_ms"] for r in ons])},
                "system_cpu_ms_plus_7s": {"off": med([during_and_after(r, "proc", "system", "cpu_ms") for r in offs]),
                                          "on": med([during_and_after(r, "proc", "system", "cpu_ms") for r in ons])},
                "per_on_run_including_following_7s": {
                    role: {k: med([during_and_after(r, "proc", role, k) for r in ons]) for k in ("cpu_ms", "ctx", "write_ops", "write_bytes", "read_ops")}
                    for role in ("collector", "serve", "svc", "system")},
                "collector_threads_cpu_ms": {t: med([during_and_after(r, "threads", t, "cpu_ms") for r in ons]) for t in thread_names},
                "collector_threads_ctx": {t: med([during_and_after(r, "threads", t, "ctx") for r in ons]) for t in thread_names},
                "lost": lost, "collector_stats": per, "stored": store_counts(t_var),
            }
            report["variants"][vname] = {"summary": summary, "runs": rows, "verify": verify}
            mp.note(f"{vname}: median paired overhead {summary['median_paired_overhead_percent']}%  {json.dumps(summary['per_on_run_including_following_7s'])}")
            (out / "diag_service_cost.json").write_text(json.dumps(report, indent=1, default=str))
    finally:
        set_variant([])
        mp.service(True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
