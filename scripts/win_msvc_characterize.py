#!/usr/bin/env python3
"""Characterize MSVC build timing on this machine WITHOUT whyfs (no collector running).

For the small (36-unit) and realistic (240-unit) MSVC workloads of the Windows gate, run N
builds each, with the idle gap before each build randomized (0.1 s or 1.5 s), and record per
run: wall time, cl phase, link phase, processes and CPU time (Job object accounting),
whether mspdbsrv.exe was running, current CPU MHz, and Defender (MsMpEng) CPU time during
the build (observed only; protection is never disabled).

  python scripts\\win_msvc_characterize.py --out DIR [--runs 32]
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import win_gate as g  # noqa: E402

k32 = ctypes.windll.kernel32


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wt.DWORD), ("TotalProcesses", wt.DWORD), ("ActiveProcesses", wt.DWORD),
                ("TotalTerminatedProcesses", wt.DWORD)]


def run_in_job(cmd: str, cwd: Path, env: dict) -> dict:
    """Run a shell command inside a fresh Job object; wall time + job accounting."""
    job = k32.CreateJobObjectW(None, None)
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, cwd=cwd, env=env, shell=True, creationflags=0x4, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)  # CREATE_SUSPENDED
    h = k32.OpenProcess(0x1F0FFF, False, p.pid)
    k32.AssignProcessToJobObject(job, h)
    ntdll = ctypes.windll.ntdll
    # resume the main thread
    th32 = subprocess.run(["powershell", "-NoProfile", "-Command", f"(Get-Process -Id {p.pid}).Threads.Id"],
                          capture_output=True, text=True) if False else None
    ntdll.NtResumeProcess(h)
    p.wait()
    wall = time.perf_counter() - t0
    info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION()
    k32.QueryInformationJobObject(job, 1, ctypes.byref(info), ctypes.sizeof(info), None)
    k32.CloseHandle(h)
    k32.CloseHandle(job)
    return {"wall_s": wall, "processes": info.TotalProcesses,
            "cpu_s": (info.TotalUserTime + info.TotalKernelTime) / 1e7, "rc": p.returncode}


def pids_of(name: str) -> list[int]:
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"], capture_output=True, text=True).stdout
    return [int(l.split('","')[1]) for l in out.splitlines() if l.startswith('"')]


def proc_cpu_s(pid: int) -> float | None:
    h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION (works on protected processes)
    if not h:
        return None
    c, e, kt, ut = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
    k32.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut))
    k32.CloseHandle(h)
    return ((kt.dwHighDateTime << 32 | kt.dwLowDateTime) + (ut.dwHighDateTime << 32 | ut.dwLowDateTime)) / 1e7


class PROCESSOR_POWER_INFORMATION(ctypes.Structure):
    _fields_ = [("Number", wt.ULONG), ("MaxMhz", wt.ULONG), ("CurrentMhz", wt.ULONG), ("MhzLimit", wt.ULONG),
                ("MaxIdleState", wt.ULONG), ("CurrentIdleState", wt.ULONG)]


def cpu_mhz() -> float:
    n = k32.GetActiveProcessorCount(0xFFFF)
    arr = (PROCESSOR_POWER_INFORMATION * n)()
    ctypes.windll.powrprof.CallNtPowerInformation(11, None, 0, ctypes.byref(arr), ctypes.sizeof(arr))
    return statistics.mean(a.CurrentMhz for a in arr)


def characterize(name: str, d: Path, menv: dict, runs: int, rnd: random.Random) -> list[dict]:
    rows = []
    defender = pids_of("MsMpEng.exe")
    for i in range(runs + 2):
        subprocess.run(g.MSVC_CLEAN, cwd=d, env=menv, shell=True, capture_output=True)
        gap = rnd.choice([0.1, 1.5])
        time.sleep(gap)
        row = {"workload": name, "i": i, "warmup": i < 2, "gap_s": gap, "mspdbsrv_running": bool(pids_of("mspdbsrv.exe")),
               "cpu_mhz_before": cpu_mhz()}
        dcpu0 = sum(proc_cpu_s(p) or 0 for p in defender)
        cl = run_in_job("cl /nologo /MP8 /O2 /c *.c >nul", d, menv)
        ln = run_in_job("link /nologo *.obj /OUT:app.exe >nul", d, menv)
        row.update(cl_s=cl["wall_s"], link_s=ln["wall_s"], wall_s=cl["wall_s"] + ln["wall_s"], cl_processes=cl["processes"],
                   cl_cpu_s=cl["cpu_s"], link_cpu_s=ln["cpu_s"], defender_cpu_s=sum(proc_cpu_s(p) or 0 for p in defender) - dcpu0,
                   ok=cl["rc"] == 0 and ln["rc"] == 0)
        rows.append(row)
        print(f"{name} {i:2} gap {gap:.1f}s  wall {row['wall_s']:.3f} (cl {row['cl_s']:.3f} link {row['link_s']:.3f})  "
              f"procs {row['cl_processes']}  mhz {row['cpu_mhz_before']:.0f}  mspdbsrv {row['mspdbsrv_running']}  "
              f"defender {row['defender_cpu_s']:.3f}s", flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runs", type=int, default=32)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if subprocess.run(["sc", "query", "whyfs"], capture_output=True, text=True).stdout.count("RUNNING"):
        st = subprocess.run(["logman", "query", "-ets"], capture_output=True, text=True).stdout
        if "whyfs-" in st:
            raise SystemExit("a whyfs collection is running: this characterization needs whyfs completely idle")
    base = Path(tempfile_dir()) / "whyfs-msvc-char"
    import shutil
    shutil.rmtree(base, ignore_errors=True)
    menv = g.msvc_env()
    g.write_c_project(base / "small")
    g.write_c_project(base / "heavy", g.PERF_UNITS, heavy=True)
    rnd = random.Random(26)
    rows = characterize("small_36", base / "small", menv, a.runs, rnd) + characterize("heavy_240", base / "heavy", menv, a.runs, rnd)
    (out / "msvc_characterization.json").write_text(json.dumps(rows, indent=1))
    for w in ("small_36", "heavy_240"):
        rs = [r for r in rows if r["workload"] == w and not r["warmup"]]
        for gap in (0.1, 1.5):
            xs = [r["wall_s"] for r in rs if r["gap_s"] == gap]
            print(f"{w:10} gap {gap}s  n={len(xs):2}  median {statistics.median(xs):.3f}  min {min(xs):.3f}  max {max(xs):.3f}")


def tempfile_dir():
    import tempfile
    return tempfile.gettempdir()


if __name__ == "__main__":
    main()
