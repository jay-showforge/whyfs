#!/usr/bin/env python3
"""Performance and resource cost of machine-wide labelling (Phase 12).

Windows: python scripts\\machine_perf.py --out DIR [--pairs 20] [--idle-min 10]        (elevated; MSI installed)
Linux:   sudo python3 scripts/machine_perf.py --user USER --out DIR [...]              (the .deb installed)
macOS:   sudo python3 scripts/machine_perf.py --user USER --out DIR [...]              (the .pkg installed;
         "off" = the launchd job booted out; workloads: make -j8 36 units, Vite, a copy program x300)

"off" = the whyfs service stopped (no ETW session / no BPF program on the machine);
"on"  = the service running in its normal steady state: the machine collector labelling the
        whole machine, not a workspace.  The workloads are the ones of the validated gates
        (Windows: MSVC 240 units /MP8 + link, Vite, native exe x300; Linux: make -j8 36 units,
        Vite, static binary x300), run in counterbalanced AB/BA pairs with a symmetric protocol
        (a warm-up build, a fixed pause, then the measured build, in both modes).

Also measured:
- background idle cost with the service on and the machine left to its own background
  activity (CPU seconds, memory, store growth and events per minute);
- store growth and events per workload;
- event loss over every collector run of the campaign;
- `whyfs why` / `whyfs label` end-to-end latency on the populated machine store.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NT = os.name == "nt"
MAC = sys.platform == "darwin"
MAC_LABEL = "org.tenzorpipe.whyfs"
sys.path.insert(0, str(REPO / "scripts"))
PAUSE_S = 1.0
STORE = (Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "whyfs" / "machine" / ".whyfs" / "whyfs.db") if NT \
    else Path("/Library/Application Support/WhyFS/machine/.whyfs/whyfs.db") if MAC \
    else Path("/var/lib/whyfs/machine/.whyfs/whyfs.db")
WHYFS = [os.path.join(os.environ.get("ProgramFiles", ""), "whyfs", "whyfs.exe")] if NT else \
    ["/usr/local/bin/whyfs"] if MAC else ["/usr/bin/whyfs"]
LOSS_KEYS = ("kernel_drops", "queue_drops", "user_unresolved", "late_records", "lost_file", "lost_sys",
             "buffers_lost_file", "buffers_lost_sys")


def note(m):
    print(time.strftime("%H:%M:%S ") + m, flush=True)


# ---------------------------------------------------------------- service control
def status() -> dict | None:
    p = subprocess.run([*WHYFS, "status", "--json"], capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except ValueError:
        return None


def service(on: bool) -> None:
    if MAC:  # off: the launchd job booted out (no Endpoint Security client at all); on: bootstrapped
        if on:
            subprocess.run(["launchctl", "bootstrap", "system", f"/Library/LaunchDaemons/{MAC_LABEL}.plist"], capture_output=True)
        else:
            subprocess.run(["launchctl", "bootout", f"system/{MAC_LABEL}"], capture_output=True)
    elif NT:
        subprocess.run(["powershell", "-NoProfile", "-Command", ("Start-Service" if on else "Stop-Service") + " whyfs"],
                       check=True, capture_output=True)
    else:
        subprocess.run(["systemctl", "start" if on else "stop", "whyfs.service"], check=True)
    deadline = time.time() + 180
    while time.time() < deadline:
        st = status() if on else None
        if on and st and st.get("collector_ready"):
            return
        if not on and not collector_pids():
            return
        time.sleep(0.5)
    raise SystemExit(f"service did not become {'ready' if on else 'stopped'}")


def collector_pids() -> list[int]:
    if NT:
        out = subprocess.run(["powershell", "-NoProfile", "-Command",
                              "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'whyfs-collect-win.exe' -or "
                              "($_.Name -eq 'python.exe' -and $_.CommandLine -match 'whyfs machine serve') } | "
                              "ForEach-Object { $_.ProcessId }"], capture_output=True, text=True).stdout
        return [int(x) for x in out.split()]
    out = subprocess.run(["pgrep", "-f", "[w]hyfs-collect|[w]hyfs machine run"], capture_output=True, text=True).stdout
    return [int(x) for x in out.split() if int(x) != os.getpid()]


def _ps(pid: int) -> tuple[float, int] | None:
    """macOS: (cpu seconds, rss bytes) from ps (no /proc)."""
    out = subprocess.run(["ps", "-o", "cputime=,rss=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
    if len(out) != 2:
        return None
    parts = out[0].split(":")  # [[dd-]hh:]mm:ss.cc
    secs = 0.0
    for p in parts:
        secs = secs * 60 + float(p.split("-")[-1])
    if "-" in parts[0]:
        secs += int(parts[0].split("-")[0]) * 86400
    return secs, int(out[1]) * 1024


def cpu_s(pids: list[int]) -> float:
    total = 0.0
    for pid in pids:
        if MAC:
            v = _ps(pid)
            total += v[0] if v else 0.0
            continue
        if NT:
            import ctypes
            from ctypes import wintypes
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.restype = wintypes.HANDLE
            h = k32.OpenProcess(0x1000, False, pid)
            if not h:
                continue
            c, e, k, u = (wintypes.FILETIME() for _ in range(4))
            if k32.GetProcessTimes(wintypes.HANDLE(h), ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
                total += (((k.dwHighDateTime << 32) | k.dwLowDateTime) + ((u.dwHighDateTime << 32) | u.dwLowDateTime)) / 1e7
            k32.CloseHandle(wintypes.HANDLE(h))
        else:
            try:
                f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
                total += (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
            except (OSError, IndexError, ValueError):
                pass
    return total


def rss_mb(pids: list[int]) -> float:
    total = 0
    for pid in pids:
        if MAC:
            v = _ps(pid)
            total += v[1] if v else 0
            continue
        if NT:
            import ctypes
            from ctypes import wintypes

            class PMC(ctypes.Structure):
                _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
                           [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                                          "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                                          "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
            k32 = ctypes.windll.kernel32
            k32.OpenProcess.restype = wintypes.HANDLE
            h = k32.OpenProcess(0x1000 | 0x0010, False, pid)
            if not h:
                continue
            m = PMC(); m.cb = ctypes.sizeof(m)
            if ctypes.windll.psapi.GetProcessMemoryInfo(wintypes.HANDLE(h), ctypes.byref(m), m.cb):
                total += m.WorkingSetSize
            k32.CloseHandle(wintypes.HANDLE(h))
        else:
            try:
                for line in open(f"/proc/{pid}/status"):
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1]) * 1024
            except OSError:
                pass
    return total / 2**20


def store_bytes() -> int:
    return sum(p.stat().st_size for p in STORE.parent.glob("whyfs.db*") if p.exists())


def store_events() -> int:
    con = sqlite3.connect(f"file:{STORE}?mode=ro", uri=True, timeout=30)
    try:
        return con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        con.close()


def loss_since(t0_ns: int) -> tuple[int, dict]:
    con = sqlite3.connect(f"file:{STORE}?mode=ro", uri=True, timeout=30)
    try:
        rows = con.execute("SELECT s.run_id, s.key, s.value FROM collector_stats s JOIN runs r ON r.id=s.run_id "
                           "WHERE r.started_ns>=?", (t0_ns,)).fetchall()
    finally:
        con.close()
    per: dict = {}
    for run, k, v in rows:
        per.setdefault(run, {})[k] = v
    total = sum(int(d.get(k, 0) or 0) for d in per.values() for k in LOSS_KEYS)
    return total, per


# ---------------------------------------------------------------- workloads
def workloads(base: Path, user: str | None):
    if NT:
        import win_gate as g
        menv = g.msvc_env()
        ws = base / "perf"
        ws.mkdir(parents=True)
        g.write_c_project(ws / "msvc", g.PERF_UNITS, heavy=True)
        g.write_vite_project(ws / "web")
        (ws / "native").mkdir()
        (ws / "native" / "copy.c").write_text(g.COPY_C)
        (ws / "native" / "raw.txt").write_text("x" * 4096)
        g.run("cl /nologo /O2 copy.c >nul", ws / "native", env=menv)

        def run(cmd, cwd, env=None, check=True):
            return g.run(cmd, cwd, env=env, check=check)[0]
        return ws, run, {
            "msvc_240_units_mp8": (g.MSVC_CLEAN, g.MSVC_BUILD, ws / "msvc", menv),
            "vite_build": ("echo.", g.VITE, ws / "web", None),
            "native_exe_x300": ("del /q out-*.txt 2>nul", r"for /L %i in (1,1,300) do @.\copy.exe raw.txt out-%i.txt", ws / "native", None),
        }, [ws / "msvc" / "app.exe", ws / "native" / "out-150.txt"]
    if MAC:
        return _mac_workloads(base, user)
    import v02_graduation as g
    ctx = g.Ctx(user, base)
    ws = base / "perf"
    ws.mkdir(parents=True)
    g.write_c_project(ws / "cproj")
    g.write_vite_project(ws / "web", Path(f"/home/{user}/vite-template"))
    (ws / "static_copy.c").write_text(g.STATIC_C)
    (ws / "raw.txt").write_text("x" * 4096)
    ctx.chown(ws)
    ctx.run_user("gcc -static -O2 static_copy.c -o static_copy", ws)

    def run(cmd, cwd, env=None, check=True):
        return ctx.run_user(cmd, cwd, check=check)[0]
    return ws, run, {
        "make_j8_36_units": ("make -s clean >/dev/null; true", "make -s -j8", ws / "cproj", None),
        "vite_build": ("true", g.VITE, ws / "web", None),
        "static_binary_x300": ("rm -f out-*.txt", "for i in $(seq 1 300); do ./static_copy raw.txt out-$i.txt; done", ws, None),
    }, [ws / "cproj" / "app", ws / "out-150.txt"]


def _mac_workloads(base: Path, user: str):
    """The Linux campaign's workloads on macOS, run as the user (clang is the system compiler; a
    macOS program cannot be linked statically, so the x300 program is an ordinary one)."""
    import pwd
    import v02_graduation as g
    pw = pwd.getpwnam(user)
    ws = base / "perf"
    ws.mkdir(parents=True)
    g.write_c_project(ws / "cproj")
    g.write_vite_project(ws / "web", Path(os.environ.get("WHYFS_VITE_TEMPLATE", f"/Users/{user}/vite-template")))
    (ws / "copy.c").write_text(g.STATIC_C)
    (ws / "raw.txt").write_text("x" * 4096)
    subprocess.run(["chown", "-R", f"{pw.pw_uid}:{pw.pw_gid}", str(ws)], check=True)
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": pw.pw_dir, "USER": user,
           "LANG": "en_US.UTF-8"}

    def run(cmd, cwd, env_=None, check=True):
        argv = ["sudo", "-u", user, "--", "env", "-i", *[f"{k}={v}" for k, v in env.items()], "bash", "-c", cmd]
        t0 = time.perf_counter()
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
        dt = time.perf_counter() - t0
        if check and p.returncode != 0:
            raise RuntimeError(f"workload failed ({p.returncode}): {cmd}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
        return dt
    run("cc -O2 copy.c -o copy_prog", ws)
    return ws, (lambda cmd, cwd, env=None, check=True: run(cmd, cwd, check=check)), {
        "make_j8_36_units": ("make -s clean >/dev/null; true", "make -s -j8", ws / "cproj", None),
        "vite_build": ("true", g.VITE, ws / "web", None),
        "copy_program_x300": ("rm -f out-*.txt", "for i in $(seq 1 300); do ./copy_prog raw.txt out-$i.txt; done", ws, None),
    }, [ws / "cproj" / "app", ws / "out-150.txt"]


def bootstrap_ci(xs, n=4000, q=(0.05, 0.95)):
    import random
    r = random.Random(1)
    meds = sorted(statistics.median(r.choice(xs) for _ in xs) for _ in range(n))
    return [meds[int(q[0] * n)], meds[int(q[1] * n) - 1]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--pairs", type=int, default=20)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--idle-min", type=float, default=10.0)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    t_campaign = time.time_ns()
    # an ordinary user folder: in scope (a temp root would only record derived temporaries)
    base = Path(tempfile.mkdtemp(prefix="whyfs-mperf-", dir=os.path.expanduser("~") if NT else
                                 f"/Users/{a.user}" if MAC else f"/home/{a.user}"))
    if not NT:
        os.chmod(base, 0o755)
    report: dict = {"platform": platform.platform(), "machine": platform.machine(), "cpu": platform.processor(),
                    "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "pairs": a.pairs, "warmups": a.warmups}

    # ---- idle: the service on, the machine left to its background activity
    service(True)
    pids = collector_pids()
    c0, b0, e0, t0 = cpu_s(pids), store_bytes(), store_events(), time.time()
    time.sleep(a.idle_min * 60)
    pids = collector_pids()
    c1, b1, e1, t1 = cpu_s(pids), store_bytes(), store_events(), time.time()
    minutes = (t1 - t0) / 60
    report["idle"] = {"minutes": round(minutes, 2), "collector_cpu_s": round(c1 - c0, 3),
                      "cpu_percent_of_one_core": round((c1 - c0) / (t1 - t0) * 100, 3), "memory_mb": round(rss_mb(pids), 1),
                      "store_growth_bytes": b1 - b0, "store_growth_mb_per_day": round((b1 - b0) / minutes * 1440 / 2**20, 1),
                      "events_stored": e1 - e0, "events_per_minute": round((e1 - e0) / minutes, 1),
                      "processes": pids}
    note(f"idle {minutes:.1f} min: collector CPU {c1 - c0:.2f}s ({report['idle']['cpu_percent_of_one_core']}% of a core), "
         f"memory {report['idle']['memory_mb']} MB, store +{(b1 - b0) / 1024:.0f} KiB, {e1 - e0} events")

    # ---- workloads
    ws, run, wl, targets = workloads(base, a.user)
    state = {"on": None}

    def ensure(on):
        if state["on"] is not on:
            service(on)
            state["on"] = on

    result = {}
    for wname, (prep, cmd, cwd, env) in wl.items():
        rows = []
        order = ["off", "on"] * a.warmups + [m for i in range(a.pairs) for m in (("off", "on") if i % 2 == 0 else ("on", "off"))]
        for idx, mode in enumerate(order):
            ensure(mode == "on")
            row = {"mode": mode, "warmup": idx < 2 * a.warmups}
            run(prep, cwd, env=env, check=False)
            row["first_build_seconds"] = run(cmd, cwd, env=env)
            run(prep, cwd, env=env, check=False)
            time.sleep(PAUSE_S)
            if mode == "on":
                pids = collector_pids()
                c0, b0, e0 = cpu_s(pids), store_bytes(), store_events()
            row["seconds"] = run(cmd, cwd, env=env)
            if mode == "on":
                time.sleep(0.2)
                row["collector_cpu_s_during_workload"] = round(cpu_s(pids) - c0, 3)
                row["store_growth_bytes"] = store_bytes() - b0
                row["events_stored_at_return"] = store_events() - e0
            rows.append(row)
            note(f"{wname} {'warmup ' if row['warmup'] else ''}{mode}: {row['seconds']:.3f}s")
        meas = [r for r in rows if not r["warmup"]]
        offs = [r["seconds"] for r in meas if r["mode"] == "off"]
        ons = [r["seconds"] for r in meas if r["mode"] == "on"]
        paired = [(ons[i] / offs[i] - 1) * 100 for i in range(min(len(ons), len(offs)))]
        on_rows = [r for r in meas if r["mode"] == "on"]
        result[wname] = {
            "command": cmd, "runs": rows, "baseline_median_s": statistics.median(offs),
            "monitored_median_s": statistics.median(ons), "paired_overheads_percent": paired,
            "median_paired_overhead_percent": statistics.median(paired), "median_paired_ci90": bootstrap_ci(paired),
            "collector_cpu_s_median": statistics.median(r["collector_cpu_s_during_workload"] for r in on_rows),
            "store_growth_bytes_median": statistics.median(r["store_growth_bytes"] for r in on_rows),
        }
        note(f"{wname}: median paired overhead {result[wname]['median_paired_overhead_percent']:+.2f}% "
             f"(CI90 {result[wname]['median_paired_ci90'][0]:+.2f} .. {result[wname]['median_paired_ci90'][1]:+.2f})")
    report["performance"] = result

    # ---- query latency on the populated machine store (the service on, end to end through the API)
    ensure(True)
    time.sleep(12 if NT else 4)
    lat = {"why": [], "label": []}
    for _ in range(15):
        for t in targets:
            for op in ("why", "label"):
                t0 = time.perf_counter()
                subprocess.run([*WHYFS, op, str(t), "--json"], capture_output=True)
                lat[op].append((time.perf_counter() - t0) * 1000)
    report["query_latency_ms"] = {k: {"median": round(statistics.median(v), 1), "p95": round(sorted(v)[int(len(v) * .95) - 1], 1)}
                                  for k, v in lat.items()}
    report["store_bytes_final"] = store_bytes()
    lost, per = loss_since(t_campaign)
    report["lost_total"] = lost
    report["collector_runs"] = per
    checks = {
        "idle_cpu_below_1pct_of_a_core": report["idle"]["cpu_percent_of_one_core"] < 1.0,
        "zero_loss": lost == 0,
        "why_cli_median_lt_100ms": report["query_latency_ms"]["why"]["median"] < 100,
        "label_cli_median_lt_100ms": report["query_latency_ms"]["label"]["median"] < 100,
        **{f"{w}.median_paired_overhead_lt_5pct": r["median_paired_overhead_percent"] < 5 for w, r in result.items()},
    }
    report["checks"] = checks
    report["verdict"] = "PASS" if all(checks.values()) else "FAIL"
    report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    (out / "machine_perf.json").write_text(json.dumps(report, indent=1, default=str))
    for k, v in checks.items():
        note(f"{'PASS' if v else 'FAIL'} {k}")
    note(f"verdict {report['verdict']}")
    shutil.rmtree(base, ignore_errors=True)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
