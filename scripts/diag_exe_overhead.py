"""Diagnostic (not a gate): where the Windows collector's cost on a process-spawn-heavy workload
comes from.  Runs the native_exe_x300 workload with the standalone machine collector under
several diagnostic configurations, counterbalanced, and prints the paired median overhead of
each plus the collector's own CPU.  Run elevated with the whyfs service not running.

  python scripts\\diag_exe_overhead.py COLLECTOR.exe [--pairs 12]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import statistics
import subprocess
import sys
import tempfile
import time
from ctypes import wintypes

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from whyfs.scope import defaults_text  # noqa: E402
from whyfs.store import connect  # noqa: E402

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = wintypes.HANDLE
CONFIGS = {"normal": {}, "no_vamap": {"WHYFS_DIAG_NO_VAMAP": "1"}, "no_kfile": {"WHYFS_DIAG_NO_KFILE": "1"},
           "discard": {"WHYFS_DIAG_DISCARD": "1"}, "kfile_no_fileio": {"WHYFS_DIAG_KFILE_KW": "1F90"}}


def cpu(pid):
    h = k32.OpenProcess(0x1000, False, pid)
    c, e, k, u = (wintypes.FILETIME() for _ in range(4))
    k32.GetProcessTimes(wintypes.HANDLE(h), ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u))
    k32.CloseHandle(wintypes.HANDLE(h))
    f = lambda t: ((t.dwHighDateTime << 32) | t.dwLowDateTime) / 1e7  # noqa: E731
    return f(k) + f(u)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("collector")
    ap.add_argument("--pairs", type=int, default=12)
    ap.add_argument("--out")
    a = ap.parse_args()
    work = pathlib.Path(tempfile.mkdtemp(prefix="whyfs-exe-", dir=os.path.expanduser("~")))
    (work / "copy.c").write_text('#include <stdio.h>\nint main(int c,char**v){FILE*i=fopen(v[1],"rb"),*o=fopen(v[2],"wb");'
                                 'char b[4096];size_t n;while((n=fread(b,1,sizeof b,i))>0)fwrite(b,1,n,o);fclose(i);fclose(o);return 0;}\n')
    vc = os.environ.get("WHYFS_VCVARS", r"C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat")
    subprocess.run(f'cmd /c ""{vc}" >nul && cl /nologo /O2 copy.c >nul"', cwd=work, shell=True, check=True)
    (work / "raw.txt").write_text("x" * 4096)
    loop = "for /L %i in (1,1,300) do @.\\copy.exe raw.txt out-%i.txt"

    def workload():
        t = time.perf_counter()
        subprocess.run(["cmd", "/c", loop], cwd=work, stdout=subprocess.DEVNULL, check=True)
        return time.perf_counter() - t

    root = tempfile.mkdtemp(prefix="whyfs-diag-", dir=os.path.expanduser("~"))
    connect(pathlib.Path(root)).close()
    sc = os.path.join(root, "scope.conf")
    open(sc, "w").write(defaults_text(True))
    report = {}
    for name, env in CONFIGS.items():
        paired, ccpu = [], []
        for i in range(a.pairs + 2):
            order = ("off", "on") if i % 2 == 0 else ("on", "off")
            t = {}
            for mode in order:
                c = None
                if mode == "on":
                    c = subprocess.Popen([a.collector, "--machine", "--root", root, "--run-id", f"diag-{name}-{i}",
                                          "--session", "whyfs-diag", "--scope", sc],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         text=True, env=dict(os.environ, **env))
                    c.stdout.readline()
                    time.sleep(1)
                    c0 = cpu(c.pid)
                time.sleep(1)
                t[mode] = workload()
                if c:
                    time.sleep(1)
                    ccpu.append(cpu(c.pid) - c0)
                    c.stdin.write("stop\n")
                    c.stdin.flush()
                    c.communicate(timeout=180)
            if i >= 2:
                paired.append((t["on"] / t["off"] - 1) * 100)
        report[name] = {"median_paired_overhead_percent": round(statistics.median(paired), 2),
                        "collector_cpu_ms_median": round(statistics.median(ccpu) * 1000, 1), "pairs": paired}
        print(f"{name:16s} overhead {report[name]['median_paired_overhead_percent']:+.2f}%   "
              f"collector CPU {report[name]['collector_cpu_ms_median']:.0f} ms / 300 execs", flush=True)
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
