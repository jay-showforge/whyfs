#!/usr/bin/env python3
"""Authoritative v0.2 eBPF graduation gate.

Run on a real Linux/WSL host with BCC and BPF privileges.  This intentionally
contains a statically linked workload that the v0.1 LD_PRELOAD backend cannot
observe, plus a parallel C build and a Node build.
"""
from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PYTHON = sys.executable


def run(root: Path, *args: str, check=True, capture=True):
    env = os.environ.copy()
    src = Path(__file__).resolve().parents[1] / "src"
    env["PYTHONPATH"] = str(src) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    p = subprocess.run(
        [PYTHON, "-m", "whyfs", *args], cwd=root, env=env, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and p.returncode != 0:
        raise RuntimeError(f"whyfs {' '.join(args)} failed ({p.returncode})\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def shell(root: Path, command: list[str], check=True):
    p = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed ({p.returncode})\n{p.stdout}\n{p.stderr}")
    return p


def write_static_copy(root: Path):
    (root / "static_copy.c").write_text(r'''#include <stdio.h>
int main(int argc,char **argv){
  if(argc!=3)return 2; FILE *in=fopen(argv[1],"rb"), *out=fopen(argv[2],"wb");
  if(!in||!out)return 3; char b[8192]; size_t n;
  while((n=fread(b,1,sizeof(b),in))>0) if(fwrite(b,1,n,out)!=n)return 4;
  fclose(in); fclose(out); return 0;
}
''')
    shell(root, ["gcc", "-static", "-O2", "static_copy.c", "-o", "static_copy"])


def write_c_project(root: Path, count: int = 36):
    src = root / "cproj"
    src.mkdir()
    (src / "common.h").write_text("#pragma once\n#define WHYFS_BIAS 7\n")
    names = []
    for i in range(count):
        name = f"u{i:02d}"
        names.append(name)
        (src / f"{name}.c").write_text(
            f'#include "common.h"\nint {name}(int x){{return x+WHYFS_BIAS+{i};}}\n'
        )
    decls = "".join(f"int {n}(int);\n" for n in names)
    calls = "+".join(f"{n}(1)" for n in names)
    (src / "main.c").write_text(f"#include <stdio.h>\n{decls}int main(void){{printf(\"%d\\n\",{calls});return 0;}}\n")
    objs = " ".join([f"{n}.o" for n in names] + ["main.o"])
    (src / "Makefile").write_text(
        f"OBJS={objs}\n"
        "app: $(OBJS)\n\t$(CC) $(OBJS) -o $@\n"
        "%.o: %.c common.h\n\t$(CC) -O2 -c $< -o $@\n"
        "clean:\n\trm -f $(OBJS) app\n"
    )
    return src


def write_node_project(root: Path):
    n = root / "nodeproj"
    (n / "src").mkdir(parents=True)
    (n / "dist").mkdir()
    (n / "src" / "a.txt").write_text("alpha\n")
    (n / "src" / "b.txt").write_text("beta\n")
    (n / "config.json").write_text('{"banner":"WHYFS"}\n')
    (n / "build.js").write_text(
        "const fs=require('fs');\n"
        "const c=JSON.parse(fs.readFileSync('config.json','utf8'));\n"
        "const a=fs.readFileSync('src/a.txt','utf8');\n"
        "const b=fs.readFileSync('src/b.txt','utf8');\n"
        "fs.writeFileSync('dist/bundle.txt', c.banner+'\\n'+a+b);\n"
    )
    return n


def timed_make(cproj: Path) -> float:
    shell(cproj, ["make", "clean"])
    t0 = time.perf_counter()
    shell(cproj, ["make", "-j4"])
    return time.perf_counter() - t0


def main() -> int:
    if not sys.platform.startswith("linux"):
        print("Gate requires Linux/WSL", file=sys.stderr)
        return 2
    for tool in ("gcc", "make", "node"):
        if not shutil.which(tool):
            print(f"Gate requires {tool}", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory(prefix="whyfs-v02-gate-") as td:
        root = Path(td).resolve()
        run(root, "init", ".")
        doctor = run(root, "doctor", "--json", check=False)
        report = {"doctor": json.loads(doctor.stdout), "checks": {}}
        if doctor.returncode != 0:
            report["verdict"] = "BLOCKED_ENVIRONMENT"
            report["reason"] = "eBPF/BCC capability check failed"
            print(json.dumps(report, indent=2))
            return 2

        write_static_copy(root)
        (root / "raw.txt").write_text("static lineage\n")
        cproj = write_c_project(root)
        nproj = write_node_project(root)

        # Baseline real-build timings before the daemon is running.
        baseline = [timed_make(cproj) for _ in range(5)]

        run(root, "daemon", "start", "--workspace", str(root))
        try:
            time.sleep(0.25)
            shell(root, ["./static_copy", "raw.txt", "static-out.txt"])
            shell(cproj, ["make", "clean"]); shell(cproj, ["make", "-j4"])
            shell(nproj, ["node", "build.js"])
            # Capture timing pairs while daemon remains continuously active.
            captured = [timed_make(cproj) for _ in range(5)]
            time.sleep(0.25)
        finally:
            run(root, "daemon", "stop", "--workspace", str(root), check=False)

        why_static = json.loads(run(root, "why", "static-out.txt", "--json").stdout)
        static_inputs = {Path(x).name for x in why_static["inputs"]}
        report["checks"]["static_binary_creator"] = Path(why_static["exe"]).name == "static_copy"
        report["checks"]["static_binary_input"] = "raw.txt" in static_inputs

        why_node = json.loads(run(nproj, "why", "dist/bundle.txt", "--json").stdout)
        node_inputs = {str(Path(x).relative_to(nproj)) for x in why_node["inputs"] if str(x).startswith(str(nproj))}
        report["checks"]["node_inputs"] = {"config.json", "src/a.txt", "src/b.txt"}.issubset(node_inputs)

        impact = json.loads(run(cproj, "impact", "common.h", "--json").stdout)
        impact_names = {Path(x["to"]).name for x in impact}
        report["checks"]["parallel_build_transitive"] = "app" in impact_names and any(x.endswith(".o") for x in impact_names)

        stats = json.loads(run(root, "stats", "--json").stdout)
        report["stats"] = stats
        report["checks"]["zero_kernel_drops"] = stats.get("kernel_drops", 1) == 0

        bmed = statistics.median(baseline)
        cmed = statistics.median(captured)
        overhead = (cmed / bmed - 1.0) * 100.0
        report["performance"] = {
            "baseline_seconds": baseline,
            "captured_seconds": captured,
            "baseline_median_s": bmed,
            "captured_median_s": cmed,
            "median_overhead_percent": overhead,
            "target_percent": 5.0,
        }
        report["checks"]["overhead_under_5pct"] = overhead < 5.0

        # DB growth per observed event is a useful regression number, not a hard
        # universal constant.  Keep it visible rather than hiding it.
        report["storage_bytes_per_event"] = stats["bytes"] / max(1, stats["events"])
        passed = all(report["checks"].values())
        report["verdict"] = "PASS" if passed else "FAIL"
        print(json.dumps(report, indent=2))
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
