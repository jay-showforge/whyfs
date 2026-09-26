#!/usr/bin/env python3
"""whyfs v0.2 eBPF graduation harness (functional + accuracy + performance).

Run as root (the daemon needs BPF privileges).  Workloads run as an ordinary
user (``--user``, default: $SUDO_USER or the workspace owner) with a Linux-only
PATH.  Every check is computed from what the daemon actually recorded; the
LD_PRELOAD backend is never used.  Raw measurements are written to --out.

Usage:  sudo python3 scripts/v02_graduation.py --out results/graduation
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import pwd
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from whyfs.daemon import capability_report, ensure_kernel_headers  # noqa: E402
from whyfs.query import history, impact, why  # noqa: E402
from whyfs.store import connect  # noqa: E402

LINUX_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
UNITS = 36


# --------------------------------------------------------------------------- helpers
class Ctx:
    def __init__(self, user: str, out: Path):
        self.user = user
        self.pw = pwd.getpwnam(user)
        self.out = out
        self.log = (out / "graduation.log").open("a", encoding="utf-8")

    def note(self, msg: str) -> None:
        line = time.strftime("%H:%M:%S ") + msg
        print(line, flush=True)
        self.log.write(line + "\n")
        self.log.flush()

    def env(self) -> dict:
        return {"PATH": LINUX_PATH, "HOME": self.pw.pw_dir, "USER": self.user, "LANG": "C.UTF-8"}

    def run_user(self, cmd: str, cwd: Path, check: bool = True) -> tuple[float, subprocess.CompletedProcess]:
        argv = ["runuser", "-u", self.user, "--", "env", "-i", *[f"{k}={v}" for k, v in self.env().items()],
                "bash", "-c", cmd]
        t0 = time.perf_counter()
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
        dt = time.perf_counter() - t0
        if check and p.returncode != 0:
            raise RuntimeError(f"workload failed ({p.returncode}): {cmd}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
        return dt, p

    def whyfs(self, *args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PATH=LINUX_PATH)
        p = subprocess.run([sys.executable, "-W", "ignore", "-m", "whyfs", *args], cwd=cwd, env=env,
                           capture_output=True, text=True)
        if check and p.returncode != 0:
            raise RuntimeError(f"whyfs {' '.join(args)} failed: {p.stdout}\n{p.stderr}")
        return p

    def chown(self, path: Path) -> None:
        subprocess.run(["chown", "-R", f"{self.pw.pw_uid}:{self.pw.pw_gid}", str(path)], check=True)


class Daemon:
    def __init__(self, ctx: Ctx, ws: Path, all_files: bool = False):
        self.ctx, self.ws, self.all_files = ctx, ws, all_files

    def __enter__(self):
        args = ["daemon", "start", "--workspace", str(self.ws)] + (["--all-files"] if self.all_files else [])
        self.ctx.whyfs(*args, cwd=self.ws)
        st = json.loads((self.ws / ".whyfs" / "daemon.json").read_text())
        self.pid, self.run_id = int(st["pid"]), st["run_id"]
        time.sleep(0.3)
        return self

    def cpu_ticks(self) -> int:
        f = Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])  # utime + stime

    def __exit__(self, *exc):
        time.sleep(0.3)
        self.ctx.whyfs("daemon", "stop", "--workspace", str(self.ws), cwd=self.ws)
        return False

    def stats(self) -> dict:
        con = connect(self.ws)
        d = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM collector_stats WHERE run_id=?",
                                                         (self.run_id,))}
        d["stored_events"] = con.execute("SELECT COUNT(*) FROM events WHERE run_id=?", (self.run_id,)).fetchone()[0]
        d["stored_processes"] = con.execute("SELECT COUNT(*) FROM processes WHERE run_id=?", (self.run_id,)).fetchone()[0]
        con.close()
        return d


# --------------------------------------------------------------------------- fixtures
STATIC_C = r"""#include <stdio.h>
int main(int argc,char **argv){ if(argc!=3) return 2; FILE *in=fopen(argv[1],"rb"), *out=fopen(argv[2],"wb");
  if(!in||!out) return 3; char b[8192]; size_t n; while((n=fread(b,1,sizeof b,in))>0) if(fwrite(b,1,n,out)!=n) return 4;
  fclose(in); fclose(out); return 0; }
"""


def write_c_project(d: Path) -> list[str]:
    d.mkdir(parents=True)
    (d / "common.h").write_text("#pragma once\n#define WHYFS_BIAS 7\n")
    names = [f"u{i:02d}" for i in range(UNITS)]
    for i, n in enumerate(names):
        (d / f"{n}.c").write_text(f'#include "common.h"\nint {n}(int x){{return x+WHYFS_BIAS+{i};}}\n')
    decls = "".join(f"int {n}(int);\n" for n in names)
    calls = "+".join(f"{n}(1)" for n in names)
    (d / "main.c").write_text('#include <stdio.h>\n' + decls + 'int main(void){printf("%d\\n",' + calls + ');return 0;}\n')
    objs = " ".join([f"{n}.o" for n in names] + ["main.o"])
    (d / "Makefile").write_text(
        f"OBJS={objs}\napp: $(OBJS)\n\t$(CC) $(OBJS) -o $@\n%.o: %.c common.h\n\t$(CC) -O2 -c $< -o $@\n"
        "clean:\n\trm -f $(OBJS) app\n"
    )
    return names + ["main"]


def write_vite_project(d: Path, template: Path) -> None:
    (d / "src").mkdir(parents=True)
    shutil.copytree(template / "node_modules", d / "node_modules", symlinks=True)
    shutil.copy2(template / "package.json", d / "package.json")
    (d / "index.html").write_text(
        '<!doctype html><html><head><title>whyfs</title></head>'
        '<body><div id="app"></div><script type="module" src="/src/main.js"></script></body></html>\n')
    (d / "src" / "main.js").write_text(
        "import { greet } from './util.js';\nimport data from './data.json';\nimport './style.css';\n"
        "document.querySelector('#app').textContent = greet(data.name);\n")
    (d / "src" / "util.js").write_text("export const greet = (n) => `hello ${n}`;\n")
    (d / "src" / "data.json").write_text('{"name": "whyfs"}\n')
    (d / "src" / "style.css").write_text("#app { color: #336; font-weight: 700; }\n")
    (d / "vite.config.js").write_text("export default { build: { outDir: 'dist', emptyOutDir: true } };\n")
    (d / "postbuild.mjs").write_text(
        "import fs from 'node:fs';\nconst dir = 'dist/assets';\nconst out = {};\n"
        "for (const f of fs.readdirSync(dir)) if (f.endsWith('.js')) out[f] = fs.readFileSync(`${dir}/${f}`, 'utf8').length;\n"
        "fs.writeFileSync('dist/report.json', JSON.stringify(out) + '\\n');\n")


VITE = "node node_modules/vite/bin/vite.js build --logLevel warn"


# --------------------------------------------------------------------------- checks
def name(p: str | None) -> str:
    return Path(p).name if p else ""


def is_as(exe: str | None) -> bool:
    return bool(re.search(r"(^|-)as$", name(exe)))


def is_ld(exe: str | None) -> bool:
    return bool(re.search(r"(^|-)ld(\.bfd|\.gold|\.lld)?$", name(exe)))


def ancestry(con, run_id: str, key: int, hops: int = 8) -> list[str]:
    out = []
    for _ in range(hops):
        r = con.execute("SELECT exe, parent_key FROM processes WHERE run_id=? AND pid=?", (run_id, key)).fetchone()
        if not r or r["parent_key"] is None:
            break
        p = con.execute("SELECT exe FROM processes WHERE run_id=? AND pid=?", (run_id, r["parent_key"])).fetchone()
        if not p:
            break
        out.append(name(p["exe"]))
        key = r["parent_key"]
    return out


def lineage_inputs(w: dict) -> set[str]:
    return set(w.get("inputs") or []) | set(w.get("inputs_via_temporaries") or [])


def functional(ctx: Ctx, base: Path, vite_template: Path) -> dict:
    ws = base / "functional"
    ws.mkdir(parents=True)
    (ws / "static_copy.c").write_text(STATIC_C)
    (ws / "raw.txt").write_text("static lineage\n")
    names = write_c_project(ws / "cproj")
    write_vite_project(ws / "web", vite_template)
    (ws / "mv").mkdir()
    (ws / "mv" / "input.txt").write_text("move me\n")
    ctx.chown(ws)
    ctx.run_user("gcc -static -O2 static_copy.c -o static_copy", ws)
    static_info = subprocess.run(["file", "-b", str(ws / "static_copy")], capture_output=True, text=True).stdout.strip()
    preload_blind = "statically linked" in static_info
    ctx.whyfs("init", str(ws), cwd=ws)
    cproj, web = ws / "cproj", ws / "web"
    t_header = t_source = 0

    with Daemon(ctx, ws) as d:
        ctx.note("functional: static binary")
        ctx.run_user("./static_copy raw.txt static-out.txt", ws)
        ctx.note("functional: parallel build #1 (clean)")
        ctx.run_user("make -s -j8", cproj)
        time.sleep(0.5)
        ctx.note("functional: header change -> build #2")
        t_header = time.time_ns()
        ctx.run_user("sed -i 's/WHYFS_BIAS 7/WHYFS_BIAS 8/' common.h && make -s -j8", cproj)
        time.sleep(0.5)
        ctx.note("functional: source change -> build #3")
        t_source = time.time_ns()
        ctx.run_user("sed -i 's/x+WHYFS_BIAS+5/x+WHYFS_BIAS+50/' u05.c && make -s -j8", cproj)
        ctx.note("functional: vite build + postbuild")
        ctx.run_user(VITE + " && node postbuild.mjs", web)
        ctx.note("functional: copy / rename / move chain")
        ctx.run_user("cp input.txt stage1.txt && mv stage1.txt stage2.txt && mkdir -p final && mv stage2.txt final/result.txt", ws / "mv")
        time.sleep(0.5)
    run_stats = d.stats()

    con = connect(ws)
    R: dict = {"workspace": str(ws), "run_id": d.run_id, "collector": run_stats, "static_file": static_info}
    checks: dict[str, bool] = {}
    outputs: list[dict] = []

    def record(label, path, expected_creator, expected_inputs, creator_ok, w):
        found = lineage_inputs(w) if w else set()
        hit = [x for x in expected_inputs if x in found]
        outputs.append({"output": label, "path": str(path), "expected_creator": expected_creator,
                        "observed_creator": w["exe"] if w else None, "creator_ok": bool(creator_ok),
                        "expected_inputs": expected_inputs, "found_inputs": hit,
                        "direct_inputs": (w or {}).get("inputs"), "via_temporaries": (w or {}).get("inputs_via_temporaries")})

    # 1. static binary
    w = why(con, str(ws / "static-out.txt"))
    checks["static_binary_is_statically_linked"] = preload_blind
    checks["static_creator"] = bool(w) and name(w["exe"]) == "static_copy"
    checks["static_input"] = bool(w) and str(ws / "raw.txt") in (w["inputs"] or [])
    record("static-out.txt", ws / "static-out.txt", "static_copy", [str(ws / "raw.txt")], checks["static_creator"], w)

    # 2. parallel native build
    header, cfiles = str(cproj / "common.h"), {n: str(cproj / f"{n}.c") for n in names}
    obj_ok = parent_ok = 0
    for n in names:
        o = cproj / f"{n}.o"
        w = why(con, str(o))
        ok = bool(w) and is_as(w["exe"])
        obj_ok += ok
        anc = ancestry(con, d.run_id, w["process_key"]) if w else []
        parent_ok += bool(anc) and "gcc" in (anc[0] or "") and any("make" in a for a in anc)
        exp = [cfiles[n]] + ([header] if n != "main" else [])
        record(f"cproj/{n}.o", o, "as", exp, ok, w)
    checks["objects_created_by_assembler"] = obj_ok == len(names)
    checks["assembler_parentage_gcc_then_make"] = parent_ok == len(names)
    w_app = why(con, str(cproj / "app"))
    checks["app_created_by_linker"] = bool(w_app) and is_ld(w_app["exe"])
    anc = ancestry(con, d.run_id, w_app["process_key"]) if w_app else []
    R["linker_ancestry"] = anc
    checks["linker_parentage_collect2_gcc_make"] = "collect2" in anc and any("gcc" in a for a in anc) and any("make" in a for a in anc)
    objs = [str(cproj / f"{n}.o") for n in names]
    checks["app_inputs_all_objects"] = bool(w_app) and set(objs) <= set(w_app["inputs"])
    record("cproj/app", cproj / "app", "ld", objs, checks["app_created_by_linker"], w_app)
    # compiler subprocess census across the three builds
    exes = [name(r["exe"]) for r in con.execute("SELECT exe FROM processes WHERE run_id=? AND exe IS NOT NULL", (d.run_id,))]
    census = {k: sum(1 for e in exes if re.search(p, e)) for k, p in
              {"cc1": r"^cc1$", "as": r"(^|-)as$", "collect2": r"^collect2$", "ld": r"(^|-)ld(\.bfd)?$",
               "gcc": r"gcc", "make": r"^make$"}.items()}
    R["process_census"] = census
    expected_cc1 = len(names) * 2 + 1  # build #1 + #2 compile everything; #3 recompiles u05
    checks["compiler_subprocesses_observed"] = census["cc1"] == expected_cc1 and census["as"] == expected_cc1
    checks["linker_subprocesses_observed"] = census["collect2"] == 3 and census["ld"] >= 3
    imp = {b for _a, b, _e, _r in impact(con, header)}
    # main.c does not #include common.h: make rebuilds main.o (declared prerequisite),
    # but the compiler never reads the header for it, so observed impact must NOT include it.
    includers = [str(cproj / f"{n}.o") for n in names if n != "main"]
    checks["header_impact_reaches_all_includers_and_app"] = set(includers) <= imp and str(cproj / "app") in imp
    checks["header_impact_excludes_non_includer"] = str(cproj / "main.o") not in imp
    # header change: every object was re-created after the edit, from the changed header
    rebuilt = 0
    for n in names[:-1]:
        h = [r for r in history(con, str(cproj / f"{n}.o"), 10) if r["kind"] == "io"]
        rebuilt += sum(1 for r in h if r["ts_ns"] >= t_header) >= 1
    checks["header_change_rebuilt_every_dependent_object"] = rebuilt == len(names) - 1
    # source change: only u05.o (+ app) rewritten after the source edit
    after_src = {n: sum(1 for r in history(con, str(cproj / f"{n}.o"), 10) if r["kind"] == "io" and r["ts_ns"] >= t_source)
                 for n in names}
    checks["source_change_rebuilt_only_affected_object"] = after_src["u05"] == 1 and sum(after_src.values()) == 1
    imp5 = {b for _a, b, _e, _r in impact(con, cfiles["u05"])}
    checks["source_impact_reaches_object_and_app"] = str(cproj / "u05.o") in imp5 and str(cproj / "app") in imp5
    w5 = why(con, str(cproj / "u05.o"))
    checks["source_change_lineage_current"] = bool(w5) and cfiles["u05"] in lineage_inputs(w5) and w5["ts_ns"] >= t_source

    # 3. vite build
    assets = sorted((web / "dist" / "assets").glob("*"))
    js = [a for a in assets if a.suffix == ".js"]
    css = [a for a in assets if a.suffix == ".css"]
    src = {k: str(web / "src" / k) for k in ("main.js", "util.js", "data.json", "style.css")}
    w_js = why(con, str(js[0])) if js else None
    w_css = why(con, str(css[0])) if css else None
    w_html = why(con, str(web / "dist" / "index.html"))
    w_rep = why(con, str(web / "dist" / "report.json"))
    checks["vite_outputs_exist"] = bool(js) and bool(css)
    checks["vite_js_creator_node"] = bool(w_js) and name(w_js["exe"]) == "node"
    checks["vite_js_inputs"] = bool(w_js) and {src["main.js"], src["util.js"], src["data.json"]} <= lineage_inputs(w_js)
    checks["vite_css_input"] = bool(w_css) and src["style.css"] in lineage_inputs(w_css)
    checks["vite_html_creator_node"] = bool(w_html) and name(w_html["exe"]) == "node"
    checks["vite_human_view_hides_node_modules"] = bool(w_js) and not any("node_modules" in p for p in w_js["inputs"]) \
        and (w_js.get("hidden_input_count") or 0) > 0
    checks["vite_postbuild_creator_and_input"] = bool(w_rep) and name(w_rep["exe"]) == "node" and (not js or str(js[0]) in w_rep["inputs"])
    imp_util = {b for _a, b, _e, _r in impact(con, src["util.js"])}
    checks["vite_transitive_impact_to_postbuild"] = str(web / "dist" / "report.json") in imp_util
    if js:
        record("web/dist/assets/*.js", js[0], "node", [src["main.js"], src["util.js"], src["data.json"]],
               checks["vite_js_creator_node"], w_js)
    if css:
        record("web/dist/assets/*.css", css[0], "node", [src["style.css"]], bool(w_css) and name(w_css["exe"]) == "node", w_css)
    record("web/dist/index.html", web / "dist" / "index.html", "node", [str(web / "index.html")], checks["vite_html_creator_node"], w_html)
    record("web/dist/report.json", web / "dist" / "report.json", "node", [str(js[0])] if js else [],
           bool(w_rep) and name(w_rep["exe"]) == "node", w_rep)

    # 4. rename / move
    final = ws / "mv" / "final" / "result.txt"
    w_mv = why(con, str(final))
    checks["rename_chain_creator_is_original_writer"] = bool(w_mv) and name(w_mv["exe"]) == "cp"
    checks["rename_chain_input_preserved"] = bool(w_mv) and str(ws / "mv" / "input.txt") in w_mv["inputs"]
    checks["rename_chain_steps_recorded"] = bool(w_mv) and len(w_mv.get("renamed_from") or []) == 2
    checks["rename_impact_reaches_final_name"] = str(final) in {b for _a, b, _e, _r in impact(con, str(ws / "mv" / "input.txt"))}
    record("mv/final/result.txt", final, "cp", [str(ws / "mv" / "input.txt")], checks["rename_chain_creator_is_original_writer"], w_mv)
    con.close()

    # 5. query behaviour transcripts (CLI)
    q = {}
    for label, args, cwd in [
        ("why_static", ["why", "static-out.txt"], ws),
        ("why_static_raw", ["why", "static-out.txt", "--raw"], ws),
        ("why_object", ["why", "u05.o"], cproj),
        ("why_app", ["why", "app", "--limit", "5"], cproj),
        ("impact_header", ["impact", "common.h"], cproj),
        ("history_object", ["history", "u05.o"], cproj),
        ("why_vite_js", ["why", str(js[0]) if js else "missing"], web),
        ("why_vite_js_raw_json", ["why", str(js[0]) if js else "missing", "--raw", "--json"], web),
        ("why_moved", ["why", "final/result.txt"], ws / "mv"),
        ("history_moved", ["history", "final/result.txt"], ws / "mv"),
    ]:
        p = ctx.whyfs(*args, cwd=cwd, check=False)
        q[label] = {"rc": p.returncode, "stdout": p.stdout}
    raw_js = json.loads(q["why_vite_js_raw_json"]["stdout"] or "{}")
    checks["raw_mode_retains_dependency_reads"] = any("node_modules" in p for p in raw_js.get("inputs", []))
    checks["query_commands_succeed"] = all(v["rc"] == 0 for v in q.values())
    R["queries"] = q

    # accuracy metrics
    n_out = len(outputs)
    creators = sum(o["creator_ok"] for o in outputs)
    exp_n = sum(len(o["expected_inputs"]) for o in outputs)
    hit_n = sum(len(o["found_inputs"]) for o in outputs)
    R["accuracy"] = {
        "tested_outputs": n_out,
        "creator_attribution": creators / n_out if n_out else 0.0,
        "expected_meaningful_inputs": exp_n,
        "found_meaningful_inputs": hit_n,
        "useful_input_recall": hit_n / exp_n if exp_n else 0.0,
        "note": "Found = direct observed reads plus inputs reached through observed derived temporaries "
                "(gcc: cc1 -> /tmp/cc*.s -> as).  For objects, the source/header are one observed hop away.",
    }
    checks["creator_attribution_ge_99pct"] = R["accuracy"]["creator_attribution"] >= 0.99
    checks["useful_input_recall_ge_95pct"] = R["accuracy"]["useful_input_recall"] >= 0.95
    checks["functional_zero_kernel_drops"] = run_stats.get("kernel_drops", 1) == 0
    checks["functional_zero_queue_drops"] = run_stats.get("queue_drops", 1) == 0
    R["outputs"] = outputs
    R["checks"] = checks
    return R


def noise_and_scope(ctx: Ctx, base: Path) -> dict:
    """--all-files capture: default view hides system noise, raw keeps it."""
    ws = base / "noise"
    ws.mkdir(parents=True)
    (ws / "in.txt").write_text("hello\n")
    (ws / "job.py").write_text("import json\nd=open('in.txt').read()\nopen('out.json','w').write(json.dumps({'n':len(d)}))\n")
    ctx.chown(ws)
    ctx.whyfs("init", str(ws), cwd=ws)
    with Daemon(ctx, ws, all_files=True) as d:
        ctx.run_user("python3 job.py", ws)
    con = connect(ws)
    w_default = why(con, str(ws / "out.json"), include_noise=False)
    w_raw = why(con, str(ws / "out.json"), include_noise=True)
    outside_rows = con.execute("SELECT COUNT(*) FROM events WHERE run_id=? AND path NOT LIKE ?",
                               (d.run_id, str(ws) + "/%")).fetchone()[0]
    con.close()
    checks = {
        "default_view_inputs_are_workspace_only": bool(w_default) and all(p.startswith(str(ws)) for p in w_default["inputs"]),
        "default_view_reports_hidden_count": bool(w_default) and (w_default["hidden_input_count"] or 0) > 0,
        "raw_view_retains_system_reads": bool(w_raw) and any(p.startswith("/usr/") for p in w_raw["inputs"]),
        "raw_evidence_stored": outside_rows > 0,
        "meaningful_input_visible": bool(w_default) and str(ws / "in.txt") in w_default["inputs"],
    }
    return {"checks": checks, "hidden": w_default["hidden_input_count"] if w_default else None,
            "raw_inputs": len(w_raw["inputs"]) if w_raw else None, "outside_rows_stored": outside_rows,
            "collector": d.stats()}


# --------------------------------------------------------------------------- performance
def performance(ctx: Ctx, base: Path, vite_template: Path, pairs: int, warmups: int) -> dict:
    ws = base / "perf"
    ws.mkdir(parents=True)
    write_c_project(ws / "cproj")
    write_vite_project(ws / "web", vite_template)
    (ws / "static_copy.c").write_text(STATIC_C)
    (ws / "raw.txt").write_text("x" * 4096)
    ctx.chown(ws)
    ctx.run_user("gcc -static -O2 static_copy.c -o static_copy", ws)
    ctx.whyfs("init", str(ws), cwd=ws)
    workloads = {
        "make_j8_36_units": ("make -s clean >/dev/null; true", "make -s -j8", ws / "cproj"),
        "vite_build": ("true", VITE, ws / "web"),
        "static_binary_x300": ("rm -f out-*.txt", "for i in $(seq 1 300); do ./static_copy raw.txt out-$i.txt; done", ws),
    }
    db = ws / ".whyfs" / "whyfs.db"
    tick = os.sysconf("SC_CLK_TCK")
    result: dict = {}
    for wname, (prep, cmd, cwd) in workloads.items():
        rows = []
        order = ["off", "on"] * warmups + [m for i in range(pairs) for m in (("off", "on") if i % 2 == 0 else ("on", "off"))]
        for idx, mode in enumerate(order):
            warm = idx < 2 * warmups
            ctx.run_user(prep, cwd, check=False)
            row = {"mode": mode, "warmup": warm}
            if mode == "off":
                row["seconds"] = ctx.run_user(cmd, cwd)[0]
            else:
                size0 = db.stat().st_size if db.exists() else 0
                with Daemon(ctx, ws) as d:
                    # The first build after a daemon (re)start pays a one-time
                    # warm-up cost; an always-on daemon's per-build overhead is
                    # measured on the next build.  The first build is kept as
                    # raw data and reported separately, never discarded silently.
                    row["first_build_after_start_seconds"] = ctx.run_user(cmd, cwd)[0]
                    ctx.run_user(prep, cwd, check=False)
                    c0 = d.cpu_ticks()
                    row["seconds"] = ctx.run_user(cmd, cwd)[0]
                    row["collector_cpu_s_during_workload"] = (d.cpu_ticks() - c0) / tick
                st = d.stats()
                row.update({k: st.get(k) for k in ("received", "submitted", "kernel_drops", "queue_drops",
                                                   "unresolved_fd", "filtered", "writer_rows", "writer_batches",
                                                   "writer_max_batch", "stored_events", "stored_processes",
                                                   "unreadable_paths", "truncated_paths")})
                row["db_growth_bytes"] = (db.stat().st_size if db.exists() else 0) - size0
            rows.append(row)
            ctx.note(f"perf {wname} {'warmup ' if warm else ''}{mode}: {row['seconds']:.3f}s")
        meas = [r for r in rows if not r["warmup"]]
        offs = [r["seconds"] for r in meas if r["mode"] == "off"]
        ons = [r["seconds"] for r in meas if r["mode"] == "on"]
        paired = [(ons[i] / offs[i] - 1) * 100 for i in range(min(len(ons), len(offs)))]
        on_rows = [r for r in meas if r["mode"] == "on"]
        result[wname] = {
            "command": cmd, "pairs": pairs, "warmup_pairs": warmups, "runs": rows,
            "baseline_median_s": statistics.median(offs), "monitored_median_s": statistics.median(ons),
            "paired_overheads_percent": paired, "median_paired_overhead_percent": statistics.median(paired),
            "median_of_medians_overhead_percent": (statistics.median(ons) / statistics.median(offs) - 1) * 100,
            "first_build_after_start_median_overhead_percent": statistics.median(
                (r["first_build_after_start_seconds"] / offs[min(i, len(offs) - 1)] - 1) * 100
                for i, r in enumerate(on_rows)),
            # Collector stats, stored events and DB growth cover the whole daemon
            # session: the first build plus the measured build.
            "builds_per_daemon_session": 2,
            "collector_cpu_s_median": statistics.median(r["collector_cpu_s_during_workload"] for r in on_rows),
            "events_received_median": statistics.median(r["received"] for r in on_rows),
            "stored_events_median": statistics.median(r["stored_events"] for r in on_rows),
            "db_growth_bytes_median": statistics.median(r["db_growth_bytes"] for r in on_rows),
            "kernel_drops_total": sum(r["kernel_drops"] for r in on_rows),
            "queue_drops_total": sum(r["queue_drops"] for r in on_rows),
            "writer_batches_median": statistics.median(r["writer_batches"] for r in on_rows),
            "writer_max_batch_max": max(r["writer_max_batch"] for r in on_rows),
        }
    # query latency on the populated perf database
    con = connect(ws)
    targets = [str(ws / "cproj" / "app"), str(ws / "cproj" / "u05.o"), str(ws / "out-150.txt")]
    js = sorted((ws / "web" / "dist" / "assets").glob("*.js"))
    if js:
        targets.append(str(js[0]))
    inproc = []
    for _ in range(40):
        for t in targets:
            t0 = time.perf_counter()
            why(con, t)
            inproc.append((time.perf_counter() - t0) * 1000)
    imp_ms = []
    for _ in range(10):
        t0 = time.perf_counter()
        impact(con, str(ws / "cproj" / "common.h"))
        imp_ms.append((time.perf_counter() - t0) * 1000)
    events_total = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.close()
    cli = []
    for _ in range(15):
        t0 = time.perf_counter()
        ctx.whyfs("why", "app", cwd=ws / "cproj")
        cli.append((time.perf_counter() - t0) * 1000)
    result["query_latency_ms"] = {
        "why_in_process_median": statistics.median(inproc), "why_in_process_p95": sorted(inproc)[int(len(inproc) * .95)],
        "impact_header_median": statistics.median(imp_ms), "why_cli_end_to_end_median": statistics.median(cli),
        "db_events_at_measurement": events_total, "db_bytes_at_measurement": (ws / ".whyfs" / "whyfs.db").stat().st_size,
    }
    return result


# --------------------------------------------------------------------------- main
def environment() -> dict:
    def cmd(*a):
        try:
            return subprocess.run(a, capture_output=True, text=True).stdout.strip().splitlines()[0]
        except Exception:
            return None
    mem = next((l for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("MemTotal")), "")
    cpu = next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("model name")), "")
    import bcc  # type: ignore
    return {"kernel": platform.release(), "machine": platform.machine(), "python": platform.python_version(),
            "cpu": cpu, "cpus": os.cpu_count(), "mem": mem, "bcc": getattr(bcc, "__version__", None),
            "clang": cmd("clang", "--version"), "gcc": cmd("gcc", "--version"), "node": cmd("node", "--version"),
            "make": cmd("make", "--version"), "doctor": capability_report()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "results" / "graduation"))
    ap.add_argument("--user", default=os.environ.get("SUDO_USER") or "")
    ap.add_argument("--base", default="")
    ap.add_argument("--vite-template", default="")
    ap.add_argument("--pairs", type=int, default=10)
    ap.add_argument("--warmups", type=int, default=2)
    ap.add_argument("--skip-perf", action="store_true")
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root: the daemon needs BPF privileges; workloads run as --user")
    ensure_kernel_headers()
    rep = capability_report()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if not rep["ready"]:
        (out / "graduation.json").write_text(json.dumps({"verdict": "BLOCKED_ENVIRONMENT", "doctor": rep}, indent=2))
        print("BLOCKED_ENVIRONMENT", rep)
        return 2
    user = a.user or pwd.getpwuid(os.stat(REPO).st_uid).pw_name
    ctx = Ctx(user, out)
    base = Path(a.base or f"/home/{user}/whyfs-graduation-ws").resolve()
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True)
    ctx.chown(base)
    template = Path(a.vite_template or f"/home/{user}/vite-template")
    report: dict = {"started": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "environment": environment(), "workload_user": user}
    ctx.note(f"graduation: user={user} base={base}")
    report["functional"] = functional(ctx, base, template)
    report["noise"] = noise_and_scope(ctx, base)
    if not a.skip_perf:
        report["performance"] = performance(ctx, base, template, a.pairs, a.warmups)
    checks = {**{f"functional.{k}": v for k, v in report["functional"]["checks"].items()},
              **{f"noise.{k}": v for k, v in report["noise"]["checks"].items()}}
    if not a.skip_perf:
        perf = report["performance"]
        for w in ("make_j8_36_units", "vite_build", "static_binary_x300"):
            checks[f"perf.{w}.median_overhead_lt_5pct"] = perf[w]["median_paired_overhead_percent"] < 5.0
            checks[f"perf.{w}.zero_drops"] = perf[w]["kernel_drops_total"] == 0 and perf[w]["queue_drops_total"] == 0
        checks["perf.why_query_median_lt_100ms"] = perf["query_latency_ms"]["why_in_process_median"] < 100
    report["checks"] = checks
    report["failed_checks"] = [k for k, v in checks.items() if not v]
    report["verdict"] = "PASS" if not report["failed_checks"] else "FAIL"
    report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    (out / "graduation.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
    ctx.note(f"verdict {report['verdict']}; failed: {report['failed_checks']}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
