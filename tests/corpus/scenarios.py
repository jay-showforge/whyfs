"""The shared cross-platform behavioural corpus: scenarios A-H with platform-neutral answers.

Each scenario prepares input files, runs steps (each a separate `wtool` process), and states
what `why`, `impact` and `history` must answer.  Answers compare file basenames and a
normalized program identity ("python" for python.exe / python3 / python3.12), so the same
expectations hold on every platform.  scripts/run_corpus.py is the per-platform harness.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

SCENARIOS = [
    {"id": "A", "title": "read input -> write output", "dir": "A",
     "files": {"in.txt": "alpha\n"},
     "steps": [["copy", "in.txt", "out.txt"]],
     "why": {"out.txt": {"creator": "python", "inputs": ["in.txt"]}},
     "impact": {"in.txt": ["out.txt"]},
     "history": {"out.txt": 1}},
    {"id": "B", "title": "source -> compiler -> binary", "dir": "B",
     "files": {"main.src": "int main;\n", "defs.h": "#define X 1\n"},
     "steps": [["cc", "main.src", "defs.h", "main.bin"]],
     "why": {"main.bin": {"creator": "python", "inputs": ["defs.h", "main.src"], "command_has": "cc"}},
     "impact": {"defs.h": ["main.bin"], "main.src": ["main.bin"]},
     "history": {"main.bin": 1}},
    {"id": "C", "title": "parent process -> child -> generated file", "dir": "C",
     "files": {"cfg.txt": "k=v\n"},
     "steps": [["spawn", "copy", "cfg.txt", "gen.txt"]],
     "why": {"gen.txt": {"creator": "python", "inputs": ["cfg.txt"], "command_has": "copy", "parent": "python",
                         "parent_command_has": "spawn"}},
     "impact": {"cfg.txt": ["gen.txt"]},
     "history": {"gen.txt": 1}},
    {"id": "D", "title": "rename generated file", "dir": "D",
     "files": {"data.txt": "d\n"},
     "steps": [["copy", "data.txt", "tmp.out"], ["rename", "tmp.out", "final.out"]],
     "why": {"final.out": {"creator": "python", "inputs": ["data.txt"], "command_has": "copy", "renamed_from": ["tmp.out"]}},
     "impact": {"data.txt": ["final.out", "tmp.out"]},
     "history": {"final.out": 1}},
    {"id": "E", "title": "overwrite output", "dir": "E",
     "files": {"a.txt": "a\n", "b.txt": "b\n"},
     "steps": [["copy", "a.txt", "out.txt"], ["copy", "b.txt", "out.txt"]],
     "why": {"out.txt": {"creator": "python", "inputs": ["b.txt"]}},
     "impact": {"b.txt": ["out.txt"]},
     "history": {"out.txt": 2}},
    {"id": "F", "title": "reopen input", "dir": "F",
     "files": {"in.txt": "f\n"},
     "steps": [["readmany", "3", "in.txt", "out.txt"]],
     "why": {"out.txt": {"creator": "python", "inputs": ["in.txt"]}},
     "impact": {"in.txt": ["out.txt"]},
     "history": {"out.txt": 1}},
    {"id": "G", "title": "parallel workers", "dir": "G",
     "files": {f"in_{i}.txt": f"g{i}\n" for i in range(8)},
     "steps": [["parallel", "8"]],
     "why": {f"out_{i}.txt": {"creator": "python", "inputs": [f"in_{i}.txt"], "command_has": f"in_{i}.txt"} for i in range(8)},
     "impact": {f"in_{i}.txt": [f"out_{i}.txt"] for i in range(8)},
     "history": {f"out_{i}.txt": 1 for i in range(8)}},
    {"id": "H", "title": "generated intermediate -> final output", "dir": "H",
     "files": {"src.txt": "h\n"},
     "steps": [["copy", "src.txt", "mid.txt"], ["copy", "mid.txt", "final.txt"]],
     "why": {"final.txt": {"creator": "python", "inputs": ["mid.txt"]}, "mid.txt": {"creator": "python", "inputs": ["src.txt"]}},
     "impact": {"src.txt": ["final.txt", "mid.txt"], "mid.txt": ["final.txt"]},
     "history": {"final.txt": 1, "mid.txt": 1}},
]


def program(exe: str | None) -> str:
    """Platform-neutral program identity: python.exe, python3, python3.12 -> python."""
    if not exe:
        return "?"
    name = re.split(r"[\\/]", exe)[-1].lower()
    name = re.sub(r"\.exe$", "", name)
    return re.sub(r"[\d.]+$", "", name) or name


def prepare(root: Path) -> None:
    for sc in SCENARIOS:
        d = root / sc["dir"]
        d.mkdir(parents=True, exist_ok=True)
        for name, text in sc["files"].items():
            (d / name).write_text(text)


def evaluate(con, root: Path, why, impact, history) -> list[dict]:
    """Run every expectation against the store; one result dict per check."""
    results = []
    for sc in SCENARIOS:
        d = root / sc["dir"]

        def check(what, ok, got, want):
            results.append({"scenario": sc["id"], "check": what, "ok": bool(ok), "got": got, "want": want})

        for f, exp in sc["why"].items():
            w = why(con, str(d / f))
            if not w:
                check(f"why {f}", False, None, exp)
                continue
            # The tool program itself (wtool.py, run by every step) is an input in the literal sense --
            # the interpreter reads it -- and a machine-wide collector sees it; the scenarios state
            # their data inputs, so the program is compared separately from them.
            tool = Path(tool_path()).name
            got_in = sorted(Path(p).name for p in (w["inputs"] or []) if Path(p).name != tool)
            check(f"why {f} creator", program(w["exe"]) == exp["creator"], program(w["exe"]), exp["creator"])
            check(f"why {f} inputs", got_in == sorted(exp["inputs"]), got_in, sorted(exp["inputs"]))
            if "command_has" in exp:
                check(f"why {f} command", exp["command_has"] in (w["command"] or ""), w["command"], exp["command_has"])
            if "renamed_from" in exp:
                got = [Path(r["from"]).name for r in w["renamed_from"]]
                check(f"why {f} renamed_from", got == exp["renamed_from"], got, exp["renamed_from"])
            if "parent" in exp:
                par = w.get("parent") or {}
                check(f"why {f} parent", program(par.get("exe")) == exp["parent"], par.get("exe"), exp["parent"])
                if "parent_command_has" in exp:
                    check(f"why {f} parent command", exp["parent_command_has"] in (par.get("command") or ""),
                          par.get("command"), exp["parent_command_has"])
        for f, want in sc["impact"].items():
            got = sorted({Path(b).name for _a, b, _e, _r in impact(con, str(d / f))})
            check(f"impact {f}", got == sorted(want), got, sorted(want))
        for f, n in sc["history"].items():
            got = len(history(con, str(d / f)))
            check(f"history {f}", got == n, got, n)
    return results


def tool_path() -> str:
    return str(Path(__file__).resolve().parent / "wtool.py")


def env_python() -> str:
    import sys
    return os.environ.get("WHYFS_CORPUS_PYTHON") or sys.executable
