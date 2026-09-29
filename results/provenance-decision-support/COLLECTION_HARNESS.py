#!/usr/bin/env python3
"""Controlled WhyFS provenance decision-support benchmark.

This benchmark is deliberately independent of the closed general agent-efficiency benchmark.
The oracle is an execution plan written before collection, not data derived from WhyFS.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

import whyfs_benchmark as base


WORKSPACE = Path("/mnt/c/Users/ftmon/Downloads/githubtestwhyfs")
RESULTS = WORKSPACE / "results/provenance-decision-support"
PRODUCT = WORKSPACE / "whyfs-agent-native-tools-final"
CANDIDATE_SHA = "c0be4efcdc7811e5fc0dd4c72ba80a514cc3dc42"
PACKAGE = Path("/home/ftmon/whyfs-native-final-build/whyfs_1.0.0_amd64.deb")
PACKAGE_SHA256 = "465ac0988641114f54d8481fb7e2a6320194a9e752b310bdd3e54593953b15ac"
MODEL = "gpt-5.6-sol"
REASONING = "medium"
CODEX = "/usr/local/bin/codex"
AUTH_SOURCE = Path("/mnt/c/Users/ftmon/.codex/auth.json")
FTMON_UID = 1001
FTMON_GID = 1001
PRIOR_EVIDENCE = (
    "agent-efficiency-pilot",
    "agent-efficiency-pilot-invalid-treatment-sandbox-20260928T2109",
    "agent-efficiency-v2-retest",
    "agent-efficiency-trust-diagnostic",
    "agent-native-tools-final",
    "agent-efficiency-final-natural",
    "agent-efficiency-generalization-holdout",
)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def write_json(path: Path, value: Any) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(args: list[str], *, cwd: Path | None = None, user: str | None = None,
        check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    command = list(args)
    if user:
        command = ["runuser", "-u", user, "--", *command]
    return subprocess.run(command, cwd=str(cwd) if cwd else None, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=timeout)


def files(base_dir: Path, mapping: dict[str, str]) -> None:
    for rel, value in mapping.items():
        write_text(base_dir / rel, value)


def git_init(case_dir: Path) -> None:
    run(["chown", "-R", "ftmon:ftmon", str(case_dir)])
    run(["git", "init", "-q"], cwd=case_dir, user="ftmon")
    run(["git", "config", "user.name", "Provenance Benchmark"], cwd=case_dir, user="ftmon")
    run(["git", "config", "user.email", "benchmark@example.invalid"], cwd=case_dir, user="ftmon")
    run(["git", "add", "."], cwd=case_dir, user="ftmon")
    run(["git", "commit", "-q", "-m", "static fixture"], cwd=case_dir, user="ftmon")


COMMON_IGNORE = "__pycache__/\n*.pyc\n"


def cases() -> dict[str, dict[str, Any]]:
    """Task wording and independent ground truth, frozen before collection."""
    return {
        "case01": {
            "name": "generated-inventory-summary",
            "target": "reports/inventory-summary.txt",
            "prompt": (
                "Examine reports/inventory-summary.txt. Determine what actually created this specific file, "
                "which input file was observed contributing to it, whether the provenance evidence is complete, "
                "and whether directly editing the summary is the right way to make a durable correction to the "
                "north inventory count. Do not modify any files. Clearly distinguish observed facts from inference."
            ),
            "facts": [
                ["latest_writer", "python3 tools/make_inventory.py"],
                ["observed_input", "data/stock.csv"],
                ["complete", True],
                ["generated_relationship", True],
            ],
            "decision": "Edit data/stock.csv and regenerate; do not treat a direct output edit as durable.",
            "execution": ["python3 tools/make_inventory.py"],
            "reads": ["data/stock.csv"], "writes": ["reports/inventory-summary.txt"],
        },
        "case02": {
            "name": "python-node-multistage-lineage",
            "target": "site/device-card.html",
            "prompt": (
                "Examine site/device-card.html. Establish the actual writer of this file and its observed upstream "
                "chain, including the intermediate and originating source. Explain which file is the source versus "
                "an intermediate if the device label must change. State whether the evidence is complete. Do not "
                "modify files, and distinguish observation from inference."
            ),
            "facts": [
                ["latest_writer", "node tools/render-card.js"],
                ["direct_input", "work/normalized.json"],
                ["upstream_source", "specs/device.yaml"],
                ["intermediate", "work/normalized.json"],
                ["complete", True],
            ],
            "decision": "Change specs/device.yaml and rerun both stages; normalized.json is generated intermediate.",
            "execution": ["python3 tools/normalize.py", "node tools/render-card.js"],
            "reads": ["specs/device.yaml", "work/normalized.json"],
            "writes": ["work/normalized.json", "site/device-card.html"],
        },
        "case03": {
            "name": "badge-one-to-many",
            "target": "theme/badge.toml",
            "prompt": (
                "Determine which downstream files were actually observed being produced from theme/badge.toml and "
                "what may therefore be affected if its color changes. Report only observed dependency relationships, "
                "state the completeness limitation, and do not modify files."
            ),
            "facts": [
                ["dependent", "web/assets/badge.svg"],
                ["dependent", "mobile/assets/badge.json"],
                ["dependent", "docs/badge.txt"],
                ["observed_only", True],
            ],
            "decision": "All three observed outputs may be affected; the observed set is not a global completeness proof.",
            "execution": ["node tools/build-badges.js"],
            "reads": ["theme/badge.toml"],
            "writes": ["web/assets/badge.svg", "mobile/assets/badge.json", "docs/badge.txt"],
        },
        "case04": {
            "name": "runtime-config-move-lineage",
            "target": "config/runtime-current.ini",
            "prompt": (
                "Determine whether config/runtime-current.ini has observed rename or move lineage, where the current "
                "file came from, and whether treating the current path as an unrelated new file would be correct. "
                "Also identify its observed later use. Do not modify files; separate observed facts from inference."
            ),
            "facts": [
                ["created_by", "python3 tools/prepare-runtime.py"],
                ["moved_from", "scratch/runtime-draft.ini"],
                ["same_identity_lineage", True],
                ["dependent", "reports/runtime-use.txt"],
                ["complete", True],
            ],
            "decision": "Treat the current path as the moved file with continuous observed lineage, not unrelated.",
            "execution": ["python3 tools/prepare-runtime.py", "mv scratch/runtime-draft.ini config/runtime-current.ini", "python3 tools/consume-runtime.py"],
            "reads": ["seed/runtime-template.ini", "config/runtime-current.ini"],
            "writes": ["scratch/runtime-draft.ini", "config/runtime-current.ini", "reports/runtime-use.txt"],
            "renames": [["scratch/runtime-draft.ini", "config/runtime-current.ini"]],
        },
        "case05": {
            "name": "sequential-index-overwrite",
            "target": "state/live-index.json",
            "prompt": (
                "Determine which process wrote the current/latest observed version of state/live-index.json, whether "
                "the path had an earlier observed writer, and what the available evidence can and cannot establish. "
                "A teammate proposes changing the bootstrap tool to alter the current file; assess that decision. Do "
                "not modify files and do not substitute filename-based inference for observed execution."
            ),
            "facts": [
                ["latest_writer", "python3 tools/rebuild-index.py"],
                ["latest_input", "records/current.json"],
                ["earlier_writer", "python3 tools/bootstrap-index.py"],
                ["multiple_writers", True],
                ["complete", True],
            ],
            "decision": "The current version came from rebuild-index.py; changing bootstrap-index.py does not address that latest write.",
            "execution": ["python3 tools/bootstrap-index.py", "python3 tools/rebuild-index.py"],
            "reads": ["seed/initial.json", "records/current.json"],
            "writes": ["state/live-index.json", "state/live-index.json"],
        },
        "case06": {
            "name": "pre-observation-vendor-cache",
            "target": "cache/vendor-snapshot.bin",
            "prompt": (
                "Determine who originally created cache/vendor-snapshot.bin, what use of it was actually observed, "
                "whether its origin evidence is complete, and what remains unknown. Do not modify files and do not "
                "invent a creator when an observation gap prevents attribution."
            ),
            "facts": [
                ["origin_unknown", True],
                ["reason", "before_recording"],
                ["dependent", "analysis/cache.sha256"],
                ["complete", False],
            ],
            "decision": "Preserve unknown original creation while reporting the later observed read/use.",
            "execution_before_observation": ["harness writes cache/vendor-snapshot.bin"],
            "execution": ["python3 tools/audit-cache.py"],
            "reads": ["cache/vendor-snapshot.bin"], "writes": ["analysis/cache.sha256"],
        },
        "case07": {
            "name": "registered-review-session",
            "target": "artifacts/",
            "prompt": (
                "Identify which files were actually observed for the supplied task ‘Review dependency licenses for "
                "release’ and its agent session. State the established agent/session attribution, distinguish the "
                "supplied task text from inferred intent, and identify any nearby file not attributed to that session. "
                "Do not modify files."
            ),
            "facts": [
                ["session_file", "artifacts/review.md"],
                ["session_file", "artifacts/findings.json"],
                ["agent", "AuditBot"],
                ["supplied_task", "Review dependency licenses for release"],
                ["not_session_file", "artifacts/ambient.log"],
            ],
            "decision": "Attribute only review.md and findings.json to the registered session; supplied task is recorded context, not inferred intent.",
            "execution": ["whyfs agent start ...", "python3 tools/run-review.py", "whyfs agent end ...", "python3 tools/ambient-write.py"],
            "writes": ["artifacts/review.md", "artifacts/findings.json", "artifacts/ambient.log"],
            "session": {"agent": "AuditBot", "task": "Review dependency licenses for release"},
        },
        "case08": {
            "name": "manual-artifact-in-dist",
            "target": "dist/release-note.txt",
            "prompt": (
                "dist/release-note.txt looks generated by convention. Determine what actually created this specific "
                "file, which observed input contributed to it, and whether its location alone proves that the repository "
                "packaging script ran. Explain what should be changed for a durable wording correction. Do not modify files."
            ),
            "facts": [
                ["latest_writer", "/usr/bin/install"],
                ["observed_input", "authored/manual-release.txt"],
                ["packaging_script_not_observed", True],
                ["complete", True],
            ],
            "decision": "Change the authored input and repeat the install/copy operation; directory convention is not execution evidence.",
            "execution": ["/usr/bin/install -D -m 644 authored/manual-release.txt dist/release-note.txt"],
            "reads": ["authored/manual-release.txt"], "writes": ["dist/release-note.txt"],
        },
        "case09": {
            "name": "empty-observed-dependents-safety",
            "target": "scratch/unused-seed.dat",
            "prompt": (
                "Establish what created scratch/unused-seed.dat and what downstream files, if any, were observed "
                "depending on it. Is that evidence sufficient to call the file globally safe to delete? Do not delete "
                "or modify anything. Preserve the distinction between observed dependency evidence and proof of safety."
            ),
            "facts": [
                ["latest_writer", "python3 tools/materialize-seed.py"],
                ["observed_dependents", []],
                ["observed_only", True],
                ["not_proof_of_safety", True],
            ],
            "decision": "Do not call it globally safe to delete merely because no dependents were observed.",
            "execution": ["python3 tools/materialize-seed.py"],
            "reads": ["inputs/seed.txt"], "writes": ["scratch/unused-seed.dat"],
        },
        "case10": {
            "name": "competing-node-exporters",
            "target": "public/channel.json",
            "prompt": (
                "Two repository exporters can plausibly produce public/channel.json. Determine which one actually "
                "generated this particular artifact, which input was observed, and whether the other exporter merely "
                "being capable of producing it proves that it ran. State evidence completeness and do not modify files."
            ),
            "facts": [
                ["latest_writer", "node tools/export-blue.js"],
                ["observed_input", "configs/channel.json"],
                ["other_generator_executed", False],
                ["complete", True],
            ],
            "decision": "The blue exporter actually ran; the red exporter’s capability is not evidence of execution.",
            "execution": ["node tools/export-blue.js"],
            "reads": ["configs/channel.json"], "writes": ["public/channel.json"],
        },
    }


def scaffold(case_id: str, root: Path) -> None:
    root.mkdir(parents=True)
    if case_id == "case01":
        files(root, {
            ".gitignore": COMMON_IGNORE + "reports/\n", "README.md": "Build the inventory summary with `python3 tools/make_inventory.py`.\n",
            "data/stock.csv": "region,count\nnorth,14\nsouth,9\n",
            "tools/make_inventory.py": """from pathlib import Path\nimport csv\nr=Path(__file__).resolve().parents[1]\nwith (r/'data/stock.csv').open() as f: rows=list(csv.DictReader(f))\no=r/'reports/inventory-summary.txt'; o.parent.mkdir(exist_ok=True)\no.write_text('\\n'.join(f\"{x['region']}: {x['count']}\" for x in rows)+'\\n')\n""",
        })
    elif case_id == "case02":
        files(root, {
            ".gitignore": COMMON_IGNORE + "work/\nsite/\n", "README.md": "Normalize then render: `python3 tools/normalize.py && node tools/render-card.js`.\n",
            "specs/device.yaml": "id: sensor-17\nlabel: Cold Room Sensor\n",
            "tools/normalize.py": """from pathlib import Path\nimport json\nr=Path(__file__).resolve().parents[1]\nd=dict(line.split(': ',1) for line in (r/'specs/device.yaml').read_text().splitlines())\no=r/'work/normalized.json'; o.parent.mkdir(exist_ok=True); o.write_text(json.dumps(d,sort_keys=True)+'\\n')\n""",
            "tools/render-card.js": """const fs=require('fs'); const d=JSON.parse(fs.readFileSync('work/normalized.json','utf8')); fs.mkdirSync('site',{recursive:true}); fs.writeFileSync('site/device-card.html',`<article data-id=\"${d.id}\">${d.label}</article>\\n`);\n""",
        })
    elif case_id == "case03":
        files(root, {
            ".gitignore": COMMON_IGNORE + "web/assets/\nmobile/assets/\ndocs/badge.txt\n", "README.md": "Build badge formats with `node tools/build-badges.js`.\n",
            "theme/badge.toml": "name = \"ready\"\ncolor = \"#2e7d32\"\n",
            "tools/build-badges.js": """const fs=require('fs'); const s=fs.readFileSync('theme/badge.toml','utf8'); const color=s.match(/color = \"([^\"]+)/)[1]; fs.mkdirSync('web/assets',{recursive:true}); fs.mkdirSync('mobile/assets',{recursive:true}); fs.mkdirSync('docs',{recursive:true}); fs.writeFileSync('web/assets/badge.svg',`<svg><rect fill=\"${color}\"/></svg>\\n`); fs.writeFileSync('mobile/assets/badge.json',JSON.stringify({color})+'\\n'); fs.writeFileSync('docs/badge.txt',`badge-color=${color}\\n`);\n""",
        })
    elif case_id == "case04":
        files(root, {
            ".gitignore": COMMON_IGNORE + "scratch/\nconfig/runtime-current.ini\nreports/\n", "README.md": "Prepare, move, then consume the runtime configuration.\n",
            "config/.gitkeep": "",
            "seed/runtime-template.ini": "endpoint=worker.internal\nretries=4\n",
            "tools/prepare-runtime.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'scratch/runtime-draft.ini'; o.parent.mkdir(exist_ok=True); o.write_text((r/'seed/runtime-template.ini').read_text())\n""",
            "tools/consume-runtime.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; d=(r/'config/runtime-current.ini').read_text(); o=r/'reports/runtime-use.txt'; o.parent.mkdir(exist_ok=True); o.write_text('consumed\\n'+d)\n""",
        })
    elif case_id == "case05":
        files(root, {
            ".gitignore": COMMON_IGNORE + "state/\n", "README.md": "The live index can be initialized or rebuilt.\n",
            "seed/initial.json": "{\"generation\":\"bootstrap\",\"items\":[\"a\"]}\n", "records/current.json": "{\"generation\":\"current\",\"items\":[\"a\",\"b\"]}\n",
            "tools/bootstrap-index.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'state/live-index.json'; o.parent.mkdir(exist_ok=True); o.write_text((r/'seed/initial.json').read_text())\n""",
            "tools/rebuild-index.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'state/live-index.json'; o.parent.mkdir(exist_ok=True); o.write_text((r/'records/current.json').read_text())\n""",
        })
    elif case_id == "case06":
        files(root, {
            ".gitignore": COMMON_IGNORE + "cache/\nanalysis/\n", "README.md": "Audit vendor snapshots with `python3 tools/audit-cache.py`.\n",
            "tools/audit-cache.py": """from pathlib import Path\nimport hashlib\nr=Path(__file__).resolve().parents[1]; d=(r/'cache/vendor-snapshot.bin').read_bytes(); o=r/'analysis/cache.sha256'; o.parent.mkdir(exist_ok=True); o.write_text(hashlib.sha256(d).hexdigest()+'\\n')\n""",
        })
        write_text(root / "cache/vendor-snapshot.bin", "opaque-vendor-snapshot-41\n")
    elif case_id == "case07":
        files(root, {
            ".gitignore": COMMON_IGNORE + "artifacts/\n", "README.md": "Review tools write under artifacts/.\n",
            "licenses/dependencies.txt": "alpha:MIT\nbeta:Apache-2.0\n",
            "tools/run-review.py": """from pathlib import Path\nimport json\nr=Path(__file__).resolve().parents[1]; rows=(r/'licenses/dependencies.txt').read_text().splitlines(); o=r/'artifacts'; o.mkdir(exist_ok=True); (o/'review.md').write_text('# License review\\n\\n'+ '\\n'.join(rows)+'\\n'); (o/'findings.json').write_text(json.dumps({'count':len(rows),'issues':0})+'\\n')\n""",
            "tools/ambient-write.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'artifacts/ambient.log'; o.parent.mkdir(exist_ok=True); o.write_text('background heartbeat\\n')\n""",
        })
    elif case_id == "case08":
        files(root, {
            ".gitignore": COMMON_IGNORE + "dist/\n", "README.md": "Release material may be staged under dist/.\n",
            "authored/manual-release.txt": "Operator-reviewed release note 12\n",
            "tools/package-release.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'dist/release-note.txt'; o.parent.mkdir(exist_ok=True); o.write_text('automated package note\\n')\n""",
        })
    elif case_id == "case09":
        files(root, {
            ".gitignore": COMMON_IGNORE + "scratch/\n", "README.md": "Materialize a scratch seed with `python3 tools/materialize-seed.py`.\n",
            "inputs/seed.txt": "transient-seed-88\n",
            "tools/materialize-seed.py": """from pathlib import Path\nr=Path(__file__).resolve().parents[1]; o=r/'scratch/unused-seed.dat'; o.parent.mkdir(exist_ok=True); o.write_text((r/'inputs/seed.txt').read_text())\n""",
        })
    elif case_id == "case10":
        files(root, {
            ".gitignore": COMMON_IGNORE + "public/\n", "README.md": "Either channel exporter can produce public/channel.json.\n",
            "configs/channel.json": "{\"channel\":\"stable\",\"revision\":7}\n",
            "tools/export-blue.js": """const fs=require('fs'); const d=fs.readFileSync('configs/channel.json','utf8'); fs.mkdirSync('public',{recursive:true}); fs.writeFileSync('public/channel.json',d);\n""",
            "tools/export-red.js": """const fs=require('fs'); const d=fs.readFileSync('configs/channel.json','utf8'); fs.mkdirSync('public',{recursive:true}); fs.writeFileSync('public/channel.json',d);\n""",
        })
    else:
        raise ValueError(case_id)
    git_init(root)


def service_ready(timeout: int = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            out = run(["whyfs", "status", "--json"], user="ftmon", check=False, timeout=12)
        except subprocess.TimeoutExpired:
            time.sleep(1)
            continue
        if out.returncode == 0:
            try:
                data = json.loads(out.stdout)
                if data.get("collector_ready") and data.get("lost") == 0:
                    return True
            except json.JSONDecodeError:
                pass
        time.sleep(1)
    return False


def execute_fixture(case_id: str, root: Path, condition: str) -> None:
    if case_id == "case01": run(["python3", "tools/make_inventory.py"], cwd=root, user="ftmon")
    elif case_id == "case02":
        run(["python3", "tools/normalize.py"], cwd=root, user="ftmon"); time.sleep(.08)
        run(["node", "tools/render-card.js"], cwd=root, user="ftmon")
    elif case_id == "case03": run(["node", "tools/build-badges.js"], cwd=root, user="ftmon")
    elif case_id == "case04":
        run(["python3", "tools/prepare-runtime.py"], cwd=root, user="ftmon"); time.sleep(.08)
        run(["mv", "scratch/runtime-draft.ini", "config/runtime-current.ini"], cwd=root, user="ftmon"); time.sleep(.08)
        run(["python3", "tools/consume-runtime.py"], cwd=root, user="ftmon")
    elif case_id == "case05":
        run(["python3", "tools/bootstrap-index.py"], cwd=root, user="ftmon"); time.sleep(.15)
        run(["python3", "tools/rebuild-index.py"], cwd=root, user="ftmon")
    elif case_id == "case06": run(["python3", "tools/audit-cache.py"], cwd=root, user="ftmon")
    elif case_id == "case07":
        sid = f"license-review-{condition}-{time.time_ns()}"
        task = "Review dependency licenses for release"
        shell = (
            f"whyfs agent start --name AuditBot --agent-version 2 --session-id {shlex.quote(sid)} "
            f"--root-pid parent --workspace {shlex.quote(str(root))} --task {shlex.quote(task)} --json >/dev/null; "
            "python3 tools/run-review.py; "
            f"whyfs agent end --session-id {shlex.quote(sid)} --json >/dev/null"
        )
        run(["bash", "-lc", shell], cwd=root, user="ftmon")
        time.sleep(.12); run(["python3", "tools/ambient-write.py"], cwd=root, user="ftmon")
    elif case_id == "case08": run(["/usr/bin/install", "-D", "-m", "644", "authored/manual-release.txt", "dist/release-note.txt"], cwd=root, user="ftmon")
    elif case_id == "case09": run(["python3", "tools/materialize-seed.py"], cwd=root, user="ftmon")
    elif case_id == "case10": run(["node", "tools/export-blue.js"], cwd=root, user="ftmon")


def snapshot_prior() -> dict[str, Any]:
    result = {}
    for name in PRIOR_EVIDENCE:
        root = WORKSPACE / "results" / name
        if not root.is_dir():
            raise RuntimeError(f"missing prior evidence {root}")
        mapping = {p.relative_to(root).as_posix(): sha256(p) for p in sorted(root.rglob("*")) if p.is_file()}
        manifest = "".join(f"{k}\0{v}\n" for k, v in mapping.items()).encode()
        result[name] = {"file_count": len(mapping), "manifest_sha256": hashlib.sha256(manifest).hexdigest(), "files": mapping}
    return result


def setup() -> None:
    if RESULTS.exists():
        raise RuntimeError(f"refusing to overwrite {RESULTS}")
    RESULTS.mkdir(parents=True)
    write_json(RESULTS / "HISTORICAL_EVIDENCE_BEFORE.json", snapshot_prior())
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_root = Path(f"/home/ftmon/whyfs-provenance-decision-{stamp}")
    private_root = Path(f"/root/whyfs-provenance-decision-{stamp}")
    run_root.mkdir(mode=0o755); private_root.mkdir(mode=0o700)
    # Stop observation while static repositories and the deliberate pre-observation case are created.
    run(["systemctl", "stop", "whyfs.service"], timeout=20)
    specs = cases()
    for case_id in specs:
        for condition in ("baseline", "whyfs"):
            scaffold(case_id, run_root / "cases" / f"{case_id}-{condition}")
    run(["systemctl", "start", "whyfs.service"], timeout=20)
    if not service_ready(40):
        raise RuntimeError("WhyFS service did not become healthy after deliberate observation boundary")
    for case_id in specs:
        for condition in ("baseline", "whyfs"):
            execute_fixture(case_id, run_root / "cases" / f"{case_id}-{condition}", condition)
            time.sleep(.10)
    # Fresh agents see only their assigned repository.
    for case_dir in (run_root / "cases").iterdir():
        run(["chown", "-R", "root:root", str(case_dir)])
        case_dir.chmod(0o700)
    seed = int.from_bytes(os.urandom(8), "big")
    rng = random.Random(seed)
    pair_order = {}
    order = []
    for case_id in specs:
        pair = ["baseline", "whyfs"]; rng.shuffle(pair); pair_order[case_id] = pair
        order.extend({"case": case_id, "condition": condition} for condition in pair)
    prompts = {cid: specs[cid]["prompt"] for cid in specs}
    manifest = {"created_at": now(), "run_root": str(run_root), "private_root": str(private_root),
                "seed": seed, "pair_order": pair_order, "run_order": order,
                "candidate_sha": CANDIDATE_SHA, "package_sha256": PACKAGE_SHA256,
                "codex": "codex-cli 0.147.0", "model": MODEL, "reasoning": REASONING}
    write_json(RESULTS / "ORACLE.json", specs)
    write_json(RESULTS / "RUN_ORDER.json", manifest)
    write_json(RESULTS / "PROMPT_HASHES.json", {cid: {"sha256": hashlib.sha256(text.encode()).hexdigest(),
                                                        "baseline_equals_whyfs": True, "prompt": text}
                                                   for cid, text in prompts.items()})
    shutil.copy2(Path(__file__), RESULTS / "FIXTURE_GENERATOR.py")
    fixture_hashes = {p.relative_to(run_root).as_posix(): sha256(p)
                      for p in sorted(run_root.rglob("*")) if p.is_file() and ".git" not in p.parts}
    write_json(RESULTS / "FIXTURE_HASHES.json", {"generator_sha256": sha256(Path(__file__)),
                                                   "pre_agent_files": fixture_hashes})
    write_text(RESULTS / "CASES.md", "# Case matrix\n\n" + "\n".join(
        f"## {cid} — {spec['name']}\n\nTarget: `{spec['target']}`\n\nDecision: {spec['decision']}\n\nRequired facts: " +
        "; ".join(f"`{key}`={json.dumps(value)}" for key, value in spec["facts"]) + "\n"
        for cid, spec in specs.items()))
    write_text(RESULTS / "METHODOLOGY.md", """# Methodology

This is a provenance decision-support benchmark, not a general coding-agent efficiency benchmark. Ten new paired fixtures are deliberately executed. The hidden oracle records the harness-planned commands, inputs, outputs, renames, order, session metadata, and intentional observation boundary independently of WhyFS. BASELINE and WHYFS receive identical provenance-explicit prompts; only WHYFS receives the frozen native MCP tool inventory. Each run is a fresh Codex 0.147.0 session using gpt-5.6-sol with medium reasoning. No agent may modify files, read another fixture, access the oracle, or access prior evidence. Correct uncertainty is epistemically correct even when runtime facts cannot be recovered from baseline evidence; recovery and precision are scored separately.
""")
    print(json.dumps(manifest, indent=2))


def load_manifest() -> dict[str, Any]:
    return json.loads((RESULTS / "RUN_ORDER.json").read_text())


def verify_product() -> dict[str, Any]:
    head = run(["git", "-c", f"safe.directory={PRODUCT}", "-C", str(PRODUCT), "rev-parse", "HEAD"]).stdout.strip()
    dirty = run(["git", "-c", f"safe.directory={PRODUCT}", "-C", str(PRODUCT), "status", "--porcelain"]).stdout
    if head != CANDIDATE_SHA or dirty:
        raise RuntimeError(f"frozen product changed: head={head}, dirty={dirty!r}")
    if sha256(PACKAGE) != PACKAGE_SHA256:
        raise RuntimeError("package hash mismatch")
    return {"candidate_sha": head, "worktree_clean": True, "package_sha256": sha256(PACKAGE),
            "installed_version": run(["dpkg-query", "-W", "-f=${Version}", "whyfs"]).stdout.strip(),
            "mcp_sha256": sha256(Path("/usr/lib/python3/dist-packages/whyfs/mcp_server.py")),
            "entrypoint_sha256": sha256(Path("/usr/bin/whyfs-mcp"))}


def baseline_isolation() -> str:
    command = ["systemd-run", "--quiet", "--wait", "--collect", "--pipe",
               f"--unit=whyfs-prov-isolation-{os.getpid()}", "--uid=ftmon", "--gid=ftmon"]
    for p in ("/run/whyfs", "/var/lib/whyfs", "/usr/bin/whyfs", "/usr/bin/whyfs-mcp",
              "/usr/lib/whyfs", "/usr/lib/python3/dist-packages/whyfs"):
        command.append(f"--property=InaccessiblePaths={p}")
    command += ["/bin/bash", "-lc", "/usr/bin/whyfs status >/dev/null 2>&1; a=$?; /usr/bin/whyfs-mcp </dev/null >/dev/null 2>&1; b=$?; python3 -c 'import whyfs.api' >/dev/null 2>&1; c=$?; test -S /run/whyfs/api.sock; d=$?; test -r /var/lib/whyfs/machine/.whyfs/whyfs.db; e=$?; printf 'cli=%s mcp=%s module=%s socket=%s db=%s\\n' \"$a\" \"$b\" \"$c\" \"$d\" \"$e\""]
    out = run(command, check=False, timeout=30)
    m = re.fullmatch(r"cli=(\d+) mcp=(\d+) module=(\d+) socket=(\d+) db=(\d+)\s*", out.stdout)
    if out.returncode or not m or any(x == "0" for x in m.groups()):
        raise RuntimeError("baseline isolation failed: " + out.stdout)
    return out.stdout.strip()


def preflight() -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RuntimeError("run as root inside WSL")
    codex = run([CODEX, "--version"]).stdout.strip()
    if codex != "codex-cli 0.147.0":
        raise RuntimeError(f"wrong Codex client: {codex}")
    if not AUTH_SOURCE.is_file():
        raise RuntimeError("missing Codex auth cache")
    if not service_ready(20):
        raise RuntimeError("WhyFS service unhealthy or lost events nonzero")
    status = json.loads(run(["whyfs", "status", "--json"], user="ftmon").stdout)
    harness_commit = run(["git", "-c", f"safe.directory={WORKSPACE}", "-C", str(WORKSPACE), "rev-parse", "HEAD"]).stdout.strip()
    env = {"recorded_at": now(), "codex": codex, "model": MODEL, "reasoning": REASONING,
           "kernel": run(["uname", "-a"]).stdout.strip(),
           "cpu_model": next((x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")), "unknown"),
           "cpu_logical": os.cpu_count(),
           "memory_kib": next((int(x.split()[1]) for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemTotal:")), None),
           "product": verify_product(), "whyfs_status": status, "baseline_isolation": baseline_isolation(),
           "harness_commit": harness_commit, "collection_harness_sha256": sha256(Path(__file__))}
    shutil.copy2(Path(__file__), RESULTS / "COLLECTION_HARNESS.py")
    write_json(RESULTS / "ENVIRONMENT.json", env)
    write_text(RESULTS / "ENVIRONMENT.md", "# Environment\n\n" + "\n".join([
        f"- Codex: `{codex}`", f"- Model/reasoning: `{MODEL}` / `{REASONING}`",
        f"- Kernel: `{env['kernel']}`", f"- CPU: `{env['cpu_model']}` ({env['cpu_logical']} logical)",
        f"- Candidate: `{CANDIDATE_SHA}`", f"- Package SHA-256: `{PACKAGE_SHA256}`",
        f"- Baseline isolation: `{env['baseline_isolation']}`", f"- Collector ready/lost: `{status.get('collector_ready')}` / `{status.get('lost')}`",
    ]) + "\n")
    print(json.dumps(env, indent=2))
    return env


def expose(path: Path) -> None:
    run(["chown", "-R", "ftmon:ftmon", str(path)])
    for d in [path, *[p for p in path.rglob("*") if p.is_dir()]]:
        d.chmod(0o755)


def hide(path: Path) -> None:
    run(["chown", "-R", "root:root", str(path)])
    path.chmod(0o700)


def snapshot_tree(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha256(p) for p in sorted(root.rglob("*"))
            if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}


def run_agent(run_id: str, condition: str, case_dir: Path, prompt: str,
              codex_home: Path, private_root: Path) -> tuple[list[str], float, int]:
    codex_home.mkdir(parents=True, mode=0o700)
    shutil.copy2(AUTH_SOURCE, codex_home / "auth.json")
    os.chown(codex_home, FTMON_UID, FTMON_GID); os.chown(codex_home / "auth.json", FTMON_UID, FTMON_GID)
    (codex_home / "auth.json").chmod(0o600)
    if condition == "whyfs":
        # Keep the treatment surface typed-only.  The server runs the exact installed frozen
        # package from a private copy, while the shell-visible CLI and globally importable
        # package are masked in the unit below.  This is containment, not a product change.
        bundle = codex_home / ".mcp-runtime"
        shutil.copytree(Path("/usr/lib/python3/dist-packages/whyfs"), bundle / "whyfs")
        run(["chown", "-R", "ftmon:ftmon", str(bundle)])
        write_text(codex_home / "config.toml", (
            '[mcp_servers.whyfs]\ncommand = "/usr/bin/python3"\n'
            'args = ["-m", "whyfs.mcp_server"]\n'
            f'env = {{ PYTHONPATH = "{bundle}" }}\n'
        ))
        os.chown(codex_home / "config.toml", FTMON_UID, FTMON_GID); (codex_home / "config.toml").chmod(0o600)
    command = ["systemd-run", "--quiet", "--wait", "--collect", "--pipe", f"--unit=whyfs-prov-{run_id}",
               "--uid=ftmon", "--gid=ftmon", f"--working-directory={case_dir}", "--setenv=HOME=/home/ftmon",
               f"--setenv=CODEX_HOME={codex_home}", f"--property=InaccessiblePaths={private_root}",
               f"--property=InaccessiblePaths={WORKSPACE}"]
    if condition == "baseline":
        for p in ("/run/whyfs", "/var/lib/whyfs", "/usr/bin/whyfs", "/usr/bin/whyfs-mcp",
                  "/usr/lib/whyfs", "/usr/lib/python3/dist-packages/whyfs"):
            command.append(f"--property=InaccessiblePaths={p}")
    else:
        # Treatment differs by the native MCP inventory only.  The MCP adapter remains available,
        # but the legacy shell CLI is deliberately not an additional treatment capability.
        for p in ("/usr/bin/whyfs", "/usr/bin/whyfs-mcp", "/usr/lib/whyfs",
                  "/usr/lib/python3/dist-packages/whyfs"):
            command.append(f"--property=InaccessiblePaths={p}")
    command += [CODEX, "exec", "--json", "--model", MODEL, "-c", f'model_reasoning_effort="{REASONING}"',
                "--dangerously-bypass-approvals-and-sandbox", "-C", str(case_dir), prompt]
    start = time.monotonic()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []
    assert proc.stdout is not None
    for line in proc.stdout:
        lines.append(line)
        if '"type":"turn.completed"' in line or '"type":"turn.failed"' in line:
            print(f"EVENT {run_id} {line.strip()[:300]}", flush=True)
    code = proc.wait(); duration = time.monotonic() - start
    lines.append(json.dumps({"harness": {"returncode": code, "duration_seconds": duration}}) + "\n")
    return lines, duration, code


def parse(lines: list[str], case_dir: Path) -> dict[str, Any]:
    parsed = base.parse_jsonl(lines, case_dir)
    mcp = []; whyfs_bytes = 0; completed = 0; first_mcp = None; sufficient_index = None
    command_rows = []; reconstruction = []
    legacy_cli = []
    for event in parsed["events"]:
        if event.get("type") != "item.completed": continue
        item = event.get("item") or {}; completed += 1
        if item.get("type") == "mcp_tool_call" and item.get("server") == "whyfs":
            result = item.get("result") or {}; texts = [x.get("text", "") for x in result.get("content", []) if x.get("type") == "text"]
            size = sum(len(x.encode("utf-8", "replace")) for x in texts); whyfs_bytes += size
            answer = None
            if texts:
                try: answer = json.loads(texts[0])
                except json.JSONDecodeError: pass
            row = {"tool": item.get("tool"), "arguments": item.get("arguments") or {}, "output_bytes": size,
                   "error": item.get("error"), "answer": answer, "completed_index": completed}
            mcp.append(row); first_mcp = completed if first_mcp is None else first_mcp
            if sufficient_index is None and isinstance(answer, dict) and not item.get("error"):
                # Manual fact scoring later decides whether it was actually sufficient for this case.
                sufficient_index = completed
        elif item.get("type") == "command_execution":
            command = item.get("command", ""); command = " ".join(command) if isinstance(command, list) else command
            command_rows.append({"command": command, "completed_index": completed})
            if (re.search(r"(?<![\w/-])(?:/usr/bin/)?whyfs(?:\s|$)", command)
                    or re.search(r"python3?\s+-m\s+whyfs|(?:import|from)\s+whyfs", command)):
                legacy_cli.append(command)
            if re.search(r"(?<![\w-])(rg|grep|find|fd|cat|sed|head|tail|stat|file|ls|tree|readlink)\b|\bgit\s+(log|show|grep|blame|status|ls-files)\b", command):
                reconstruction.append({"command": command, "completed_index": completed,
                                       "before_first_whyfs": first_mcp is None})
    parsed["whyfs_calls"] = len(mcp); parsed["whyfs_operations"] = [x["tool"] for x in mcp]
    parsed["context_bytes_by_tool"]["whyfs"] = whyfs_bytes; parsed["context_bytes"] += whyfs_bytes
    parsed["ordinary_context_bytes"] = parsed["context_bytes"] - whyfs_bytes
    parsed["manual_reconstruction_operations"] = len(reconstruction)
    parsed["reconstruction_operations"] = reconstruction
    parsed["natural_use"] = {"used": bool(mcp), "first_tool": mcp[0]["tool"] if mcp else None,
                             "calls": len(mcp), "output_bytes": whyfs_bytes,
                             "ordinary_reconstruction_before_first_call": sum(x["before_first_whyfs"] for x in reconstruction),
                             "ordinary_reconstruction_after_first_call": sum(not x["before_first_whyfs"] for x in reconstruction),
                             "ignored": not bool(mcp), "legacy_cli_attempts": legacy_cli, "calls_detail": mcp}
    parsed["command_rows"] = command_rows
    return parsed


def sanitize(text: str) -> str:
    return base.sanitize(text)


def collect() -> None:
    preflight()
    manifest = load_manifest(); specs = cases(); run_root = Path(manifest["run_root"]); private_root = Path(manifest["private_root"])
    raw_results = []
    for index, item in enumerate(manifest["run_order"], 1):
        cid, condition = item["case"], item["condition"]
        run_id = f"{index:02d}-{cid}-{condition}"; case_dir = run_root / "cases" / f"{cid}-{condition}"
        expose(case_dir); before = snapshot_tree(case_dir)
        run_home = run_root / "agent-homes" / run_id
        lines, duration, code = run_agent(run_id, condition, case_dir, specs[cid]["prompt"],
                                          run_home, private_root)
        parsed = parse(lines, case_dir); after = snapshot_tree(case_dir)
        changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        transcript = sanitize("".join(lines)); write_text(RESULTS / "transcripts" / f"{run_id}.jsonl", transcript)
        metadata = {"run_id": run_id, "case": cid, "condition": condition, "duration_seconds": duration,
                    "returncode": code, "usage": parsed["usage"], "thread_id": parsed["thread_id"]}
        write_json(RESULTS / "raw" / "usage" / f"{run_id}.json", metadata)
        row = {"run_id": run_id, "case": cid, "case_name": specs[cid]["name"], "condition": condition,
               "prompt_sha256": hashlib.sha256(specs[cid]["prompt"].encode()).hexdigest(),
               "duration_seconds": duration, "returncode": code, "changed_files": changed,
               "final_response": parsed["final_response"], "metrics": {k: v for k, v in parsed.items() if k not in ("events", "final_response")}}
        write_json(RESULTS / "per-run" / f"{run_id}.json", row); raw_results.append(row)
        hide(case_dir)
        run(["chown", "-R", "root:root", str(run_home)])
        run_home.chmod(0o700)
        if code != 0 or changed:
            raise RuntimeError(f"invalid run {run_id}: returncode={code}, changed={changed}")
        print(f"DONE {run_id} tokens={parsed['usage']['total_tokens']} tools={parsed['tool_calls']} whyfs={parsed['whyfs_calls']}", flush=True)
    write_json(RESULTS / "RAW_RESULTS.json", raw_results)
    write_json(RESULTS / "INVALIDATED_RUNS.json", {"count": 0, "runs": []})


def collect_replacements(source: Path) -> None:
    """Keep valid original baselines and replace only the objectively invalid treatment condition."""
    preflight()
    manifest = load_manifest(); specs = cases(); run_root = Path(manifest["run_root"]); private_root = Path(manifest["private_root"])
    source_results = json.loads((source / "RAW_RESULTS.json").read_text())
    baselines = [x for x in source_results if x["condition"] == "baseline"]
    if len(baselines) != 10:
        raise RuntimeError("replacement source does not contain exactly ten valid baseline runs")
    (RESULTS / "transcripts").mkdir(parents=True, exist_ok=True)
    combined = []
    for row in baselines:
        run_id = row["run_id"]
        shutil.copy2(source / "transcripts" / f"{run_id}.jsonl", RESULTS / "transcripts" / f"{run_id}.jsonl")
        (RESULTS / "per-run").mkdir(parents=True, exist_ok=True)
        (RESULTS / "raw" / "usage").mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / "per-run" / f"{run_id}.json", RESULTS / "per-run" / f"{run_id}.json")
        shutil.copy2(source / "raw" / "usage" / f"{run_id}.json", RESULTS / "raw" / "usage" / f"{run_id}.json")
        combined.append(row)
    replacement_order = []
    for index, cid in enumerate(specs, 1):
        condition = "whyfs"; run_id = f"R{index:02d}-{cid}-whyfs"
        replacement_order.append({"case": cid, "condition": condition, "run_id": run_id})
        case_dir = run_root / "cases" / f"{cid}-{condition}"
        if not service_ready(5):
            raise RuntimeError(f"WhyFS service became unhealthy before {run_id}")
        expose(case_dir); before = snapshot_tree(case_dir); run_home = run_root / "agent-homes" / run_id
        lines, duration, code = run_agent(run_id, condition, case_dir, specs[cid]["prompt"], run_home, private_root)
        parsed = parse(lines, case_dir); after = snapshot_tree(case_dir)
        changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        write_text(RESULTS / "transcripts" / f"{run_id}.jsonl", sanitize("".join(lines)))
        metadata = {"run_id": run_id, "case": cid, "condition": condition, "duration_seconds": duration,
                    "returncode": code, "usage": parsed["usage"], "thread_id": parsed["thread_id"]}
        write_json(RESULTS / "raw" / "usage" / f"{run_id}.json", metadata)
        row = {"run_id": run_id, "case": cid, "case_name": specs[cid]["name"], "condition": condition,
               "prompt_sha256": hashlib.sha256(specs[cid]["prompt"].encode()).hexdigest(),
               "duration_seconds": duration, "returncode": code, "changed_files": changed,
               "final_response": parsed["final_response"], "metrics": {k: v for k, v in parsed.items() if k not in ("events", "final_response")}}
        write_json(RESULTS / "per-run" / f"{run_id}.json", row); combined.append(row)
        hide(case_dir); run(["chown", "-R", "root:root", str(run_home)]); run_home.chmod(0o700)
        if code != 0 or changed:
            raise RuntimeError(f"invalid replacement {run_id}: returncode={code}, changed={changed}")
        print(f"DONE {run_id} tokens={parsed['usage']['total_tokens']} tools={parsed['tool_calls']} whyfs={parsed['whyfs_calls']} legacy={len(parsed['natural_use']['legacy_cli_attempts'])}", flush=True)
    combined.sort(key=lambda x: (x["case"], 0 if x["condition"] == "baseline" else 1))
    write_json(RESULTS / "RAW_RESULTS.json", combined)
    invalid_treatment = [{"run_id": x["run_id"], "case": x["case"],
                          "reason": "legacy WhyFS CLI was shell-accessible, violating typed-interface-only treatment"}
                         for x in source_results if x["condition"] == "whyfs"]
    write_json(RESULTS / "INVALIDATED_RUNS.json", {"count": len(invalid_treatment), "runs": invalid_treatment,
                                                     "preserved_at": str(source)})
    original_order = json.loads((source / "RUN_ORDER.json").read_text())
    write_json(RESULTS / "PRIMARY_RUN_ORDER.json", {"original_randomized_order": original_order["run_order"],
                                                      "replacement_order": replacement_order,
                                                      "note": "Valid baseline runs retained; each invalid treatment run replaced once with a fresh fixture and CLI denied."})


SECOND_REPLACEMENT_CASES = ("case01", "case06")


def setup_second_replacement() -> None:
    """Fresh fixtures for the two runs that discovered the importable legacy module."""
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    run_root = Path(f"/home/ftmon/whyfs-provenance-decision-second-replacement-{stamp}")
    private_root = Path(f"/root/whyfs-provenance-decision-second-replacement-{stamp}")
    run_root.mkdir(mode=0o755); private_root.mkdir(mode=0o700)
    run(["systemctl", "stop", "whyfs.service"], timeout=20)
    for cid in SECOND_REPLACEMENT_CASES:
        scaffold(cid, run_root / "cases" / f"{cid}-whyfs")
    run(["systemctl", "start", "whyfs.service"], timeout=20)
    if not service_ready(40):
        raise RuntimeError("WhyFS service did not become healthy for second replacement")
    for cid in SECOND_REPLACEMENT_CASES:
        execute_fixture(cid, run_root / "cases" / f"{cid}-whyfs", "whyfs")
        time.sleep(.10)
    for case_dir in (run_root / "cases").iterdir():
        run(["chown", "-R", "root:root", str(case_dir)]); case_dir.chmod(0o700)
    manifest = {"created_at": now(), "run_root": str(run_root), "private_root": str(private_root),
                "cases": list(SECOND_REPLACEMENT_CASES), "reason": "legacy Python module bypass",
                "candidate_sha": CANDIDATE_SHA, "package_sha256": PACKAGE_SHA256,
                "codex": "codex-cli 0.147.0", "model": MODEL, "reasoning": REASONING}
    write_json(RESULTS / "SECOND_REPLACEMENT_MANIFEST.json", manifest)
    write_json(RESULTS / "SECOND_REPLACEMENT_FIXTURE_HASHES.json", {
        "generator_sha256": sha256(Path(__file__)),
        "pre_agent_files": {p.relative_to(run_root).as_posix(): sha256(p)
                            for p in sorted(run_root.rglob("*")) if p.is_file() and ".git" not in p.parts},
    })
    print(json.dumps(manifest, indent=2))


def collect_second_replacement() -> None:
    preflight()
    manifest = json.loads((RESULTS / "SECOND_REPLACEMENT_MANIFEST.json").read_text())
    specs = cases(); run_root = Path(manifest["run_root"]); private_root = Path(manifest["private_root"])
    rows = json.loads((RESULTS / "RAW_RESULTS.json").read_text())
    invalidated = json.loads((RESULTS / "INVALIDATED_RUNS.json").read_text())
    new_rows = []
    for index, cid in enumerate(SECOND_REPLACEMENT_CASES, 1):
        old = next(x for x in rows if x["case"] == cid and x["condition"] == "whyfs")
        invalidated["runs"].append({"run_id": old["run_id"], "case": cid,
                                     "reason": "legacy Python module/API was shell-accessible; typed-interface-only treatment violated"})
        run_id = f"S{index:02d}-{cid}-whyfs"; case_dir = run_root / "cases" / f"{cid}-whyfs"
        existing = RESULTS / "per-run" / f"{run_id}.json"
        if existing.is_file():
            row = json.loads(existing.read_text()); new_rows.append(row)
            print(f"RETAIN {run_id}: valid completed replacement preserved after detector-only abort", flush=True)
            continue
        if not service_ready(5):
            raise RuntimeError(f"WhyFS service unhealthy before {run_id}")
        expose(case_dir); before = snapshot_tree(case_dir); run_home = run_root / "agent-homes" / run_id
        lines, duration, code = run_agent(run_id, "whyfs", case_dir, specs[cid]["prompt"], run_home, private_root)
        parsed = parse(lines, case_dir); after = snapshot_tree(case_dir)
        changed = sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))
        write_text(RESULTS / "transcripts" / f"{run_id}.jsonl", sanitize("".join(lines)))
        metadata = {"run_id": run_id, "case": cid, "condition": "whyfs", "duration_seconds": duration,
                    "returncode": code, "usage": parsed["usage"], "thread_id": parsed["thread_id"]}
        write_json(RESULTS / "raw" / "usage" / f"{run_id}.json", metadata)
        row = {"run_id": run_id, "case": cid, "case_name": specs[cid]["name"], "condition": "whyfs",
               "prompt_sha256": hashlib.sha256(specs[cid]["prompt"].encode()).hexdigest(),
               "duration_seconds": duration, "returncode": code, "changed_files": changed,
               "final_response": parsed["final_response"],
               "metrics": {k: v for k, v in parsed.items() if k not in ("events", "final_response")}}
        write_json(RESULTS / "per-run" / f"{run_id}.json", row); new_rows.append(row)
        hide(case_dir); run(["chown", "-R", "root:root", str(run_home)]); run_home.chmod(0o700)
        if code != 0 or changed:
            raise RuntimeError(f"invalid second replacement {run_id}: returncode={code}, changed={changed}")
        if any(re.search(r"python3?\s+-m\s+whyfs|(?:import|from)\s+whyfs", x)
               for x in parsed["natural_use"]["legacy_cli_attempts"]):
            raise RuntimeError(f"legacy Python module bypass remained possible in {run_id}")
        print(f"DONE {run_id} tokens={parsed['usage']['total_tokens']} tools={parsed['tool_calls']} "
              f"whyfs={parsed['whyfs_calls']} legacy={len(parsed['natural_use']['legacy_cli_attempts'])}", flush=True)
    rows = [x for x in rows if not (x["condition"] == "whyfs" and x["case"] in SECOND_REPLACEMENT_CASES)] + new_rows
    rows.sort(key=lambda x: (x["case"], 0 if x["condition"] == "baseline" else 1))
    write_json(RESULTS / "RAW_RESULTS.json", rows)
    invalidated["count"] = len(invalidated["runs"])
    write_json(RESULTS / "INVALIDATED_RUNS.json", invalidated)
    order = json.loads((RESULTS / "PRIMARY_RUN_ORDER.json").read_text())
    order["second_replacement_order"] = [{"case": cid, "condition": "whyfs", "run_id": f"S{i:02d}-{cid}-whyfs"}
                                           for i, cid in enumerate(SECOND_REPLACEMENT_CASES, 1)]
    order["note"] += " Two replacements that bypassed the CLI mask through the Python module were replaced with fresh fixtures and both legacy surfaces denied."
    write_json(RESULTS / "PRIMARY_RUN_ORDER.json", order)


DIAGNOSTIC_CALLS = {
    "case01": [("source_chain", {"path": "reports/inventory-summary.txt"})],
    "case02": [("source_chain", {"path": "site/device-card.html"})],
    "case03": [("observed_dependents", {"path": "theme/badge.toml"})],
    "case04": [("file_origin", {"path": "config/runtime-current.ini"}), ("observed_dependents", {"path": "config/runtime-current.ini"})],
    "case05": [("file_origin", {"path": "state/live-index.json"}), ("source_chain", {"path": "state/live-index.json"})],
    "case06": [("file_origin", {"path": "cache/vendor-snapshot.bin"}), ("observed_dependents", {"path": "cache/vendor-snapshot.bin"})],
    "case07": [("session_files", {"agent": "AuditBot", "supplied_task": "Review dependency licenses for release", "workspace": "."})],
    "case08": [("source_chain", {"path": "dist/release-note.txt"})],
    "case09": [("file_origin", {"path": "scratch/unused-seed.dat"}), ("observed_dependents", {"path": "scratch/unused-seed.dat"})],
    "case10": [("source_chain", {"path": "public/channel.json"})],
}


def mcp_call(cwd: Path, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "benchmark-diagnostic", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
    ]
    start = time.perf_counter_ns()
    proc = subprocess.run(["runuser", "-u", "ftmon", "--", "/usr/bin/whyfs-mcp"], cwd=str(cwd),
                          input="".join(json.dumps(x, separators=(",", ":")) + "\n" for x in messages),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
    elapsed = (time.perf_counter_ns() - start) / 1_000_000
    replies = [json.loads(x) for x in proc.stdout.splitlines() if x.strip().startswith("{")]
    reply = next(x for x in replies if x.get("id") == 2)
    content = reply["result"]["content"]; text = "".join(x.get("text", "") for x in content if x.get("type") == "text")
    try: answer = json.loads(text)
    except json.JSONDecodeError: answer = text
    return {"tool": tool, "arguments": arguments, "latency_ms": elapsed,
            "output_bytes": len(text.encode()), "is_error": reply["result"].get("isError"), "answer": answer}


def diagnostic() -> None:
    manifest = load_manifest(); run_root = Path(manifest["run_root"]); rows = {}
    for cid, calls in DIAGNOSTIC_CALLS.items():
        root = run_root / "cases" / f"{cid}-whyfs"; expose(root)
        rows[cid] = {"minimum_call_count": len(calls), "calls": [mcp_call(root, name, args) for name, args in calls]}
        rows[cid]["total_output_bytes"] = sum(x["output_bytes"] for x in rows[cid]["calls"])
        rows[cid]["total_latency_ms"] = sum(x["latency_ms"] for x in rows[cid]["calls"])
        hide(root)
    write_json(RESULTS / "DIRECT_RETRIEVAL_DIAGNOSTIC.json", rows)
    print(json.dumps(rows, indent=2))


def finish_integrity() -> None:
    before = json.loads((RESULTS / "HISTORICAL_EVIDENCE_BEFORE.json").read_text())
    after = snapshot_prior()
    write_json(RESULTS / "HISTORICAL_EVIDENCE_AFTER.json", after)
    write_json(RESULTS / "HISTORICAL_EVIDENCE_INTEGRITY.json", {"unchanged": before == after})
    if before != after:
        raise RuntimeError("prior authoritative evidence changed")


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "help"
    if command == "setup": setup()
    elif command == "preflight": preflight()
    elif command == "diagnostic": diagnostic()
    elif command == "collect": collect()
    elif command == "collect-replacements" and len(sys.argv) == 3: collect_replacements(Path(sys.argv[2]))
    elif command == "setup-second-replacement": setup_second_replacement()
    elif command == "collect-second-replacement": collect_second_replacement()
    elif command == "finish-integrity": finish_integrity()
    else:
        print("usage: whyfs_provenance_decision_support.py setup|preflight|diagnostic|collect|collect-replacements SOURCE|setup-second-replacement|collect-second-replacement|finish-integrity")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
