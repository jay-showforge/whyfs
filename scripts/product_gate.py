#!/usr/bin/env python3
"""Product-behaviour gate: install once, never initialize, and every meaningful file has a label.

Linux:   sudo python3 scripts/product_gate.py --user USER --out DIR   (workloads and queries run as USER)
Windows: python scripts\\product_gate.py --out DIR                    (as the installed user)
Requires the whyfs machine service to be running (Linux: whyfs.service / `whyfs machine run`;
Windows: the whyfs service).  No `whyfs init` is ever run; no directory is registered.

  A  no workspace: a file in an ordinary home folder is labelled
  B  Desktop, Documents, a source folder and an arbitrary custom directory are all labelled
  C  a file moved to another directory keeps its provenance (same file identity)
  D  a normal, non-agent application: OS provenance, user, and no agent claimed
  E  a registered agent session: the real process chain is kept and the session is attached
  F  two agent sessions: attribution stays separate (files and labels never merge)
  G  an unregistered agent-like program: OS provenance works, the agent stays unknown
  H  intent: task text appears exactly as supplied; without it, whyfs claims no intent
  P  privacy: another user's records are invisible to a normal user (Linux: root vs USER);
     secrets in command lines and task text never reach the store
Exit 0 only if every check passes.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NT = os.name == "nt"
SETTLE = 9.0 if NT else 3.0  # Windows ETW reorder window + writer batch; Linux ring drain + batch
PY = sys.executable if NT else "python3"
INSTALLED = "--installed" in sys.argv


def whyfs_cmd() -> list[str]:
    if INSTALLED:
        exe = shutil.which("whyfs") or (os.path.join(os.environ.get("ProgramFiles", ""), "whyfs", "whyfs.exe") if NT else "whyfs")
        return [exe]
    return [PY, "-m", "whyfs"]


def env():
    e = dict(os.environ)
    if not INSTALLED:
        e["PYTHONPATH"] = str(REPO / "src")
    return e


class Gate:
    def __init__(self, user: str | None, out: Path):
        self.user, self.out = user, out
        self.checks: dict[str, bool] = {}
        self.detail: dict[str, object] = {}
        self.home = Path(os.path.expanduser(f"~{user}") if (user and not NT) else os.path.expanduser("~"))
        self.tag = "whyfs-gate-" + uuid.uuid4().hex[:8]
        self.made: list[Path] = []

    # ---- running things as the user
    def as_user(self, argv: list[str]) -> list[str]:
        if not NT and self.user and os.geteuid() == 0:
            return ["runuser", "-u", self.user, "--", "env", *(f"{k}={v}" for k, v in env().items()
                                                               if k in ("PYTHONPATH", "PATH", "LANG")), *argv]
        return argv

    def run(self, argv, cwd=None, check=True):
        p = subprocess.run(self.as_user(argv), cwd=cwd, capture_output=True, text=True, env=env())
        if check and p.returncode != 0:
            raise RuntimeError(f"{argv} failed: {p.stdout}{p.stderr}")
        return p

    def api(self, op, as_root=False, **params):
        argv = [*whyfs_cmd(), "api", op, json.dumps(params)]
        p = subprocess.run(argv if as_root else self.as_user(argv), capture_output=True, text=True, env=env())
        try:
            reply = json.loads(p.stdout)
        except ValueError:
            raise RuntimeError(f"api {op}: {p.stdout}{p.stderr}")
        return reply

    def label(self, path, as_root=False):
        r = self.api("get_file_provenance", as_root=as_root, path=str(path))
        return r.get("result") if r.get("ok") else {"status": "error", "error": r.get("error")}

    def mkdir(self, p: Path) -> Path:
        p.mkdir(parents=True, exist_ok=True)
        if not NT and self.user and os.geteuid() == 0:
            subprocess.run(["chown", f"{self.user}:", str(p)], check=True)
        self.made.append(p)
        return p

    def check(self, name, ok, detail=None):
        self.checks[name] = bool(ok)
        if detail is not None:
            self.detail[name] = detail
        print(f"  {'PASS' if ok else 'FAIL'} {name}" + ("" if ok or detail is None else f"   {str(detail)[:300]}"))

    def write_file(self, path: Path, content_from: Path | None = None, via_wmi=False):
        code = ("import sys; d=open(sys.argv[1]).read() if len(sys.argv)>2 else 'x'; "
                "open(sys.argv[-1],'w').write(d.upper())")
        args = [PY, "-c", code] + ([str(content_from)] if content_from else []) + [str(path)]
        if via_wmi:
            return self.wmi(args, cwd=path.parent)
        self.run(args, cwd=path.parent)

    def wmi(self, args, cwd):
        """Windows: start a process through WMI (its parent is the WMI provider host), so its
        ancestry has no agent: the chain an ordinary desktop application would have."""
        line = subprocess.list2cmdline(args)
        ps = (f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments "
              f"@{{CommandLine='{line.replace(chr(39), chr(39) * 2)}'; CurrentDirectory='{cwd}'}}; "
              "if ($r.ReturnValue -ne 0) { exit 1 }; $p = $r.ProcessId; "
              "while (Get-Process -Id $p -ErrorAction SilentlyContinue) { Start-Sleep -Milliseconds 100 }")
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True, capture_output=True)


AGENT = r'''
import json, os, subprocess, sys
whyfs, name, sid, task, script = json.loads(sys.argv[1])
args = [*whyfs, "agent", "start", "--name", name, "--session-id", sid, "--root-pid", str(os.getpid()), "--json"]
if task:
    args += ["--task", task]
subprocess.run(args, check=True, capture_output=True)
for step in script:  # agent -> shell -> tool: cmd.exe on Windows, sh on Linux
    if os.name == "nt":
        subprocess.run(step, shell=True, check=True)
    else:
        subprocess.run(["sh", "-c", step], check=True)
subprocess.run([*whyfs, "agent", "end", "--session-id", sid], check=True, capture_output=True)
'''

GEN = "import json, sys; json.dump({'from': [open(p).read() for p in sys.argv[2:]]}, open(sys.argv[1], 'w'))\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--installed", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if not NT and os.geteuid() != 0:
        raise SystemExit("run as root on Linux; workloads and queries run as --user")
    g = Gate(a.user, out)
    for _ in range(120):  # the service may still be attaching its collector
        st = g.api("status")
        if st.get("ok") and st["result"].get("collector_ready"):
            break
        time.sleep(1)
    else:
        raise SystemExit(f"the whyfs machine service is not ready: {st}")
    me = st["result"]["requester"]
    for pth in (Path.cwd(), g.home):
        for q in [pth, *pth.parents]:
            if (q / ".whyfs").is_dir():
                print(f"  note: {q} is an initialized workspace; the gate uses fresh directories outside it")
    base = g.mkdir(g.home / g.tag)
    t0 = time.time()

    # ---------------- A: no workspace initialized
    a_file = base / "notes" / "summary.txt"
    g.mkdir(a_file.parent)
    src = base / "notes" / "source.txt"
    src.write_text("alpha beta\n")
    if not NT and a.user and os.geteuid() == 0:
        subprocess.run(["chown", f"{a.user}:", str(src)], check=True)
    g.write_file(a_file, src)
    # ---------------- B: different directories
    b_dirs = {"desktop": g.home / "Desktop" / g.tag, "documents": g.home / "Documents" / g.tag,
              "source": g.home / "src" / g.tag / "app",
              "custom": (Path(r"C:\whyfs-gate-custom") if NT else Path("/srv/whyfs-gate-custom")) / g.tag}
    b_files = {}
    for k, d in b_dirs.items():
        g.mkdir(d)
        f = d / f"{k}-output.dat"
        g.write_file(f)
        b_files[k] = f
    # ---------------- C: rename / move to another directory
    c_src = g.mkdir(base / "c-from") / "moving.txt"
    g.write_file(c_src, src)
    c_dst = g.mkdir(base / "c-to") / "moved.txt"
    g.run([PY, "-c", "import os, sys; os.replace(sys.argv[1], sys.argv[2])", str(c_src), str(c_dst)])
    # ---------------- D: a normal application (Windows: launched outside the agent's tree)
    d_file = g.mkdir(base / "d-app") / "app-output.txt"
    g.write_file(d_file, src, via_wmi=NT)
    # ---------------- E, F, H: registered agent sessions
    wcmd = whyfs_cmd()
    agent_py = base / "gate_agent.py"
    agent_py.write_text(AGENT)
    gen = base / "gen.py"
    gen.write_text(GEN)
    e_dir, f_dir = g.mkdir(base / "e-agent"), g.mkdir(base / "f-agent-b")
    sid_a, sid_b, sid_h = (f"gate-{x}-{uuid.uuid4().hex[:8]}" for x in "abh")
    task_a = "Build the checkout redesign (gate task text, token=SECRETVAL_TASK)"
    q = (lambda p: f'"{p}"') if NT else (lambda p: f"'{p}'")
    script_a = [f"{q(PY)} {q(gen)} {q(e_dir / 'file.json')} {q(src)}"]
    g.run([PY, str(agent_py), json.dumps([wcmd, "GateAgent-A", sid_a, task_a, script_a])], cwd=e_dir)
    # F: agent B reads A's output and writes its own; no task text (H without intent)
    script_b = [f"{q(PY)} {q(gen)} {q(f_dir / 'b-out.json')} {q(e_dir / 'file.json')}"]
    g.run([PY, str(agent_py), json.dumps([wcmd, "GateAgent-B", sid_b, None, script_b])], cwd=f_dir)
    # ---------------- G: an unregistered, agent-like program (not a known agent install)
    # a native program *named* like an agent (claude), outside any agent install layout
    g_dir = g.mkdir(base / "g-unknown")
    fake = g_dir / ("claude.exe" if NT else "claude")
    csrc = g_dir / "fake.c"
    csrc.write_text('#include <stdio.h>\n'
                    'int main(int c, char **v) { FILE *f = fopen(v[1], "w"); '
                    'if (!f) return 1; fputs("u", f); fclose(f); return 0; }\n')
    if NT:
        vc = os.environ.get("WHYFS_VCVARS", r"C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat")
        subprocess.run(f'cmd /c ""{vc}" >nul && cl /nologo fake.c /Fe:claude.exe >nul"', cwd=g_dir, check=True, shell=True)
    else:
        subprocess.run(["gcc", "-O2", "-o", str(fake), str(csrc)], check=True)
        os.chmod(fake, 0o755)
    g_file = g_dir / "unknown.txt"
    if NT:
        g.wmi([str(fake), str(g_file)], cwd=g_dir)
    else:
        g.run([str(fake), str(g_file)], cwd=g_dir)
    # ---------------- secrets on command lines (machine store)
    s_file = g.mkdir(base / "s-secret") / "s.txt"
    g.run([PY, "-c", "import sys; open(sys.argv[1],'w').write('s')", str(s_file), "--password", "SECRETVAL_CMD",
           "API_KEY=SECRETVAL_KEY"], cwd=s_file.parent)
    # ---------------- P: another user's file (Linux: written by root)
    p_file = None
    if not NT and a.user:
        p_dir = Path("/srv/whyfs-gate-custom") / (g.tag + "-root")
        p_dir.mkdir(parents=True, exist_ok=True)
        p_file = p_dir / "root-made.txt"
        subprocess.run([PY, "-c", f"open('{p_file}','w').write('r')"], check=True)
    time.sleep(SETTLE)
    workload_s = time.time() - t0

    # ======================== checks
    def labelled(lb):
        return isinstance(lb, dict) and lb.get("status") == "labelled"

    la = g.label(a_file)
    g.check("A.no_init_file_is_labelled", labelled(la), la)
    g.check("A.creator_is_the_writing_process", labelled(la) and os.path.basename(la["created_by"]["exe"] or "").lower()
            .startswith("python"), la.get("created_by") if isinstance(la, dict) else la)
    g.check("A.user_recorded", labelled(la) and la.get("user") == me, (la.get("user"), me) if isinstance(la, dict) else la)
    g.check("A.input_recorded", labelled(la) and any(os.path.basename(p) == "source.txt" for p in la["inputs"]),
            la.get("inputs") if isinstance(la, dict) else la)
    g.check("A.file_identity_matches", labelled(la) and la["identity"]["check"] == "match", la.get("identity") if isinstance(la, dict) else la)
    g.check("A.no_workspace_store_created", not any((p / ".whyfs").exists() for p in [base, a_file.parent]))
    for k, f in b_files.items():
        lb = g.label(f)
        g.check(f"B.{k}_labelled", labelled(lb), lb if not labelled(lb) else None)
    lc = g.label(c_dst)
    g.check("C.moved_file_keeps_provenance", labelled(lc) and any(os.path.basename(r["from"]) == "moving.txt"
                                                                 for r in lc.get("renamed_from") or []), lc)
    g.check("C.original_writer_and_input_follow", labelled(lc) and os.path.basename(lc["created_by"]["exe"] or "")
            .lower().startswith("python") and any(os.path.basename(p) == "source.txt" for p in lc["inputs"]), lc)
    g.check("C.identity_follows_the_move", labelled(lc) and lc["identity"]["check"] == "match", lc.get("identity") if isinstance(lc, dict) else lc)
    g.check("C.old_path_not_labelled_as_existing", (g.label(c_src) or {}).get("exists") is False)
    ld = g.label(d_file)
    g.check("D.normal_app_labelled", labelled(ld), ld)
    g.check("D.no_agent_claimed", labelled(ld) and ld["agent"] is None, ld.get("agent") if isinstance(ld, dict) else ld)
    g.check("D.user_recorded", labelled(ld) and ld.get("user") == me)
    le = g.label(e_dir / "file.json")
    chain = [os.path.basename(c["exe"] or "?").lower() for c in (le.get("process_chain") or [])] if isinstance(le, dict) else []
    g.check("E.agent_output_labelled", labelled(le), le)
    g.check("E.actual_creator_is_the_generator", labelled(le) and "gen.py" in (le["created_by"]["command"] or ""),
            le.get("created_by") if isinstance(le, dict) else le)
    g.check("E.real_process_chain_kept", labelled(le) and len(chain) >= 3 and chain[-1].startswith("python")
            and any(c in ("sh", "bash", "dash", "cmd.exe") for c in chain), chain)
    g.check("E.session_attached", labelled(le) and (le.get("agent") or {}).get("session_id") == sid_a
            and le["agent"]["source"] == "registered" and le["agent"]["agent_name"] == "GateAgent-A", le.get("agent") if isinstance(le, dict) else le)
    g.check("E.evidence_says_both", labelled(le) and "OS-observed" in le["evidence"] and "registered agent" in le["evidence"])
    lf = g.label(f_dir / "b-out.json")
    g.check("F.second_agent_attributed_separately", labelled(lf) and (lf.get("agent") or {}).get("session_id") == sid_b, lf.get("agent") if isinstance(lf, dict) else lf)
    fa = g.api("get_files_by_agent", session_id=sid_a).get("result") or []
    fb = g.api("get_files_by_agent", session_id=sid_b).get("result") or []
    names_a = {os.path.basename(x["path"]) for x in fa}
    names_b = {os.path.basename(x["path"]) for x in fb}
    g.check("F.files_by_agent_do_not_merge", "file.json" in names_a and "b-out.json" in names_b
            and "b-out.json" not in names_a and "file.json" not in names_b, {"a": sorted(names_a), "b": sorted(names_b)})
    g.check("F.b_read_a_output_is_an_input_not_an_attribution", labelled(lf) and any(os.path.basename(p) == "file.json" for p in lf["inputs"]))
    sa = g.api("get_agent_session", session_id=sid_a).get("result") or {}
    g.check("F.sessions_ended_and_owned", sa.get("ended_ns") is not None and sa.get("user") == me, sa)
    lg = g.label(g_file)
    g.check("G.unregistered_program_os_provenance", labelled(lg) and lg["created_by"]["exe"].lower().endswith(fake.name), lg)
    g.check("G.agent_unknown_not_invented", labelled(lg) and lg["agent"] is None, lg.get("agent") if isinstance(lg, dict) else lg)
    sys.path.insert(0, str(REPO / "src"))
    from whyfs.redact import redact_text  # supplied text, with secrets redacted by the shared policy
    g.check("H.task_text_as_supplied", labelled(le) and (le.get("intent") or {}).get("task") ==
            redact_text(task_a) and "SECRETVAL" not in json.dumps(le.get("intent")) and "supplied by the agent" in le["intent"]["source"], le.get("intent") if isinstance(le, dict) else le)
    g.check("H.no_task_no_intent", labelled(lf) and lf["intent"]["task"] is None and "does not infer" in lf["intent"]["note"],
            lf.get("intent") if isinstance(lf, dict) else lf)
    ls = g.label(s_file)
    g.check("P.secret_command_redacted", labelled(ls) and "SECRETVAL" not in json.dumps(ls) and "<redacted>" in (ls["created_by"]["command"] or ""),
            ls.get("created_by") if isinstance(ls, dict) else ls)
    if p_file is not None:
        lp_user, lp_root = g.label(p_file), g.label(p_file, as_root=True)
        g.check("P.other_users_records_invisible", isinstance(lp_user, dict) and lp_user.get("status") == "no-record", lp_user)
        g.check("P.administrator_sees_all", labelled(lp_root), lp_root)
    # the store itself (read directly, as administrator): no secret anywhere
    from_store = _store_bytes()
    g.check("P.store_free_of_secrets", from_store is not None and b"SECRETVAL" not in from_store
            and "SECRETVAL".encode("utf-16-le") not in from_store, None if from_store is not None else "store unreadable")
    # the human label renders
    ex = g.api("explain_file", path=str(e_dir / "file.json"))
    txt = (ex.get("result") or {}).get("text", "")
    g.check("label_text_renders", all(k in txt for k in ("Created by:", "Process chain:", "Agent:", "Task:", "Why:", "Evidence:")), txt[:400])
    (out / "label_example.txt").write_text(txt, encoding="utf-8")
    st2 = g.api("status", as_root=True).get("result") or {}
    g.check("zero_loss", st2.get("lost") == 0, st2.get("collector_stats"))

    ok = all(g.checks.values())
    rep = {"platform": platform.platform(), "machine": platform.machine(), "installed": INSTALLED, "requester": me,
           "workload_s": round(workload_s, 2), "checks": g.checks, "failed": [k for k, v in g.checks.items() if not v],
           "detail": {k: v for k, v in g.detail.items() if not g.checks.get(k, True)},
           "store_status": {k: st2.get(k) for k in ("store_bytes", "visible", "collector_stats", "lost")},
           "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (out / "product_gate.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(f"product gate on {platform.system()} {platform.machine()}: {sum(g.checks.values())}/{len(g.checks)} checks")
    if ok:
        for p in [base, *b_dirs.values(), *( [p_file.parent] if p_file else [])]:
            shutil.rmtree(p, ignore_errors=True)
    return 0 if ok else 1


def _store_bytes() -> bytes | None:
    from_dir = (Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "whyfs" / "machine" / ".whyfs") if NT \
        else Path("/var/lib/whyfs/machine/.whyfs")
    try:
        return b"".join(p.read_bytes() for p in from_dir.iterdir() if p.is_file())
    except OSError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
