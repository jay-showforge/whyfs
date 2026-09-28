"""Observation-integrity gate: the forced-outage scenario on the installed service.

  Linux:   sudo python3 scripts/outage_gate.py --user USER --out DIR
  Windows: python scripts\\outage_gate.py --out DIR            (elevated)

1. whyfs running; create File A; A's label is complete.
2. Kill the whole observer unexpectedly (Linux: SIGKILL to every process of whyfs.service;
   Windows: terminate the whyfs service process tree).  Nothing is restarted by this script.
3. Create File B while nothing is observing.
4. Wait for the OS service manager to recover the observer by itself (systemd Restart=,
   Windows service recovery actions) and for the collector to be ready again.
5. Create File C.
6. A: labelled, origin complete (the outage is listed as a later gap);
   B: no creator; explicitly incomplete, appeared while whyfs was not recording (after a crash);
   C: labelled, complete, no later gaps;
   the service reports the recorded gap; the human label explains it;
   the service is configured to start with the OS and to restart after a crash.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

NT = os.name == "nt"
SETTLE = 12.0 if NT else 4.0


def whyfs() -> list[str]:
    exe = shutil.which("whyfs") or (os.path.join(os.environ.get("ProgramFiles", ""), "whyfs", "whyfs.exe") if NT else "whyfs")
    return [exe]


class Gate:
    def __init__(self, user, out: Path):
        self.user, self.out = user, out
        self.checks: dict[str, bool] = {}
        self.detail: dict[str, object] = {}
        self.home = Path(os.path.expanduser(f"~{user}") if (user and not NT) else os.path.expanduser("~"))

    def as_user(self, argv):
        if not NT and self.user and os.geteuid() == 0:
            return ["runuser", "-u", self.user, "--", *argv]
        return argv

    def check(self, name, ok, detail=None):
        self.checks[name] = bool(ok)
        if detail is not None:
            self.detail[name] = detail
        print(f"  {'PASS' if ok else 'FAIL'} {name}" + ("" if ok else f"  {json.dumps(detail, default=str)[:600]}"))

    def api(self, op, **params):
        p = subprocess.run(self.as_user([*whyfs(), "api", op, json.dumps(params)]), capture_output=True, text=True)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": False, "error": (p.stdout + p.stderr).strip()[-400:]}

    def label(self, path):
        r = self.api("get_file_provenance", path=str(path))
        return r.get("result") if r.get("ok") else {"status": "error", "error": r.get("error")}

    def ready(self) -> bool:
        r = self.api("status")
        return bool(r.get("ok") and r["result"].get("collector_ready") and r["result"].get("collector_running"))

    def write(self, dst: Path, src: Path):
        code = "import sys; open(sys.argv[2],'w').write(open(sys.argv[1]).read().upper())"
        subprocess.run(self.as_user([sys.executable if NT else "python3", "-c", code, str(src), str(dst)]), check=True)


def observer_pids() -> list[int]:
    if NT:
        out = subprocess.run(["sc", "queryex", "whyfs"], capture_output=True, text=True).stdout
        pid = next((int(line.split(":")[1]) for line in out.splitlines() if "PID" in line), 0)
        return [pid] if pid else []
    out = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "whyfs.service"], capture_output=True, text=True).stdout
    return [int(out.strip())] if out.strip().isdigit() and int(out.strip()) else []


def kill_observer() -> dict:
    """Terminate the observer abruptly: no clean stop, no drain, no end-of-run record."""
    before = observer_pids()
    if NT:
        r = subprocess.run(["taskkill", "/F", "/T", "/PID", str(before[0])], capture_output=True, text=True) if before else None
        how = f"taskkill /F /T /PID {before[0]} (service process, its Python host and the collector)" if before else "no pid"
        rc = r.returncode if r else None
    else:
        r = subprocess.run(["systemctl", "kill", "--signal=SIGKILL", "whyfs.service"], capture_output=True, text=True)
        how, rc = "systemctl kill --signal=SIGKILL whyfs.service (every process of the unit)", r.returncode
    return {"pids_before": before, "how": how, "rc": rc, "at_ns": time.time_ns()}


def service_config() -> dict:
    if NT:
        q = subprocess.run(["sc", "qc", "whyfs"], capture_output=True, text=True).stdout
        f = subprocess.run(["sc", "qfailure", "whyfs"], capture_output=True, text=True).stdout
        return {"auto_start": "AUTO_START" in q, "restart_on_failure": "RESTART" in f.upper(),
                "sc_qc": q.strip().splitlines()[-8:], "sc_qfailure": f.strip().splitlines()[-4:]}
    en = subprocess.run(["systemctl", "is-enabled", "whyfs.service"], capture_output=True, text=True).stdout.strip()
    rs = subprocess.run(["systemctl", "show", "-p", "Restart", "--value", "whyfs.service"], capture_output=True, text=True).stdout.strip()
    wb = subprocess.run(["systemctl", "show", "-p", "WantedBy", "--value", "whyfs.service"], capture_output=True, text=True).stdout.strip()
    return {"auto_start": en == "enabled" and "multi-user.target" in wb, "restart_on_failure": rs in ("on-failure", "always"),
            "is_enabled": en, "Restart": rs, "WantedBy": wb}


def collector_pid(g: Gate) -> int | None:
    st = g.api("status").get("result") or {}
    try:
        return json.loads(Path(os.environ["ProgramData"], "whyfs", "machine", ".whyfs", "machine-ready.json")
                          .read_text())["collector_pid"]
    except (OSError, ValueError, KeyError):
        return st.get("collector_pid")


def windows_session_checks(g: Gate, base: Path, src: Path) -> None:
    """Windows: nothing else may silently blind the machine collector.
    1. An explicit workspace capture (whyfs init + daemon start/stop) runs through the same
       service; stopping it must not stop the machine collector's ETW sessions.
    2. If a session is stopped from outside anyway (logman), the collector must exit and be
       restarted -- never keep running without events."""
    ws = base / "workspace-capture"
    ws.mkdir()
    for args in (["init", "."], ["daemon", "start", "--workspace", str(ws)], ["daemon", "stop", "--workspace", str(ws)]):
        subprocess.run([*whyfs(), *args], cwd=ws, capture_output=True, text=True)
    time.sleep(2)
    d = base / "D.txt"
    g.write(d, src)
    time.sleep(SETTLE)
    ld = g.label(d)
    g.check("workspace_capture_does_not_blind_the_machine_collector", ld.get("status") == "labelled",
            {k: ld.get(k) for k in ("status", "note")})
    before = collector_pid(g)
    r = subprocess.run(["logman", "stop", "whyfs-machine", "-ets"], capture_output=True, text=True)
    t0 = time.monotonic()
    restarted = False
    while time.monotonic() - t0 < 120:
        pid = collector_pid(g)
        if pid and pid != before and g.ready():
            restarted = True
            break
        time.sleep(1)
    g.check("externally_stopped_session_restarts_the_collector", restarted,
            {"logman_rc": r.returncode, "pid_before": before, "pid_after": collector_pid(g),
             "after_s": round(time.monotonic() - t0, 1)})
    time.sleep(2)
    e = base / "E.txt"
    g.write(e, src)
    time.sleep(SETTLE)
    le = g.label(e)
    g.check("labels_resume_after_the_session_restart", le.get("status") == "labelled" and le["observation"]["complete"],
            {k: le.get(k) for k in ("status", "observation")})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    g = Gate(a.user, out)
    for _ in range(180):
        if g.ready():
            break
        time.sleep(1)
    else:
        raise SystemExit("the whyfs service is not ready")
    base = g.home / ("whyfs-outage-" + uuid.uuid4().hex[:8])
    base.mkdir()
    if not NT and a.user:
        subprocess.run(["chown", f"{a.user}:", str(base)], check=True)
    src = base / "input.txt"
    subprocess.run(g.as_user([sys.executable if NT else "python3", "-c",
                              f"open({str(src)!r},'w').write('observation integrity\\n')"]), check=True)
    fa, fb, fc = base / "A.txt", base / "B.txt", base / "C.txt"
    timeline: dict[str, object] = {}

    cfg = service_config()
    g.check("service_starts_with_the_os", cfg["auto_start"], cfg)
    g.check("service_restarts_after_a_crash", cfg["restart_on_failure"], cfg)

    # 1. A while observing
    g.write(fa, src)
    timeline["A_ns"] = time.time_ns()
    time.sleep(SETTLE)
    la = g.label(fa)
    g.check("A_complete_before_the_outage", la.get("status") == "labelled" and la["observation"]["complete"], la.get("observation"))

    # 2. kill the observer
    kill = kill_observer()
    timeline["kill"] = kill
    time.sleep(0.5)
    down = not g.ready()
    # 3. B while nothing observes
    g.write(fb, src)
    timeline["B_ns"] = time.time_ns()
    still_down = not g.ready()
    g.check("observer_was_down_when_B_appeared", down and still_down, {"down_after_kill": down, "down_after_B": still_down})

    # 4. automatic recovery (nothing is restarted here)
    t0 = time.monotonic()
    recovered = False
    while time.monotonic() - t0 < 300:
        if g.ready():
            recovered = True
            break
        time.sleep(1)
    timeline["recovered_after_s"] = round(time.monotonic() - t0, 1)
    after = observer_pids()
    g.check("observer_recovered_automatically", recovered and after and after != kill["pids_before"],
            {"after_s": timeline["recovered_after_s"], "pids_after": after, "pids_before": kill["pids_before"]})

    # 5. C after recovery
    time.sleep(2)
    g.write(fc, src)
    timeline["C_ns"] = time.time_ns()
    time.sleep(SETTLE)

    # 6. the three labels, and the recorded gap
    la, lb, lc = g.label(fa), g.label(fb), g.label(fc)
    oa, ob, oc = la.get("observation") or {}, lb.get("observation") or {}, lc.get("observation") or {}
    g.check("A_labelled_with_complete_origin", la.get("status") == "labelled" and oa.get("complete") is True, oa)
    g.check("A_lists_the_outage_as_a_later_gap", any("stopped unexpectedly" in x for x in oa.get("later_gaps") or []), oa)
    g.check("B_has_no_fabricated_creator", lb.get("status") in ("no-record", "not-observed") and "created_by" not in lb,
            {k: lb.get(k) for k in ("status", "created_by", "note")})
    g.check("B_explicitly_incomplete", ob.get("complete") is False and bool(ob.get("gaps")), ob)
    gap = ob.get("file_time_in_gap") or {}
    g.check("B_appeared_during_the_recorded_gap", bool(gap) and gap.get("after_crash") is True, ob)
    g.check("C_labelled_complete_after_recovery", lc.get("status") == "labelled" and oc.get("complete") is True
            and not oc.get("later_gaps"), oc)
    st = g.api("status").get("result") or {}
    gaps = st.get("recording_gaps") or []
    g.check("service_reports_the_gap", any(x.get("after_crash") for x in gaps[:3]), gaps[:3])
    txt = subprocess.run(g.as_user([*whyfs(), "label", str(fb)]), capture_output=True, text=True).stdout
    g.check("human_label_explains_B", "not recording" in txt and "origin was not observed" in txt, txt[-600:])
    (out / "label_B.txt").write_text(txt, encoding="utf-8")
    (out / "labels.json").write_text(json.dumps({"A": la, "B": lb, "C": lc}, indent=1, default=str), encoding="utf-8")

    if NT:
        windows_session_checks(g, base, src)

    ok = all(g.checks.values())
    rep = {"platform": platform.platform(), "machine": platform.machine(), "checks": g.checks,
           "failed": [k for k, v in g.checks.items() if not v], "detail": g.detail, "timeline": timeline,
           "service_config": cfg, "recording_gaps": gaps[:5], "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (out / "outage_gate.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(f"outage gate on {platform.system()} {platform.machine()}: {sum(g.checks.values())}/{len(g.checks)} checks")
    if ok:
        shutil.rmtree(base, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
