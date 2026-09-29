"""Exact-artifact tests of the macOS package, on a disposable Mac (a CI runner), as root:

  sudo python3 packaging/macos/test_pkg.py --pkg A.pkg --pkg-upgrade B.pkg --user USER --out DIR

Install, files and ownership, architecture, the launchd job (RunAtLoad, KeepAlive, loaded,
running), the Endpoint Security client, the command, a live label, the WhyFS window (launch
link, page, API), the Finder Quick Actions (lint, run by `automator`, the same command
Finder runs), WhyFS.app, upgrade (store kept), uninstall (store kept), reinstall (earlier labels
back), purge.  Results: pkg_test.json.

Full Disk Access: an Endpoint Security client runs only after the user grants it Full Disk
Access in System Settings.  When the client is refused for that reason alone (ERR_NOT_PERMITTED),
this test makes the same grant in the system TCC database (possible here: SIP is off on CI
runners) and records that it did so.  It never makes that grant silently.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import plistlib
import pwd
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

LABEL = "org.tenzorpipe.whyfs"
IDENT = "org.tenzorpipe.whyfs"
LIB = Path("/Library/WhyFS")
COLLECTOR_APP = LIB / "WhyFSCollector.app"
COLLECTOR = COLLECTOR_APP / "Contents" / "MacOS" / "whyfs-collect"
PLIST = Path(f"/Library/LaunchDaemons/{LABEL}.plist")
STORE = Path("/Library/Application Support/WhyFS/machine")
ES_STATE = STORE / ".whyfs" / "endpoint-security.json"
TCC_DB = Path("/Library/Application Support/com.apple.TCC/TCC.db")


def sh(cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


class T:
    def __init__(self, user: str, out: Path):
        self.user, self.out = user, out
        pw = pwd.getpwnam(user)
        self.uid, self.gid, self.home = pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)
        self.checks: dict[str, bool] = {}
        self.detail: dict[str, object] = {}
        self.notes: list[str] = []

    def check(self, name, ok, detail=None):
        self.checks[name] = bool(ok)
        if detail is not None:
            self.detail[name] = detail
        print(f"  {'PASS' if ok else 'FAIL'} {name}" + ("" if ok else f"  {json.dumps(detail, default=str)[:800]}"), flush=True)
        return ok

    def as_user(self, cmd, env=None, **kw):
        e = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(self.home), "USER": self.user, **(env or {})}
        return subprocess.run([str(c) for c in cmd], user=self.uid, group=self.gid, env=e, capture_output=True,
                              text=True, **kw)

    def whyfs_json(self, *args):
        p = self.as_user(["/usr/local/bin/whyfs", *args, "--json"])
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"error": (p.stdout + p.stderr)[-600:]}

    def api(self, op, **params):
        p = self.as_user(["/usr/local/bin/whyfs", "api", op, json.dumps(params)])
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"ok": False, "error": (p.stdout + p.stderr)[-600:]}


def job() -> dict:
    p = sh(["launchctl", "print", f"system/{LABEL}"])
    d = {"loaded": p.returncode == 0}
    for line in p.stdout.splitlines():
        s = line.strip()
        if s.startswith("state = "):
            d["state"] = s.split("=", 1)[1].strip()
        elif s.startswith("pid = "):
            d["pid"] = int(s.split("=", 1)[1])
    return d


def es_state() -> dict | None:
    try:
        return json.loads(ES_STATE.read_text())
    except (OSError, ValueError):
        return None


def wait(pred, timeout=120, step=1.0):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return pred()


def grant_full_disk_access() -> dict:
    """What a user does in System Settings > Privacy & Security > Full Disk Access, written to the
    system TCC database: the WhyFS collector app (by bundle identifier and by path)."""
    con = sqlite3.connect(TCC_DB)
    cols = [r[1] for r in con.execute("PRAGMA table_info(access)")]
    now = int(time.time())
    rows = []
    for client, ctype in (("org.tenzorpipe.whyfs.collector", 0), (str(COLLECTOR), 1)):
        v = {"service": "kTCCServiceSystemPolicyAllFiles", "client": client, "client_type": ctype, "auth_value": 2,
             "auth_reason": 4, "auth_version": 1, "csreq": None, "policy_id": None, "indirect_object_identifier_type": 0,
             "indirect_object_identifier": "UNUSED", "indirect_object_code_identity": None, "flags": 0,
             "last_modified": now, "pid": None, "pid_version": None, "boot_uuid": "UNUSED", "last_reminded": now}
        vals = [v.get(c) for c in cols]
        con.execute(f"INSERT OR REPLACE INTO access({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)
        rows.append(client)
    con.commit()
    con.close()
    sh(["killall", "tccd"])  # reload the database
    return {"granted_to": rows, "columns": cols}


def quick_action_probe(t: T, target: Path) -> dict:
    """A diagnostic Quick Action built exactly like the shipped ones (build_pkg.workflow), whose
    script records its arguments and environment: what a WhyFS Quick Action receives."""
    import tempfile
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from build_pkg import workflow
    dump = t.home / f".whyfs-qa-probe-{os.getpid()}.txt"
    info, doc = workflow("probe", f'{{ echo "ARGS:$*"; env; }} > "{dump}"\n', folders=False)
    d = Path(tempfile.mkdtemp()) / "probe.workflow" / "Contents"
    d.mkdir(parents=True)
    with open(d / "Info.plist", "wb") as f:
        plistlib.dump(info, f)
    with open(d / "document.wflow", "wb") as f:
        plistlib.dump(doc, f)
    os.chmod(d.parents[1], 0o755)
    r = t.as_user(["/usr/bin/automator", "-i", target, d.parent], env={"WHYFS_UI_BROWSER": "none", "WHYFS_PROBE": "1"},
                  timeout=120)
    text = dump.read_text() if dump.exists() else ""
    dump.unlink(missing_ok=True)
    return {"rc": r.returncode, "ran": bool(text), "args": next((x[5:] for x in text.splitlines() if x.startswith("ARGS:")), None),
            "caller_env_passed": "WHYFS_PROBE=1" in text, "env_keys": sorted({x.split("=", 1)[0] for x in text.splitlines()
                                                                               if "=" in x and not x.startswith("ARGS:")})}


def ui_roundtrip(t: T, target: Path) -> dict:
    """The WhyFS window: `whyfs ui --file F` (headless) hands over a one-time launch link; the
    page and its API then answer as a browser would see them."""
    t.as_user(["/usr/local/bin/whyfs", "ui", "--file", target], env={"WHYFS_UI_BROWSER": "none"})
    url_file = t.home / ".cache" / "whyfs" / "last-launch.url"
    url = url_file.read_text().strip() if url_file.exists() else ""
    res = {"url": url.split("?")[0]}
    if not url:
        return res
    jar = http.cookiejar.CookieJar()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect)
    try:
        op.open(url, timeout=10)
    except urllib.error.HTTPError as e:
        res["launch_status"] = e.code
        res["location"] = e.headers.get("Location")
    base = url.split("/launch")[0]
    with op.open(base + "/", timeout=10) as r:
        res["page_status"], res["page_is_whyfs"] = r.status, b"WhyFS" in r.read()
    req = urllib.request.Request(base + "/api", method="POST", headers={"X-Whyfs": "1", "Content-Type": "application/json"},
                                 data=json.dumps({"op": "get_file_provenance", "params": {"path": str(target)}}).encode())
    with op.open(req, timeout=20) as r:
        reply = json.loads(r.read())
    res["api_status"] = (reply.get("result") or {}).get("status")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pkg", required=True)
    ap.add_argument("--pkg-upgrade", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    t = T(a.user, out)
    arch = os.uname().machine

    # ------------------------------------------------ install
    p = sh(["installer", "-pkg", a.pkg, "-target", "/"])
    (out / "install.log").write_text(p.stdout + p.stderr)
    t.check("install_succeeds", p.returncode == 0, p.stderr[-800:])
    info = sh(["pkgutil", "--pkg-info", IDENT]).stdout
    t.check("receipt_recorded", "version:" in info, info)
    must = [COLLECTOR, LIB / "bin" / "whyfs", LIB / "runtime" / "bin" / "python3", LIB / "scope-default.conf",
            LIB / "uninstall.sh", LIB / "LICENSE", LIB / "THIRD_PARTY_NOTICES.txt", PLIST, Path("/usr/local/bin/whyfs"),
            Path("/Applications/WhyFS.app/Contents/MacOS/WhyFS")]
    missing = [str(m) for m in must if not m.exists()]
    t.check("files_installed", not missing, missing)
    loose = []
    for base in (LIB, PLIST, Path("/Applications/WhyFS.app")):
        for f in ([base] if base.is_file() else [base, *base.rglob("*")]):
            st = os.lstat(f)
            if st.st_uid != 0 or (st.st_mode & 0o022 and not os.path.islink(f)):
                loose.append(str(f))
    t.check("installed_files_root_owned_not_writable_by_others", not loose, loose[:20])
    lic = (LIB / "LICENSE").read_text()
    t.check("license_installed", "Business Source License 1.1" in lic and "Change Date:          2030-09-28" in lic)
    arches = {str(f): sh(["lipo", "-archs", f]).stdout.strip() for f in (COLLECTOR, LIB / "runtime" / "bin" / "python3.12")
              if f.exists()}
    t.check("native_architecture", all(v == arch for v in arches.values()) and len(arches) == 2, arches)
    pl = plistlib.loads(PLIST.read_bytes())
    t.check("service_starts_with_the_os", pl.get("RunAtLoad") is True, pl)
    t.check("service_restarts_after_a_crash", pl.get("KeepAlive") is True, pl)
    t.check("launchd_program_is_the_collector", pl["ProgramArguments"][0] == str(COLLECTOR), pl["ProgramArguments"])
    lint = {str(f): sh(["plutil", "-lint", f]).returncode for f in [PLIST, *Path("/Library/Services").glob("WhyFS - *.workflow/Contents/*"),
                                                                   Path("/Applications/WhyFS.app/Contents/Info.plist"),
                                                                   COLLECTOR_APP / "Contents" / "Info.plist"]}
    t.check("property_lists_valid", len(lint) >= 13 and not any(lint.values()), lint)
    j = wait(lambda: job().get("state") == "running" and job(), 60)
    t.check("service_running_after_install", bool(j), job())

    # ------------------------------------------------ Endpoint Security
    es = wait(es_state, 90)
    t.detail["es_first"] = es
    fda = None
    if es and es.get("result") == "ERR_NOT_PERMITTED":
        fda = grant_full_disk_access()
        t.notes.append("Endpoint Security was refused for Full Disk Access (ERR_NOT_PERMITTED); the test granted it "
                       "in the TCC database, as a user does in System Settings")
        ES_STATE.unlink(missing_ok=True)
        sh(["launchctl", "kickstart", "-k", f"system/{LABEL}"])
        es = wait(lambda: (s := es_state()) and s, 90)
    t.detail["es_after"] = es
    t.detail["full_disk_access"] = fda
    es_ok = bool(es and es.get("result") == "SUCCESS")
    t.check("endpoint_security_client_running", es_ok, es)
    blocked = bool(es and es.get("result") in ("ERR_NOT_ENTITLED",))
    ready = wait(lambda: (t.api("status").get("result") or {}).get("collector_ready"), 90) if es_ok else False
    t.check("collector_ready", bool(ready), t.api("status"))

    # ------------------------------------------------ the command and a live label
    work = t.home / f"whyfs-pkgtest-{os.getpid()}"
    t.as_user(["/bin/mkdir", "-p", work])
    work = Path(sh(["/usr/bin/python3", "-c", "import os,sys; print(os.path.realpath(sys.argv[1]))", work]).stdout.strip())
    t.as_user(["/bin/sh", "-c", f"cd '{work}' && echo 'x,y' > in.csv && /usr/bin/awk '{{print toupper($0)}}' in.csv > out.txt"])
    time.sleep(3)
    ver = t.as_user(["/usr/local/bin/whyfs", "--version"]).stdout.strip()
    t.check("command_runs", ver.startswith("whyfs "), ver)
    lb = wait(lambda: (x := t.whyfs_json("label", work / "out.txt")).get("status") == "labelled" and x, 30) \
        or t.whyfs_json("label", work / "out.txt")
    t.detail["label_out"] = lb
    t.check("live_label_names_the_creator", os.path.basename((lb.get("created_by") or {}).get("exe") or "") == "awk", lb)
    t.check("live_label_names_the_input", str(work / "in.csv") in (lb.get("inputs") or []), lb.get("inputs"))
    txt = t.as_user(["/usr/local/bin/whyfs", "label", work / "out.txt"]).stdout
    t.check("human_label", "awk" in txt, txt[-600:])

    # ------------------------------------------------ the WhyFS window, Quick Actions, WhyFS.app
    ui = ui_roundtrip(t, work / "out.txt")
    t.check("whyfs_window_answers", ui.get("launch_status") == 303 and ui.get("page_status") == 200 and ui.get("page_is_whyfs")
            and ui.get("api_status") == "labelled", ui)
    url_file = t.home / ".cache" / "whyfs" / "last-launch.url"
    # Automator runs a Run Shell Script action in a helper launched in the user's launchd session,
    # not with the caller's environment: the headless switch goes into that session (as Finder's
    # own launches would see it), and a diagnostic workflow records what the action receives.
    t.detail["quick_action_environment"] = quick_action_probe(t, work / "out.txt")
    sh(["launchctl", "asuser", str(t.uid), "sudo", "-u", t.user, "launchctl", "setenv", "WHYFS_UI_BROWSER", "none"])
    qa = {}
    for wf in sorted(Path("/Library/Services").glob("WhyFS - *.workflow")):
        url_file.unlink(missing_ok=True)
        r = t.as_user(["/usr/bin/automator", "-i", work / "out.txt", wf], env={"WHYFS_UI_BROWSER": "none"}, timeout=120)
        wait(url_file.exists, 20, 0.2)
        url = url_file.read_text() if url_file.exists() else ""
        qa[wf.name] = {"rc": r.returncode, "stderr": r.stderr[-300:], "url_params": url.split("?", 1)[-1].split("&", 1)[-1]}
    sh(["launchctl", "asuser", str(t.uid), "sudo", "-u", t.user, "launchctl", "unsetenv", "WHYFS_UI_BROWSER"])
    want = {"WhyFS - Why does this file exist.workflow": "file=", "WhyFS - What created this file.workflow": "view=created",
            "WhyFS - What depends on this file.workflow": "view=impact", "WhyFS - Show WhyFS history.workflow": "view=history",
            "WhyFS - Search WhyFS.workflow": "path="}
    t.check("quick_actions_installed", sorted(qa) == sorted(want), sorted(qa))
    t.check("quick_actions_run_the_whyfs_window", all(qa.get(k, {}).get("rc") == 0 and v in qa.get(k, {}).get("url_params", "")
                                                      for k, v in want.items()), qa)
    url_file.unlink(missing_ok=True)
    r = t.as_user(["/Applications/WhyFS.app/Contents/MacOS/WhyFS"], env={"WHYFS_UI_BROWSER": "none"})
    t.check("whyfs_app_opens_the_window", r.returncode == 0 and url_file.exists(), r.stderr[-300:])

    # ------------------------------------------------ upgrade
    def events_total():
        try:
            c = sqlite3.connect(f"file:{STORE / '.whyfs' / 'whyfs.db'}?mode=ro", uri=True)
            n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            c.close()
            return n
        except sqlite3.Error:
            return -1
    before_n, before_pid = events_total(), job().get("pid")
    p = sh(["installer", "-pkg", a.pkg_upgrade, "-target", "/"])
    (out / "upgrade.log").write_text(p.stdout + p.stderr)
    t.check("upgrade_succeeds", p.returncode == 0, p.stderr[-800:])
    t.check("upgrade_receipt", sh(["pkgutil", "--pkg-info", IDENT]).stdout != info, sh(["pkgutil", "--pkg-info", IDENT]).stdout)
    j2 = wait(lambda: job().get("state") == "running" and job(), 60)
    t.check("service_running_after_upgrade", bool(j2) and j2.get("pid") != before_pid, {"before": before_pid, "after": job()})
    wait(lambda: (t.api("status").get("result") or {}).get("collector_ready"), 90)
    t.check("store_kept_on_upgrade", events_total() >= before_n > 0, {"before": before_n, "after": events_total()})
    t.check("labels_survive_upgrade", t.whyfs_json("label", work / "out.txt").get("status") == "labelled")

    # ------------------------------------------------ uninstall (store kept), reinstall, purge
    p = sh([LIB / "uninstall.sh"])
    t.check("uninstall_succeeds", p.returncode == 0, p.stdout + p.stderr)
    left = [str(x) for x in (LIB, PLIST, Path("/usr/local/bin/whyfs"), Path("/Applications/WhyFS.app"),
                             *Path("/Library/Services").glob("WhyFS - *.workflow")) if os.path.lexists(x)]
    t.check("uninstall_removes_the_program", not left and not job()["loaded"], {"left": left, "job": job()})
    t.check("uninstall_keeps_the_store", (STORE / ".whyfs" / "whyfs.db").exists())
    t.check("uninstall_forgets_the_receipt", IDENT not in sh(["pkgutil", "--pkgs"]).stdout)
    p = sh(["installer", "-pkg", a.pkg_upgrade, "-target", "/"])
    t.check("reinstall_succeeds", p.returncode == 0, p.stderr[-800:])
    wait(lambda: (t.api("status").get("result") or {}).get("collector_ready"), 120)
    t.check("earlier_labels_back_after_reinstall", t.whyfs_json("label", work / "out.txt").get("status") == "labelled")
    p = sh([LIB / "uninstall.sh", "--purge"])
    t.check("purge_removes_the_store", p.returncode == 0 and not STORE.parent.exists(), p.stdout + p.stderr)
    shutil.rmtree(work, ignore_errors=True)

    rep = {"arch": arch, "macos": sh(["sw_vers", "-productVersion"]).stdout.strip(), "pkg": Path(a.pkg).name,
           "pkg_upgrade": Path(a.pkg_upgrade).name, "checks": t.checks,
           "failed": [k for k, v in t.checks.items() if not v], "detail": t.detail, "notes": t.notes,
           "endpoint_security": "BLOCKED_EXTERNAL" if blocked else ("PASS" if es_ok else "FAIL")}
    (out / "pkg_test.json").write_text(json.dumps(rep, indent=1, default=str))
    print(f"pkg test on macOS {rep['macos']} {arch}: {sum(t.checks.values())}/{len(t.checks)} checks")
    return 0 if all(t.checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
