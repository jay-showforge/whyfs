"""Live Endpoint Security test of the macOS collector (run as root: sudo python3 scripts/macos_live_es.py).

The collector (built here, ad-hoc signed with the Endpoint Security entitlement unless --binary
is given) creates a real Endpoint Security client and records a real workload run as the
invoking user (SUDO_UID) in a directory in that user's home.  The shared label code then reads
the store.  The live capture (--es-record) is replayed and must give the same records.

Verdict (live_es.json):
  PASS              the client started, received real events, and every check held
  BLOCKED_EXTERNAL  es_new_client refused (ERR_NOT_ENTITLED / ERR_NOT_PERMITTED): Apple's
                    entitlement or a Full Disk Access grant is missing; not a product result
  FAIL              the client ran, and a check failed (a product defect)
Environment facts that qualify a PASS (SIP state, signing) are recorded with it.
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from whyfs import macos  # noqa: E402
from whyfs.scope import defaults_text  # noqa: E402
from whyfs.store import connect  # noqa: E402


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--binary", help="use this collector as is (no build, no signing)")
    a = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run as root (sudo): an Endpoint Security client needs root")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    uid = int(os.environ.get("SUDO_UID", "0"))
    gid = int(os.environ.get("SUDO_GID", "0"))
    home = Path(pwd.getpwuid(uid).pw_dir)
    result: dict = {"checks": {}, "env": {
        "uname_m": os.uname().machine, "macos": sh(["sw_vers", "-productVersion"]).stdout.strip(),
        "sip": sh(["csrutil", "status"]).stdout.strip(), "user_uid": uid}}

    bindir = Path(tempfile.mkdtemp(prefix="whyfs-live-bin-"))
    os.chmod(bindir, 0o755)
    if a.binary:
        binary = Path(a.binary)
        result["env"]["signing"] = "as given"
    else:
        binary = macos.build_collector(bindir / "whyfs-collect", sign="-")
        result["env"]["signing"] = "ad hoc, with com.apple.developer.endpoint-security.client"
    result["env"]["binary_arch"] = sh(["lipo", "-archs", str(binary)]).stdout.strip()
    result["env"]["codesign"] = sh(["codesign", "-dv", "--entitlements", "-", str(binary)]).stderr.strip()[-600:]

    # the writer refuses a store path through a symbolic link (SQLITE_OPEN_NOFOLLOW): /var is one
    root = Path(macos.true_path(tempfile.mkdtemp(prefix="whyfs-live-store-")))
    os.chmod(root, 0o700)
    con = connect(root)
    con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES(?,?,?,?,?,?)",
                ("live", time.time_ns(), str(root), "live test", str(root), "es-native"))
    con.commit()
    con.close()
    scope = root / "scope-default.conf"
    scope.write_text(defaults_text(False, True))
    cap = out / "live-capture.jsonl"
    if cap.exists():
        cap.unlink()
    col = subprocess.Popen([str(binary), "--es", "--machine", "--scope", str(scope), "--root", str(root),
                            "--run-id", "live", "--es-record", str(cap)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first = col.stdout.readline()
    try:
        hello = json.loads(first) if first.strip() else {}
    except ValueError:
        hello = {"raw": first}
    result["es_new_client"] = hello.get("name") or ("SUCCESS" if hello.get("ready") else None)
    if not hello.get("ready"):
        col.wait(timeout=30)
        result["collector_exit"] = col.returncode
        result["collector_stderr"] = col.stderr.read()[-2000:]
        if hello.get("name") in ("ERR_NOT_ENTITLED", "ERR_NOT_PERMITTED"):
            result["verdict"] = "BLOCKED_EXTERNAL"
            result["reason"] = f"es_new_client: {hello.get('name')} (Apple Endpoint Security entitlement / Full Disk Access)"
        else:
            result["verdict"] = "FAIL"
            result["reason"] = f"collector did not start: {hello or first!r}"
        (out / "live_es.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] == "BLOCKED_EXTERNAL" else 1

    # ---------------- the workload, as the user, in the user's home (in scope by default)
    work = Path(tempfile.mkdtemp(prefix="whyfs-live-", dir=home))
    os.chown(work, uid, gid)
    work = Path(macos.true_path(str(work)))

    def as_user(cmd, **kw):
        return subprocess.run(cmd, cwd=work, user=uid, group=gid, check=True, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(home)}, **kw)
    time.sleep(1.0)
    as_user(["/bin/sh", "-c", "printf 'a,b\\n1,2\\n' > input.csv"])
    as_user(["/usr/bin/python3", "-c",
             "d=open('input.csv').read(); open('report.txt','w').write(d.upper())", "--token", "LIVESECRET123"])
    as_user(["/bin/sh", "-c", "cat report.txt > published.txt"])
    as_user(["/bin/mv", "published.txt", "final.txt"])
    as_user(["/bin/cp", "-c", "final.txt", "cloned.txt"])      # clonefile (APFS)
    as_user(["/bin/cp", "final.txt", "copied.txt"])
    as_user(["/bin/sh", "-c", "echo one > reused.txt"])
    as_user(["/bin/rm", "reused.txt"])
    as_user(["/usr/bin/python3", "-c", "open('reused.txt','w').write('two')"])
    as_user(["/bin/sh", "-c", "echo gone > scratch.txt; rm scratch.txt"])
    time.sleep(2.0)

    col.send_signal(signal.SIGTERM)
    try:
        col.wait(timeout=120)
    except subprocess.TimeoutExpired:
        col.kill()
        col.wait()
    rest = col.stdout.read().strip().splitlines()
    stats = json.loads(rest[-1]) if rest else {}
    result["collector_exit"] = col.returncode
    result["stats"] = stats
    result["stderr_tail"] = col.stderr.read()[-2000:]
    con = connect(root)
    con.execute("UPDATE runs SET ended_ns=? WHERE id='live'", (time.time_ns(),))
    con.commit()

    from whyfs.label import explain_file

    def label(name):
        return explain_file(con, str(work / name))
    labels = {n: label(n) for n in ("input.csv", "report.txt", "final.txt", "cloned.txt", "copied.txt", "reused.txt")}
    (out / "live-labels.json").write_text(json.dumps(labels, indent=2, default=str))
    rows = [dict(r) for r in con.execute("SELECT e.kind, e.path, e.path2, e.is_read, e.is_write, e.api, e.file_id, p.exe, "
                                         "p.command, p.user FROM events e LEFT JOIN processes p ON p.run_id=e.run_id "
                                         "AND p.pid=e.pid WHERE e.path LIKE ? OR e.path2 LIKE ? ORDER BY e.id",
                                         (str(work) + "/%", str(work) + "/%"))]
    (out / "live-events.json").write_text(json.dumps(rows, indent=2))
    c = result["checks"]

    def by(name):
        return labels[name]

    def exe(name):
        return (by(name).get("created_by") or {}).get("exe")
    c["events_received"] = stats.get("received", 0) > 0
    c["report_created_by_python"] = by("report.txt").get("status") == "labelled" and "python" in (exe("report.txt") or "")
    c["report_input_is_input_csv"] = str(work / "input.csv") in (by("report.txt").get("inputs") or [])
    c["report_identity_match"] = (by("report.txt").get("identity") or {}).get("check") == "match"
    c["final_moved_from_published"] = str(work / "published.txt") in json.dumps(by("final.txt").get("renamed_from"))
    c["final_created_by_shell"] = os.path.basename(exe("final.txt") or "") in ("sh", "bash", "zsh", "cat")
    c["clone_labelled"] = by("cloned.txt").get("status") == "labelled" and os.path.basename(exe("cloned.txt") or "") == "cp"
    c["copy_labelled"] = by("copied.txt").get("status") == "labelled" and os.path.basename(exe("copied.txt") or "") == "cp"
    c["reused_path_is_the_second_writer"] = "python" in (exe("reused.txt") or "")
    c["report_dependents_include_final"] = str(work / "final.txt") in json.dumps(by("report.txt").get("dependents"))
    # nothing persisted in the evidence store holds the secret (the --es-record capture is a raw
    # diagnostic, owner-only, like Linux --record)
    dump = "\n".join(con.iterdump())
    c["secret_redacted_in_store"] = "LIVESECRET123" not in dump and any("--token" in (r.get("command") or "") for r in rows)
    c["capture_owner_only"] = (cap.stat().st_mode & 0o077) == 0
    c["user_attributed"] = all((r.get("user") in (f"uid:{uid}", None)) for r in rows if r["is_write"])
    c["no_loss"] = stats.get("kernel_drops", 0) == 0 and stats.get("queue_drops", 0) == 0
    c["unlinked_recorded"] = any(r["kind"] == "unlink" and r["path"] == str(work / "scratch.txt") for r in rows)
    # the capture replays to the records the live run stored (the replay boundary is faithful)
    rp = subprocess.run([str(binary), "--es-replay", str(cap), "--machine", "--scope", str(scope), "--root", str(root),
                         "--run-id", "live", "--emit"], capture_output=True, text=True)
    rec = [json.loads(x) for x in rp.stdout.splitlines()[:-1]]
    replayed = sorted((r["kind"], bytes.fromhex(r["path"]).decode("utf-8", "replace") if r.get("path") else None,
                       r.get("api")) for r in rec if r["kind"] != "process")
    stored = sorted((r["kind"], r["path"], r["api"]) for r in
                    [dict(x) for x in con.execute("SELECT kind, path, api FROM events WHERE run_id='live'")])
    c["capture_replays_to_the_stored_records"] = replayed == stored
    result["replay_vs_store"] = {"replayed": len(replayed), "stored": len(stored)}
    con.close()
    result["verdict"] = "PASS" if all(c.values()) else "FAIL"
    result["work_dir"] = str(work)
    (out / "live_es.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    shutil.rmtree(bindir, ignore_errors=True)
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
