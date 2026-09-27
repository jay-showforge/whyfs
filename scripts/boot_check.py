"""After an OS boot, with no user action: whyfs is running, recording, and the time the machine
was down is a recorded gap.  Run as root (Linux) / elevated (Windows) right after boot.

  sudo python3 scripts/boot_check.py --user USER --out DIR --shutdown-at-ns NS
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from outage_gate import Gate, SETTLE, service_config  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--user", default=os.environ.get("SUDO_USER"))
    ap.add_argument("--shutdown-at-ns", type=int, required=True, help="when the OS was shut down")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    g = Gate(a.user, out)
    boot = {}
    if os.name != "nt":
        boot["uptime_s"] = float(open("/proc/uptime").read().split()[0])
        boot["whyfs_active"] = subprocess.run(["systemctl", "is-active", "whyfs.service"], capture_output=True, text=True).stdout.strip()
        boot["started_by"] = subprocess.run(["systemctl", "show", "-p", "ActiveEnterTimestamp,NRestarts", "whyfs.service"],
                                            capture_output=True, text=True).stdout.strip().splitlines()
    t0 = time.monotonic()
    while time.monotonic() - t0 < 300 and not g.ready():
        time.sleep(1)
    boot["ready_after_check_start_s"] = round(time.monotonic() - t0, 1)
    cfg = service_config()
    g.check("service_configured_to_start_with_the_os", cfg["auto_start"], cfg)
    g.check("recording_after_boot_without_user_action", g.ready(), boot)
    st = g.api("status").get("result") or {}
    gaps = st.get("recording_gaps") or []
    g.check("shutdown_is_a_recorded_gap", any(x.get("to") and x.get("from") for x in gaps[:3]) and bool(gaps), gaps[:3])
    f = g.home / f"whyfs-after-boot-{int(time.time())}.txt"
    subprocess.run(g.as_user([sys.executable if os.name == "nt" else "python3", "-c",
                              f"open({str(f)!r},'w').write('after boot')"]), check=True)
    time.sleep(SETTLE)
    lb = g.label(f)
    g.check("file_after_boot_labelled_complete", lb.get("status") == "labelled" and (lb.get("observation") or {}).get("complete"),
            lb.get("observation"))
    try:
        f.unlink()
    except OSError:
        pass
    rep = {"platform": platform.platform(), "checks": g.checks, "failed": [k for k, v in g.checks.items() if not v],
           "detail": g.detail, "boot": boot, "service_config": cfg, "recording_gaps": gaps[:5],
           "shutdown_at_ns": a.shutdown_at_ns}
    (out / "boot_check.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    print(f"boot check on {platform.system()} {platform.machine()}: {sum(g.checks.values())}/{len(g.checks)} checks")
    return 0 if all(g.checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
