"""End-to-end Windows flow as an ordinary user (run via asuser.exe): no elevation anywhere.

init -> daemon start (service) -> workload -> daemon stop -> why / impact / history (CLI)."""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
env = dict(os.environ, PYTHONPATH=str(REPO / "src"))


def whyfs(*args, cwd):
    return subprocess.run([sys.executable, "-m", "whyfs", *args], cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8")


def main():
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    print("elevated:", admin)
    ws = Path(os.environ["TEMP"]) / "whyfs-e2e-user"
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir()
    print(whyfs("init", ".", cwd=ws).stdout.strip())
    r = whyfs("daemon", "start", cwd=ws)
    print("start:", r.returncode, (r.stdout + r.stderr).strip())
    time.sleep(1)
    (ws / "data.txt").write_text("3\n1\n2\n")
    subprocess.run(f'"{sys.executable}" -c "open(\'sorted.txt\',\'w\').writelines(sorted(open(\'data.txt\')))"', cwd=ws, shell=True)
    subprocess.run('cmd /c "type sorted.txt > report.txt"', cwd=ws, shell=True)
    time.sleep(0.5)
    r = whyfs("daemon", "status", "--json", cwd=ws)
    print("status running:", json.loads(r.stdout).get("running"))
    r = whyfs("daemon", "stop", cwd=ws)
    print("stop:", r.returncode, (r.stdout + r.stderr).strip())
    print(whyfs("why", "report.txt", cwd=ws).stdout)
    print(whyfs("impact", "data.txt", cwd=ws).stdout)
    print(whyfs("history", "sorted.txt", cwd=ws).stdout)
    s = json.loads(whyfs("stats", "--json", cwd=ws).stdout)
    print("stats:", {k: s.get(k) for k in ("events", "processes", "kernel_drops", "queue_drops", "user_unresolved", "late_records", "writer_failed")})
    print("store owner:", subprocess.run(["powershell", "-NoProfile", "-Command", f"(Get-Acl '{ws / '.whyfs' / 'whyfs.db'}').Owner"],
                                         capture_output=True, text=True).stdout.strip())


if __name__ == "__main__":
    main()
