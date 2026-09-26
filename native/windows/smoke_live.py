"""Live smoke test of the Windows collector (run elevated): workload -> collector -> why/impact."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from whyfs.query import impact, why  # noqa: E402
from whyfs.store import connect  # noqa: E402

EXE = Path(os.environ.get("WHYFS_COLLECT_WIN", r"C:\Users\ftmon\whyfs-win-build\whyfs-collect-win.exe"))
SQLITE = Path(sys.base_prefix) / "DLLs" / "sqlite3.dll"
VCVARS = r"C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat"


def user_sid() -> str:
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    return out.strip().split(",")[-1].strip('"')


def main():
    ws = Path(os.environ.get("TEMP")) / "whyfs-smoke-ws"
    shutil.rmtree(ws, ignore_errors=True)
    ws.mkdir()
    con = connect(ws)
    con.execute("INSERT INTO runs(id,started_ns,cwd,command,workspace,collector) VALUES('smoke',?,?,?,?,?)",
                (time.time_ns(), str(ws), "smoke", str(ws), "etw-native"))
    con.commit()
    con.close()
    args = [str(EXE), "--root", str(ws), "--run-id", "smoke", "--sqlite", str(SQLITE), "--user-sid", user_sid(),
            "--temp-root", os.environ["TEMP"], "--session", "whyfs-smoke", "--record", str(ws.parent / "whyfs-smoke.rec")]
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    print("collector:", p.stdout.readline().strip())
    time.sleep(1.0)
    (ws / "in.txt").write_text("hello\nworld\n")
    (ws / "main.c").write_text('#include <stdio.h>\nint add(int,int);\nint main(void){printf("%d\\n",add(1,2));return 0;}\n')
    (ws / "add.c").write_text("int add(int a,int b){return a+b;}\n")
    t0 = time.perf_counter()
    steps = [
        'cmd /c "type in.txt > copy.txt"',
        f'"{sys.executable}" -c "open(\'upper.txt\',\'w\').write(open(\'copy.txt\').read().upper())"',
        'cmd /c "move upper.txt final.txt"',
        'cmd /c "del copy.txt"',
        f'"{sys.executable}" -c "open(\'copy.txt\',\'w\').write(open(\'final.txt\').read())"',
        ".\\build.bat",
        'cmd /c ".\\app.exe > result.txt"',
    ]
    (ws / "build.bat").write_text(f'@call "{VCVARS}" >nul\r\ncl /nologo /c main.c add.c || exit /b 1\r\n'
                                  "link /nologo main.obj add.obj /OUT:app.exe || exit /b 1\r\n")
    for s in steps:
        r = subprocess.run(s, cwd=ws, shell=True, capture_output=True, text=True)
        print(f"  [{r.returncode}] {s[:90]}" + (f"  !! {(r.stdout + r.stderr).strip()[-300:]}" if r.returncode else ""))
    print(f"workload {time.perf_counter() - t0:.2f}s")
    time.sleep(0.5)
    p.stdin.write("stop\n")
    p.stdin.flush()
    out, _ = p.communicate(timeout=60)
    print("stats:", out.strip().splitlines()[-1])
    con = connect(ws)
    for f in ("final.txt", "copy.txt", "main.obj", "app.exe", "result.txt"):
        w = why(con, str(ws / f))
        if not w:
            print(f"why {f}: NONE")
            continue
        print(f"why {f}: exe={w['exe']} inputs={[Path(x).name for x in w['inputs']]} via_tmp={[Path(x).name for x in w.get('inputs_via_temporaries', [])]}"
              f" renamed={[Path(r['from']).name for r in w['renamed_from']]} cmd={w['command']!r} parent={(w.get('parent') or {}).get('exe')}")
    for f in ("in.txt", "add.c"):
        print(f"impact {f}:", sorted({Path(b).name for _a, b, _e, _r in impact(con, str(ws / f))}))
    print("events", con.execute("SELECT COUNT(*) FROM events").fetchone()[0], "processes", con.execute("SELECT COUNT(*) FROM processes").fetchone()[0])
    con.close()


if __name__ == "__main__":
    main()

