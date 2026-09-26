#!/usr/bin/env python3
"""Paired benchmark of the native capture backend (not Python CLI startup)."""
from pathlib import Path
import os, statistics, subprocess, sys, tempfile, time, uuid

ROOT=Path(__file__).resolve().parents[1]
ENV={**os.environ,"PYTHONPATH":str(ROOT/"src")}

with tempfile.TemporaryDirectory() as td:
    d=Path(td)
    subprocess.run([sys.executable,"-m","whyfs","init","."],cwd=d,env=ENV,check=True,stdout=subprocess.DEVNULL)
    script=d/"work.py"
    script.write_text("""from pathlib import Path\nimport shutil\nr=Path('data')\nif r.exists(): shutil.rmtree(r)\nr.mkdir()\nfor i in range(3000):(r/f'f{i}.txt').write_text(str(i))\ns=0\nfor i in range(3000):s+=int((r/f'f{i}.txt').read_text())\nPath('sum.txt').write_text(str(s))\n""")
    # Build collector once.
    subprocess.run([sys.executable,"-m","whyfs","trace","--workspace",".","--","true"],cwd=d,env=ENV,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    lib=d/".whyfs/libwhyfs.so"
    def one(capture: bool):
        env=os.environ.copy(); log=None
        if capture:
            log=d/".whyfs"/f"bench-{uuid.uuid4().hex}.jsonl"
            env.update(LD_PRELOAD=str(lib),WHYFS_LOG=str(log),WHYFS_RUN_ID="bench",WHYFS_ROOT=str(d),WHYFS_CAPTURE_ALL="0")
        t=time.perf_counter(); subprocess.run([sys.executable,"work.py"],cwd=d,env=env,check=True,stdout=subprocess.DEVNULL); dt=time.perf_counter()-t
        if log: log.unlink(missing_ok=True)
        return dt
    one(False); one(True)  # warmup
    pairs=[]
    for i in range(7):
        if i%2==0: b,t=one(False),one(True)
        else: t,b=one(True),one(False)
        pairs.append((b,t,(t/b-1)*100))
    print(f"baseline median: {statistics.median(x[0] for x in pairs):.4f}s")
    print(f"capture median:  {statistics.median(x[1] for x in pairs):.4f}s")
    print(f"median paired native-capture overhead: {statistics.median(x[2] for x in pairs):.2f}%")
    print("paired overheads: " + ", ".join(f"{x[2]:.1f}%" for x in pairs))
