"""Summarize etw_probe output: per process, which probe-dir files were created/read/written/renamed/deleted."""
import re
import sys
from collections import defaultdict

MARK = sys.argv[2] if len(sys.argv) > 2 else "whyfsprobe"
fo_name = {}   # FileObject -> name
key_name = {}  # FileKey -> name
ops = defaultdict(list)
images = {}
for line in open(sys.argv[1], encoding="utf-8-sig"):
    m = re.match(r"^(\w+) id=(\d+) v=\d+ task=(\S*) op=\S*\s+pid=(\d+) tid=\d+ ts=(\d+) \|(.*)$", line.rstrip("\n"))
    if not m:
        continue
    prov, eid, task, pid, ts, rest = m.groups()
    f = dict(re.findall(r"(\w+)=(\S*)", rest))
    if prov == "PROC" and task == "ProcessStart":
        images[f["ProcessID"]] = f.get("ImageName", "").rsplit("\\", 1)[-1]
        continue
    if prov != "FILE":
        continue
    name = None
    if "FileName" in f and MARK in f["FileName"] and task in ("Create", "CreateNewFile"):
        name = f["FileName"].split(MARK + "\\", 1)[-1]
        fo_name[f["FileObject"]] = name
        ops[pid].append(f"{task}({name}) opts={f.get('CreateOptions')} share={f.get('ShareAccess')}")
        continue
    fo = f.get("FileObject")
    name = fo_name.get(fo)
    if name and "FileKey" in f:
        key_name[f["FileKey"]] = name
    if name is None and f.get("FileKey") in key_name:
        name = key_name[f["FileKey"]] + "(by key)"
    if not name:
        continue
    if task in ("Read", "Write"):
        ops[pid].append(f"{task}({name}) size={f.get('IOSize')} ioflags={f.get('IOFlags')}")
    elif task in ("RenamePath", "DeletePath", "SetDelete", "Rename", "SetInformation"):
        p = f.get("FilePath", "")
        ops[pid].append(f"{task}({name}) -> {p.split(MARK + chr(92), 1)[-1] if p else ''}")
for pid, lst in ops.items():
    print(f"== pid {pid} {images.get(pid, '(root: powershell)')}")
    last = None
    for o in lst:
        if o != last:
            print("   ", o)
        last = o

