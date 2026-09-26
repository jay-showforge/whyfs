import re, struct, sys
fo, key, procs, hits = {}, {}, {}, []
for line in open(sys.argv[1], encoding="utf-8-sig"):
    m = re.match(r"^SYSP .*opc=1 .*?\| .*ProcessId=(0x[0-9A-F]+) .*ImageFileName=(\S+)", line)
    if m: procs[int(m.group(1), 16)] = m.group(2); continue
    m = re.match(r"^FILE id=(\d+) .*?\|(.*)$", line.rstrip())
    if m:
        eid, f = int(m.group(1)), dict(re.findall(r"(\w+)=(\S*)", m.group(2)))
        if eid in (12, 30) and "FileName" in f:
            fo[f["FileObject"]] = f["FileName"].split("whyfsprobe\\")[-1] if "whyfsprobe" in f["FileName"] else None
        elif eid == 11:
            key.pop(f.get("FileKey"), None)
        elif "FileObject" in f and "FileKey" in f and f["FileObject"] in fo:
            key[f["FileKey"]] = fo[f["FileObject"]]
        continue
    m = re.match(r"^MAP opc=37 hpid=(\d+) .*raw=([0-9a-f]+)", line)
    if m:
        view, k, misc, size, off, pid = struct.unpack("<QQQQQI", bytes.fromhex(m.group(2)))
        name = key.get("0x%016X" % k, "<unknown key>")
        if name and name != "<unknown key>": hits.append((pid, procs.get(pid, "?"), name, hex(misc), size))
for h in hits: print(h)

