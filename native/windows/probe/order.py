import re, sys
created = {}; seen_ts = {}; inversions = 0; late_create = 0; total = 0; prev_ts = {}; back = {"FILE": 0, "SYSP": 0, "PROC": 0}
first_use = {}
for n, line in enumerate(open(sys.argv[1], encoding="utf-8-sig")):
    m = re.match(r"^(FILE|SYSP|PROC) id=(\d+) .*?ts=(\d+) \|(.*)$", line.rstrip())
    if not m: continue
    prov, eid, ts = m.group(1), int(m.group(2)), int(m.group(3))
    if prov in prev_ts and ts < prev_ts[prov]: back[prov] += 1
    prev_ts[prov] = max(ts, prev_ts.get(prov, 0))
    if prov != "FILE": continue
    f = dict(re.findall(r"(\w+)=(\S*)", m.group(4)))
    fo = f.get("FileObject")
    if eid in (12, 30):
        if fo in first_use and first_use[fo] < ts: late_create += 1
        created[fo] = ts
    elif eid in (15, 16) and fo:
        total += 1
        if fo not in created: first_use.setdefault(fo, ts)
print("delivery order: out-of-order timestamps per provider (file session is FILE+PROC):", back)
print("read/write events of tracked processes:", total, "; Create delivered after a use of its FileObject:", late_create)
