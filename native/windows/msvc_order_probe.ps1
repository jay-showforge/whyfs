# Which files does one MSVC cl process read before writing each object? (lineage precision probe)
param([string]$Flags = "")
$ws = "$env:TEMP\whyfs-msvc-order"
New-Item -ItemType Directory -Force $ws | Out-Null
'#define B 7' | Set-Content "$ws\common.h"
foreach ($i in 1..4) { "#include `"common.h`"`nint u$i(int x){return x+B+$i;}" | Set-Content "$ws\u$i.c" }
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$env:PYTHONPATH = "$repo\src"
& C:\Python313\python.exe -m whyfs init $ws | Out-Null
& C:\Python313\python.exe -m whyfs daemon start --workspace $ws | Out-Null
Start-Sleep 1
& cmd.exe /c "cd /d $ws && call C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat >nul && cl /nologo $Flags /c u1.c u2.c u3.c u4.c >nul"
Start-Sleep 1
& C:\Python313\python.exe -m whyfs daemon stop --workspace $ws | Out-Null
@"
import sqlite3, sys
sys.path.insert(0, r'$repo\src')
from whyfs.query import why
c = sqlite3.connect(r'$ws\.whyfs\whyfs.db'); c.row_factory = sqlite3.Row
for r in c.execute("select ts_ns, pid, is_read, path from events where kind='io' order by ts_ns"):
    print('  ', r['ts_ns'] % 10**9, r['pid'] & 0xffffffff, 'R' if r['is_read'] else 'W', r['path'].split('\\')[-1])
for i in range(1, 5):
    w = why(c, r'$ws\u%d.obj' % i)
    print('why u%d.obj ->' % i, sorted(p.split('\\')[-1] for p in w['inputs']), 'pid', w['pid'])
"@ | & C:\Python313\python.exe -
