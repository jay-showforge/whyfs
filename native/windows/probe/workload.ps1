# Probe workload: exercise each operation whyfs must observe, in a marker directory.
$d = Join-Path $env:TEMP "whyfsprobe"
Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
New-Item -ItemType Directory $d | Out-Null
Set-Location $d
Set-Content -Path in.txt -Value "hello probe"
cmd /c "type in.txt > out_cmd.txt"                                  # child process, redirection
& C:\Python313\python.exe -c "open('out_py.txt','w').write(open('in.txt').read())"   # read + write
& C:\Python313\python.exe -c "import mmap;f=open('in.txt','rb');m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);open('out_mmap.txt','wb').write(m[:5])"
& C:\Python313\python.exe -c "import os;[open('in.txt').read() for _ in range(3)];open('reopen.txt','w').write('x')"
Rename-Item out_py.txt renamed.txt
Move-Item renamed.txt moved.txt
Remove-Item out_cmd.txt
Set-Content -Path out_cmd.txt -Value "recreated"
& C:\Python313\python.exe -c "import os;os.replace('moved.txt','replaced.txt')"
Copy-Item $env:TEMP\probe_main.c main.c; Copy-Item $env:TEMP\probe_add.c add.c
cmd /c "call C:\BuildTools2022\VC\Auxiliary\Build\vcvars64.bat >nul && cl /nologo /c main.c add.c && link /nologo main.obj add.obj /OUT:app.exe"
.\app.exe
