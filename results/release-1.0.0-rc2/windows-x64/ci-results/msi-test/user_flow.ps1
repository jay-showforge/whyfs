$ws = Join-Path $env:TEMP 'whyfs-msi-user-ws'
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory $ws | Out-Null; Set-Location $ws
$w = 'C:\Program Files\whyfs\whyfs.exe'
'3','1','2' | Set-Content data.txt
& $w init . | Out-Null
& $w daemon start | Out-Null; "start $LASTEXITCODE"
Start-Sleep 1
cmd /c "sort data.txt > sorted.txt"
cmd /c "type sorted.txt > report.txt"
Rename-Item report.txt final.txt
& $w daemon stop | Out-Null; "stop $LASTEXITCODE"
& $w why final.txt --json | Out-File -Encoding utf8 why.json
& $w impact data.txt --json | Out-File -Encoding utf8 impact.json
& $w history final.txt --json | Out-File -Encoding utf8 history.json
& $w stats --json | Out-File -Encoding utf8 stats.json
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"elevated $admin"
