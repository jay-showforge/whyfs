$d = Join-Path $env:USERPROFILE 'whyfs-msi-probe'
if (Test-Path $d) { Remove-Item -Recurse -Force $d }
New-Item -ItemType Directory $d | Out-Null; Set-Location $d
'probe' | Set-Content in.txt
cmd /c "type in.txt > out.txt"
Start-Sleep 10
& 'C:\Program Files\whyfs\whyfs.exe' label (Join-Path $d 'out.txt') --json | Out-File -Encoding utf8 (Join-Path $d 'label.json')
& 'C:\Program Files\whyfs\whyfs.exe' status --json | Out-File -Encoding utf8 (Join-Path $d 'status.json')
