# Upgrade / downgrade / data-retention test of the Windows installer (run elevated).
#   powershell -ExecutionPolicy Bypass -File native\windows\test_msi_upgrade.ps1 -Old OLD.msi -New NEW.msi -Out DIR
# OLD and NEW are the same payload built with make_msi.py --version (lower / higher ProductVersion).
param([Parameter(Mandatory)][string]$Old, [Parameter(Mandatory)][string]$New, [string]$Out = "$env:TEMP\whyfs-msi-upgrade")
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force $Out | Out-Null
$results = [ordered]@{}
function Check($name, $ok, $detail = "") { $results[$name] = [bool]$ok; "{0,-5} {1} {2}" -f ($(if ($ok) {"PASS"} else {"FAIL"})), $name, $detail }
$UPGRADE = "{6E1B3F0A-3C8E-4B8B-9E3A-5D3C7A4F2B11}"
$inst = Join-Path $env:ProgramFiles "whyfs"
$installer = New-Object -ComObject WindowsInstaller.Installer
function Related { @($installer.RelatedProducts($UPGRADE)) }
function Version($code) { (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$code").DisplayVersion }
function Msi($verb, $file, $log) { (Start-Process msiexec.exe -ArgumentList "$verb `"$((Resolve-Path $file).Path)`" /qn /norestart /l*v `"$Out\$log`"" -Wait -PassThru).ExitCode }
function PathCount { @([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";" | Where-Object { $_.TrimEnd("\") -eq $inst }).Count }

foreach ($c in Related) { Start-Process msiexec.exe -ArgumentList "/x $c /qn /norestart" -Wait | Out-Null }
Check "precondition_no_product" (@(Related).Count -eq 0)

# 1. install the older version and record provenance in a workspace
Check "old_install_exit_0" ((Msi "/i" $Old "old-install.log") -eq 0)
$oldCode = @(Related)[0]; $oldVer = Version $oldCode
$ws = Join-Path $env:TEMP "whyfs-upgrade-ws"
if (Test-Path $ws) { Remove-Item -Recurse -Force $ws }
New-Item -ItemType Directory $ws | Out-Null
Push-Location $ws
"a" | Set-Content in.txt
& "$inst\whyfs.exe" init . | Out-Null
& "$inst\whyfs.exe" daemon start | Out-Null
Start-Sleep 1
cmd /c "type in.txt > before.txt"
& "$inst\whyfs.exe" daemon stop | Out-Null
Pop-Location

# 2. major upgrade in place
Check "upgrade_exit_0" ((Msi "/i" $New "upgrade.log") -eq 0)
$codes = @(Related)
Check "single_product_after_upgrade" ($codes.Count -eq 1) ($codes -join ",")
$newVer = Version $codes[0]
Check "product_version_advanced" ([version]$newVer -gt [version]$oldVer) "$oldVer -> $newVer"
$svc = Get-Service whyfs -ErrorAction SilentlyContinue
Check "service_running_after_upgrade" ($svc -and $svc.Status -eq "Running")
Check "single_path_entry" ((PathCount) -eq 1)
Push-Location $ws
$w1 = & "$inst\whyfs.exe" why before.txt --json | ConvertFrom-Json
Check "workspace_history_kept_across_upgrade" ((Split-Path $w1.exe -Leaf) -eq "cmd.exe") $w1.exe
& "$inst\whyfs.exe" daemon start | Out-Null
Start-Sleep 1
cmd /c "type before.txt > after.txt"
& "$inst\whyfs.exe" daemon stop | Out-Null
$w2 = & "$inst\whyfs.exe" why after.txt --json | ConvertFrom-Json
Check "collects_after_upgrade" ((@($w2.inputs) | ForEach-Object { Split-Path $_ -Leaf }) -contains "before.txt")
Pop-Location

# 3. downgrade is refused and leaves the newer product intact
$rc = Msi "/i" $Old "downgrade.log"
Check "downgrade_refused" ($rc -ne 0) "exit $rc"
Check "newer_product_intact" ($newVer -and (@(Related).Count -eq 1) -and ((Version @(Related)[0]) -eq $newVer) -and ((Get-Service whyfs).Status -eq "Running"))

# 4. uninstall: program gone, the users' workspace stores stay (policy: user data is never removed)
Check "uninstall_exit_0" ((Msi "/x" $New "uninstall.log") -eq 0)
Check "no_product_left" (@(Related).Count -eq 0)
Check "files_and_service_removed" (-not (Test-Path $inst) -and -not (Get-Service whyfs -ErrorAction SilentlyContinue))
Check "path_entry_removed" ((PathCount) -eq 0)
Check "user_data_kept" (Test-Path "$ws\.whyfs\whyfs.db")
Remove-Item -Recurse -Force $ws
$results | ConvertTo-Json | Set-Content "$Out\msi_upgrade.json" -Encoding utf8
$failed = @($results.GetEnumerator() | Where-Object { -not $_.Value })
"msi upgrade test: $($results.Count - $failed.Count)/$($results.Count) checks ($oldVer -> $newVer)"
if ($failed) { exit 1 }
