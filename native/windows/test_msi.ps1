# Clean-install test of the Windows installer (run elevated; the user flow runs non-elevated).
#   powershell -ExecutionPolicy Bypass -File native\windows\test_msi.ps1 -Msi dist\whyfs-<v>-x64.msi -Out results\msi-test
param([Parameter(Mandatory)][string]$Msi, [string]$Out = "$env:TEMP\whyfs-msi-test", [string]$AsUser = "C:\Users\ftmon\whyfs-win-build\asuser.exe")
$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force $Out | Out-Null
$results = [ordered]@{}
function Check($name, $ok, $detail = "") { $results[$name] = [bool]$ok; "{0,-5} {1} {2}" -f ($(if ($ok) {"PASS"} else {"FAIL"})), $name, $detail }
$inst = Join-Path $env:ProgramFiles "whyfs"
function MachinePath { ([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";" | ForEach-Object { $_.TrimEnd("\") }) -join ";" }

# 0. clean machine state: no whyfs product, service or install directory
$installer = New-Object -ComObject WindowsInstaller.Installer
foreach ($code in @($installer.RelatedProducts("{6E1B3F0A-3C8E-4B8B-9E3A-5D3C7A4F2B11}"))) {
    Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait | Out-Null
}
if (Get-Service whyfs -ErrorAction SilentlyContinue) { & "$inst\whyfs-svc.exe" uninstall | Out-Null }
if (Test-Path $inst) { Remove-Item -Recurse -Force $inst }
Check "precondition_clean" (-not (Get-Service whyfs -ErrorAction SilentlyContinue) -and -not (Test-Path $inst))

# 1. silent install
$p = Start-Process msiexec.exe -ArgumentList "/i `"$((Resolve-Path $Msi).Path)`" /qn /norestart /l*v `"$Out\install.log`"" -Wait -PassThru
Check "install_exit_0" ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
$svc = Get-Service whyfs -ErrorAction SilentlyContinue
Check "service_installed_and_running" ($svc -and $svc.Status -eq "Running") "$($svc.Status)"
Check "service_autostart" ((Get-CimInstance Win32_Service -Filter "Name='whyfs'").StartMode -eq "Auto")
Check "on_machine_path" ((MachinePath) -split ";" -contains $inst)
$ver = & "$inst\whyfs.exe" --version 2>&1
Check "launcher_version" ($ver -match "whyfs \d") "$ver"
$acl = (Get-Acl $inst).Access | Where-Object { $_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write|Modify|FullControl" }
Check "install_dir_not_user_writable" (-not $acl)

# 2. everyday use as a standard user, installed binaries only
$flow = "$Out\user_flow.ps1"
@"
`$ws = Join-Path `$env:TEMP 'whyfs-msi-user-ws'
if (Test-Path `$ws) { Remove-Item -Recurse -Force `$ws }
New-Item -ItemType Directory `$ws | Out-Null; Set-Location `$ws
`$w = '$inst\whyfs.exe'
'3','1','2' | Set-Content data.txt
& `$w init . | Out-Null
& `$w daemon start | Out-Null; "start `$LASTEXITCODE"
Start-Sleep 1
cmd /c "sort data.txt > sorted.txt"
cmd /c "type sorted.txt > report.txt"
Rename-Item report.txt final.txt
& `$w daemon stop | Out-Null; "stop `$LASTEXITCODE"
& `$w why final.txt --json | Out-File -Encoding utf8 why.json
& `$w impact data.txt --json | Out-File -Encoding utf8 impact.json
& `$w history final.txt --json | Out-File -Encoding utf8 history.json
& `$w stats --json | Out-File -Encoding utf8 stats.json
`$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"elevated `$admin"
"@ | Set-Content $flow -Encoding ascii
$uo = & $AsUser "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$flow`"" 2>&1
$uo | Set-Content "$Out\user_flow.out" -Encoding utf8
$ws = Join-Path $env:TEMP "whyfs-msi-user-ws"
Check "user_flow_not_elevated" (($uo -join "`n") -match "elevated False")
Check "user_daemon_start_stop" (($uo -join "`n") -match "start 0" -and ($uo -join "`n") -match "stop 0") ($uo -join " | ")
try {
    $why = Get-Content "$ws\why.json" -Raw | ConvertFrom-Json
    $imp = Get-Content "$ws\impact.json" -Raw | ConvertFrom-Json
    $st = Get-Content "$ws\stats.json" -Raw | ConvertFrom-Json
    Check "why_creator_cmd" ((Split-Path $why.exe -Leaf) -eq "cmd.exe") $why.exe
    Check "why_inputs" ((@($why.inputs) | ForEach-Object { Split-Path $_ -Leaf }) -contains "sorted.txt")
    Check "why_renamed_from" ((Split-Path $why.renamed_from[0].from -Leaf) -eq "report.txt")
    $tos = @($imp | ForEach-Object { Split-Path $_.to -Leaf })
    Check "impact_chain" (($tos -contains "sorted.txt") -and ($tos -contains "final.txt")) ($tos -join ",")
    Check "zero_loss" (([int]$st.kernel_drops + [int]$st.queue_drops + [int]$st.user_unresolved + [int]$st.late_records) -eq 0)
} catch { Check "user_flow_outputs" $false "$_" }

# 3. uninstall
$p = Start-Process msiexec.exe -ArgumentList "/x `"$((Resolve-Path $Msi).Path)`" /qn /norestart /l*v `"$Out\uninstall.log`"" -Wait -PassThru
Check "uninstall_exit_0" ($p.ExitCode -eq 0) "exit $($p.ExitCode)"
Check "service_removed" (-not (Get-Service whyfs -ErrorAction SilentlyContinue))
Check "files_removed" (-not (Test-Path $inst))
Check "path_entry_removed" (-not ((MachinePath) -split ";" -contains $inst))
Check "no_orphan_etw_sessions" (-not ((logman query -ets) -match "whyfs"))
Check "user_data_kept" (Test-Path "$ws\.whyfs\whyfs.db")
$results | ConvertTo-Json | Set-Content "$Out\msi_test.json" -Encoding utf8
$failed = @($results.GetEnumerator() | Where-Object { -not $_.Value })
"msi clean-install test: $($results.Count - $failed.Count)/$($results.Count) checks"
if ($failed) { exit 1 }
