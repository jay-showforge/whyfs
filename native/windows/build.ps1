# Build the Windows native binaries (service + collector) for x64 and ARM64 with MSVC and
# stage them where the package expects them: src/whyfs/_bin/win-<arch>/.
#   powershell -ExecutionPolicy Bypass -File native\windows\build.ps1 [-Arch x64|arm64|all]
param([string]$Arch = "all", [string]$VsRoot = "C:\BuildTools2022")
$ErrorActionPreference = "Continue"  # native tools write progress to stderr; failures are checked explicitly
$repo = (Resolve-Path "$PSScriptRoot\..\..").Path
$src = "$repo\src\whyfs\native\windows"
$vcvarsall = "$VsRoot\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvarsall)) { throw "MSVC not found at $VsRoot" }
$targets = if ($Arch -eq "all") { @("x64", "arm64") } else { @($Arch) }
$ok = $true
foreach ($a in $targets) {
    $vcarg = if ($a -eq "x64") { "x64" } else { "x64_arm64" }   # host x64, target arm64 (cross)
    $out = "$repo\src\whyfs\_bin\win-$a"
    $obj = "$env:TEMP\whyfs-build-$a"
    New-Item -ItemType Directory -Force $out, $obj | Out-Null
    foreach ($name in "whyfs-collect-win", "whyfs-svc") {
        $cmd = "call `"$vcvarsall`" $vcarg >nul && cl /nologo /O2 /W4 /wd4100 /GS /guard:cf `"$src\$name.c`" /Fe:`"$out\$name.exe`" /Fo:`"$obj\\`" /link /guard:cf /DYNAMICBASE /NXCOMPAT"
        $log = cmd /c $cmd 2>&1
        if ($LASTEXITCODE -ne 0) { Write-Host "[$a] $name FAILED"; $log | Select-Object -Last 15 | ForEach-Object { Write-Host "   $_" }; $ok = $false; continue }
        $warn = $log | Select-String "warning"
        Write-Host ("[{0}] {1}.exe built ({2} warnings)" -f $a, $name, @($warn).Count)
    }
    # architecture check of what was staged
    foreach ($f in Get-ChildItem "$out\*.exe", "$out\*.dll" -ErrorAction SilentlyContinue) {
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $pe = [BitConverter]::ToInt32($bytes, 0x3C)
        $machine = [BitConverter]::ToUInt16($bytes, $pe + 4)
        $m = @{0x8664 = "x64"; 0xAA64 = "arm64"; 0x14C = "x86"}[[int]$machine]
        Write-Host ("[{0}]   {1,-24} PE machine {2}" -f $a, $f.Name, $m)
        if ($m -ne $a) { Write-Host "   ARCHITECTURE MISMATCH"; $ok = $false }
    }
}
if (-not $ok) { exit 1 }

