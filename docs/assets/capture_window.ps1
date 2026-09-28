# Capture a local page in a separate Chrome/Edge app window (its own temporary profile) and save
# exactly that window's pixels.  Used when headless screenshots are not available.
#   capture_window.ps1 -Url file:///...  -Out docs\assets\whyfs-window.png [-Width 1440 -Height 1000]
param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Out, [int]$Width = 1440, [int]$Height = 1000)
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System; using System.Runtime.InteropServices;
public static class W {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int s);
  public struct RECT { public int L, T, R, B; }
}
"@
[W]::SetProcessDPIAware() | Out-Null
$browser = @("C:\Program Files\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$prof = Join-Path $env:TEMP ("whyfs-shot-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
Start-Process $browser -ArgumentList "--user-data-dir=`"$prof`"", "--no-first-run", "--no-default-browser-check", "--force-device-scale-factor=1",
    "--window-position=20,20", "--window-size=$Width,$Height", "--app=$Url" | Out-Null
$h = [IntPtr]::Zero
for ($i = 0; $i -lt 40 -and $h -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 250
    $ids = Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" | Where-Object { $_.CommandLine -match [regex]::Escape($prof) } | ForEach-Object { $_.ProcessId }
    $h = (Get-Process -Id $ids -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1).MainWindowHandle
}
if ($h -eq [IntPtr]::Zero) { throw "no browser window" }
Start-Sleep 5   # page scripts render
[W]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 800
$r = New-Object W+RECT
[W]::DwmGetWindowAttribute($h, 9, [ref]$r, 16) | Out-Null   # DWMWA_EXTENDED_FRAME_BOUNDS: without the invisible border
$bmp = New-Object System.Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Get-CimInstance Win32_Process -Filter "Name='chrome.exe' OR Name='msedge.exe'" | Where-Object { $_.CommandLine -match [regex]::Escape($prof) } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep 1
Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue
"captured {0}x{1} -> {2}" -f ($r.R - $r.L), ($r.B - $r.T), $Out
