# Screenshot of the Explorer context menu with the WhyFS entries (Windows 11: the classic menu,
# "Show more options").  Opens an Explorer window on FOLDER, selects FILE, opens the classic
# context menu (Shift+F10) and the WhyFS submenu, and captures only the Explorer window and the
# menus.  Keys are sent only while that Explorer window is in the foreground.
param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string]$Out)
Add-Type -AssemblyName System.Drawing, System.Windows.Forms
Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text; using System.Collections.Generic;
public static class U {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr p);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hh, bool r);
  [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int a, out RECT r, int s);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr m);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetMenuString(IntPtr m, uint i, StringBuilder s, int n, uint f);
  [DllImport("user32.dll")] public static extern bool GetMenuItemRect(IntPtr h, IntPtr m, uint i, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
  public struct POINT { public int X, Y; }
  public struct RECT { public int L, T, R, B; }
  public static List<string> Popups() {
    var l = new List<string>();
    EnumWindows((h, p) => { var sb = new StringBuilder(128); GetClassName(h, sb, 128);
      if (IsWindowVisible(h)) l.Add(sb.ToString()); return true; }, IntPtr.Zero);
    return l;
  }
  public static List<IntPtr> Menus() {
    var l = new List<IntPtr>();
    EnumWindows((h, p) => { var sb = new StringBuilder(64); GetClassName(h, sb, 64);
      if (sb.ToString() == "#32768" && IsWindowVisible(h)) l.Add(h); return true; }, IntPtr.Zero);
    return l;
  }
}
"@
[U]::SetProcessDPIAware() | Out-Null
$shell = New-Object -ComObject Shell.Application
$shell.Open($Folder)
$win = $null
for ($i = 0; $i -lt 40 -and -not $win; $i++) {
    Start-Sleep -Milliseconds 250
    $win = $shell.Windows() | Where-Object { $_.Document -and $_.Document.Folder.Self.Path -eq $Folder } | Select-Object -First 1
}
if (-not $win) { throw "no Explorer window for $Folder" }
$h = [IntPtr]$win.HWND
[U]::ShowWindow($h, 1) | Out-Null
[U]::MoveWindow($h, 60, 60, 1500, 900, $true) | Out-Null
Start-Sleep 1
$item = $win.Document.Folder.ParseName((Split-Path $File -Leaf))
$win.Document.SelectItem($item, 1 + 4 + 8 + 16)   # select, deselect others, ensure visible, focus
[U]::SetForegroundWindow($h) | Out-Null
Start-Sleep -Milliseconds 700
if ([U]::GetForegroundWindow() -ne $h) { $win.Quit(); throw "Explorer is not in the foreground: no keys sent" }
[System.Windows.Forms.SendKeys]::SendWait("+{F10}")          # the context menu for the selection
Start-Sleep -Milliseconds 900
if (-not ([U]::Menus())) {                                   # Windows 11 shows its new menu first:
    [System.Windows.Forms.SendKeys]::SendWait("{UP}")        # "Show more options" is its last item
    Start-Sleep -Milliseconds 300
    [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
    Start-Sleep -Milliseconds 1200
}
if (-not ([U]::Menus())) {
    if ($env:WHYFS_SHOT_DEBUG) { [U]::Popups() | ForEach-Object { "popup: $_" } }
    $win.Quit(); throw "no context menu opened"
}
$menu = @([U]::Menus())[0]
$hm = [U]::SendMessage($menu, 0x01E1, [IntPtr]::Zero, [IntPtr]::Zero)   # MN_GETHMENU
$idx = -1
for ($k = 0; $k -lt [U]::GetMenuItemCount($hm); $k++) {
    $sb = New-Object System.Text.StringBuilder 256
    [U]::GetMenuString($hm, [uint32]$k, $sb, 256, 0x400) | Out-Null   # MF_BYPOSITION
    if ($sb.ToString().Replace("&", "") -eq "WhyFS") { $idx = $k; break }
}
if ($idx -lt 0) { [System.Windows.Forms.SendKeys]::SendWait("{ESC}"); $win.Quit(); throw "no WhyFS entry in the classic menu" }
$ir = New-Object U+RECT
[U]::GetMenuItemRect([IntPtr]::Zero, $hm, [uint32]$idx, [ref]$ir) | Out-Null
$saved = New-Object U+POINT; [U]::GetCursorPos([ref]$saved) | Out-Null
for ($k = 0; $k -lt 6 -and @([U]::Menus()).Count -lt 2; $k++) {   # hover (small moves): the submenu opens
    [U]::SetCursorPos([int](($ir.L + $ir.R) / 2) + $k, [int](($ir.T + $ir.B) / 2)) | Out-Null
    Start-Sleep -Milliseconds 700
}
if (@([U]::Menus()).Count -lt 2) { [U]::SetCursorPos($saved.X, $saved.Y) | Out-Null; [System.Windows.Forms.SendKeys]::SendWait("{ESC}{ESC}"); $win.Quit(); throw "the WhyFS submenu did not open" }
$rects = @()
$r = New-Object U+RECT
[U]::DwmGetWindowAttribute($h, 9, [ref]$r, 16) | Out-Null; $rects += $r
foreach ($m in [U]::Menus()) { $mr = New-Object U+RECT; [U]::GetWindowRect($m, [ref]$mr) | Out-Null; $rects += $mr }
$L = [int]::MaxValue; $T = [int]::MaxValue; $R = [int]::MinValue; $B = [int]::MinValue
foreach ($x in $rects) {  # struct fields: Measure-Object cannot read them
    if ($x.L -lt $L) { $L = $x.L }; if ($x.T -lt $T) { $T = $x.T }
    if ($x.R -gt $R) { $R = $x.R }; if ($x.B -gt $B) { $B = $x.B }
}
$bmp = New-Object System.Drawing.Bitmap ($R - $L), ($B - $T)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.Clear([System.Drawing.Color]::White)
foreach ($x in $rects) {   # only the Explorer window and the menus, nothing else on screen
    $g.CopyFromScreen($x.L, $x.T, $x.L - $L, $x.T - $T, (New-Object System.Drawing.Size ($x.R - $x.L), ($x.B - $x.T)))
}
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
[U]::SetCursorPos($saved.X, $saved.Y) | Out-Null
[System.Windows.Forms.SendKeys]::SendWait("{ESC}{ESC}{ESC}")
Start-Sleep -Milliseconds 300
$win.Quit()
"captured {0}x{1} ({2} menus) -> {3}" -f ($R - $L), ($B - $T), ($rects.Count - 1), $Out
