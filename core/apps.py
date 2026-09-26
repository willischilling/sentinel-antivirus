"""Lists the desktop apps installed on this PC (for the firewall's app list):
Start Menu shortcuts (all users and this user) plus the programs registered in
Windows' installed-apps list, each with its icon. Windows' own programs,
uninstallers and Sentinel itself are left out.

It runs in one PowerShell call (resolving shortcuts needs the Shell COM
object, and icons come from System.Drawing), which takes a few seconds, so
callers run it on a worker thread and keep the result.
"""
import base64
import json
import os
import subprocess
from dataclasses import dataclass

CREATE_NO_WINDOW = 0x08000000

_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Drawing
$sh = New-Object -ComObject WScript.Shell
$seen = @{}
$found = New-Object System.Collections.Generic.List[object]
function Add-App($name, $path) {
  if (-not $path) { return }
  $path = [Environment]::ExpandEnvironmentVariables($path.Trim('"'))
  $key = $path.ToLower()
  if (-not $key.EndsWith('.exe') -or $seen.ContainsKey($key) -or -not (Test-Path -LiteralPath $path)) { return }
  $seen[$key] = 1
  $icon = $null
  try {
    $bmp = [System.Drawing.Icon]::ExtractAssociatedIcon($path).ToBitmap()
    $ms = New-Object IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $icon = [Convert]::ToBase64String($ms.ToArray())
  } catch {}
  $found.Add([pscustomobject]@{ name = $name; path = $path; icon = $icon })
}
foreach ($dir in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
                   "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")) {
  Get-ChildItem -LiteralPath $dir -Recurse -Filter *.lnk | ForEach-Object {
    Add-App $_.BaseName $sh.CreateShortcut($_.FullName).TargetPath }
}
foreach ($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
  Get-ItemProperty $key | Where-Object { $_.DisplayName -and $_.DisplayIcon } | ForEach-Object {
    Add-App $_.DisplayName (($_.DisplayIcon -split ',')[0]) }
}
ConvertTo-Json -InputObject $found.ToArray() -Compress
"""

SKIP_WORDS = ("uninstall", "unins0", "setup", "installer", "update.exe", "crashhandler", "crashpad",
              "package cache", "redist")


@dataclass
class InstalledApp:
    name: str
    path: str
    icon_png: bytes | None


def installed_apps() -> list[InstalledApp]:
    encoded = base64.b64encode(_SCRIPT.encode("utf-16-le")).decode()
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                         capture_output=True, text=True, timeout=180, creationflags=CREATE_NO_WINDOW)
    data = json.loads(out.stdout or "[]")
    if isinstance(data, dict):  # PowerShell emits a bare object for a single result
        data = [data]
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    apps, names = [], set()
    for item in data:
        path, name = item.get("path") or "", (item.get("name") or "").strip()
        lower = path.lower()
        if (not name or os.path.normcase(path).startswith(windows) or any(w in lower for w in SKIP_WORDS)
                or "sentinel antivirus" in lower):
            continue
        if name.lower() in names:  # e.g. a second, versioned copy of the same browser
            continue
        names.add(name.lower())
        icon = base64.b64decode(item["icon"]) if item.get("icon") else None
        apps.append(InstalledApp(name, path, icon))
    return sorted(apps, key=lambda a: a.name.lower())
