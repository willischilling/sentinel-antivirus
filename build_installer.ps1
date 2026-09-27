$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

Write-Host "== Cleaning previous build output ==" -ForegroundColor Cyan
Remove-Item -Recurse -Force "$root\build", "$root\dist" -ErrorAction SilentlyContinue

Write-Host "== Building Sentinel.exe (main app, onedir) ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onedir --windowed --name Sentinel `
    --icon "$root\assets\icon.ico" `
    --hidden-import pystray._win32 `
    --hidden-import yara `
    --collect-submodules llama_cpp `
    --collect-binaries llama_cpp `
    --collect-data llama_cpp `
    --add-data "$root\assets\icon.ico;assets" `
    --add-data "$root\assets\icon.png;assets" `
    --add-data "$root\assets\emblem.png;assets" `
    --add-data "$root\assets\world_dots.png;assets" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\gui.py"

Write-Host "== Building Uninstall.exe ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed --name Uninstall `
    --icon "$root\assets\icon.ico" `
    --paths "$root\installer" `
    --paths "$root" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\installer\uninstall.py"

Copy-Item "$root\assets\icon.ico" "$root\dist\icon.ico" -Force

# Sentinel Browser runs on Microsoft's WebView2. Its SDK (the .NET wrapper and loader DLLs) comes
# from NuGet, pinned to one version and checked against its SHA-256.
$wv2Version = "1.0.4191.47"
$wv2Sha256 = "f492bbf547d0da329553b6727435b677579b1e9f91cc9e4a1ad029366d5f23d0"
$lib = "$root\browser\lib"
if (-not (Test-Path "$lib\Microsoft.Web.WebView2.Core.dll")) {
    Write-Host "== Downloading the WebView2 SDK $wv2Version ==" -ForegroundColor Cyan
    $pkg = Join-Path $env:TEMP "webview2-$wv2Version.zip"
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$wv2Version/microsoft.web.webview2.$wv2Version.nupkg" -OutFile $pkg -UseBasicParsing
    if ((Get-FileHash $pkg -Algorithm SHA256).Hash.ToLower() -ne $wv2Sha256) { throw "WebView2 SDK checksum mismatch" }
    $unpacked = Join-Path $env:TEMP "webview2-$wv2Version"
    Expand-Archive $pkg $unpacked -Force
    New-Item -ItemType Directory -Force $lib | Out-Null
    Copy-Item "$unpacked\lib\net462\Microsoft.Web.WebView2.Core.dll", "$unpacked\lib\net462\Microsoft.Web.WebView2.WinForms.dll", "$unpacked\runtimes\win-x64\native\WebView2Loader.dll" $lib
}

Write-Host "== Building SentinelBrowser.exe (private browser, onedir) ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onedir --windowed --name SentinelBrowser `
    --icon "$root\assets\icon.ico" `
    --paths "$root" `
    --hidden-import clr `
    --hidden-import yara `
    --add-data "$root\browser\web;browser/web" `
    --add-binary "$lib\Microsoft.Web.WebView2.Core.dll;browser/lib" `
    --add-binary "$lib\Microsoft.Web.WebView2.WinForms.dll;browser/lib" `
    --add-binary "$lib\WebView2Loader.dll;browser/lib" `
    --add-data "$root\assets\icon.ico;browser" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\browser_main.py"

Write-Host "== Building SentinelSetup.exe (installer wizard) ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed --name SentinelSetup `
    --icon "$root\assets\icon.ico" `
    --paths "$root\installer" `
    --paths "$root" `
    --add-data "$root\dist\Sentinel;payload/app" `
    --add-data "$root\dist\Uninstall.exe;payload" `
    --add-data "$root\dist\SentinelBrowser;payload/browser" `
    --add-data "$root\dist\icon.ico;payload" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\installer\installer.py"

Write-Host ""
Write-Host "Done. Installer at: $root\dist\SentinelSetup.exe" -ForegroundColor Green
