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
    --add-data "$root\assets\icon.ico;assets" `
    --add-data "$root\assets\icon.png;assets" `
    --add-data "$root\assets\emblem.png;assets" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\gui.py"

Write-Host "== Building Uninstall.exe ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed --name Uninstall `
    --icon "$root\assets\icon.ico" `
    --paths "$root\installer" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\installer\uninstall.py"

Copy-Item "$root\assets\icon.ico" "$root\dist\icon.ico" -Force

Write-Host "== Building SentinelSetup.exe (installer wizard) ==" -ForegroundColor Cyan
python -m PyInstaller --noconfirm --onefile --windowed --name SentinelSetup `
    --icon "$root\assets\icon.ico" `
    --paths "$root\installer" `
    --add-data "$root\dist\Sentinel;payload/app" `
    --add-data "$root\dist\Uninstall.exe;payload" `
    --add-data "$root\dist\icon.ico;payload" `
    --distpath "$root\dist" --workpath "$root\build" --specpath "$root\build" `
    "$root\installer\installer.py"

Write-Host ""
Write-Host "Done. Installer at: $root\dist\SentinelSetup.exe" -ForegroundColor Green
