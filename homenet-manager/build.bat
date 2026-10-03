@echo off
rem Builds Home Network Manager into a single double-clickable .exe.
rem Just double-click this file. It needs Python installed (python.org/downloads,
rem with "Add Python to PATH" checked during setup).
setlocal
cd /d "%~dp0"

echo.
echo ===== Building Home Network Manager =====
echo.

python --version >nul 2>&1
if errorlevel 1 (
  echo Python was not found.
  echo Install it from https://python.org/downloads
  echo and tick "Add Python to PATH" on the first screen, then run this again.
  echo.
  pause
  exit /b 1
)

echo Installing build tools (pyinstaller) and the one dependency (psutil)...
python -m pip install --upgrade pip
python -m pip install pyinstaller psutil
if errorlevel 1 (
  echo Could not install the build tools. Check your internet connection and try again.
  pause
  exit /b 1
)

echo.
echo Building the app... (this takes a minute)
python -m PyInstaller --noconsole --onefile --name "HomeNetManager" --icon "assets\icon.ico" --add-data "assets\icon.ico;assets" main.py

echo.
if exist "dist\HomeNetManager.exe" (
  echo ========================================================
  echo  Done!  Your app is here:  dist\HomeNetManager.exe
  echo  Double-click it to run, or drag it to your Desktop.
  echo ========================================================
) else (
  echo Build did not produce the exe. Scroll up to see what went wrong.
)
echo.
pause
