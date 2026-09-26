"""Uninstalls Sentinel Antivirus: removes shortcuts, registry entries, and the
install directory (including this running exe, via a detached cleanup).

Every step runs even if an earlier one fails, and each is logged to
%TEMP%\\Sentinel-uninstall.log, so a partial failure never leaves the rest
(like shortcuts pointing at deleted files) behind unexplained.
"""
import os
import subprocess
import sys
import tempfile
import time
import tkinter as tk
import traceback
import winreg
from pathlib import Path
from tkinter import messagebox

from common import (
    APP_EXE_NAME, APP_NAME, INSTALL_DIR, LEGACY_DESKTOP_DIR, REG_RUN_KEY, REG_RUN_VALUE,
    REG_UNINSTALL_KEY, START_MENU_DIR, desktop_dir,
)

LOG_PATH = Path(tempfile.gettempdir()) / "Sentinel-uninstall.log"
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008


def log(message: str):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {message}\n")
    except OSError:
        pass


def step(name, action) -> bool:
    try:
        action()
        log(f"OK    {name}")
        return True
    except Exception:
        log(f"FAIL  {name}\n{traceback.format_exc()}")
        return False


def kill_running_app():
    # Ends both the window and the background protection (same exe).
    subprocess.run(["taskkill", "/IM", APP_EXE_NAME, "/F"], capture_output=True, check=False,
                   creationflags=CREATE_NO_WINDOW)
    time.sleep(1)  # give Windows a moment to release the files


def remove_shortcuts():
    links = [START_MENU_DIR / f"{APP_NAME}.lnk", LEGACY_DESKTOP_DIR / f"{APP_NAME}.lnk"]
    try:
        links.append(desktop_dir() / f"{APP_NAME}.lnk")
    except OSError:
        log("could not resolve the Desktop folder; using the legacy location only")
    for link in links:
        link.unlink(missing_ok=True)
        if link.exists():
            raise OSError(f"{link} is still there")


def remove_startup_entry():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, REG_RUN_VALUE)
    except FileNotFoundError:
        pass


def remove_uninstall_entry():
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL_KEY)
    except FileNotFoundError:
        pass


def schedule_folder_removal():
    """This exe lives inside INSTALL_DIR, so it can't delete the folder while
    running. A detached cmd retries the delete for a while after we exit. It
    runs from %TEMP%, because a process can't remove its own current folder."""
    target = str(INSTALL_DIR)
    # A script file avoids cmd's quoting rules for one-line loops. `ping` is the
    # delay because `timeout` exits immediately without a console window.
    script = Path(tempfile.gettempdir()) / f"sentinel-cleanup-{os.getpid()}.cmd"
    script.write_text(
        "@echo off\r\n"
        "for /L %%i in (1,1,30) do (\r\n"
        "  ping -n 2 127.0.0.1 >nul\r\n"
        f'  rmdir /s /q "{target}" 2>nul\r\n'
        f'  if not exist "{target}" goto done\r\n'
        ")\r\n"
        ":done\r\n"
        'del "%~f0"\r\n',
        encoding="mbcs",
    )
    subprocess.Popen(["cmd", "/c", str(script)], cwd=tempfile.gettempdir(),
                     creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW, close_fds=True)


def main():
    os.chdir(tempfile.gettempdir())  # never hold the install folder open ourselves
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)  # keep the dialog in front of other windows

    confirm = messagebox.askyesno(
        f"{APP_NAME} Uninstall",
        f"Uninstall {APP_NAME}?\n\n"
        "This will remove the application, its scan history, and any quarantined files.",
        parent=root,
    )
    if not confirm:
        log("cancelled by user")
        sys.exit(0)

    log(f"uninstalling from {INSTALL_DIR}")
    results = [
        step("close running Sentinel", kill_running_app),
        step("remove shortcuts", remove_shortcuts),
        step("remove start-with-Windows entry", remove_startup_entry),
        step("remove Apps & Features entry", remove_uninstall_entry),
        step("schedule install folder removal", schedule_folder_removal),
    ]
    if all(results):
        messagebox.showinfo(f"{APP_NAME} Uninstall", f"{APP_NAME} has been uninstalled.", parent=root)
    else:
        messagebox.showwarning(
            f"{APP_NAME} Uninstall",
            f"{APP_NAME} was mostly removed, but some steps failed.\nDetails: {LOG_PATH}",
            parent=root,
        )
    sys.exit(0)


if __name__ == "__main__":
    main()
