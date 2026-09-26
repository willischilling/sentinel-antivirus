"""Uninstalls Sentinel Antivirus: removes shortcuts, registry entry, and the
install directory (including this running exe, via a detached self-delete).
"""
import subprocess
import sys
import tkinter as tk
import winreg
from tkinter import messagebox

from common import (
    APP_EXE_NAME, APP_NAME, INSTALL_DIR, LEGACY_DESKTOP_DIR, REG_RUN_KEY, REG_RUN_VALUE,
    REG_UNINSTALL_KEY, START_MENU_DIR, desktop_dir,
)


def kill_running_app():
    subprocess.run(
        ["taskkill", "/IM", APP_EXE_NAME, "/F"],
        capture_output=True, check=False,
    )


def remove_shortcuts():
    (START_MENU_DIR / f"{APP_NAME}.lnk").unlink(missing_ok=True)
    for desktop in (desktop_dir(), LEGACY_DESKTOP_DIR):
        (desktop / f"{APP_NAME}.lnk").unlink(missing_ok=True)


def remove_registry_entry():
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL_KEY)
    except FileNotFoundError:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, REG_RUN_VALUE)
    except FileNotFoundError:
        pass


def self_delete_install_dir():
    # This process's own exe lives inside INSTALL_DIR, so it can't delete the
    # folder while running. Spawn a detached helper that waits for this
    # process to exit, then removes the folder.
    DETACHED_PROCESS = 0x00000008
    CREATE_NO_WINDOW = 0x08000000
    subprocess.Popen(
        ["cmd", "/c", "timeout", "/t", "2", "/nobreak", ">nul", "&",
         "rmdir", "/s", "/q", str(INSTALL_DIR)],
        creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
        close_fds=True,
    )


def main():
    root = tk.Tk()
    root.withdraw()

    confirm = messagebox.askyesno(
        f"{APP_NAME} Uninstall",
        f"Uninstall {APP_NAME}?\n\n"
        "This will remove the application, its scan history, and any quarantined files.",
    )
    if not confirm:
        sys.exit(0)

    kill_running_app()
    remove_shortcuts()
    remove_registry_entry()

    messagebox.showinfo(f"{APP_NAME} Uninstall", f"{APP_NAME} has been uninstalled.")

    self_delete_install_dir()
    sys.exit(0)


if __name__ == "__main__":
    main()
