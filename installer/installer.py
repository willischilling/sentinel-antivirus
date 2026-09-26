"""Sentinel Antivirus setup wizard. Bundled by PyInstaller together with the
pre-built app exe and uninstaller exe as payload data.
"""
import shutil
import subprocess
import sys
import time
import tkinter as tk
import winreg
from pathlib import Path
from tkinter import messagebox, ttk

from common import (
    APP_EXE_NAME,
    APP_NAME,
    APP_SUBDIR,
    ICON_NAME,
    INSTALL_DIR,
    LEGACY_DESKTOP_DIR,
    PUBLISHER,
    REG_RUN_KEY,
    REG_RUN_VALUE,
    REG_UNINSTALL_KEY,
    START_MENU_DIR,
    UNINSTALL_EXE_NAME,
    VERSION,
    desktop_dir,
)
from shortcut import create_shortcut

BG = "#111317"
CARD = "#1e222a"
BORDER = "#2a2f3a"
TEXT = "#e8eaed"
TEXT_MUTED = "#8b93a3"
ACCENT = "#5b8def"
ACCENT_DARK = "#3a63b8"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")


def payload_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "payload"
    # Dev fallback: run against the freshly built dist/ folder.
    return Path(__file__).resolve().parent.parent / "dist"


def configure_style(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT, font=FONT)
    style.configure("TFrame", background=BG)
    style.configure("Card.TFrame", background=CARD)
    style.configure("TLabel", background=BG, foreground=TEXT, font=FONT)
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED, font=("Segoe UI", 9))
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
    style.configure("Card.TCheckbutton", background=BG, foreground=TEXT, font=FONT)
    style.map("Card.TCheckbutton", background=[("active", BG)])
    style.configure(
        "Accent.TButton", background=ACCENT, foreground="#0c0e12",
        borderwidth=0, focuscolor=ACCENT, font=FONT_BOLD, padding=(16, 9),
    )
    style.map("Accent.TButton", background=[("active", ACCENT_DARK)])
    style.configure(
        "Ghost.TButton", background=CARD, foreground=TEXT, borderwidth=1,
        bordercolor=BORDER, focuscolor=CARD, font=FONT, padding=(14, 8),
    )
    style.map("Ghost.TButton", background=[("active", BORDER)])
    style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=CARD, borderwidth=0)


class SetupWizard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} Setup")
        self.geometry("480x450")
        self.resizable(False, False)
        self.configure(bg=BG)
        try:
            self.iconbitmap(str(payload_dir() / ICON_NAME))
        except tk.TclError:
            pass
        configure_style(self)

        self.desktop_shortcut_var = tk.BooleanVar(value=True)
        self.launch_after_var = tk.BooleanVar(value=True)
        self.autostart_var = tk.BooleanVar(value=True)

        self.container = ttk.Frame(self, padding=28)
        self.container.pack(fill="both", expand=True)
        self._build_welcome_page()

    def _clear(self):
        for child in self.container.winfo_children():
            child.destroy()

    def _build_welcome_page(self):
        self._clear()
        ttk.Label(self.container, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        ttk.Label(self.container, text=f"Version {VERSION}", style="Muted.TLabel").pack(anchor="w", pady=(2, 20))

        card = ttk.Frame(self.container, style="Card.TFrame", padding=16)
        card.pack(fill="x")
        ttk.Label(card, text="This will install Sentinel Antivirus for your user account.",
                  background=CARD, foreground=TEXT, font=FONT, wraplength=400, justify="left").pack(anchor="w")
        ttk.Label(card, text=f"Install location:\n{INSTALL_DIR}", background=CARD,
                  foreground=TEXT_MUTED, font=("Segoe UI", 9), justify="left").pack(anchor="w", pady=(10, 0))

        ttk.Checkbutton(self.container, text="Create a desktop shortcut", variable=self.desktop_shortcut_var,
                         style="Card.TCheckbutton").pack(anchor="w", pady=(20, 4))
        ttk.Checkbutton(self.container, text="Start Sentinel when Windows starts (recommended)",
                         variable=self.autostart_var, style="Card.TCheckbutton").pack(anchor="w", pady=(0, 4))
        ttk.Checkbutton(self.container, text="Launch Sentinel Antivirus after installing", variable=self.launch_after_var,
                         style="Card.TCheckbutton").pack(anchor="w")

        self.status_label = ttk.Label(self.container, text="", style="Muted.TLabel")
        self.status_label.pack(anchor="w", pady=(20, 6))
        self.progress = ttk.Progressbar(self.container, mode="indeterminate")

        btn_row = ttk.Frame(self.container)
        btn_row.pack(side="bottom", fill="x", pady=(20, 0))
        ttk.Button(btn_row, text="Cancel", style="Ghost.TButton", command=self.destroy).pack(side="right")
        self.install_btn = ttk.Button(btn_row, text="Install", style="Accent.TButton", command=self._run_install)
        self.install_btn.pack(side="right", padx=(0, 8))

    def _run_install(self):
        self.install_btn.configure(state="disabled")
        self.progress.pack(fill="x", pady=(0, 8))
        self.progress.start(12)
        self.status_label.configure(text="Installing...")
        self.update_idletasks()
        try:
            self._do_install()
        except Exception as e:
            self.progress.stop()
            messagebox.showerror(f"{APP_NAME} Setup", f"Installation failed:\n{e}")
            self.install_btn.configure(state="normal")
            return
        self.progress.stop()
        self._build_finish_page()

    def _status(self, text):
        self.status_label.configure(text=text)
        self.update_idletasks()

    def _do_install(self):
        src = payload_dir()
        app_src = src / "app"
        if not (app_src / APP_EXE_NAME).is_file() or not (src / UNINSTALL_EXE_NAME).is_file():
            if not getattr(sys, "frozen", False):
                raise RuntimeError(
                    "This is the installer's source code, not the installer itself, so it has no "
                    "app files to install.\n\nRun SentinelSetup.exe instead (it's in the main folder "
                    "of the download), or build it first with build_installer.ps1.")
            raise RuntimeError("This installer is incomplete or damaged (the app files are missing). "
                               "Please download it again.")

        # An upgrade can't overwrite files the running app has open. This ends
        # both the window and the background agent (same exe).
        subprocess.run(["taskkill", "/IM", APP_EXE_NAME, "/F"], capture_output=True, check=False,
                       creationflags=0x08000000)
        app_exe = INSTALL_DIR / APP_SUBDIR / APP_EXE_NAME
        icon = INSTALL_DIR / ICON_NAME
        uninstall_exe = INSTALL_DIR / UNINSTALL_EXE_NAME
        try:
            self._status("Copying files...")
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            self._copy_with_retry(lambda: shutil.copytree(app_src, INSTALL_DIR / APP_SUBDIR, dirs_exist_ok=True))
            for name in (UNINSTALL_EXE_NAME, ICON_NAME):
                if (src / name).is_file():
                    self._copy_with_retry(lambda n=name: shutil.copy2(src / n, INSTALL_DIR / n))
            # Nothing may point at the app until it's verifiably in place.
            if not app_exe.is_file() or not uninstall_exe.is_file():
                raise RuntimeError("Sentinel's files didn't finish copying. Another security program may "
                                   "have blocked them.")

            self._status("Registering with Windows...")
            self._write_uninstall_registry(app_exe, icon, uninstall_exe)

            self._status("Creating shortcuts...")
            app_dir = INSTALL_DIR / APP_SUBDIR
            create_shortcut(START_MENU_DIR / f"{APP_NAME}.lnk", app_exe, app_dir, icon,
                            description="Signature + heuristic antivirus scanner")
            desktop_link = desktop_dir() / f"{APP_NAME}.lnk"
            legacy_link = LEGACY_DESKTOP_DIR / f"{APP_NAME}.lnk"
            if legacy_link != desktop_link:
                legacy_link.unlink(missing_ok=True)
            if self.desktop_shortcut_var.get():
                create_shortcut(desktop_link, app_exe, app_dir, icon,
                                description="Signature + heuristic antivirus scanner")
            else:
                desktop_link.unlink(missing_ok=True)

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY) as key:
                if self.autostart_var.get():
                    winreg.SetValueEx(key, REG_RUN_VALUE, 0, winreg.REG_SZ, f'"{app_exe}" --agent')
                else:
                    try:
                        winreg.DeleteValue(key, REG_RUN_VALUE)
                    except FileNotFoundError:
                        pass
        except Exception:
            if not app_exe.is_file():
                self._remove_dangling_entries()
                shutil.rmtree(INSTALL_DIR / APP_SUBDIR, ignore_errors=True)
                try:
                    INSTALL_DIR.rmdir()  # only succeeds if nothing else (user data) is in it
                except OSError:
                    pass
            raise

    @staticmethod
    def _copy_with_retry(copy, attempts=5):
        """Files of a just-closed Sentinel can stay locked for a moment."""
        for attempt in range(attempts):
            try:
                return copy()
            except PermissionError:
                if attempt == attempts - 1:
                    raise
                time.sleep(1)

    @staticmethod
    def _remove_dangling_entries():
        """After a failed install, remove anything that would point at a missing
        Sentinel.exe, so the user isn't left with broken shortcuts."""
        for link in (START_MENU_DIR / f"{APP_NAME}.lnk", desktop_dir() / f"{APP_NAME}.lnk"):
            link.unlink(missing_ok=True)
        for hive_key, value in ((REG_RUN_KEY, REG_RUN_VALUE), (REG_UNINSTALL_KEY, None)):
            try:
                if value:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, hive_key, 0, winreg.KEY_SET_VALUE) as k:
                        winreg.DeleteValue(k, value)
                else:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, hive_key)
            except FileNotFoundError:
                pass

    def _write_uninstall_registry(self, app_exe: Path, icon: Path, uninstall_exe: Path):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_UNINSTALL_KEY) as key:
            winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, VERSION)
            winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, PUBLISHER)
            winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(INSTALL_DIR))
            winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(icon))
            winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{uninstall_exe}"')
            winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)

    def _build_finish_page(self):
        self._clear()
        ttk.Label(self.container, text="Installation Complete", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            self.container,
            text=f"{APP_NAME} has been installed.\nYou can find it in the Start Menu.",
            style="Muted.TLabel", justify="left",
        ).pack(anchor="w", pady=(10, 0))

        btn_row = ttk.Frame(self.container)
        btn_row.pack(side="bottom", fill="x", pady=(20, 0))
        ttk.Button(btn_row, text="Finish", style="Accent.TButton", command=self._finish).pack(side="right")

    def _finish(self):
        if self.launch_after_var.get():
            app_exe = INSTALL_DIR / APP_EXE_NAME
            if app_exe.exists():
                subprocess.Popen([str(app_exe)], cwd=str(INSTALL_DIR))
        self.destroy()


if __name__ == "__main__":
    SetupWizard().mainloop()
