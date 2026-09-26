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
    save_language,
    saved_language,
)
from core import i18n
from core.i18n import t
from shortcut import create_shortcut
from theme import ACCENT, ACCENT_DARK, BG, BORDER, CARD, CARD_HOVER, TEXT, TEXT_MUTED

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI Semibold", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_TITLE = ("Segoe UI Semibold", 17)


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
    style.configure("Muted.TLabel", background=BG, foreground=TEXT_MUTED, font=FONT_SMALL)
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
    style.configure("Card.TCheckbutton", background=BG, foreground=TEXT, font=FONT)
    style.map("Card.TCheckbutton", background=[("active", BG)])
    style.configure(
        "Accent.TButton", background=ACCENT, foreground="#ffffff", borderwidth=0,
        lightcolor=ACCENT, darkcolor=ACCENT, focuscolor=ACCENT, font=FONT_BOLD, padding=(18, 9),
    )
    style.map("Accent.TButton", background=[("disabled", BORDER), ("active", ACCENT_DARK)])
    style.configure(
        "Ghost.TButton", background=CARD, foreground=TEXT, borderwidth=1, bordercolor=BORDER,
        lightcolor=CARD, darkcolor=CARD, focuscolor=CARD, font=FONT, padding=(16, 8),
    )
    style.map("Ghost.TButton", background=[("active", CARD_HOVER)])
    style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor=CARD, borderwidth=0,
                    lightcolor=ACCENT, darkcolor=ACCENT)


class SetupWizard(tk.Tk):
    def __init__(self):
        super().__init__()
        i18n.set_language(saved_language())  # a reinstall keeps the language already chosen
        self.geometry("500x500")
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

    def _language_picker(self, parent):
        row = tk.Frame(parent, bg=BG)
        for code, native in i18n.LANGUAGES.items():
            selected = code == i18n.current()
            link = tk.Label(row, text=native, bg=ACCENT_DARK if selected else BG,
                            fg=TEXT if selected else TEXT_MUTED, font=FONT_BOLD if selected else FONT,
                            padx=8, pady=3, cursor="hand2")
            link.pack(side="left", padx=(0, 4))
            link.bind("<Button-1>", lambda e, c=code: self._set_language(c))
        return row

    def _set_language(self, code):
        if code != i18n.current():
            i18n.set_language(code)
            self._build_welcome_page()  # checkbox choices are kept (same variables)

    def _build_welcome_page(self):
        self._clear()
        self.title(t("setup_title"))
        ttk.Label(self.container, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        ttk.Label(self.container, text=t("setup_version", version=VERSION),
                  style="Muted.TLabel").pack(anchor="w", pady=(2, 14))
        self._language_picker(self.container).pack(anchor="w", pady=(0, 16))

        card = ttk.Frame(self.container, style="Card.TFrame", padding=16)
        card.pack(fill="x")
        tk.Label(card, text=t("setup_intro"), bg=CARD, fg=TEXT, font=FONT, wraplength=410,
                 justify="left").pack(anchor="w")
        tk.Label(card, text=t("setup_location", path=INSTALL_DIR), bg=CARD, fg=TEXT_MUTED,
                 font=FONT_SMALL, justify="left", wraplength=410).pack(anchor="w", pady=(10, 0))

        for text, var, pady in ((t("setup_desktop"), self.desktop_shortcut_var, (20, 4)),
                                (t("setup_autostart"), self.autostart_var, (0, 4)),
                                (t("setup_launch"), self.launch_after_var, (0, 0))):
            ttk.Checkbutton(self.container, text=text, variable=var,
                            style="Card.TCheckbutton").pack(anchor="w", pady=pady)

        self.status_label = ttk.Label(self.container, text="", style="Muted.TLabel")
        self.status_label.pack(anchor="w", pady=(16, 6))
        self.progress = ttk.Progressbar(self.container, mode="indeterminate")

        btn_row = ttk.Frame(self.container)
        btn_row.pack(side="bottom", fill="x", pady=(16, 0))
        ttk.Button(btn_row, text=t("setup_cancel"), style="Ghost.TButton", command=self.destroy).pack(side="right")
        self.install_btn = ttk.Button(btn_row, text=t("setup_install"), style="Accent.TButton",
                                      command=self._run_install)
        self.install_btn.pack(side="right", padx=(0, 8))

    def _run_install(self):
        self.install_btn.configure(state="disabled")
        self.progress.pack(fill="x", pady=(0, 8))
        self.progress.start(12)
        self.status_label.configure(text=t("setup_installing"))
        self.update_idletasks()
        try:
            self._do_install()
        except Exception as e:
            self.progress.stop()
            messagebox.showerror(t("setup_title"), t("setup_failed", error=e))
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
            raise RuntimeError(t("setup_err_damaged" if getattr(sys, "frozen", False) else "setup_err_source"))

        # An upgrade can't overwrite files the running app has open. This ends
        # both the window and the background agent (same exe).
        subprocess.run(["taskkill", "/IM", APP_EXE_NAME, "/F"], capture_output=True, check=False,
                       creationflags=0x08000000)
        app_exe = INSTALL_DIR / APP_SUBDIR / APP_EXE_NAME
        icon = INSTALL_DIR / ICON_NAME
        uninstall_exe = INSTALL_DIR / UNINSTALL_EXE_NAME
        try:
            self._status(t("setup_copying"))
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            self._copy_with_retry(lambda: shutil.copytree(app_src, INSTALL_DIR / APP_SUBDIR, dirs_exist_ok=True))
            for name in (UNINSTALL_EXE_NAME, ICON_NAME):
                if (src / name).is_file():
                    self._copy_with_retry(lambda n=name: shutil.copy2(src / n, INSTALL_DIR / n))
            # Nothing may point at the app until it's verifiably in place.
            if not app_exe.is_file() or not uninstall_exe.is_file():
                raise RuntimeError(t("setup_err_copy"))

            self._status(t("setup_registering"))
            self._write_uninstall_registry(app_exe, icon, uninstall_exe)
            save_language(i18n.current())

            self._status(t("setup_shortcuts"))
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
        ttk.Label(self.container, text=t("setup_complete"), style="Title.TLabel").pack(anchor="w")
        tk.Label(self.container, text=t("setup_complete_msg"), bg=BG, fg=TEXT_MUTED, font=FONT,
                 justify="left", wraplength=430).pack(anchor="w", pady=(10, 0))

        btn_row = ttk.Frame(self.container)
        btn_row.pack(side="bottom", fill="x", pady=(20, 0))
        ttk.Button(btn_row, text=t("setup_finish"), style="Accent.TButton", command=self._finish).pack(side="right")

    def _finish(self):
        if self.launch_after_var.get():
            app_exe = INSTALL_DIR / APP_SUBDIR / APP_EXE_NAME
            if app_exe.exists():
                subprocess.Popen([str(app_exe)], cwd=str(app_exe.parent))
        self.destroy()


if __name__ == "__main__":
    SetupWizard().mainloop()
