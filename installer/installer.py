"""Sentinel Antivirus setup wizard. Bundled by PyInstaller together with the
pre-built app exe and uninstaller exe as payload data.
"""
import ctypes
import os
import shutil
import stat
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
    BROWSER_EXE_NAME,
    BROWSER_NAME,
    BROWSER_SUBDIR,
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
OLD_SUFFIX = ".sentinel-old"  # a locked file from the previous version, moved aside so the new one fits
CREATE_NO_WINDOW = 0x08000000


class FileInUseError(RuntimeError):
    """A file of the previous version couldn't be replaced, even after moving it aside."""


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


def _startup_entry_exists() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY) as key:
            winreg.QueryValueEx(key, REG_RUN_VALUE)
        return True
    except FileNotFoundError:
        return False


class SetupWizard(tk.Tk):
    def __init__(self, update_mode: bool = False, quiet: bool = False):
        super().__init__()
        # Quiet: a background update by Sentinel itself. No window at all, and afterwards
        # only the background protection is restarted (the main window wasn't open).
        self.quiet = update_mode and quiet
        if self.quiet:
            self.withdraw()
        i18n.set_language(saved_language())  # a reinstall keeps the language already chosen
        self.update_mode = update_mode
        self.geometry("500x530")
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
        self.browser_var = tk.BooleanVar(value=True)

        self.container = ttk.Frame(self, padding=28)
        self.container.pack(fill="both", expand=True)
        if update_mode:
            # Keep whatever the user chose last time; ask nothing.
            self.desktop_shortcut_var.set((desktop_dir() / f"{APP_NAME}.lnk").exists())
            self.autostart_var.set(_startup_entry_exists())
            self.browser_var.set((INSTALL_DIR / BROWSER_SUBDIR / BROWSER_EXE_NAME).exists())  # keep the choice
            self._build_update_page()
            self.after(400, self._run_update)
        else:
            self._build_welcome_page()

    def _build_update_page(self):
        self._clear()
        self.title(t("setup_title"))
        self.geometry("500x230")
        ttk.Label(self.container, text=t("setup_updating_title"), style="Title.TLabel").pack(anchor="w")
        tk.Label(self.container, text=t("setup_updating_msg", version=VERSION), bg=BG, fg=TEXT_MUTED,
                 font=FONT, justify="left", wraplength=440).pack(anchor="w", pady=(8, 18))
        self.status_label = ttk.Label(self.container, text="", style="Muted.TLabel")
        self.status_label.pack(anchor="w", pady=(0, 6))
        self.progress = ttk.Progressbar(self.container, mode="indeterminate")
        self.progress.pack(fill="x")
        self.progress.start(12)

    def _run_update(self):
        try:
            self._do_install()
        except Exception as e:
            self.progress.stop()
            if self.quiet:  # nobody's watching: give up quietly, Sentinel tries again later
                self.destroy()
                return
            messagebox.showerror(t("setup_title"), t("setup_failed", error=e))
            self.update_mode = False
            self.geometry("500x530")
            self._build_welcome_page()  # fall back to the normal installer so the user can retry
            return
        self.launch_after_var.set(True)
        self._finish()

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

        options = [(t("setup_desktop"), self.desktop_shortcut_var, (20, 4))]
        if (payload_dir() / BROWSER_SUBDIR).is_dir():
            options.append((t("setup_browser"), self.browser_var, (0, 4)))
        for text, var, pady in (*options,
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
        # both the window and the background agent (same exe), then waits for
        # Windows to finish tearing them down; killed processes keep their exe
        # locked for a moment after taskkill returns.
        images = (APP_EXE_NAME, BROWSER_EXE_NAME)  # an open Sentinel Browser locks its files too
        for image in images:
            subprocess.run(["taskkill", "/IM", image, "/F"], capture_output=True, check=False,
                           creationflags=CREATE_NO_WINDOW)
        for image in images:
            self._wait_for_exit(image)
        self._end_elevated_copies(images)
        self._remove_old_files()
        app_exe = INSTALL_DIR / APP_SUBDIR / APP_EXE_NAME
        icon = INSTALL_DIR / ICON_NAME
        uninstall_exe = INSTALL_DIR / UNINSTALL_EXE_NAME
        try:
            self._status(t("setup_copying"))
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)
            self._copy_tree(app_src, INSTALL_DIR / APP_SUBDIR)
            for name in (UNINSTALL_EXE_NAME, ICON_NAME):
                if (src / name).is_file():
                    self._copy_file(src / name, INSTALL_DIR / name, time.monotonic() + 20)
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

            self._install_browser(src, icon)

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

    def _install_browser(self, src: Path, icon: Path):
        """Sentinel Browser: its own folder and shortcuts, or removes them if it's been unticked."""
        browser_dir = INSTALL_DIR / BROWSER_SUBDIR
        links = [START_MENU_DIR / f"{BROWSER_NAME}.lnk", desktop_dir() / f"{BROWSER_NAME}.lnk"]
        if self.browser_var.get() and (src / BROWSER_SUBDIR).is_dir():
            self._status(t("setup_browser_copying"))
            self._copy_tree(src / BROWSER_SUBDIR, browser_dir)
            exe = browser_dir / BROWSER_EXE_NAME
            create_shortcut(links[0], exe, browser_dir, icon, description="Private browsing protected by Sentinel")
            if self.desktop_shortcut_var.get():
                create_shortcut(links[1], exe, browser_dir, icon, description="Private browsing protected by Sentinel")
            else:
                links[1].unlink(missing_ok=True)
        else:
            for link in links:
                link.unlink(missing_ok=True)
            shutil.rmtree(browser_dir, ignore_errors=True)

    @staticmethod
    def _is_running(image_name) -> bool:
        out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH"],
                             capture_output=True, text=True, creationflags=CREATE_NO_WINDOW).stdout
        return image_name.lower() in out.lower()

    def _wait_for_exit(self, image_name, timeout=20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self._is_running(image_name):
                return True
            time.sleep(0.5)
        return False

    def _end_elevated_copies(self, images):
        """A Sentinel started as administrator (or a one-shot --elevated helper) survives our
        taskkill, and keeps its files locked. Ending it takes the Windows admin prompt."""
        running = [image for image in images if self._is_running(image)]
        if not running or self.quiet:  # quiet update: nobody to ask; the copy below decides
            return
        if not messagebox.askokcancel(t("setup_title"), t("setup_admin_close")):
            return
        from core import elevate

        args = subprocess.list2cmdline(["/F", *(part for image in running for part in ("/IM", image))])
        info = elevate.SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(elevate.SHELLEXECUTEINFOW),
                                         fMask=elevate.SEE_MASK_NOCLOSEPROCESS, lpVerb="runas",
                                         lpFile="taskkill.exe", lpParameters=args, nShow=0)
        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
            return  # declined: try the copy anyway, it may still work by moving files aside
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 30_000)
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
        for image in running:
            self._wait_for_exit(image)

    @staticmethod
    def _remove_old_files():
        """Deletes files an earlier install moved aside. Ones still in use stay for next time."""
        for old in INSTALL_DIR.rglob(f"*{OLD_SUFFIX}"):
            try:
                old.unlink()
            except OSError:
                pass

    def _copy_tree(self, src: Path, dst: Path, timeout=20.0):
        """Like copytree(dirs_exist_ok=True), but each file goes through _copy_file,
        so one locked file doesn't fail the whole copy."""
        deadline = time.monotonic() + timeout
        dst.mkdir(parents=True, exist_ok=True)
        for path in src.rglob("*"):
            target = dst / path.relative_to(src)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                self._copy_file(path, target, deadline)

    @staticmethod
    def _copy_file(src: Path, dst: Path, deadline: float):
        """Copies one file over the old version. Files of a just-closed Sentinel (or ones an
        antivirus is scanning) can stay locked. Windows won't let a locked file be overwritten,
        but usually lets it be renamed, so the old one is moved aside (deleted on the next
        install) and the new one takes its place. Otherwise retry until the deadline."""
        moved_aside = False
        while True:
            try:
                shutil.copy2(src, dst)
                return
            except OSError as e:
                if isinstance(e, PermissionError) and not moved_aside and dst.exists():
                    try:
                        os.chmod(dst, stat.S_IWRITE)  # a read-only file can't be overwritten either
                        os.replace(dst, dst.with_name(f"{dst.name}.{time.time_ns()}{OLD_SUFFIX}"))
                        moved_aside = True
                        continue
                    except OSError:
                        pass
                if time.monotonic() >= deadline:
                    if isinstance(e, PermissionError):
                        raise FileInUseError(t("setup_err_locked", file=dst.name)) from e
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
                args = [str(app_exe), "--agent"] if self.quiet else [str(app_exe)]
                subprocess.Popen(args, cwd=str(app_exe.parent))
        self.destroy()


if __name__ == "__main__":
    SetupWizard(update_mode="--update" in sys.argv, quiet="--quiet" in sys.argv).mainloop()
