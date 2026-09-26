"""Background protection agent (Sentinel.exe --agent).

Runs without a main window so protection keeps going after the dashboard is
closed: watches files and processes, shows threat popups, owns the tray icon,
and writes to the shared activity log the main window displays.
"""
import queue
import threading
import time
import tkinter as tk
from pathlib import Path

import psutil

import launcher
import single_instance
from core import (
    activity, authenticode, database, i18n, paths, quarantine, scanner, settings, signatures, threat_intel,
)
from core.i18n import number, t
from gui import clip, configure_style, default_watch_path
from monitor import file_watcher, process_watcher, ransomware_watcher, startup_watcher
import theme as C
from toast import ToastManager

# Startup locations keep stable English names internally (they're part of the
# saved baseline); these map them to translated display names.
LOCATION_KEYS = {
    "Startup registry (your account)": "loc_run_user",
    "Run-once registry (your account)": "loc_runonce_user",
    "Startup registry (all users)": "loc_run_all",
    "Run-once registry (all users)": "loc_runonce_all",
    "Startup registry (all users, 32-bit)": "loc_run_all32",
    "Startup folder (your account)": "loc_folder_user",
    "Startup folder (all users)": "loc_folder_all",
    "Scheduled task": "loc_task",
}
LANGUAGE_CHECK_SECONDS = 2.0


def location_name(location: str) -> str:
    key = LOCATION_KEYS.get(location)
    return t(key) if key else location


class Agent(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        # Listen for "stop" before the slower setup below, so turning
        # protection off right after turning it on still works.
        self.events: "queue.Queue" = queue.Queue()
        single_instance.AGENT.listen(lambda: self.events.put(("stop", None)))
        configure_style(self)
        self._settings_mtime = None
        self._next_language_check = 0.0
        self._sync_language()

        database.init_db()
        if database.signature_count() == 0:
            signatures.seed_default_signatures()

        self.toasts = ToastManager(self)
        self._open_toasts = {}
        self._notified = set()

        saved = settings.load().get("watch_path")
        watch_path = saved if saved and Path(saved).exists() else default_watch_path()
        self.observer = file_watcher.watch(
            [watch_path], on_result=lambda r: self.events.put(("file", r))
        )
        self.proc_stop_flag = [False]
        threading.Thread(
            target=process_watcher.monitor_loop,
            args=(1.0, lambda a: self.events.put(("process", a)), self.proc_stop_flag),
            daemon=True,
        ).start()

        threading.Thread(
            target=startup_watcher.watch_loop,
            args=(lambda e: self.events.put(("startup", self._assess_startup(e))), self.proc_stop_flag),
            daemon=True,
        ).start()
        personal = ransomware_watcher.default_folders()
        self.ransom_observer = ransomware_watcher.watch(
            personal, lambda a: self.events.put(("ransomware", a))) if personal else None

        self.tray = self._start_tray()
        activity.log(t("log_started", folder=watch_path), "muted")
        threading.Thread(target=self._update_loop, daemon=True).start()
        self.after(100, self._pump)

    def _sync_language(self):
        """The window saves language and theme changes to the settings file;
        follow them here without a restart (popups, log lines, tray menu)."""
        try:
            mtime = settings.SETTINGS_PATH.stat().st_mtime_ns
        except FileNotFoundError:
            mtime = None
        if mtime != self._settings_mtime:
            self._settings_mtime = mtime
            self._theme_choice = settings.load().get("theme", "dark")
        # Checked every time, since "Match Windows" can change without the file changing.
        palette = C.resolve(getattr(self, "_theme_choice", "dark"))
        if palette != C.current:
            C.apply(palette)
            configure_style(self)  # popup buttons
        if mtime == getattr(self, "_language_mtime", object()):
            return
        self._language_mtime = mtime
        before = i18n.current()
        i18n.set_language(settings.load().get("language"))
        tray = getattr(self, "tray", None)
        if tray and i18n.current() != before:
            tray.icon.title = t("tray_title")
            tray.icon.update_menu()

    def _update_loop(self):
        """Keeps malware fingerprints and YARA rules current while protecting."""
        while True:
            if threat_intel.needs_update():
                try:
                    result = threat_intel.update()
                    activity.log(t("log_intel_updated", hashes=number(result["hashes"]),
                                   rules=number(result["rules"])), "muted")
                except RuntimeError:
                    pass  # the window is already running an update
                except Exception as e:
                    activity.log(t("log_intel_failed", error=e), "warn")
            time.sleep(600)

    def _start_tray(self):
        try:
            from tray import Tray

            tray = Tray(
                paths.resource("assets/icon.png"),
                t("tray_title"),
                [
                    (lambda item: t("tray_open"), lambda: self.events.put(("open_ui", None)), True),
                    (lambda item: t("tray_turn_off"), lambda: self.events.put(("turn_off", None)), False),
                ],
            )
            tray.start()
            return tray
        except Exception:
            return None

    def _pump(self):
        if time.monotonic() >= self._next_language_check:
            self._next_language_check = time.monotonic() + LANGUAGE_CHECK_SECONDS
            self._sync_language()
        processed = 0
        try:
            while processed < 40:
                kind, payload = self.events.get_nowait()
                if kind == "file":
                    self._on_file_alert(payload)
                elif kind == "process":
                    self._on_process_alert(payload)
                elif kind == "startup":
                    self._on_startup_alert(*payload)
                elif kind == "ransomware":
                    self._on_ransomware_alert(payload)
                elif kind == "open_ui":
                    launcher.open_ui()
                elif kind == "turn_off":
                    settings.save(protection_on=False)
                    self._shutdown()
                    return
                elif kind == "stop":
                    self._shutdown()
                    return
                processed += 1
        except queue.Empty:
            pass
        self.after(50, self._pump)

    def _shutdown(self):
        for observer in (self.observer, self.ransom_observer):
            if observer:
                observer.stop()
                observer.join()
        self.proc_stop_flag[0] = True  # also stops the process and startup watchers
        if self.tray:
            self.tray.stop()
        activity.log(t("log_stopped"), "muted")
        self.destroy()

    def _log_failure(self, target):
        return lambda action, err: activity.log(
            t("log_action_failed", action=action, target=target, error=err), "warn")

    # ------------------------------------------------------------ alerts --
    def _on_file_alert(self, result):
        # A file being written fires several change events; only notify once
        # per path while its popup is open, and once per (path, content) ever.
        path_key = str(result.path)
        seen_key = (path_key, result.file_hash)
        if path_key in self._open_toasts or seen_key in self._notified:
            return
        self._notified.add(seen_key)

        is_threat = result.verdict == "signature_match"
        if is_threat:
            activity.log(t("log_threat", path=result.path, name=result.signature_name), "threat")
        else:
            activity.log(t("log_suspicious", path=result.path, flags="; ".join(result.heuristic_flags)), "warn")
        self._notify_file(result, is_threat)

    def _notify_file(self, result, is_threat: bool):
        path = result.path
        path_key = str(path)
        if is_threat:
            reason = result.signature_name
            title, accent, detail = t("toast_virus_detected"), C.BAD, t("toast_matches_known", name=reason)
        else:
            flags = result.heuristic_flags
            reason = flags[0]
            detail = t("toast_more", flag=reason, n=len(flags) - 1) if len(flags) > 1 else reason
            title, accent = t("toast_suspicious_file"), C.WARN

        def do_quarantine():
            dest = quarantine.quarantine_file(path, reason)
            activity.log(t("log_quarantined", path=path, dest=dest.name), "muted")
            return t("msg_moved_quarantine")

        def do_delete():
            path.unlink()
            database.log_scan(path_key, "deleted", reason)
            activity.log(t("log_deleted", path=path), "muted")
            return t("msg_file_deleted")

        toast = self.toasts.show(
            title=title,
            filename=path.name,
            detail=detail,
            location=str(path.parent),
            accent=accent,
            actions=[
                (t("btn_quarantine"), "Accent.TButton", do_quarantine),
                (t("btn_delete"), "Danger.TButton", do_delete),
                (t("btn_ignore"), "Ghost.TButton", lambda: None),
            ],
            on_error=self._log_failure(path),
        )
        self._open_toasts[path_key] = toast
        toast.bind("<Destroy>", lambda e: self._open_toasts.pop(path_key, None)
                   if e.widget is toast else None)
        self._beep(is_threat)

    def _on_process_alert(self, alert):
        activity.log(t("log_process_match", pid=alert.pid, name=alert.name, threat=alert.signature_name),
                     "threat")
        exe = Path(alert.exe_path)

        def end_process():
            if not process_watcher.kill_process(alert.pid):
                raise RuntimeError(t("err_admin_blocked"))
            activity.log(t("log_ended", pid=alert.pid, name=alert.name), "muted")
            return t("msg_program_ended")

        def end_and_quarantine():
            end_process()
            dest = quarantine.quarantine_file(exe, alert.signature_name)
            activity.log(t("log_quarantined", path=exe, dest=dest.name), "muted")
            return t("msg_program_ended_quarantined")

        self.toasts.show(
            title=t("toast_virus_running"),
            filename=alert.name,
            detail=t("toast_matches_known", name=alert.signature_name),
            location=str(exe.parent),
            accent=C.BAD,
            actions=[
                (t("btn_end_program"), "Danger.TButton", end_process),
                (t("btn_quarantine"), "Accent.TButton", end_and_quarantine),
                (t("btn_ignore"), "Ghost.TButton", lambda: None),
            ],
            on_error=self._log_failure(alert.name),
        )
        self._beep(True)

    # ------------------------------------------------------ startup alerts --
    @staticmethod
    def _assess_startup(entry):
        """Runs on the watcher thread (may take a moment): what does the entry launch, and is it bad?"""
        program = startup_watcher.target_program(entry)
        result = scanner.scan_file(program) if program else None
        signature = authenticode.check(program) if program else authenticode.UNSIGNED
        return entry, program, result, signature

    def _on_startup_alert(self, entry, program, result, signature):
        is_threat = bool(result and result.verdict == "signature_match")
        subject = program.name if program else entry.name
        is_task = entry.kind == "task"
        if (is_task and not is_threat and entry.name.startswith("\\Microsoft\\")
                and signature.signed and "Microsoft" in (signature.publisher or "")):
            # Windows adds and updates its own tasks all the time; don't pop up for those.
            activity.log(t("log_windows_task", name=entry.name), "muted")
            return
        trusted = None if is_threat else startup_watcher.trusted_reason(entry, program, signature)
        if trusted:
            by = t("trusted_component") if trusted == "component" else trusted
            activity.log(t("log_trusted_startup", name=entry.name, publisher=by), "muted")
            return
        short_name = entry.name.rsplit("\\", 1)[-1]
        if is_threat:
            title, accent = t("startup_virus_task" if is_task else "startup_virus_program"), C.BAD
            detail = t("toast_matches_known", name=result.signature_name)
        elif signature.signed:
            title, accent = t("startup_new_task" if is_task else "startup_new_program"), C.ACCENT
            detail = t("startup_signed", name=subject, publisher=signature.publisher)
        else:
            title, accent = t("startup_new_task" if is_task else "startup_new_program"), C.WARN
            detail = t("startup_unsigned", name=subject)
        location = location_name(entry.location)
        activity.log(t("log_startup_added", name=entry.name, location=location, command=entry.command),
                     "threat" if is_threat else "warn")

        def remove_entry():
            startup_watcher.remove(entry)
            activity.log(t("log_startup_removed", name=entry.name, command=entry.command), "muted")
            return t("msg_task_deleted") if is_task else t("msg_removed_startup")

        def remove_and_quarantine():
            remove_entry()
            if program:
                for proc in psutil.process_iter(["pid", "exe"]):
                    if proc.info.get("exe") and Path(proc.info["exe"]) == program:
                        process_watcher.kill_process(proc.pid)
                dest = quarantine.quarantine_file(program, result.signature_name)
                activity.log(t("log_quarantined", path=program, dest=dest.name), "muted")
            return t("msg_removed_quarantined")

        actions = [(t("btn_quarantine"), "Accent.TButton", remove_and_quarantine)] if is_threat and program else []
        actions += [(t("btn_remove"), "Danger.TButton", remove_entry), (t("btn_keep"), "Ghost.TButton", lambda: None)]
        self.toasts.show(
            title=title,
            filename=t("startup_runs_schedule" if is_task else "startup_runs_boot", name=short_name),
            detail=detail,
            location=clip(f"{location}: {entry.command}", 150), accent=accent, actions=actions,
            on_error=self._log_failure(entry.name),
        )
        self._beep(is_threat)

    # --------------------------------------------------- ransomware alerts --
    def _on_ransomware_alert(self, alert):
        activity.log(t("log_ransomware", n=alert.damaged, folder=alert.folder, examples=", ".join(alert.examples),
                       name=alert.suspect_name or t("unknown")), "threat")
        actions = []
        if alert.suspect_pid:
            publisher = authenticode.check(Path(alert.suspect_exe)).publisher if alert.suspect_exe else None
            mb = number(round(alert.written_mb))
            detail = t("ransom_cause" if alert.confirmed else "ransom_likely_cause",
                       name=alert.suspect_name, mb=mb)
            if publisher:
                detail = t("ransom_signed", detail=detail, publisher=publisher)

            def end_program():
                if not process_watcher.kill_process(alert.suspect_pid):
                    raise RuntimeError(t("err_admin_blocked"))
                activity.log(t("log_ended", pid=alert.suspect_pid, name=alert.suspect_name), "muted")
                return t("msg_program_ended")

            def end_and_quarantine():
                end_program()
                if alert.suspect_exe:
                    dest = quarantine.quarantine_file(Path(alert.suspect_exe), "Ransomware-like behavior")
                    activity.log(t("log_quarantined", path=alert.suspect_exe, dest=dest.name), "muted")
                return t("msg_ransom_quarantined")

            actions = [(t("btn_end_program"), "Danger.TButton", end_program),
                       (t("btn_quarantine"), "Accent.TButton", end_and_quarantine)]
        else:
            detail = t("ransom_unknown")
        actions.append((t("btn_ignore"), "Ghost.TButton", lambda: None))
        self.toasts.show(
            title=t("toast_possible_ransomware"), filename=t("ransom_unreadable", n=alert.damaged),
            detail=detail, location=alert.folder, accent=C.BAD, actions=actions,
            on_error=self._log_failure(alert.folder),
        )
        self._beep(True)

    @staticmethod
    def _beep(is_threat: bool):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONHAND if is_threat else winsound.MB_ICONEXCLAMATION)
        except (ImportError, RuntimeError):
            pass


def main():
    if not single_instance.AGENT.acquire():
        return  # already protecting
    Agent().mainloop()
