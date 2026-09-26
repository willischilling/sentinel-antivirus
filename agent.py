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
    activity, authenticode, database, paths, quarantine, scanner, settings, signatures, threat_intel,
)
from gui import clip, configure_style, default_watch_path
from monitor import file_watcher, process_watcher, ransomware_watcher, startup_watcher
from theme import ACCENT, BAD, WARN
from toast import ToastManager


class Agent(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        # Listen for "stop" before the slower setup below, so turning
        # protection off right after turning it on still works.
        self.events: "queue.Queue" = queue.Queue()
        single_instance.AGENT.listen(lambda: self.events.put(("stop", None)))
        configure_style(self)

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
        activity.log(f"Protection started — watching {watch_path}", "muted")
        threading.Thread(target=self._update_loop, daemon=True).start()
        self.after(100, self._pump)

    def _update_loop(self):
        """Keeps malware fingerprints and YARA rules current while protecting."""
        while True:
            if threat_intel.needs_update():
                try:
                    result = threat_intel.update(lambda msg: None)
                    activity.log(
                        f"Threat database updated: {result['hashes']:,} malware fingerprints, "
                        f"{result['rules']:,} YARA rules", "muted")
                except RuntimeError:
                    pass  # the window is already running an update
                except Exception as e:
                    activity.log(f"Threat database update failed (will retry): {e}", "warn")
            time.sleep(600)

    def _start_tray(self):
        try:
            from tray import Tray

            tray = Tray(
                paths.resource("assets/icon.png"),
                "Sentinel — Protection On",
                [
                    ("Open Sentinel", lambda: self.events.put(("open_ui", None)), True),
                    ("Turn Off Protection", lambda: self.events.put(("turn_off", None)), False),
                ],
            )
            tray.start()
            return tray
        except Exception:
            return None

    def _pump(self):
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
        activity.log("Protection stopped", "muted")
        self.destroy()

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
            activity.log(f"THREAT DETECTED: {result.path} ({result.signature_name})", "threat")
        else:
            activity.log(f"Suspicious file: {result.path} — {'; '.join(result.heuristic_flags)}", "warn")
        self._notify_file(result, is_threat)

    def _notify_file(self, result, is_threat: bool):
        path = result.path
        path_key = str(path)
        if is_threat:
            reason = result.signature_name
            title, accent, detail = "Virus detected", BAD, f"Matches known threat: {reason}"
        else:
            flags = result.heuristic_flags
            reason = flags[0]
            more = f" (+{len(flags) - 1} more)" if len(flags) > 1 else ""
            title, accent, detail = "Suspicious file", WARN, f"{reason}{more}"

        def do_quarantine():
            dest = quarantine.quarantine_file(path, reason)
            activity.log(f"Quarantined {path} -> {dest.name}", "muted")
            return "Moved to quarantine."

        def do_delete():
            path.unlink()
            database.log_scan(path_key, "deleted", reason)
            activity.log(f"Deleted {path}", "muted")
            return "File deleted."

        toast = self.toasts.show(
            title=title,
            filename=path.name,
            detail=detail,
            location=str(path.parent),
            accent=accent,
            actions=[
                ("Quarantine", "Accent.TButton", do_quarantine),
                ("Delete", "Danger.TButton", do_delete),
                ("Ignore", "Ghost.TButton", lambda: None),
            ],
            on_error=lambda action, err: activity.log(f"{action} failed for {path}: {err}", "warn"),
        )
        self._open_toasts[path_key] = toast
        toast.bind("<Destroy>", lambda e: self._open_toasts.pop(path_key, None)
                   if e.widget is toast else None)
        self._beep(is_threat)

    def _on_process_alert(self, alert):
        activity.log(f"Process match: PID {alert.pid} ({alert.name}) -> {alert.signature_name}", "threat")
        exe = Path(alert.exe_path)

        def end_process():
            if not process_watcher.kill_process(alert.pid):
                raise RuntimeError("Windows blocked it (it may be running as administrator)")
            activity.log(f"Ended PID {alert.pid} ({alert.name})", "muted")
            return "Program ended."

        def end_and_quarantine():
            end_process()
            dest = quarantine.quarantine_file(exe, alert.signature_name)
            activity.log(f"Quarantined {exe} -> {dest.name}", "muted")
            return "Program ended and file quarantined."

        self.toasts.show(
            title="Virus running",
            filename=alert.name,
            detail=f"Matches known threat: {alert.signature_name}",
            location=str(exe.parent),
            accent=BAD,
            actions=[
                ("End Program", "Danger.TButton", end_process),
                ("Quarantine", "Accent.TButton", end_and_quarantine),
                ("Ignore", "Ghost.TButton", lambda: None),
            ],
            on_error=lambda action, err: activity.log(f"{action} failed for {alert.name}: {err}", "warn"),
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
            activity.log(f"Windows added scheduled task {entry.name}", "muted")
            return
        when = "on a schedule" if is_task else "when Windows starts"
        noun = "scheduled task" if is_task else "startup program"
        if is_threat:
            title, accent = f"Virus added as a {noun}", BAD
            detail = f"{subject} matches known threat: {result.signature_name}"
        elif signature.signed:
            title, accent = f"New {noun}", ACCENT
            detail = f"{subject} is signed by {signature.publisher}"
        else:
            title, accent = f"New {noun}", WARN
            detail = f"{subject} isn't signed by a known publisher"
        activity.log(f"Startup entry added: {entry.name} ({entry.location}) -> {entry.command}",
                     "threat" if is_threat else "warn")

        def remove_entry():
            startup_watcher.remove(entry)
            activity.log(f"Removed {noun} {entry.name} (was: {entry.command})", "muted")
            return "Scheduled task deleted." if is_task else "Removed from startup."

        def remove_and_quarantine():
            remove_entry()
            if program:
                for proc in psutil.process_iter(["pid", "exe"]):
                    if proc.info.get("exe") and Path(proc.info["exe"]) == program:
                        process_watcher.kill_process(proc.pid)
                dest = quarantine.quarantine_file(program, result.signature_name)
                activity.log(f"Quarantined {program} -> {dest.name}", "muted")
            return "Removed from startup and quarantined."

        actions = [("Quarantine", "Accent.TButton", remove_and_quarantine)] if is_threat and program else []
        actions += [("Remove", "Danger.TButton", remove_entry), ("Keep", "Ghost.TButton", lambda: None)]
        self.toasts.show(
            title=title, filename=f"{entry.name.rsplit(chr(92), 1)[-1]} will run {when}", detail=detail,
            location=clip(f"{entry.location}: {entry.command}", 150), accent=accent, actions=actions,
            on_error=lambda action, err: activity.log(f"{action} failed for startup entry {entry.name}: {err}", "warn"),
        )
        self._beep(is_threat)

    # --------------------------------------------------- ransomware alerts --
    def _on_ransomware_alert(self, alert):
        examples = ", ".join(alert.examples)
        activity.log(f"POSSIBLE RANSOMWARE: {alert.damaged} files became unreadable in {alert.folder} "
                     f"(e.g. {examples}); likely cause: {alert.suspect_name or 'unknown'}", "threat")
        actions = []
        if alert.suspect_pid:
            publisher = authenticode.check(Path(alert.suspect_exe)).publisher if alert.suspect_exe else None
            certainty = "Cause" if alert.confirmed else "Likely cause"
            detail = f"{certainty}: {alert.suspect_name} ({alert.written_mb:.0f} MB written just now"
            if alert.confirmed:
                detail += ", has files open in this folder"
            detail += ")"
            if publisher:
                detail += f". Signed by {publisher}"

            def end_program():
                if not process_watcher.kill_process(alert.suspect_pid):
                    raise RuntimeError("Windows blocked it (it may be running as administrator)")
                activity.log(f"Ended {alert.suspect_name} (PID {alert.suspect_pid})", "muted")
                return "Program ended."

            def end_and_quarantine():
                end_program()
                if alert.suspect_exe:
                    dest = quarantine.quarantine_file(Path(alert.suspect_exe), "Ransomware-like behavior")
                    activity.log(f"Quarantined {alert.suspect_exe} -> {dest.name}", "muted")
                return ("Program ended and quarantined. Restore damaged files from OneDrive's "
                        "version history or a backup.")

            actions = [("End Program", "Danger.TButton", end_program),
                       ("Quarantine", "Accent.TButton", end_and_quarantine)]
        else:
            detail = "Couldn't tell which program is doing it. Check what's running now."
        actions.append(("Ignore", "Ghost.TButton", lambda: None))
        self.toasts.show(
            title="Possible ransomware", filename=f"{alert.damaged} files suddenly became unreadable",
            detail=detail, location=alert.folder, accent=BAD, actions=actions,
            on_error=lambda action, err: activity.log(f"{action} failed: {err}", "warn"),
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
