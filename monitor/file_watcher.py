"""Real-time filesystem monitoring: scan new/modified files as they appear."""
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core import paths, scanner

# Browsers write downloads to a temp name, then rename it when finished; the
# rename arrives as on_moved, so the completed file still gets scanned.
IN_PROGRESS_SUFFIXES = {".crdownload", ".part", ".partial", ".download", ".tmp"}
QUARANTINE_DIR = paths.QUARANTINE_DIR.resolve()


class ScanOnChangeHandler(FileSystemEventHandler):
    def __init__(self, on_result=None):
        super().__init__()
        self.on_result = on_result or (lambda r: None)

    def _handle(self, path_str: str):
        path = Path(path_str)
        if path.suffix.lower() in IN_PROGRESS_SUFFIXES:
            return
        try:
            if path.resolve().is_relative_to(QUARANTINE_DIR) or not path.is_file():
                return
        except OSError:
            return
        result = scanner.scan_file(path)
        if result.verdict in ("signature_match", "suspicious"):
            self.on_result(result)

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path)


def watch(paths: list[str], on_result=None) -> Observer:
    """Starts watching the given paths in the background. Returns the Observer
    so the caller can call .stop() / .join() on it.
    """
    handler = ScanOnChangeHandler(on_result=on_result)
    observer = Observer()
    for path in paths:
        observer.schedule(handler, path, recursive=True)
    observer.start()
    return observer
