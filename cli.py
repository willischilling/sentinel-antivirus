"""Command-line interface for the antivirus."""
import argparse
import sys
import threading
import time
from pathlib import Path

from core import database, quarantine, scanner, signatures
from monitor import file_watcher, process_watcher


def cmd_init(args):
    database.init_db()
    signatures.seed_default_signatures()
    print(f"Database initialized at core/../data/signatures.db")
    print(f"Signatures loaded: {database.signature_count()}")


def cmd_import(args):
    signatures.import_signature_list(Path(args.file))
    print(f"Imported signatures. Total now: {database.signature_count()}")


def cmd_scan(args):
    target = Path(args.path)
    total = 0
    threats = 0
    for result in scanner.scan_directory(target, recursive=not args.no_recursive):
        total += 1
        if result.verdict == "signature_match":
            threats += 1
            print(f"[THREAT] {result.path}  ->  {result.signature_name}")
            if args.quarantine:
                dest = quarantine.quarantine_file(result.path, result.signature_name)
                print(f"         quarantined -> {dest}")
        elif result.verdict == "suspicious":
            threats += 1
            print(f"[SUSPICIOUS] {result.path}")
            for flag in result.heuristic_flags:
                print(f"    - {flag}")
        elif result.verdict == "error":
            print(f"[SKIP] {result.path} ({result.error})")

    print(f"\nScan complete: {total} files scanned, {threats} flagged.")


def cmd_watch(args):
    print(f"Watching {args.path} for real-time file changes... (Ctrl+C to stop)")

    def on_result(result):
        if result.verdict == "signature_match":
            print(f"\n[REALTIME THREAT] {result.path} -> {result.signature_name}")
            if args.quarantine:
                dest = quarantine.quarantine_file(result.path, result.signature_name)
                print(f"         quarantined -> {dest}")
        else:
            print(f"\n[REALTIME SUSPICIOUS] {result.path}: {result.heuristic_flags}")

    observer = file_watcher.watch([args.path], on_result=on_result)

    stop_flag = [False]

    def on_proc_alert(alert):
        print(
            f"\n[PROCESS ALERT] PID {alert.pid} ({alert.name}) at {alert.exe_path} "
            f"matches signature '{alert.signature_name}'"
        )
        answer = input("Terminate this process? [y/N]: ").strip().lower()
        if answer == "y":
            ok = process_watcher.kill_process(alert.pid)
            print("Terminated." if ok else "Failed to terminate (check permissions).")

    proc_thread = threading.Thread(
        target=process_watcher.monitor_loop,
        args=(args.interval, on_proc_alert, stop_flag),
        daemon=True,
    )
    proc_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        stop_flag[0] = True
        observer.stop()
        observer.join()


def cmd_procscan(args):
    alerts = process_watcher.scan_running_processes()
    if not alerts:
        print("No running processes matched known-bad signatures.")
        return
    for alert in alerts:
        print(f"[PROCESS THREAT] PID {alert.pid} ({alert.name}) -> {alert.signature_name}")
        print(f"    path: {alert.exe_path}")


def cmd_quarantine_list(args):
    rows = quarantine.list_quarantine()
    if not rows:
        print("Quarantine is empty.")
        return
    for qid, original, qpath, reason, when in rows:
        print(f"[{qid}] {when}  reason={reason}")
        print(f"     original: {original}")
        print(f"     stored:   {qpath}")


def cmd_quarantine_restore(args):
    result = quarantine.restore_file(args.id)
    if result:
        print(f"Restored to {result}")
    else:
        print("No such quarantine entry.")


def cmd_quarantine_delete(args):
    ok = quarantine.delete_permanently(args.id)
    print("Deleted." if ok else "No such quarantine entry.")


def main():
    parser = argparse.ArgumentParser(prog="antivirus", description="A signature + heuristic antivirus scanner.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize the signature database").set_defaults(func=cmd_init)

    p_import = sub.add_parser("import-sigs", help="Import a signature list file (sha256 name per line)")
    p_import.add_argument("file")
    p_import.set_defaults(func=cmd_import)

    p_scan = sub.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("path")
    p_scan.add_argument("--no-recursive", action="store_true")
    p_scan.add_argument("--quarantine", action="store_true", help="Auto-quarantine signature matches")
    p_scan.set_defaults(func=cmd_scan)

    p_watch = sub.add_parser("watch", help="Real-time monitor a directory + running processes")
    p_watch.add_argument("path")
    p_watch.add_argument("--quarantine", action="store_true", help="Auto-quarantine signature matches")
    p_watch.add_argument("--interval", type=float, default=5.0, help="Process scan interval (seconds)")
    p_watch.set_defaults(func=cmd_watch)

    sub.add_parser("procscan", help="One-shot scan of running processes").set_defaults(func=cmd_procscan)

    p_qlist = sub.add_parser("quarantine-list", help="List quarantined files")
    p_qlist.set_defaults(func=cmd_quarantine_list)

    p_qrestore = sub.add_parser("quarantine-restore", help="Restore a quarantined file")
    p_qrestore.add_argument("id", type=int)
    p_qrestore.set_defaults(func=cmd_quarantine_restore)

    p_qdelete = sub.add_parser("quarantine-delete", help="Permanently delete a quarantined file")
    p_qdelete.add_argument("id", type=int)
    p_qdelete.set_defaults(func=cmd_quarantine_delete)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
