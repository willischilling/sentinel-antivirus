"""Sentinel Browser (SentinelBrowser.exe): a private browser with Sentinel's protection built in.
See browser/app.py."""
import sys


def main():
    from core import crashlog

    crashlog.install("browser")
    from browser import app

    sys.exit(app.main())


if __name__ == "__main__":
    main()
