"""Weekly security report: what Sentinel saw and did over the last 7 days, and
the security score compared with the week before.

Built by the background agent once a week (or on demand from the Report page)
from what's already recorded: quarantine and detections in the database, the
Wi-Fi devices list, Windows' camera/mic records, the browser guard and
ransomware shield state, and the security checks. Reports are kept locally
(the last 12) and never sent anywhere.
"""
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import database, paths, settings

REPORT_DIR = paths.DATA_DIR / "reports"
EVERY = timedelta(days=7)
KEEP = 12


def _since(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def build(protection_on: bool = True) -> dict:
    start = _since(7)
    stamp = start.strftime("%Y-%m-%d %H:%M:%S")  # the database stores UTC like this
    report = {"made": datetime.now(timezone.utc).isoformat(), "from": start.isoformat()}
    try:
        with database.connect() as conn:
            # A file found in several scans counts once.
            threats = conn.execute("SELECT MAX(detail) FROM scan_log WHERE verdict = 'signature_match' "
                                   "AND scanned_at >= ? GROUP BY path", (stamp,)).fetchall()
            suspicious = conn.execute("SELECT COUNT(DISTINCT path) FROM scan_log WHERE verdict = 'suspicious' "
                                      "AND scanned_at >= ?", (stamp,)).fetchone()[0]
            quarantined = conn.execute("SELECT COUNT(*) FROM quarantine WHERE quarantined_at >= ?",
                                       (stamp,)).fetchone()[0]
    except sqlite3.Error:
        threats, suspicious, quarantined = [], 0, 0
    names = [t[0] for t in threats if t[0]]
    report["threats"] = len(names)
    report["threat_names"] = sorted({n.rsplit(": ", 1)[-1] for n in names})[:5]  # the malware names
    report["suspicious"] = suspicious
    report["quarantined"] = quarantined
    last = settings.load().get("last_scan") or {}
    report["last_scan"] = last.get("time")

    new_devices = []
    for network in (settings.load().get("known_devices") or {}).values():
        for mac, info in network.items():
            if info.get("first") and datetime.fromisoformat(info["first"]) >= start:
                new_devices.append(info.get("label") or mac)
    report["new_devices"] = new_devices[:10]

    try:
        from . import privacy

        report["camera_mic"] = sorted({u.name for u in privacy.usage() if u.start and u.start >= start})[:10]
    except Exception:
        report["camera_mic"] = []
    report["link_warnings"] = sum(1 for a in settings.load().get("link_alerts") or []
                                  if datetime.fromisoformat(a["time"]) >= start)
    try:
        from . import hijack

        report["browser_items"] = len(hijack.current())
    except Exception:
        report["browser_items"] = None
    try:
        from . import shield

        report["shield_blocks"] = sum(b.count for b in shield.blocked(7))
    except Exception:
        report["shield_blocks"] = None
    try:
        from . import security_score

        checks = security_score.gather(protection_on, None, None)
        report["score"] = security_score.score(checks)
        report["todo"] = [c.key for c in checks if c.ok is False]
    except Exception:
        report["score"], report["todo"] = None, []
    previous = latest()
    report["previous_score"] = previous.get("score") if previous else None
    return report


def save(report: dict) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / (datetime.now().strftime("%Y-%m-%d_%H%M%S") + ".json")
    path.write_text(json.dumps(report, indent=1), encoding="utf-8")
    for old in sorted(REPORT_DIR.glob("*.json"))[:-KEEP]:
        old.unlink(missing_ok=True)
    settings.save(last_report=report["made"])
    return path


def latest() -> dict | None:
    try:
        newest = max(REPORT_DIR.glob("*.json"))
        return json.loads(newest.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def due() -> bool:
    last = settings.load().get("last_report")
    if not last:
        # The first report comes a week after this feature first ran, so it has a week to cover.
        first = settings.load().get("report_started")
        if not first:
            settings.save(report_started=datetime.now(timezone.utc).isoformat())
            return False
        return datetime.now(timezone.utc) - datetime.fromisoformat(first) >= EVERY
    return datetime.now(timezone.utc) - datetime.fromisoformat(last) >= EVERY


def enabled() -> bool:
    return settings.load().get("weekly_report", True)
