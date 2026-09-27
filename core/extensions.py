"""Browser extension checker: lists the extensions installed in Chrome, Edge,
Brave, Vivaldi, Opera and Firefox for this Windows account, and rates each one.

- Known bad: on Malicious Extension Sentry (github.com/toborrm9/malicious_extension_sentry,
  MIT licensed, updated daily): about 6,800 Chrome and Edge extensions removed from the
  stores for malware, spyware, adware, search hijacking or policy violations. Also when
  the browser itself has flagged it (Chrome's own blocklist).
- Risky: installed from outside the web store (loaded from a folder, the command line or
  a policy, which is how adware and stealers sneak extensions in) with access to every
  website or to powerful browser features.
- Powerful: from the store, but can read and change every website, or has several
  sensitive permissions. Normal for ad blockers and password managers; worth a look for
  anything you don't recognise.

Only the extension ID list is downloaded; nothing about your extensions is sent anywhere.
"""
import csv
import glob
import hashlib
import io
import json
import os
import subprocess
import urllib.request
import winreg
from dataclasses import dataclass, field
from pathlib import Path

from . import database

SENTRY_URL = ("https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/"
              "malicious_extensions_detailed.csv")
USER_AGENT = "Sentinel-Antivirus/1.0"
LOCAL = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
ROAMING = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
CREATE_NO_WINDOW = 0x08000000

# (key, display name, user data folder, exe for App Paths, extension page, single-profile folder)
CHROMIUM = [
    ("chrome", "Google Chrome", LOCAL / "Google" / "Chrome" / "User Data", "chrome.exe", "chrome://extensions/?id={id}", False),
    ("edge", "Microsoft Edge", LOCAL / "Microsoft" / "Edge" / "User Data", "msedge.exe", "edge://extensions/?id={id}", False),
    ("brave", "Brave", LOCAL / "BraveSoftware" / "Brave-Browser" / "User Data", "brave.exe", "brave://extensions/?id={id}", False),
    ("vivaldi", "Vivaldi", LOCAL / "Vivaldi" / "User Data", "vivaldi.exe", "vivaldi://extensions/?id={id}", False),
    ("opera", "Opera", ROAMING / "Opera Software" / "Opera Stable", "opera.exe", "opera://extensions/?id={id}", True),
    ("operagx", "Opera GX", ROAMING / "Opera Software" / "Opera GX Stable", "opera.exe", "opera://extensions/?id={id}", True),
]
FIREFOX_PROFILES = ROAMING / "Mozilla" / "Firefox" / "Profiles"
STORE_UPDATE_HOSTS = ("clients2.google.com", "edge.microsoft.com", "extension-updates.opera.com",
                      "addons.mozilla.org", "addons.cdn.mozilla.net")

# Chrome's extension "location" values
UNPACKED, COMMAND_LINE = 4, 8
POLICY = (7, 9)
BUILT_IN = (5, 10)  # parts of the browser itself

BROAD_HOSTS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/",
               "file:///*", "*://*"}
# Permission -> translation key of what it lets the extension do
SENSITIVE = {
    "cookies": "ext_perm_cookies",
    "webRequest": "ext_perm_webrequest",
    "webRequestBlocking": "ext_perm_webrequest",
    "declarativeNetRequestWithHostAccess": "ext_perm_webrequest",
    "debugger": "ext_perm_debugger",
    "proxy": "ext_perm_proxy",
    "nativeMessaging": "ext_perm_native",
    "clipboardRead": "ext_perm_clipboard",
    "history": "ext_perm_history",
    "management": "ext_perm_management",
    "desktopCapture": "ext_perm_capture",
    "tabCapture": "ext_perm_capture",
    "privacy": "ext_perm_privacy",
}
# Malicious Extension Sentry reasons -> (level, translation key)
REASONS = {
    "Malware": ("malicious", "ext_reason_malware"),
    "Spyware": ("malicious", "ext_reason_spyware"),
    "Adware": ("malicious", "ext_reason_adware"),
    "Search Hijacking": ("malicious", "ext_reason_hijack"),
    "Bundling Unwanted Software": ("flagged", "ext_reason_unwanted"),
    "Potentially Unwanted Software": ("flagged", "ext_reason_unwanted"),
    "Policy Violation": ("flagged", "ext_reason_policy"),
    "In store but Suspicious": ("flagged", "ext_reason_suspicious"),
    "Critical Vulnerability": ("flagged", "ext_reason_vulnerable"),
}
# Chrome's own blocklist_state values
CHROME_BLOCKLIST = {1: ("malicious", "ext_reason_browser_malware"), 2: ("flagged", "ext_reason_vulnerable"),
                    3: ("flagged", "ext_reason_policy"), 4: ("flagged", "ext_reason_unwanted")}
LEVELS = ("malicious", "flagged", "risky", "powerful", "ok")
CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".wasm", ".html", ".htm", ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs")

SCHEMA = "CREATE TABLE IF NOT EXISTS bad_extensions (id TEXT PRIMARY KEY, reason TEXT, name TEXT) WITHOUT ROWID;"


@dataclass
class Extension:
    browser: str          # key from CHROMIUM, or "firefox"
    browser_name: str
    profile: str          # the profile's display name
    ext_id: str
    name: str
    version: str
    enabled: bool
    folder: Path | None
    source: str           # "store", "outside", "policy"
    broad: bool           # can read and change every website
    permissions: list = field(default_factory=list)   # translation keys, no repeats
    level: str = "ok"
    reason: str | None = None                          # translation key for known-bad / flagged
    known_bad_files: int = 0


# ------------------------------------------------------------- bad list --
def install(progress=lambda key: None):
    """Downloads the known-bad extension list into the threat database."""
    progress("intel_downloading_extensions")
    request = urllib.request.Request(SENTRY_URL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        text = response.read().decode("utf-8-sig", errors="replace")
    rows = []
    for row in csv.DictReader(io.StringIO(text)):
        ext_id = (row.get("extension_id") or "").strip().lower()
        if len(ext_id) == 32 and ext_id.isalpha():
            rows.append((ext_id, (row.get("reason") or "").strip(), (row.get("name") or "").strip()))
    if len(rows) < 1000:
        raise RuntimeError("the malicious extension list looks incomplete")
    with database.connect() as conn:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM bad_extensions")
        conn.executemany("INSERT OR REPLACE INTO bad_extensions VALUES (?, ?, ?)", rows)
    database.set_meta(bad_extensions=len(rows))


def list_installed() -> bool:
    return bool(database.get_meta("bad_extensions"))


def _bad_list(ids) -> dict:
    ids = list(ids)
    if not ids:
        return {}
    with database.connect() as conn:
        conn.executescript(SCHEMA)
        marks = ",".join("?" * len(ids))
        return {row[0]: row[1] for row in conn.execute(
            f"SELECT id, reason FROM bad_extensions WHERE id IN ({marks})", ids)}


# ------------------------------------------------------------- scanning --
def scan() -> list[Extension]:
    """Every extension in every supported browser profile, riskiest first."""
    found = []
    for key, name, data_dir, _exe, _page, single in CHROMIUM:
        if not data_dir.is_dir():
            continue
        for profile_dir, profile_name in _chromium_profiles(data_dir, single):
            try:
                found += _chromium_extensions(key, name, profile_dir, profile_name)
            except Exception:
                continue  # one unreadable profile shouldn't hide the rest
    try:
        found += _firefox_extensions()
    except Exception:
        pass
    bad = _bad_list({e.ext_id for e in found if e.browser != "firefox"})
    for ext in found:
        _rate(ext, bad.get(ext.ext_id))
    return sorted(found, key=lambda e: (LEVELS.index(e.level), not e.enabled, e.name.lower()))


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}


def _chromium_profiles(data_dir: Path, single: bool):
    if single:  # Opera keeps one profile in the folder itself
        yield data_dir, ""
        return
    names = _read_json(data_dir / "Local State").get("profile", {}).get("info_cache", {})
    for folder in sorted(data_dir.iterdir()):
        if folder.is_dir() and (folder.name == "Default" or folder.name.startswith("Profile ")) \
                and (folder / "Preferences").exists():
            yield folder, names.get(folder.name, {}).get("name") or folder.name


def _chromium_extensions(browser, browser_name, profile_dir: Path, profile_name: str) -> list[Extension]:
    settings = {}
    for prefs_file in ("Preferences", "Secure Preferences"):  # newer Chrome keeps them in the second
        prefs = _read_json(profile_dir / prefs_file)
        for ext_id, info in prefs.get("extensions", {}).get("settings", {}).items():
            settings.setdefault(ext_id, {}).update(info)
    result = []
    for ext_id, info in settings.items():
        location = info.get("location")
        if location in BUILT_IN or len(ext_id) != 32:
            continue
        folder = _chromium_folder(profile_dir, ext_id, info.get("path"))
        manifest = _read_json(folder / "manifest.json") if folder else {}
        manifest = manifest or info.get("manifest") or {}
        if not manifest or "theme" in manifest:
            continue  # uninstalled leftovers and themes
        disabled = bool(info.get("disable_reasons")) or info.get("state") == 0
        update_url = manifest.get("update_url", "")
        if location in POLICY:
            source = "policy"
        elif location in (UNPACKED, COMMAND_LINE):
            source = "outside"
        elif info.get("from_webstore") or any(h in update_url for h in STORE_UPDATE_HOSTS):
            source = "store"
        else:
            source = "outside"
        broad, perms = _permissions(manifest)
        ext = Extension(browser, browser_name, profile_name, ext_id,
                        _display_name(manifest, folder) or ext_id, str(manifest.get("version", "")),
                        not disabled, folder, source, broad, perms)
        blocked = info.get("blocklist_state", info.get("blacklist_state"))
        if blocked in CHROME_BLOCKLIST:
            ext.level, ext.reason = CHROME_BLOCKLIST[blocked]
        result.append(ext)
    return result


def _chromium_folder(profile_dir: Path, ext_id: str, path_value) -> Path | None:
    if path_value:
        path = Path(path_value)
        if not path.is_absolute():
            path = profile_dir / "Extensions" / path
        if (path / "manifest.json").exists():
            return path
    versions = [p for p in (profile_dir / "Extensions" / ext_id).glob("*") if (p / "manifest.json").exists()]
    return max(versions, key=lambda p: p.stat().st_mtime) if versions else None


def _display_name(manifest: dict, folder: Path | None) -> str:
    name = str(manifest.get("name", "")).strip()
    if name.startswith("__MSG_") and folder:
        key = name[6:].rstrip("_").lower()
        for locale in (manifest.get("default_locale"), "en", "en_US"):
            if not locale:
                continue
            messages = _read_json(folder / "_locales" / locale / "messages.json")
            for k, v in messages.items():
                if k.lower() == key and isinstance(v, dict) and v.get("message"):
                    return v["message"].strip()
        return ""
    return name


def _permissions(manifest: dict) -> tuple[bool, list]:
    perms = [p for p in manifest.get("permissions", []) if isinstance(p, str)]
    hosts = [p for p in perms if "://" in p or p == "<all_urls>"]
    hosts += [p for p in manifest.get("host_permissions", []) if isinstance(p, str)]
    for script in manifest.get("content_scripts", []) or []:
        if isinstance(script, dict):
            hosts += [m for m in script.get("matches", []) if isinstance(m, str)]
    broad = any(h in BROAD_HOSTS or h.startswith(("*://*/", "http://*/", "https://*/")) for h in hosts)
    keys = list(dict.fromkeys(SENSITIVE[p] for p in perms if p in SENSITIVE))
    return broad, keys


def _firefox_extensions() -> list[Extension]:
    result = []
    for profile in sorted(FIREFOX_PROFILES.glob("*")):
        data = _read_json(profile / "extensions.json")
        for addon in data.get("addons", []):
            if addon.get("type") != "extension" or addon.get("location") != "app-profile":
                continue
            perms = addon.get("userPermissions") or {}
            manifest = {"permissions": list(perms.get("permissions") or []) + list(perms.get("origins") or [])}
            broad, keys = _permissions(manifest)
            source_uri = addon.get("sourceURI") or ""
            source = "store" if any(h in source_uri for h in STORE_UPDATE_HOSTS) or addon.get("signedState") == 2 \
                else "outside"
            name = (addon.get("defaultLocale") or {}).get("name") or addon.get("id", "")
            path = Path(addon["path"]) if addon.get("path") else None
            result.append(Extension("firefox", "Firefox", profile.name.split(".", 1)[-1], addon.get("id", ""), name,
                                    str(addon.get("version", "")), bool(addon.get("active")), path, source, broad,
                                    keys))
    return result


def _rate(ext: Extension, bad_reason: str | None):
    if bad_reason is not None:
        level, key = REASONS.get(bad_reason, ("flagged", "ext_reason_removed"))
        if ext.level != "malicious":  # the browser's own verdict can only make it worse
            ext.level, ext.reason = level, key
    if ext.level in ("malicious", "flagged"):
        return
    # Store extensions are reviewed and number in the thousands of files; fingerprinting
    # them made a scan take minutes. Sideloaded ones are where malware files turn up.
    ext.known_bad_files = _known_bad_files(ext.folder) if ext.source != "store" else 0
    if ext.known_bad_files:
        ext.level, ext.reason = "malicious", "ext_reason_bad_files"
    elif ext.source != "store" and (ext.broad or ext.permissions):
        ext.level = "risky"
    elif ext.broad or len(ext.permissions) >= 2:
        ext.level = "powerful"


def _known_bad_files(folder: Path | None) -> int:
    """How many of the extension's files match known malware fingerprints."""
    if not folder or not folder.is_dir():
        return 0
    hashes = []
    for root, _dirs, files in os.walk(folder):
        for name in files:
            if not name.lower().endswith(CODE_SUFFIXES):
                continue
            try:
                path = Path(root) / name
                if path.stat().st_size <= 20 * 1024 * 1024:
                    hashes.append(hashlib.sha256(path.read_bytes()).hexdigest())
            except OSError:
                continue
            if len(hashes) >= 3000:
                break
    return len(database.lookup_signatures(hashes)) if hashes else 0


# ----------------------------------------------------------- management --
def browser_exe(browser: str) -> str | None:
    exe_name = next((c[3] for c in CHROMIUM if c[0] == browser), "firefox.exe" if browser == "firefox" else None)
    if not exe_name:
        return None
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}") as key:
                path = winreg.QueryValue(key, None)
                if path and Path(path.strip('"')).exists():
                    return path.strip('"')
        except OSError:
            continue
    candidates = {
        "opera": glob.glob(str(LOCAL / "Programs" / "Opera" / "opera.exe")),
        "operagx": glob.glob(str(LOCAL / "Programs" / "Opera GX" / "opera.exe")),
    }.get(browser, [])
    return candidates[0] if candidates else None


def open_manager(ext: Extension) -> bool:
    """Opens the browser's page for this extension, where it can be turned off or removed."""
    exe = browser_exe(ext.browser)
    if not exe:
        return False
    if ext.browser == "firefox":
        target = "about:addons"
    else:
        target = next(c[4] for c in CHROMIUM if c[0] == ext.browser).format(id=ext.ext_id)
    subprocess.Popen([exe, target], creationflags=CREATE_NO_WINDOW)
    return True
