"""Stealer guard: notices programs going after your saved logins.

Password stealers (RedLine, Lumma, the fake "Roblox executors" and "free Nitro"
tools) grab browser passwords and cookies, Discord tokens, Roblox and Steam
logins and crypto wallets within seconds of starting. Fingerprints only catch
the ones already known, so this watches for what they all have to do:

- open the files those logins live in. Only programs that aren't signed by a
  publisher (and script runners like Python, PowerShell and Java, which run
  whatever they're given) are checked, so the browser reading its own
  passwords never counts.
- leave stolen data behind: a copy of a browser's password or cookie database
  outside the browser, a Discord token or Roblox sign-in cookie in a plain
  file, or a list of passwords or cookies being collected in Temp or AppData.

This module holds the checks and what's remembered (the switch, programs you
allowed, the last warnings). monitor/stealer_watcher.py does the watching.
Nothing is sent anywhere, and the contents of these files are never stored.
"""
import base64
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import settings

RECENT_KEEP = 20
INSPECT_MAX_SIZE = 8 * 1024 * 1024  # bigger files aren't stolen-data dumps
INSPECT_READ = 1024 * 1024          # database schemas and dumps show in the first part
CATEGORIES = ("passwords", "cookies", "discord", "roblox", "steam", "minecraft", "telegram", "wallet")

# Programs that run whatever script they're given: a signature on them says nothing about
# the script. Java is here because malicious Minecraft mods run inside javaw.exe.
SCRIPT_HOSTS = {
    "python.exe", "pythonw.exe", "py.exe", "pyw.exe", "node.exe", "powershell.exe", "pwsh.exe",
    "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "java.exe", "javaw.exe", "autohotkey.exe", "autohotkey64.exe", "autoit3.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "bun.exe", "deno.exe",
}
# A wallet or chat app opening its own data is fine even when it isn't signed.
OWNERS = {
    "telegram": ("telegram.exe",),
    "wallet": ("exodus.exe", "electrum", "atomic wallet.exe", "coinomi.exe", "guarda.exe", "armoryqt.exe",
               "bitcoin-qt.exe", "wasabi"),
    "steam": ("steam.exe", "steamwebhelper.exe", "steamservice.exe"),
}
# Browser wallet extensions: MetaMask, Phantom, Binance, Trust Wallet, Coinbase, Ronin, Rabby, Keplr.
WALLET_EXTENSIONS = (
    "nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "fhbohimaelbohpjbbldcngcnapndodjp",
    "egjidjbpglichdcondbcbdnbeeppgdph", "hnfanknocfeofbddgcijnmhnfnkdnaad", "fnjhmkhhmkbjkkabndcnnogagogbneec",
    "acmacodkjbdgmoleebolmdjonilkdbch", "dmkamcknogkgcdfhhbddcghachkejeap",
)
WALLET_DIRS = (
    "\\exodus\\exodus.wallet\\", "\\electrum\\wallets\\", "\\atomic\\local storage\\leveldb\\",
    "\\ethereum\\keystore\\", "\\coinomi\\coinomi\\wallets\\", "\\guarda\\local storage\\leveldb\\",
    "\\armory\\", "\\bitcoin\\wallets\\", "\\wasabi\\client\\wallets\\",
)
_DISCORD_DATA = re.compile(r"\\(discord|discordcanary|discordptb|discorddevelopment|lightcord)\\local storage\\leveldb\\")
_BROWSER_PASSWORDS = {"login data", "login data for account", "web data", "local state"}
_BROWSER_COOKIES = {"cookies", "extension cookies"}
_FIREFOX_PASSWORDS = {"logins.json", "key4.db", "key3.db", "signons.sqlite"}

# What a stealer's collected data looks like.
_ROBLOX_COOKIE = b"_|WARNING:-DO-NOT-SHARE-THIS."
_DISCORD_TOKEN = re.compile(rb"([A-Za-z0-9_-]{23,28})\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}|mfa\.[A-Za-z0-9_-]{84}")
_NETSCAPE_COOKIE = re.compile(r"^#?\.?[\w.-]+\t(TRUE|FALSE)\t/\S*\t(TRUE|FALSE)\t\d+\t\S+\t", re.MULTILINE | re.IGNORECASE)
_PASSWORD_LINE = re.compile(r"^\s*(pass(word)?|pwd)\s*[:=]\s*\S", re.MULTILINE | re.IGNORECASE)
_SITE_LINE = re.compile(r"^\s*(url|host|site|origin|website|soft|browser)\s*[:=]\s*\S", re.MULTILINE | re.IGNORECASE)


def _key(path: str) -> str:
    return str(path).replace("/", "\\").lower()


def _base_name(lowered: str) -> str:
    name = lowered.rsplit("\\", 1)[-1]
    for suffix in ("-journal", "-wal", "-shm"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def classify(path: str) -> str | None:
    """Which kind of saved login this file holds (one of CATEGORIES), or None."""
    p = _key(path)
    name = _base_name(p)
    browser = "\\user data\\" in p or "\\opera software\\" in p
    if browser:
        if any(ext in p for ext in WALLET_EXTENSIONS):
            return "wallet"
        if name in _BROWSER_PASSWORDS:
            return "passwords"
        if name in _BROWSER_COOKIES or "\\local storage\\leveldb\\" in p:
            return "cookies"  # signed-in sessions (web Discord keeps its token in Local Storage)
    if "\\profiles\\" in p and ("\\mozilla\\" in p or "\\thunderbird\\" in p or "\\waterfox\\" in p
                                or "\\librewolf\\" in p):
        if name in _FIREFOX_PASSWORDS:
            return "passwords"
        if name == "cookies.sqlite":
            return "cookies"
    if _DISCORD_DATA.search(p):
        return "discord"
    if "\\roblox\\localstorage\\" in p or name == "robloxcookies.dat":
        return "roblox"
    if ("\\steam\\config\\" in p and name in ("loginusers.vdf", "config.vdf")) or (
            "\\steam\\" in p and name.startswith("ssfn")):
        return "steam"
    if "\\.minecraft\\" in p and name.startswith(("launcher_accounts", "launcher_msa_credentials")):
        return "minecraft"
    if "\\telegram desktop\\tdata\\" in p:
        return "telegram"
    if any(d in p for d in WALLET_DIRS) or name == "wallet.dat":
        return "wallet"
    return None


def is_owner(exe_name: str, category: str) -> bool:
    name = exe_name.lower()
    return any(name == o or (not o.endswith(".exe") and name.startswith(o)) for o in OWNERS.get(category, ()))


# ------------------------------------------------------------ stolen data --
def _is_real_store(path: Path) -> bool:
    """A browser's or app's own database (they keep the standard names, next to their other
    profile files), as opposed to a stealer's copy of it."""
    for folder in (path.parent, path.parent.parent):
        if (folder / "Preferences").is_file() or (folder / "prefs.js").is_file():
            return True
    return False


def _discord_token(data: bytes) -> bool:
    for match in _DISCORD_TOKEN.finditer(data):
        first = match.group(1)
        if first is None:
            return True  # an old "mfa." token
        try:  # a real token starts with the account's numeric ID, base64-encoded
            user_id = base64.urlsafe_b64decode(first + b"=" * (-len(first) % 4))
        except ValueError:
            continue
        if user_id.isdigit() and 17 <= len(user_id) <= 20:
            return True
    return False


def inspect(path: Path) -> str | None:
    """If this file looks like stolen login data, which kind (one of CATEGORIES)."""
    p = _key(path)
    if "\\local storage\\leveldb\\" in p or "\\indexeddb\\" in p or "\\session storage\\" in p:
        return None  # apps' own storage (Discord's real token lives here)
    try:
        size = path.stat().st_size
        if not 20 <= size <= INSPECT_MAX_SIZE:
            return None
        with open(path, "rb") as f:
            data = f.read(INSPECT_READ)
    except OSError:
        return None
    if data.startswith(b"SQLite format 3\x00"):
        if b"CREATE TABLE logins" in data or (b"nssPrivate" in data and b"metaData" in data):
            kind = "passwords"
        elif (b"CREATE TABLE cookies" in data and b"encrypted_value" in data) or b"CREATE TABLE moz_cookies" in data:
            kind = "cookies"
        else:
            return None
        return None if _is_real_store(path) else kind
    if b'"os_crypt"' in data and b'"encrypted_key"' in data:  # Local State: the key to the passwords
        return None if _is_real_store(path) or _has_profile_dirs(path) else "passwords"
    if b'"encryptedPassword"' in data and b'"encryptedUsername"' in data:  # Firefox logins.json
        return None if _is_real_store(path) else "passwords"
    if _ROBLOX_COOKIE in data:
        return "roblox"
    if _discord_token(data):
        return "discord"
    if data.count(b"\x00") > len(data) // 4:  # UTF-16 text
        text = data.decode("utf-16", errors="ignore")
    else:
        text = data.decode("utf-8", errors="ignore")
    if len(_NETSCAPE_COOKIE.findall(text)) >= 10:
        return "cookies"
    if len(_PASSWORD_LINE.findall(text)) >= 3 and _SITE_LINE.search(text):
        return "passwords"
    return None


def _has_profile_dirs(path: Path) -> bool:
    return any((path.parent / d).is_dir() for d in ("Default", "Network", "Local Storage"))


# ------------------------------------------------------------- settings --
def enabled() -> bool:
    return settings.load().get("stealer_guard", True)


def allowed() -> set[str]:
    return {_key(p) for p in settings.load().get("stealer_allowed") or []}


def allow(exe: str):
    names = list(dict.fromkeys((settings.load().get("stealer_allowed") or []) + [exe]))
    settings.save(stealer_allowed=names)


def disallow(exe: str):
    settings.save(stealer_allowed=[p for p in settings.load().get("stealer_allowed") or [] if _key(p) != _key(exe)])


def remember(program: str | None, exe: str | None, kind: str, categories, file: str | None = None):
    """Keeps the last few warnings for the Stealer guard page and the weekly report."""
    recent = settings.load().get("stealer_alerts") or []
    recent.insert(0, {"time": datetime.now(timezone.utc).isoformat(), "program": program, "exe": exe,
                      "kind": kind, "categories": sorted(categories), "file": file})
    settings.save(stealer_alerts=recent[:RECENT_KEEP])


def recent() -> list[dict]:
    return settings.load().get("stealer_alerts") or []


def protected_here() -> list[str]:
    """Which kinds of saved logins exist on this PC (for the page)."""
    local = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    roaming = Path(os.environ.get("APPDATA", Path.home()))
    from . import extensions

    found = []
    if any(d.is_dir() for _k, _n, d, *_ in extensions.CHROMIUM) or extensions.FIREFOX_PROFILES.is_dir():
        found += ["passwords", "cookies"]
    checks = {
        "discord": [roaming / n for n in ("discord", "discordcanary", "discordptb")],
        "roblox": [local / "Roblox"],
        "steam": [Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Steam"],
        "minecraft": [roaming / ".minecraft"],
        "telegram": [roaming / "Telegram Desktop"],
        "wallet": [roaming / "Exodus", roaming / "Electrum", roaming / "atomic"],
    }
    for category, folders in checks.items():
        if any(f.is_dir() for f in folders):
            found.append(category)
    return found
