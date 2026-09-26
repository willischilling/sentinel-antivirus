"""Sentinel VPN: a WireGuard tunnel, set up from a config file (for example
from Proton VPN's free plan), run by the official WireGuard for Windows.

Setting up needs administrator rights once (one Windows prompt):
  - installs WireGuard if it's missing (official MSI, signature checked)
  - stores the config where only Windows and administrators can read it,
    since it holds the tunnel's private key
  - creates the tunnel service, set to start only when asked, and lets
    this Windows user start and stop it
After that, the on/off switch just starts and stops that service, no prompt.

WireGuard blocks all traffic outside the tunnel while it's connected when the
config routes everything through it (0.0.0.0/0), so nothing leaks around it.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

TUNNEL = "SentinelVPN"
SERVICE = f"WireGuardTunnel${TUNNEL}"
PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Sentinel Antivirus" / "vpn"
CONF_PATH = PROGRAM_DATA / f"{TUNNEL}.conf"
WIREGUARD_EXE = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WireGuard" / "wireguard.exe"
WIREGUARD_INDEX = "https://download.wireguard.com/windows-client/"
WIREGUARD_PUBLISHER = "WireGuard LLC"
IP_INFO_URL = "https://ipwho.is/"
USER_AGENT = "Sentinel-Antivirus/1.0"
CREATE_NO_WINDOW = 0x08000000
PROTON_SIGNUP = "https://account.protonvpn.com/signup"
PROTON_DOWNLOADS = "https://account.protonvpn.com/downloads"

# Config keys that run commands. WireGuard for Windows ignores them by default,
# but a config that has them isn't one Sentinel should install.
FORBIDDEN_KEYS = {"preup", "postup", "predown", "postdown"}


@dataclass
class VpnConfig:
    text: str
    server: str          # e.g. "US-FREE#34"
    country: str | None  # two-letter code, if the server name gives one
    endpoint: str        # host:port
    address: str
    full_tunnel: bool    # routes all internet traffic (and blocks leaks)

    @property
    def host(self) -> str:
        return self.endpoint.rsplit(":", 1)[0].strip("[]")


def parse_config(text: str, filename: str = "") -> VpnConfig:
    """Checks a WireGuard config and pulls out what the app shows. Raises ValueError."""
    section, values, server = None, {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            # Proton labels the server in a comment under [Peer], e.g. "# US-FREE#34"
            label = line.lstrip("# ").strip()
            if section == "peer" and re.fullmatch(r"[A-Z]{2}(-[A-Z]{2})?[-#A-Z0-9]*", label):
                server = server or label
            continue
        if line.startswith("["):
            section = line.strip("[]").strip().lower()
            continue
        if "=" in line and section in ("interface", "peer"):
            key, value = (part.strip() for part in line.split("=", 1))
            if key.lower() in FORBIDDEN_KEYS:
                raise ValueError(f"the config runs commands ({key}), which Sentinel doesn't allow")
            values[(section, key.lower())] = value
    required = [("interface", "privatekey"), ("interface", "address"), ("peer", "publickey"),
                ("peer", "endpoint"), ("peer", "allowedips")]
    missing = [key for sec, key in required if (sec, key) not in values]
    if missing:
        raise ValueError("this isn't a WireGuard config (missing " + ", ".join(missing) + ")")
    endpoint = values[("peer", "endpoint")]
    if ":" not in endpoint:
        raise ValueError("the server address has no port")
    if not server:
        stem = Path(filename).stem
        server = stem if stem else endpoint.rsplit(":", 1)[0]
    match = re.match(r"(?:wg-)?([A-Za-z]{2})(?:[-_#]|$)", server)
    allowed = values[("peer", "allowedips")].replace(" ", "")
    return VpnConfig(text=text, server=server, country=match.group(1).upper() if match else None,
                     endpoint=endpoint, address=values[("interface", "address")],
                     full_tunnel="0.0.0.0/0" in allowed.split(","))


# ------------------------------------------------------------------ status --
def wireguard_installed() -> bool:
    return WIREGUARD_EXE.is_file()


def status() -> str:
    """'not_setup', 'stopped', 'starting', 'running' or 'stopping'."""
    out = _sc("query", SERVICE)
    if out.returncode != 0:
        return "not_setup"
    text = out.stdout
    for word, state in (("RUNNING", "running"), ("START_PENDING", "starting"),
                        ("STOP_PENDING", "stopping"), ("STOPPED", "stopped")):
        if word in text:
            return state
    return "stopped"


def connect():
    result = _sc("start", SERVICE)
    if result.returncode != 0 and "1056" not in result.stdout:  # 1056: already running
        from . import elevate  # permissions were reset somehow: ask once more

        elevate.run("vpnstart")


def disconnect():
    result = _sc("stop", SERVICE)
    if result.returncode != 0 and "1062" not in result.stdout:  # 1062: not started
        from . import elevate

        elevate.run("vpnstop")


def _sc(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["sc.exe", *args], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)


# ------------------------------------------------------------------- setup --
def download_wireguard(progress=lambda done, total: None) -> Path:
    """Downloads the official WireGuard MSI and checks it's signed by WireGuard LLC."""
    from . import authenticode

    arch = "arm64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").upper() == "ARM64" else "amd64"
    index = _get(WIREGUARD_INDEX).decode("utf-8", "replace")
    names = re.findall(rf'href="(wireguard-{arch}-[\d.]+\.msi)"', index)
    if not names:
        raise RuntimeError("couldn't find the WireGuard installer")
    name = max(names, key=lambda n: [int(x) for x in re.findall(r"\d+", n)])
    target = Path(tempfile.gettempdir()) / name
    request = urllib.request.Request(WIREGUARD_INDEX + name, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response, open(target, "wb") as f:
        total, done = int(response.headers.get("Content-Length") or 0), 0
        while chunk := response.read(1 << 16):
            f.write(chunk)
            done += len(chunk)
            progress(done, total)
    signature = authenticode.check(target)
    if not signature.signed or signature.publisher != WIREGUARD_PUBLISHER:
        target.unlink(missing_ok=True)
        raise RuntimeError("the WireGuard installer isn't signed by WireGuard LLC, so it wasn't installed")
    return target


def setup(config: VpnConfig, msi: Path | None):
    """Installs the tunnel (one admin prompt). Replaces any earlier Sentinel VPN config."""
    from . import elevate

    fd, tmp = tempfile.mkstemp(prefix="sentinel-vpn-", suffix=".conf")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(config.text)
    try:
        elevate.run("vpnsetup", tmp, str(msi) if msi else "-", current_user_sid())
    finally:
        Path(tmp).unlink(missing_ok=True)


def remove():
    from . import elevate

    elevate.run("vpnremove")


# ---------------------------------------------- elevated side (via elevate) --
def elevated_setup(conf_tmp: str, msi: str, user_sid: str):
    from . import authenticode

    text = Path(conf_tmp).read_text(encoding="utf-8")
    parse_config(text)  # re-check here: the admin side trusts nothing it was handed
    _lock_down_dir()
    if msi != "-" and not wireguard_installed():
        local = PROGRAM_DATA / Path(msi).name
        shutil.copyfile(msi, local)  # copy first, then check the copy nobody else can change
        signature = authenticode.check(local)
        if not signature.signed or signature.publisher != WIREGUARD_PUBLISHER:
            local.unlink(missing_ok=True)
            raise RuntimeError("the WireGuard installer isn't signed by WireGuard LLC")
        result = subprocess.run(["msiexec.exe", "/i", str(local), "/qn", "/norestart", "DO_NOT_LAUNCH=1"],
                                capture_output=True, creationflags=CREATE_NO_WINDOW)
        local.unlink(missing_ok=True)
        if result.returncode not in (0, 3010):
            raise RuntimeError(f"WireGuard didn't install (error {result.returncode})")
    if not wireguard_installed():
        raise RuntimeError("WireGuard isn't installed")
    if _sc("query", SERVICE).returncode == 0:
        _wireguard("/uninstalltunnelservice", TUNNEL)
        _wait_gone()
    CONF_PATH.write_text(text, encoding="utf-8")
    _wireguard("/installtunnelservice", str(CONF_PATH))  # also connects
    _sc("config", SERVICE, "start=", "demand")  # don't reconnect at boot unless asked
    _allow_user_start_stop(user_sid)


def elevated_remove():
    if _sc("query", SERVICE).returncode == 0 and wireguard_installed():
        _wireguard("/uninstalltunnelservice", TUNNEL)
        _wait_gone()
    shutil.rmtree(PROGRAM_DATA, ignore_errors=True)


def _lock_down_dir():
    PROGRAM_DATA.mkdir(parents=True, exist_ok=True)
    # Only Windows (SYSTEM) and administrators: the config holds a private key.
    subprocess.run(["icacls", str(PROGRAM_DATA), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
                    "/grant:r", "*S-1-5-32-544:(OI)(CI)F"], capture_output=True, creationflags=CREATE_NO_WINDOW)


def _allow_user_start_stop(user_sid: str):
    """Adds a rule to the tunnel service so this Windows user can start, stop and query it."""
    if not re.fullmatch(r"S-1-5-21(-\d+){4}", user_sid):
        raise RuntimeError(f"unexpected account ID {user_sid!r}")
    current = _sc("sdshow", SERVICE).stdout.strip()
    ace = f"(A;;RPWPLCRC;;;{user_sid})"  # start, stop, query status, read permissions
    if ace in current or not current.startswith("D:"):
        return
    head, sep, tail = current.partition("S:")
    result = _sc("sdset", SERVICE, head + ace + (sep + tail if sep else ""))
    if result.returncode != 0:
        raise RuntimeError("couldn't let your account turn the VPN on and off: " + result.stdout.strip())


def current_user_sid() -> str:
    """This Windows account's ID (run on the normal, unelevated side)."""
    out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                         creationflags=CREATE_NO_WINDOW).stdout
    return out.strip().split(",")[-1].strip('"')


def _wireguard(*args):
    result = subprocess.run([str(WIREGUARD_EXE), *args], capture_output=True, text=True,
                            creationflags=CREATE_NO_WINDOW)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or f"wireguard {args[0]} failed")


def _wait_gone(timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end and _sc("query", SERVICE).returncode == 0:
        time.sleep(0.3)


# ----------------------------------------------------------- IP / location --
def _get(url: str, timeout=15) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def ip_info(ip: str = "") -> dict | None:
    """{'ip', 'city', 'country', 'country_code', 'latitude', 'longitude'} for an IP, or for
    this PC's public IP when ip is empty. None if the lookup fails."""
    try:
        data = json.loads(_get(IP_INFO_URL + ip))
    except (OSError, ValueError):
        return None
    if not data.get("success", False):
        return None
    return {key: data.get(key) for key in ("ip", "city", "country", "country_code", "latitude", "longitude")}
