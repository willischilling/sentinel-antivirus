"""Wi-Fi / home network scanner: which devices are on your network, who made
them, and a few quick checks of the router.

- Finding devices: a small, harmless UDP packet goes to every address in your
  local /24 subnet. That makes Windows look up each address's network card
  (ARP), and every device that's there answers that lookup, even ones that
  ignore the packet itself. The answers are read from Windows' ARP table.
- Names: the name your router gives each device (reverse DNS), when it has one.
- Makers: the first half of each network card address is registered to its
  manufacturer; the list comes from the IEEE (standards-oui.ieee.org), cached
  for 30 days. Phones often use a random "private" address, shown as such.
- Router checks: whether it answers on Telnet or FTP (old, unencrypted remote
  access that shouldn't be on) and whether UPnP is on (lets apps open ports on
  the router by themselves).

Only your own network is scanned, and only once each time you ask.
"""
import csv
import io
import ipaddress
import json
import re
import socket
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import paths, settings

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_PATH = paths.DATA_DIR / "oui.json"
OUI_MAX_AGE = 30 * 24 * 3600
CREATE_NO_WINDOW = 0x08000000
USER_AGENT = "Sentinel-Antivirus/1.0"
_ARP_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\w+)", re.I)
_IFACE_LINE = re.compile(r"^\S.*?:\s*(\d+\.\d+\.\d+\.\d+)\s+---", re.I)

# (words in the maker or name) -> kind, for a friendlier label
KINDS = [
    (("apple", "iphone", "ipad"), "apple"),
    (("samsung", "oneplus", "xiaomi", "huawei", "oppo", "vivo", "motorola", "google", "pixel", "android"), "phone"),
    (("nintendo", "sony interactive", "playstation", "xbox", "valve"), "console"),
    (("roku", "lg electronics", "vizio", "tcl", "hisense", "chromecast", "amazon", "fire tv"), "tv"),
    (("sonos", "bose", "echo", "harman"), "speaker"),
    (("hp inc", "hewlett", "canon", "epson", "brother"), "printer"),
    (("ring", "arlo", "wyze", "hikvision", "dahua", "nest"), "camera"),
    (("intel", "realtek", "dell", "lenovo", "asustek", "micro-star", "gigabyte", "liteon", "azurewave",
      "hon hai", "microsoft", "desktop", "laptop"), "computer"),
    (("espressif", "tuya", "shelly", "philips lighting", "signify", "ecobee", "irobot", "gaoshengda", "wiz",
      "lifx", "govee", "meross", "tp-link", "kasa"), "smart"),
]


@dataclass
class Device:
    ip: str
    mac: str
    name: str | None = None      # from the router (reverse DNS)
    maker: str | None = None
    kind: str = "unknown"
    private_mac: bool = False    # a randomized phone/tablet address
    this_pc: bool = False
    router: bool = False
    new: bool = False            # first seen in the last day


@dataclass
class ScanResult:
    network: str                 # e.g. 192.168.1.0/24
    network_id: str              # the router's hardware address: identifies "this network"
    gateway: str
    devices: list = field(default_factory=list)
    router_issues: list = field(default_factory=list)   # translation keys


# ------------------------------------------------------------------ makers --
def maker_table() -> dict:
    try:
        fresh = time.time() - OUI_PATH.stat().st_mtime < OUI_MAX_AGE
        if fresh:
            return json.loads(OUI_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    try:
        request = urllib.request.Request(OUI_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read().decode("utf-8", errors="replace")
        table = {}
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 3 and len(row[1]) == 6:
                table[row[1].upper()] = _short_maker(row[2])
        if len(table) > 10_000:
            OUI_PATH.write_text(json.dumps(table, separators=(",", ":")), encoding="utf-8")
            return table
    except (OSError, ValueError):
        pass
    try:  # offline: an old list is better than none
        return json.loads(OUI_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_SUFFIXES = {"inc", "corp", "corporation", "corporate", "co", "company", "ltd", "limited", "llc", "gmbh", "sa",
             "ag", "plc", "technologies", "technology", "electronics", "communications", "international", "group",
             "holdings", "industrial", "industries", "manufacturing", "systems", "network", "networks", "ab", "bv"}


def _short_maker(org: str) -> str:
    """'HUAWEI TECHNOLOGIES CO.,LTD' -> 'Huawei', 'Intel Corporate' -> 'Intel'."""
    words = [w for w in re.split(r"[\s,.]+", org.strip()) if w]
    while len(words) > 1 and words[-1].lower() in _SUFFIXES:
        words.pop()
    name = " ".join(words)
    if name.isupper() and len(name) > 4:
        name = name.title()
    return name[:40]


def _kind(maker: str | None, name: str | None) -> str:
    text = f"{maker or ''} {name or ''}".lower()
    for words, kind in KINDS:
        if any(w in text for w in words):
            return kind
    return "unknown"


# ----------------------------------------------------------------- network --
def local_network():
    """(this PC's IPv4, prefix length, gateway) for the connection Windows uses for the internet."""
    script = r"""
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
if ($r) { $a = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{ ip = $a.IPAddress; prefix = $a.PrefixLength; gateway = $r.NextHop } | ConvertTo-Json -Compress }
"""
    import base64

    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                          base64.b64encode(script.encode("utf-16-le")).decode()],
                         capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW).stdout.strip()
    if not out:
        raise RuntimeError("no_network")
    data = json.loads(out)
    return data["ip"], int(data["prefix"]), data["gateway"]


def arp_table(own_ip: str) -> dict[str, str]:
    """{ip: mac} Windows currently knows on this PC's network (no packets sent)."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15,
                         creationflags=CREATE_NO_WINDOW).stdout
    found, ours = {}, False
    for line in out.splitlines():
        iface = _IFACE_LINE.match(line)
        if iface:
            ours = iface.group(1) == own_ip
            continue
        m = _ARP_LINE.match(line)
        if ours and m and m.group(3).lower() == "dynamic":
            mac = m.group(2).lower()
            if mac != "ff-ff-ff-ff-ff-ff" and not mac.startswith("01-00-5e"):
                found[m.group(1)] = mac
    return found


def _own_mac(own_ip: str) -> str | None:
    import psutil

    for addrs in psutil.net_if_addrs().values():
        if any(a.address == own_ip for a in addrs):
            for a in addrs:
                if a.family == psutil.AF_LINK:
                    return a.address.lower().replace(":", "-")
    return None


def _sweep(net: ipaddress.IPv4Network, own_ip: str):
    """Nudge every address so Windows resolves it (see the module notes)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for host in net.hosts():
            if str(host) != own_ip:
                try:
                    sock.sendto(b"\0", (str(host), 9))  # port 9: "discard"
                except OSError:
                    pass
                time.sleep(0.002)
    finally:
        sock.close()


def _reverse_name(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except OSError:
        return None
    name = name.split(".")[0]
    return None if not name or name.replace("-", "").isdigit() or name == ip else name


def _router_issues(gateway: str) -> list[str]:
    issues = []
    for port, key in ((23, "net_issue_telnet"), (21, "net_issue_ftp")):
        try:
            with socket.create_connection((gateway, port), timeout=1.5):
                issues.append(key)
        except OSError:
            pass
    if _upnp_on(gateway):
        issues.append("net_issue_upnp")
    return issues


def _upnp_on(gateway: str) -> bool:
    message = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
               "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    try:
        sock.sendto(message, ("239.255.255.250", 1900))
        end = time.monotonic() + 2.5
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if addr[0] == gateway and b"InternetGatewayDevice" in data:
                return True
    except OSError:
        pass
    finally:
        sock.close()
    return False


def scan() -> ScanResult:
    own_ip, prefix, gateway = local_network()
    net = ipaddress.ip_network(f"{own_ip}/{max(prefix, 24)}", strict=False)  # at most 254 addresses
    _sweep(net, own_ip)
    time.sleep(2.5)  # let the lookups come back
    table = {ip: mac for ip, mac in arp_table(own_ip).items() if ipaddress.ip_address(ip) in net}
    own_mac = _own_mac(own_ip)
    if own_mac:
        table[own_ip] = own_mac
    ouis = maker_table()
    pool = ThreadPoolExecutor(40)
    issues = pool.submit(_router_issues, gateway)
    lookups = {ip: pool.submit(_reverse_name, ip) for ip in table}
    wait(list(lookups.values()), timeout=3)  # devices without a name can take seconds to say so
    names = {ip: f.result() if f.done() else None for ip, f in lookups.items()}
    pool.shutdown(wait=False)
    network_id = table.get(gateway, gateway)
    known = _known(network_id)
    now = datetime.now(timezone.utc)
    devices = []
    for ip, mac in table.items():
        private = mac[1] in "26ae"  # "locally administered": a randomized address
        maker = None if private else ouis.get(mac.replace("-", "")[:6].upper())
        first = known.get(mac, {}).get("first")
        dev = Device(ip, mac, names.get(ip), maker, _kind(maker, names.get(ip)), private,
                     this_pc=ip == own_ip, router=ip == gateway)
        if private:
            dev.kind = "phone"  # phones and tablets use random addresses
        if dev.router:
            dev.kind = "router"
        elif dev.this_pc:
            dev.kind = "computer"
        dev.new = bool(known) and (first is None or (now - datetime.fromisoformat(first)).total_seconds() < 86400)
        devices.append(dev)
    remember(network_id, devices)
    devices.sort(key=lambda d: (not d.router, not d.this_pc, not d.new, ipaddress.ip_address(d.ip)))
    return ScanResult(str(net), network_id, gateway, devices, issues.result())


# ----------------------------------------------------------- known devices --
def _known(network_id: str) -> dict:
    return (settings.load().get("known_devices") or {}).get(network_id, {})


def remember(network_id: str, devices):
    """Adds devices to this network's known list (first-seen time is kept)."""
    everything = settings.load().get("known_devices") or {}
    known = everything.setdefault(network_id, {})
    now = datetime.now(timezone.utc).isoformat()
    for dev in devices:
        entry = known.setdefault(dev.mac, {"first": now})
        entry["last"] = now
        entry["ip"] = dev.ip
        if dev.name or dev.maker:
            entry["label"] = dev.name or dev.maker
    settings.save(known_devices=everything)


def alerts_on() -> bool:
    return settings.load().get("network_alerts", True)


def check_new_devices(network=None) -> list[tuple[str, str]]:
    """For the background agent: (ip, mac) of devices that just joined a network
    seen before, without sending anything (only Windows' ARP table is read).
    A network seen for the first time is learned quietly. `network` is a cached
    local_network() result."""
    own_ip, _prefix, gateway = network or local_network()
    table = arp_table(own_ip)
    if gateway not in table:
        return []
    network_id = table[gateway]
    everything = settings.load().get("known_devices") or {}
    if network_id not in everything:
        remember(network_id, [Device(ip, mac) for ip, mac in table.items()])
        return []
    known = everything[network_id]
    new = [(ip, mac) for ip, mac in table.items() if mac not in known]
    if new:
        remember(network_id, [Device(ip, mac) for ip, mac in new])
    return new


def describe(mac: str) -> str | None:
    """A maker name for an alert, from the cached list (never downloads)."""
    if mac[1] in "26ae":
        return None
    try:
        return json.loads(OUI_PATH.read_text(encoding="utf-8")).get(mac.replace("-", "")[:6].upper())
    except (OSError, ValueError):
        return None
