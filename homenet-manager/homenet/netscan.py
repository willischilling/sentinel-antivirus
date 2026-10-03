"""Finds the devices on your own home network, and who made each one.

- A small, harmless UDP packet is sent to every address in your local subnet.
  That makes Windows look up each address's network card (ARP); devices that
  are there answer, and the answers are read from Windows' ARP table.
- Names come from the router (reverse DNS) when a device has one.
- Makers come from the first half of each network-card address, which is
  registered to a manufacturer (the IEEE list, cached for 30 days). Phones
  often use a random "private" address and are shown as such.

Only your own network is scanned, and only when you ask.
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
from dataclasses import dataclass

from . import settings

OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_PATH = settings.data_dir() / "oui.json"
OUI_MAX_AGE = 30 * 24 * 3600
CREATE_NO_WINDOW = 0x08000000
USER_AGENT = "HomeNetManager/1.0"
_ARP_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\w+)", re.I)
_IFACE_LINE = re.compile(r"^\S.*?:\s*(\d+\.\d+\.\d+\.\d+)\s+---", re.I)

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
    (("espressif", "tuya", "shelly", "philips lighting", "signify", "ecobee", "irobot", "wiz",
      "lifx", "govee", "meross", "tp-link", "kasa"), "smart"),
]


@dataclass
class Device:
    ip: str
    mac: str
    name: str | None = None
    maker: str | None = None
    kind: str = "unknown"
    private_mac: bool = False
    this_pc: bool = False
    router: bool = False


@dataclass
class ScanResult:
    network: str          # e.g. 192.168.1.0/24
    network_id: str       # the router's hardware address: identifies "this network"
    gateway: str
    devices: list


# ------------------------------------------------------------------ makers --
def maker_table() -> dict:
    try:
        if time.time() - OUI_PATH.stat().st_mtime < OUI_MAX_AGE:
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
    try:
        return json.loads(OUI_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


_SUFFIXES = {"inc", "corp", "corporation", "corporate", "co", "company", "ltd", "limited", "llc", "gmbh", "sa",
             "ag", "plc", "technologies", "technology", "electronics", "communications", "international", "group",
             "holdings", "industrial", "industries", "manufacturing", "systems", "network", "networks", "ab", "bv"}


def _short_maker(org: str) -> str:
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
    """(this PC's IPv4, prefix length, gateway, this PC's MAC) for the internet
    connection. The MAC comes from the same adapter Windows uses for the route,
    so no third-party library is needed."""
    script = r"""
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
if ($r) { $a = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  $ad = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{ ip = $a.IPAddress; prefix = $a.PrefixLength; gateway = $r.NextHop; mac = $ad.MacAddress } | ConvertTo-Json -Compress }
"""
    import base64

    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                          base64.b64encode(script.encode("utf-16-le")).decode()],
                         capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW).stdout.strip()
    if not out:
        raise RuntimeError("no_network")
    data = json.loads(out)
    mac = (data.get("mac") or "").lower().replace(":", "-") or None
    return data["ip"], int(data["prefix"]), data["gateway"], mac


def arp_table(own_ip: str) -> dict[str, str]:
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


def _sweep(net: ipaddress.IPv4Network, own_ip: str):
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


def scan() -> ScanResult:
    own_ip, prefix, gateway, own_mac = local_network()
    net = ipaddress.ip_network(f"{own_ip}/{max(prefix, 24)}", strict=False)  # at most 254 addresses
    _sweep(net, own_ip)
    time.sleep(2.5)
    table = {ip: mac for ip, mac in arp_table(own_ip).items() if ipaddress.ip_address(ip) in net}
    if own_mac:
        table[own_ip] = own_mac
    ouis = maker_table()
    pool = ThreadPoolExecutor(40)
    lookups = {ip: pool.submit(_reverse_name, ip) for ip in table}
    wait(list(lookups.values()), timeout=3)
    names = {ip: f.result() if f.done() else None for ip, f in lookups.items()}
    pool.shutdown(wait=False)
    network_id = table.get(gateway, gateway)
    devices = []
    for ip, mac in table.items():
        private = mac[1] in "26ae"
        maker = None if private else ouis.get(mac.replace("-", "")[:6].upper())
        dev = Device(ip, mac, names.get(ip), maker, _kind(maker, names.get(ip)), private,
                     this_pc=ip == own_ip, router=ip == gateway)
        if private:
            dev.kind = "phone"
        if dev.router:
            dev.kind = "router"
        elif dev.this_pc:
            dev.kind = "computer"
        devices.append(dev)
    devices.sort(key=lambda d: (not d.router, not d.this_pc, ipaddress.ip_address(d.ip)))
    return ScanResult(str(net), network_id, gateway, devices)
