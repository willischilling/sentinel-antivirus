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
def _run(cmd, timeout=30) -> subprocess.CompletedProcess:
    """Run a console command from a windowed app. stdin must be DEVNULL: a
    no-console app has no valid stdin handle, and inheriting it can make the
    child (PowerShell especially) exit silently with no output."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                          creationflags=CREATE_NO_WINDOW, errors="replace")


def _own_ip() -> str | None:
    """This PC's IPv4 on the internet-facing connection. Connecting a UDP socket
    sends nothing; it only makes Windows pick the outgoing interface."""
    for target in ("8.8.8.8", "1.1.1.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((target, 80))
                ip = sock.getsockname()[0]
                if ip and not ip.startswith(("0.", "127.")):
                    return ip
        except OSError:
            continue
    return None


def _from_powershell():
    script = r"""
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
if ($r) { $a = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  $ad = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1
  [pscustomobject]@{ ip = $a.IPAddress; prefix = $a.PrefixLength; gateway = $r.NextHop; mac = $ad.MacAddress } | ConvertTo-Json -Compress }
"""
    import base64

    result = _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode()])
    out = result.stdout.strip()
    if not out:
        return None, f"powershell rc={result.returncode} stderr={result.stderr.strip()[:300]}"
    data = json.loads(out)
    if not data.get("ip") or not data.get("gateway"):
        return None, f"powershell incomplete: {out[:300]}"
    return (data["ip"], int(data.get("prefix") or 24), data["gateway"], data.get("mac")), None


_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_MAC = re.compile(r"\b([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\b")


def _from_ipconfig(own_ip: str | None):
    """Parse `ipconfig /all`: find the adapter block holding our IP (or any
    block with a default gateway) and read its gateway, MAC and subnet mask."""
    text = _run(["ipconfig", "/all"]).stdout
    blocks = re.split(r"\r?\n(?=\S)", text)  # each adapter starts at a non-indented line
    for block in blocks:
        ips = re.findall(r"IPv4[^:\n]*:\s*" + _IPV4, block)
        if not ips or (own_ip and own_ip not in ips):
            continue
        gateway = None
        lines = block.splitlines()
        for i, line in enumerate(lines):
            if "gateway" in line.lower():
                found = re.findall(_IPV4, line)
                # the IPv4 gateway may sit on the next line after an IPv6 one
                if not found and i + 1 < len(lines):
                    found = re.findall(_IPV4, lines[i + 1])
                if found:
                    gateway = found[0]
                    break
        if not gateway:
            continue
        mac = _MAC.search(block)
        mask = re.search(r"(?:Subnet Mask|Subnetzmaske|Masque)[^:\n]*:\s*" + _IPV4, block)
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask.group(1)}").prefixlen if mask else 24
        return (own_ip or ips[0], prefix, gateway, mac.group(1) if mac else None), None
    return None, "ipconfig: no adapter with this IP and a gateway"


def _gateway_from_route() -> str | None:
    for line in _run(["route", "print", "-4", "0.0.0.0"]).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return parts[2]
    return None


def local_network():
    """(this PC's IPv4, prefix length, gateway, this PC's MAC) for the internet
    connection. Tries PowerShell, then `ipconfig /all`, then `route print`, so a
    quirk in one of them doesn't stop the scan."""
    from . import settings

    own_ip = _own_ip()
    notes = [f"own_ip={own_ip}"]
    for source in (_from_powershell, lambda: _from_ipconfig(own_ip)):
        try:
            found, why = source()
        except Exception as e:  # keep going to the next source
            found, why = None, f"{type(e).__name__}: {e}"
        if found:
            ip, prefix, gateway, mac = found
            mac = (mac or "").lower().replace(":", "-") or None
            return ip, prefix, gateway, mac
        notes.append(why)
    gateway = _gateway_from_route()
    if own_ip and gateway:
        return own_ip, 24, gateway, None
    notes.append(f"route gateway={gateway}")
    settings.log_crash("no_network", "\n".join(notes))
    raise RuntimeError("no_network")


def arp_table(own_ip: str) -> dict[str, str]:
    out = _run(["arp", "-a"], timeout=15).stdout
    found, ours = {}, False
    for line in out.splitlines():
        iface = _IFACE_LINE.match(line)
        if iface:
            ours = iface.group(1) == own_ip
            continue
        m = _ARP_LINE.match(line)
        if ours and m:  # (the "dynamic"/"static" word is translated on non-English Windows)
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
