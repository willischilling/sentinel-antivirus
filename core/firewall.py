"""Controls the built-in Windows Firewall, through its own COM interface
(HNetCfg.FwPolicy2) in PowerShell. Sentinel doesn't add a firewall of its
own: Windows' firewall is a real, kernel-level filter, and this is a simpler
control panel for it, like other security suites have.

Reading the state works as a normal user. Every change goes through the
Windows admin prompt (core/elevate.py), with arguments checked on the admin
side. Rules Sentinel creates are grouped as "Sentinel Antivirus", so they're
easy to find in Windows' own firewall settings and never mixed up with others.
"""
import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

GROUP = "Sentinel Antivirus"
LOCKDOWN_RULE = "Sentinel: Lockdown"
BLOCK_PREFIX = "Sentinel: Block "
PROFILES = {1: "domain", 2: "private", 4: "public"}
CREATE_NO_WINDOW = 0x08000000

_STATUS_SCRIPT = r"""
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$profiles = foreach ($p in 1, 2, 4) {
  [pscustomobject]@{ type = $p; on = $fw.FirewallEnabled($p); inAct = $fw.DefaultInboundAction($p);
                     outAct = $fw.DefaultOutboundAction($p); blockAll = $fw.BlockAllInboundTraffic($p) } }
$rules = @($fw.Rules | Where-Object { $_.Grouping -eq '%GROUP%' } | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; app = $_.ApplicationName; desc = $_.Description; dir = $_.Direction;
                     on = $_.Enabled } })
$net = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; category = "$($_.NetworkCategory)" } })
[pscustomobject]@{ current = $fw.CurrentProfileTypes; profiles = @($profiles); rules = $rules; networks = $net } |
  ConvertTo-Json -Depth 4 -Compress
""".replace("%GROUP%", GROUP)


@dataclass
class BlockedApp:
    name: str      # rule name (shared by all of this app's rules)
    path: str      # the program that was picked
    covered: set = field(default_factory=set)  # every program file its rules block (normcased)

    def missing(self) -> list[str]:
        """Program files of this app that its rules don't cover (e.g. after it updated itself
        into a new version folder)."""
        return [exe for exe in related_exes(self.path) if os.path.normcase(exe) not in self.covered]


@dataclass
class FirewallStatus:
    enabled: bool             # on for the network type in use right now
    all_enabled: bool         # on for every network type
    inbound_blocked: bool
    outbound_blocked: bool
    lockdown: bool
    network: str | None       # "Public", "Private", "DomainAuthenticated"
    network_name: str | None
    blocked_apps: list[BlockedApp] = field(default_factory=list)

    @property
    def mode(self) -> str:
        """'off', 'lockdown', 'standard' or 'custom' (changed outside Sentinel)."""
        if not self.enabled:
            return "off"
        if self.lockdown:
            return "lockdown"
        if self.inbound_blocked and not self.outbound_blocked:
            return "standard"
        return "custom"


def _run_ps(script: str, timeout=60) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)


def status() -> FirewallStatus:
    out = _run_ps(_STATUS_SCRIPT)
    data = json.loads(out.stdout or "null")
    if not data:
        raise RuntimeError((out.stderr or "couldn't read the firewall state").strip()[:200])
    profiles = {p["type"]: p for p in data["profiles"]}
    current = [t for t in PROFILES if data["current"] & t] or [4]
    active = [profiles[t] for t in current]
    rules = data.get("rules") or []
    by_name: dict[str, BlockedApp] = {}
    for rule in rules:
        if not rule["name"].startswith(BLOCK_PREFIX):
            continue
        app = by_name.setdefault(rule["name"], BlockedApp(rule["name"], rule.get("desc") or rule.get("app") or ""))
        if rule.get("app"):
            app.covered.add(os.path.normcase(rule["app"]))
    blocked = list(by_name.values())
    networks = data.get("networks") or []
    return FirewallStatus(
        enabled=all(p["on"] for p in active),
        all_enabled=all(p["on"] for p in profiles.values()),
        inbound_blocked=all(p["inAct"] == 0 for p in active),   # NET_FW_ACTION: 0 block, 1 allow
        outbound_blocked=all(p["outAct"] == 0 for p in active),
        lockdown=any(r["name"] == LOCKDOWN_RULE and r["on"] for r in rules),
        network=networks[0]["category"] if networks else None,
        network_name=networks[0]["name"] if networks else None,
        blocked_apps=sorted(blocked, key=lambda b: Path(b.path).name.lower()),
    )


# ------------------------------------------------ changes (admin prompt) --
def turn_on():
    _elevated("on")


def set_mode(mode: str):
    _elevated("mode", mode)


def block_app(path: str):
    _elevated("block", path)


def unblock_app(rule_name: str):
    _elevated("unblock", rule_name)


def _elevated(*args):
    from . import elevate

    elevate.run("firewall", *args)


def related_exes(path: str, limit: int = 60) -> list[str]:
    """The program files that make up an app, starting from the one the user picked.

    Many apps start through a small launcher and run the real program from a version
    folder: Discord's shortcut opens Discord\\Discord.exe, but the app that connects is
    Discord\\app-1.0.9259\\Discord.exe. So this returns the picked program, copies of it
    (same file name) in folders below it, and for Squirrel-installed apps (Discord, Slack,
    Teams...: an Update.exe next to app-* folders) the helper programs in those folders.
    It never widens to other programs in shared folders, so blocking Word doesn't block Excel.
    """
    picked = Path(path)
    found = [str(picked)]
    base = picked.parent
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if not base.is_dir() or os.path.normcase(str(base)).startswith(windows):
        return found
    squirrel = (base / "Update.exe").is_file() and any(base.glob("app-*"))
    seen = {os.path.normcase(str(picked))}
    for depth_glob in ("*/*.exe", "*/*/*.exe", "*/*/*/*.exe"):
        for exe in base.glob(depth_glob):
            key = os.path.normcase(str(exe))
            if key in seen:
                continue
            same_name = exe.name.lower() == picked.name.lower()
            helper = squirrel and exe.relative_to(base).parts[0].lower().startswith("app-")
            if same_name or helper:
                seen.add(key)
                found.append(str(exe))
                if len(found) >= limit:
                    return found
    return found


def running_processes(paths) -> list:
    """Running processes started from any of these program files."""
    import psutil

    wanted = {os.path.normcase(p) for p in paths}
    procs = []
    for proc in psutil.process_iter(["exe"]):
        exe = proc.info.get("exe")
        if exe and os.path.normcase(exe) in wanted:
            procs.append(proc)
    return procs


def rule_name_for(path: str) -> str:
    digest = hashlib.sha1(os.path.normcase(path).encode("utf-8")).hexdigest()[:6]
    return f"{BLOCK_PREFIX}{Path(path).name} ({digest})"


def _q(value: str) -> str:
    """A PowerShell single-quoted string literal."""
    return "'" + value.replace("'", "''") + "'"


def _new_rule(name: str, direction: int, app: str | None = None, description: str = "") -> str:
    lines = ["$r = New-Object -ComObject HNetCfg.FWRule", f"$r.Name = {_q(name)}", f"$r.Grouping = {_q(GROUP)}",
             f"$r.Description = {_q(description)}", f"$r.Direction = {direction}",  # 1 in, 2 out
             "$r.Action = 0", "$r.Profiles = 7", "$r.Enabled = $true"]
    if app:
        lines.append(f"$r.ApplicationName = {_q(app)}")
    lines.append("$fw.Rules.Add($r)")
    return "\n".join(lines)


def _remove_rules(name: str) -> str:
    # Rules.Remove deletes one rule per call; the inbound and outbound rule share a name.
    return f"while (@($fw.Rules | Where-Object {{ $_.Name -eq {_q(name)} }}).Count) {{ $fw.Rules.Remove({_q(name)}) }}"


def elevated(action: str, args: list[str]):
    """Runs on the admin side. Only these fixed changes are possible, with checked arguments."""
    script = ["$fw = New-Object -ComObject HNetCfg.FwPolicy2"]
    if action == "on":
        script += [f"$fw.FirewallEnabled({t}) = $true" for t in PROFILES]
    elif action == "mode" and args and args[0] in ("standard", "lockdown"):
        lockdown = args[0] == "lockdown"
        for t in PROFILES:
            script += [f"$fw.FirewallEnabled({t}) = $true", f"$fw.DefaultInboundAction({t}) = 0",
                       f"$fw.DefaultOutboundAction({t}) = 1",
                       f"$fw.BlockAllInboundTraffic({t}) = ${'true' if lockdown else 'false'}"]
        script.append(_remove_rules(LOCKDOWN_RULE))
        if lockdown:
            # A block rule beats every allow rule, so this stops all outgoing traffic too.
            script.append(_new_rule(LOCKDOWN_RULE, 2, description="All network traffic blocked by Sentinel"))
    elif action == "block" and args:
        path = args[0]
        if not (Path(path).is_file() and path.lower().endswith(".exe")):
            raise RuntimeError(f"not a program: {path}")
        windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        if os.path.normcase(path).startswith(windows):
            raise RuntimeError("Windows' own programs can't be blocked here; it could break Windows")
        name = rule_name_for(path)
        script.append(_remove_rules(name))
        for exe in related_exes(path):  # the picked program plus its real/versioned copies
            script += [_new_rule(name, 1, exe, path), _new_rule(name, 2, exe, path)]
    elif action == "unblock" and args and args[0].startswith(BLOCK_PREFIX):
        script.append(_remove_rules(args[0]))
    else:
        raise RuntimeError(f"unknown firewall action {action!r}")
    body = "\n".join(script)
    wrapped = ("$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'\n"
               f"try {{\n{body}\n}} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")
    result = _run_ps(wrapped)
    if result.returncode != 0:
        errors = [line[7:] for line in result.stdout.splitlines() if line.startswith("ERROR: ")]
        raise RuntimeError(errors[-1].strip() if errors else "the firewall change failed")
