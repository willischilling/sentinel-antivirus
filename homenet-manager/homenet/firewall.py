"""Pauses and resumes THIS PC's internet through the built-in Windows Firewall.

Pausing adds a single outbound block rule ("Home Network: Internet Paused").
A block rule beats every allow rule, so this cuts all outgoing traffic without
changing the firewall's mode or any other rule. Resuming removes it. Every
change goes through the one Windows admin prompt (elevate.py).
"""
import base64
import subprocess

GROUP = "Home Network Manager"
PAUSE_RULE = "Home Network: Internet Paused"
PROFILES = (1, 2, 4)  # domain, private, public
CREATE_NO_WINDOW = 0x08000000


def _run_ps(script: str, timeout=60) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                          creationflags=CREATE_NO_WINDOW)


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def pause_internet():
    from . import elevate
    elevate.run("firewall", "pause")


def resume_internet():
    from . import elevate
    elevate.run("firewall", "resume")


def internet_paused() -> bool:
    """Whether this PC's internet is currently paused (reads state, no admin)."""
    script = ("$fw = New-Object -ComObject HNetCfg.FwPolicy2; "
              "@($fw.Rules | Where-Object { $_.Name -eq " + _q(PAUSE_RULE) + " -and $_.Enabled }).Count")
    out = _run_ps(script, timeout=30).stdout.strip()
    return out.isdigit() and int(out) > 0


# ------------------------------------------------ admin side (one prompt) --
def _remove_rule(name: str) -> str:
    return (f"while (@($fw.Rules | Where-Object {{ $_.Name -eq {_q(name)} }}).Count) "
            f"{{ $fw.Rules.Remove({_q(name)}) }}")


def _block_rule(name: str, description: str) -> str:
    return "\n".join([
        "$r = New-Object -ComObject HNetCfg.FWRule",
        f"$r.Name = {_q(name)}", f"$r.Grouping = {_q(GROUP)}", f"$r.Description = {_q(description)}",
        "$r.Direction = 2", "$r.Action = 0", "$r.Profiles = 7", "$r.Enabled = $true",
        "$fw.Rules.Add($r)",
    ])


def elevated(action: str, args: list[str]):
    """Admin side: only pause or resume, with no free-form arguments."""
    if action not in ("pause", "resume"):
        raise RuntimeError(f"unknown firewall action {action!r}")
    script = ["$fw = New-Object -ComObject HNetCfg.FwPolicy2", _remove_rule(PAUSE_RULE)]
    if action == "pause":
        script += [f"$fw.FirewallEnabled({p}) = $true" for p in PROFILES]
        script.append(_block_rule(PAUSE_RULE, "Internet paused by Home Network Manager"))
    body = "\n".join(script)
    result = _run_ps("$ErrorActionPreference = 'Stop'\n"
                     f"try {{\n{body}\n}} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")
    if result.returncode != 0:
        errors = [line[7:] for line in result.stdout.splitlines() if line.startswith("ERROR: ")]
        raise RuntimeError(errors[-1].strip() if errors else "couldn't change the firewall")
