"""Browser hijack guard: notices when something changes where your browser goes.

Watched (these are what adware and "search helpers" change, and what people
rarely change themselves):
- Browser policies in the registry for Chrome, Edge, Brave and Firefox, per
  user and for all users. That's how hijackers force a homepage, a search
  engine or extensions you can't remove ("Managed by your organization").
- The Windows hosts file, which can quietly send a website's name to another
  server.
- Windows' proxy settings, which can route all web traffic through someone else.

The first check records how things are; after that, changes are reported with
the choice to undo them or keep them. Undoing a policy or a hosts-file change
needs administrator rights (one Windows prompt): Windows only lets
administrators change those, which also means a hijacker needed them too.
"""
import json
import os
import winreg
from dataclasses import dataclass
from pathlib import Path

from . import paths

BASELINE = paths.DATA_DIR / "browser_guard.json"
HOSTS = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
POLICY_KEYS = {
    r"Software\Policies\Google\Chrome": "Google Chrome",
    r"Software\Policies\Microsoft\Edge": "Microsoft Edge",
    r"Software\Policies\BraveSoftware\Brave": "Brave",
    r"Software\Policies\Mozilla\Firefox": "Firefox",
}
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_VALUES = ("ProxyEnable", "ProxyServer", "AutoConfigURL")
DELETE = "::delete::"  # "remove this value", on the elevated command line
HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
# Policy names worth describing in plain words (translation keys)
POLICY_WORDS = {
    "homepagelocation": "guard_what_homepage",
    "restoreonstartupurls": "guard_what_startup",
    "restoreonstartup": "guard_what_startup",
    "newtabpagelocation": "guard_what_newtab",
    "defaultsearchprovidersearchurl": "guard_what_search",
    "defaultsearchprovidername": "guard_what_search",
    "defaultsearchproviderenabled": "guard_what_search",
    "extensioninstallforcelist": "guard_what_extensions",
    "extensionsettings": "guard_what_extensions",
    "proxyserver": "guard_what_proxy",
    "proxymode": "guard_what_proxy",
    "proxypacurl": "guard_what_proxy",
    "proxysettings": "guard_what_proxy",
}


@dataclass
class Item:
    """One watched setting. key is stable and unique, e.g.
    'policy|HKLM|Software\\Policies\\Google\\Chrome\\ExtensionInstallForcelist|1'."""
    key: str
    kind: str            # "policy", "hosts" or "proxy"
    label: str           # browser name, "hosts file" or "proxy"
    what: str            # translation key: what it controls
    value: str

    @property
    def needs_admin(self) -> bool:
        return self.kind in ("hosts", "policy")


@dataclass
class Change:
    item: Item                 # the setting as it is now (or as it was, when removed)
    old: str | None            # None: newly added
    new: str | None            # None: removed


# --------------------------------------------------------------- reading --
def _policy_items() -> list[Item]:
    items = []
    for hive_name, hive in HIVES.items():
        for base, browser in POLICY_KEYS.items():
            stack = [base]
            while stack:
                path = stack.pop()
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                except OSError:
                    continue
                with key:
                    for i in range(1000):
                        try:
                            stack.append(path + "\\" + winreg.EnumKey(key, i))
                        except OSError:
                            break
                    for i in range(1000):
                        try:
                            name, value, _type = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        leaf = path.rsplit("\\", 1)[-1].lower() if path != base else name.lower()
                        what = POLICY_WORDS.get(name.lower()) or POLICY_WORDS.get(leaf) or "guard_what_policy"
                        items.append(Item(f"policy|{hive_name}|{path}|{name}", "policy", browser, what, str(value)))
    return items


def _hosts_lines() -> list[str]:
    try:
        text = HOSTS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            lines.append(" ".join(line.split()))
    return lines


def _proxy_items() -> list[Item]:
    items = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
            values = {}
            for name in PROXY_VALUES:
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except OSError:
        return items
    if values.get("ProxyEnable") and values.get("ProxyServer"):
        items.append(Item("proxy|ProxyServer", "proxy", "Windows", "guard_what_proxy", str(values["ProxyServer"])))
    if values.get("AutoConfigURL"):
        items.append(Item("proxy|AutoConfigURL", "proxy", "Windows", "guard_what_pac", str(values["AutoConfigURL"])))
    return items


def current() -> list[Item]:
    items = _policy_items()
    items += [Item(f"hosts|{line}", "hosts", "hosts", "guard_what_hosts", line) for line in _hosts_lines()
              if not _harmless_hosts_line(line)]
    items += _proxy_items()
    return items


def _harmless_hosts_line(line: str) -> bool:
    """localhost entries Windows and dev tools add."""
    parts = line.split()
    return len(parts) >= 2 and all(p in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback")
                                   or p.endswith((".localhost", ".test")) for p in parts[1:]) \
        and parts[0] in ("127.0.0.1", "::1", "0.0.0.0")


# -------------------------------------------------------------- baseline --
def _load() -> dict | None:
    try:
        return json.loads(BASELINE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(items: dict):
    BASELINE.write_text(json.dumps(items, indent=1), encoding="utf-8")


def check() -> list[Change]:
    """What changed since the last check that was kept. The first check just records."""
    now = {i.key: i for i in current()}
    base = _load()
    if base is None:
        _save({k: {"value": i.value, "kind": i.kind, "label": i.label, "what": i.what} for k, i in now.items()})
        return []
    changes = []
    for key, item in now.items():
        old = base.get(key)
        if old is None:
            changes.append(Change(item, None, item.value))
        elif old["value"] != item.value:
            changes.append(Change(item, old["value"], item.value))
    for key, old in base.items():
        if key not in now:
            changes.append(Change(Item(key, old["kind"], old["label"], old["what"], old["value"]), old["value"], None))
    return changes


def accept(changes):
    """Keeps these changes: they become the new normal."""
    base = _load() or {}
    for c in changes:
        if c.new is None:
            base.pop(c.item.key, None)
        else:
            base[c.item.key] = {"value": c.new, "kind": c.item.kind, "label": c.item.label, "what": c.item.what}
    _save(base)


def undo(changes):
    """Puts these settings back. Added ones are removed, changed or removed ones restored."""
    for c in changes:
        _set(c.item, c.old)
    accept([Change(c.item, c.new, c.old) for c in changes])


def remove(item: Item):
    """Removes a setting that's there now (from the Browser guard page)."""
    _set(item, None)
    accept([Change(item, item.value, None)])


def _set(item: Item, value: str | None):
    """Sets (value) or deletes (None) one watched setting."""
    if item.kind == "policy":  # Policies keys are admin-only, even the per-user ones
        from . import elevate

        _, hive_name, path, name = item.key.split("|", 3)
        elevate.run("browserguard", "policy", hive_name, path, name, DELETE if value is None else value)
    elif item.kind == "hosts":
        from . import elevate

        elevate.run("browserguard", "hostsadd" if value is not None else "hostsremove", item.value)
    elif item.kind == "proxy":
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
            if item.key == "proxy|ProxyServer":
                if value is None:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                else:
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, value)
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            elif value is None:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, value)


def _policy_write(hive, path, name, value):
    if not any(path.lower().startswith(base.lower()) for base in POLICY_KEYS):
        raise RuntimeError(f"not a browser policy: {path}")
    if value is None:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass
    else:
        with winreg.CreateKeyEx(hive, path, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            kind = winreg.REG_DWORD if value.isdigit() and len(value) < 10 else winreg.REG_SZ
            winreg.SetValueEx(key, name, 0, kind, int(value) if kind == winreg.REG_DWORD else value)


def elevated(action: str, args: list[str]):
    """Admin side: only all-users browser policies and single hosts-file lines."""
    if action == "policy" and len(args) == 4 and args[0] in HIVES:
        _policy_write(HIVES[args[0]], args[1], args[2], None if args[3] == DELETE else args[3])
    elif action in ("hostsremove", "hostsadd") and len(args) == 1:
        line = " ".join(args[0].split())
        if not line or "\n" in line or len(line) > 300:
            raise RuntimeError("not a hosts-file line")
        text = HOSTS.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if action == "hostsremove":
            kept = [l for l in lines if " ".join(l.split("#", 1)[0].split()) != line]
        else:
            kept = lines + [line]
        HOSTS.write_text("\r\n".join(kept) + "\r\n", encoding="utf-8")
    else:
        raise RuntimeError(f"unknown browser guard action {action!r}")


def describe(item: Item) -> str:
    """The setting's value, shortened for a popup."""
    value = item.value
    if item.kind == "policy":
        value = f"{item.key.rsplit('|', 1)[1]} = {value}"
    return value if len(value) <= 90 else value[:89] + "…"
