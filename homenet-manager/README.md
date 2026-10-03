# Home Network Manager

A standalone, GVTC/CommandIQ-style control panel for **your own** home network.
It does not depend on any other app.

- **See every device** on your Wi-Fi, with its maker; name each one, give it a
  profile (Me / Family / Kids / Guest / Other), and search or sort the list.
- **Pause or resume the internet** for a device — now, on an **off-hours
  schedule**, or with a one-click **Focus timer** that auto-resumes.
- **Block websites** by category (adult, social, games, streaming, ads) or your
  own list, and **keep the blocks in place** with a background check.
- **Admin PIN** protects your own access: pausing or resuming the admin device
  needs the PIN, so no one else can keep you offline.
- **Overview dashboard** with stat tiles and a quick **speed test** (download +
  latency).
- **New-device alerts**: devices seen for the first time are flagged NEW, with
  first/last-seen history.
- **Activity log** of what the app did, and a **saveable HTML report**.
- **Dark & light themes**, plus scan-on-launch and keep-running options.

## Scope and what is actually enforced

This only manages **your own** home network. It never touches a network or
device you don't own.

| What | This PC | Other devices on your network |
|------|---------|-------------------------------|
| Pause / resume internet | **Enforced** — a Windows Firewall outbound block rule cuts all traffic and resumes it | **Managed policy** — stored and shown as managed, to apply at your router |
| Block websites | **Enforced** — hosts file (every browser & app) + a family DNS filter for adult content | **Managed policy** — to apply at your router |

A desktop app can't flip another device's internet on or off without going
through the router — that's a hardware boundary. So for other devices, the app
records your policy and shows it as *managed*, the same way an ISP's own app is
a front-end to the router.

## Running

Requires **Windows** (it uses the Windows Firewall, the hosts file, and the DNS
client) and **Python 3.11+**.

```powershell
# no third-party dependencies needed
python main.py
```

Pausing this PC, applying website blocks, and switching the DNS filter each ask
for the one Windows administrator prompt. Everything else — scanning, naming
devices, profiles, choosing what to block — needs no special rights.

## How it works

- **Devices** — a harmless UDP sweep of your own subnet makes Windows resolve
  each address; the app reads the results from the ARP table and labels makers
  from the public IEEE list (cached locally).
- **Pause / resume (this PC)** — adds or removes one Windows Firewall outbound
  block rule, "Home Network: Internet Paused". It doesn't change your firewall
  mode or any other rule.
- **Website blocking (this PC)** — writes the chosen domains into a clearly
  marked block in `C:\Windows\System32\drivers\etc\hosts` (and only ever
  rewrites its own block), plus switches on Cloudflare for Families DNS for the
  adult category.
- **Staying applied** — every few minutes the app reads the hosts file (no admin
  needed) and, if its block was changed, puts it back. Re-applying needs the one
  admin prompt, so it asks once when a change first appears rather than every
  few minutes. Turn this off with "Keep these blocks enforced".
- **Settings** live in `%LOCALAPPDATA%\HomeNetManager\settings.json`; the admin
  PIN is stored only as a salted hash.

## Project layout

```
main.py                entry point (also the admin helper via --elevated)
homenet/
  settings.py          JSON settings in %LOCALAPPDATA%\HomeNetManager
  netscan.py           device discovery + maker lookup
  control.py           devices, profiles, PIN, blocklist, enforcement state
  firewall.py          pause / resume this PC (admin side)
  hostsblock.py        website blocking via the hosts file (admin side)
  dns.py               family DNS filter for adult content (admin side)
  elevate.py           one-shot Windows admin prompt + action dispatch
  watcher.py           background check that keeps blocks applied
  widgets.py           custom-drawn cards, buttons, toggles, banner
  ui.py                the window (sidebar dashboard)
```

## Building a single double-clickable .exe

Easiest: **double-click `build.bat`**. It installs the build tool, builds the
app, and leaves `dist\HomeNetManager.exe` — a single file you can double-click
or drag to your Desktop. (You still need Python installed first.)

Or by hand:

```powershell
pip install pyinstaller
pyinstaller --noconsole --onefile --name "HomeNetManager" main.py
```

The elevate helper re-launches the same executable, so the one-file build works
as-is.
