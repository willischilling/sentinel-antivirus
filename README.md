# Sentinel Antivirus

A Windows antivirus built from scratch in Python: an on-demand scanner, real-time protection that keeps running in the background, behavior monitoring, and a desktop app with its own installer.

Sentinel checks files against over a million real malware fingerprints and nearly 5,000 YARA rules, looks inside archives, verifies publisher signatures, and watches for programs adding themselves to startup and for ransomware-like activity.

> **This is a portfolio / learning project, not a replacement for Microsoft Defender.** It has no kernel driver, so it reacts to threats rather than blocking them before they run. Keep Defender on. See [Limitations](#limitations).

![Dashboard](docs/screenshots/dashboard.png)

| Protection off | Scanner | Behavior alerts |
|---|---|---|
| ![Protection off](docs/screenshots/dashboard-off.png) | ![Scanner](docs/screenshots/scanner.png) | ![Alerts](docs/screenshots/alerts.png) |

## Features

### Detection
Every file goes through these layers, strongest first:

1. **Known malware fingerprints.** SHA-256 hashes from [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch): the full history of over 1.1 million samples, plus a rolling feed of the last 48 hours with malware family names (for example "Mirai (MalwareBazaar)").
2. **YARA rules.** The [YARA Forge](https://github.com/YARAHQ/yara-forge) "core" rule set (about 5,000 curated rules, chosen for low false positives), which detects whole malware families rather than single files. Rules with a score of 70 or more count as a threat; lower scores count as suspicious.
3. **Archive contents.** ZIP and JAR are read in memory. 7-Zip, RAR, TAR, CAB and ISO files are listed and extracted with Windows' own Microsoft-signed `tar.exe` (libarchive), so no third-party tools are bundled. Archives inside archives are followed up to two levels deep, across formats.
4. **Heuristics.** Suspicious strings (encoded PowerShell, process-injection APIs, shadow copy deletion...), double extensions like `invoice.pdf.exe`, and obfuscated scripts.

**Publisher signature check.** Weak signals (heuristics and low-score YARA hits) are dropped for files with a valid Authenticode signature, verified with Windows' own `WinVerifyTrust`. This covers both embedded signatures and the catalog signatures most Windows system files use. A signed file with even one byte changed fails the check. Known-malware fingerprints and strong YARA hits still apply to signed files, since malware is occasionally signed with stolen certificates.

**Archive safety limits:**
- Contents are checked against size and compression-ratio limits before anything is extracted, so archive bombs are flagged without being expanded.
- A program hidden inside a password-protected archive is flagged as suspicious. RAR archives with encrypted file names are flagged too.

### Real-time protection
This runs as a separate background process (`Sentinel.exe --agent`), so it keeps going after the window is closed. It stops only when you switch it off. If it was on when the computer shut down, it comes back at the next sign-in.

| Layer | What it does |
|---|---|
| Download protection | Scans new files in the watched folder (Downloads by default) as soon as they finish downloading. |
| Program protection | Checks each new program within about a second of it starting, plus a background sweep of everything already running. |
| Startup protection | Alerts when a program adds itself to the registry Run keys, a Startup folder, or Task Scheduler. |
| Ransomware protection | Watches Documents, Desktop, Pictures, Music, Videos and Downloads for many files suddenly turning into unreadable data or being renamed to strange extensions. |

**Alerts.** These appear as popups in the bottom-right corner, with buttons to act on them:
- Quarantine or Delete a file.
- End a running program, or End and quarantine it.
- Remove or Keep a startup entry or scheduled task.

Nothing is ended or deleted without a click.

**Ransomware alerts** name the program most likely responsible: the process writing the most to disk right now. The alert says "Cause" instead of "Likely cause" when that process also has files open in the affected folder.

**Threat database updates.** The fingerprint list and YARA rules update automatically every 6 hours. The first download is about 45 MB; later updates take a few seconds.

### Desktop app
- A dashboard with protection status, last scan, quarantine count, recent detections and threat database status.
- A scanner for Downloads, Desktop, Documents or any folder, with an animated progress ring.
- Quarantine: files are moved to an isolated folder and renamed so they can't run, and can be restored or permanently deleted.
- Detection history.
- A system tray icon, and an option to start with Windows.
- **Five languages:** English, 简体中文 (Chinese), हिन्दी (Hindi), Español and Français. Sentinel starts in your Windows display language when it's one of these. You can change it on the Settings page or in the installer, and the whole app switches instantly: popups, the tray menu, the activity log and the uninstaller too. Dates, times and numbers use each language's local format.
- Opening Sentinel while it's already running brings up the existing window instead of starting a second copy.

### Installer
`SentinelSetup.exe` installs for the current user only, so no admin rights are needed. It has a language picker, and it:
- adds Start Menu and desktop shortcuts
- adds an entry to Windows' Apps list with a working uninstaller
- can start protection when you sign in (optional)

## Getting started

### Download
Run **[SentinelSetup.exe](SentinelSetup.exe)**. It's in the main folder of this repo, so it's also included if you use **Code → Download ZIP**. You can also get it from the [latest release](https://github.com/willischilling/sentinel-antivirus/releases/latest), whose notes include a SHA-256 checksum for verifying the download.

The installer isn't code-signed, so Windows SmartScreen will warn you: click **More info → Run anyway**.

`installer/installer.py` is the installer's *source code*. Running it directly won't install anything, because the app files are only packed in when `SentinelSetup.exe` is built.

### Requirements
- Windows 10 or 11. Scanning 7-Zip and RAR needs a recent Windows 11 `tar.exe`; everything else works on Windows 10.
- Python 3.11 or newer. It was developed on Python 3.13.

### Run from source
```bash
pip install -r requirements.txt
python gui.py
```

When run from source, all data (database, quarantine, settings, activity log) lives in `data/` and `quarantine/` inside the project folder. The installed app stores it in `%LOCALAPPDATA%\Sentinel Antivirus`.

The first time real-time protection is on, the background process downloads the threat database. You can also start this from the dashboard with **Update now**.

### Build the installer
```bash
pip install pyinstaller
powershell -ExecutionPolicy Bypass -File build_installer.ps1
```
This produces:
- `dist\Sentinel\`: the app, built with `--onedir` so it starts quickly
- `dist\Uninstall.exe`
- `dist\SentinelSetup.exe`: the installer, which bundles the other two. It's also copied to the repo root.

### Command line
There's also a basic CLI (`cli.py`) that uses the same scanning engine:
```bash
python cli.py scan C:\Users\me\Downloads --quarantine
python cli.py procscan
python cli.py quarantine-list
python cli.py import-sigs my_hashes.txt    # lines of: <sha256> <name>
```

## How it works

```
gui.py ─────── main window (dashboard, scanner, quarantine, history)
  │             starts/stops the agent, shows its live activity
  │
  ├─ launcher.py ──────── spawns / signals the agent and the window
  ├─ single_instance.py ─ named mutexes + events (one window, one agent)
  │
agent.py ───── background protection (gui.py --agent)
  ├─ monitor/file_watcher.py ─────── new files in the watched folder
  ├─ monitor/process_watcher.py ──── new and running programs
  ├─ monitor/startup_watcher.py ──── Run keys, Startup folders, scheduled tasks
  ├─ monitor/ransomware_watcher.py ─ mass file encryption in personal folders
  ├─ toast.py / tray.py ──────────── popups and tray icon
  └─ core/threat_intel.py ────────── automatic threat database updates

core/
  scanner.py ───── runs the detection layers on a file
  signatures.py ── hashing;  database.py ── SQLite (fingerprints, history, quarantine, settings)
  yara_engine.py ─ compiled YARA rules;  archives.py ── archive scanning
  authenticode.py  publisher signature verification (WinVerifyTrust via ctypes)
  heuristics.py ── suspicious strings, double extensions, entropy
  quarantine.py, activity.py, settings.py, autostart.py, paths.py

installer/  ── setup wizard, uninstaller, shortcut creation
widgets.py, theme.py ── custom UI widgets (rounded cards, switches, rings) and colors
core/i18n.py, core/translations.py ── the 5 languages (about 220 phrases each), plurals and local formats
```

Design notes:
- **Two processes.** The window and the protection agent communicate through Windows named events and a shared activity log and SQLite database. That's why closing or quitting the window doesn't stop protection.
- **Responsive UI.** Scans run on worker threads and report back through a queue. The main thread drains that queue in small batches, so a burst of results can't freeze the window.
- **Compact fingerprint storage.** The 1.1 million fingerprints are stored as 32-byte blobs in a `WITHOUT ROWID` SQLite table. That keeps the database to about 50 MB with lookups around 1 ms.
- **Process check cache.** Each program's verdict is cached by path, modification time and size, and the cache is cleared when the threat database updates. A running program's file is only re-read when something has changed.
- **Antialiased UI.** Tk can't draw smooth curves on Windows, so rounded corners, switches and rings are drawn with Pillow at 4x size and scaled down.

## Testing notes

Everything was tested with harmless stand-ins, never real malware:
- **Signature matches:** a text file whose hash was added to the local list, and a copy of Windows' `ping.exe` registered the same way as a "known bad" running program.
- **YARA:** test rules that match marker strings.
- **Archives:** ZIP, RAR (made with WinRAR), 7z, TAR.GZ and ISO archives containing those stand-ins, including nested and password-protected ones.
- **Startup and task alerts:** a test registry key, a scratch folder, and a scheduled task set to run in 2099.

Measured results:
- **False positives:** none on 500 Windows System32 files or on 1,147 files in a real Downloads folder.
- **New-program check:** a known-bad program spotted about 0.5 seconds after starting; about 0.3% of one CPU core once settled.

## Limitations

- **No pre-execution blocking.** Blocking a program before it runs requires a Windows kernel driver. Sentinel detects and responds within about a second instead.
- **Brand-new malware can be missed.** If no fingerprint, YARA rule or heuristic covers it, it won't be caught.
- **Ransomware detection reacts after the fact.** It triggers after about 10 files are affected. The "likely cause" is a best guess based on disk activity, so check the name before ending a program. Bait files and automatic pausing of suspects were designed but left out because they couldn't be properly tested.
- **Download protection watches one folder** (Downloads by default).
- **Archive limits:** archives larger than 256 MB unpacked, and encrypted archive contents, can't be scanned inside.
- **Runs as the current user.** It can't end programs running as administrator, or remove all-users startup entries, without elevation.

## Credits

- Malware fingerprints: [MalwareBazaar](https://bazaar.abuse.ch/) by abuse.ch
- YARA rules: [YARA Forge](https://github.com/YARAHQ/yara-forge), which packages rules from many open-source authors under their respective licenses
- Libraries: [yara-python](https://github.com/VirusTotal/yara-python), [watchdog](https://github.com/gorakhargosh/watchdog), [psutil](https://github.com/giampaolo/psutil), [pystray](https://github.com/moses-palmer/pystray), [Pillow](https://python-pillow.org/), [PyInstaller](https://pyinstaller.org/)

Threat data is downloaded at runtime and not redistributed with the app. Only hash lists and rule text are downloaded, never malware samples.
