"""Open a file safely in Windows Sandbox: a throwaway copy of Windows that's
wiped completely when you close it, so whatever the file does can't reach
your real PC.

Sentinel copies the file into a fresh folder, shares only that folder with the
sandbox (read-only), and opens the file inside it. By default the sandbox has
no internet, no clipboard, microphone, camera or printer access, which also
stops malware inside from downloading anything else or phoning home.

Windows Sandbox comes with Windows 10/11 Pro, Enterprise and Education. It's
an optional feature: turning it on needs the admin prompt and a restart.
"""
import os
import shutil
import subprocess
import time
import uuid
import winreg
from pathlib import Path
from xml.sax.saxutils import escape

SANDBOX_EXE = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
WORK_DIR = Path(os.environ.get("TEMP", Path.home())) / "SentinelSandbox"
INSIDE = r"C:\Users\WDAGUtilityAccount\Desktop\Sentinel"
SUPPORTED_EDITIONS = ("professional", "enterprise", "education", "server", "iot")
CREATE_NO_WINDOW = 0x08000000


def status() -> str:
    """'ready', 'off' (this Windows has it, but it isn't turned on) or 'unsupported' (Windows Home)."""
    if SANDBOX_EXE.exists():
        return "ready"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            edition = str(winreg.QueryValueEx(key, "EditionID")[0]).lower()
    except OSError:
        edition = ""
    return "off" if any(edition.startswith(e) for e in SUPPORTED_EDITIONS) else "unsupported"


def running() -> bool:
    import psutil

    return any((p.info.get("name") or "").lower() in ("windowssandbox.exe", "windowssandboxclient.exe")
               for p in psutil.process_iter(["name"]))


def open_file(path: str, internet: bool = False) -> Path:
    """Starts Windows Sandbox with a copy of the file and opens it there. Returns the
    .wsb configuration used. Raises RuntimeError with a translation key when it can't."""
    src = Path(path)
    if not src.is_file():
        raise RuntimeError("sandbox_err_missing")
    if status() != "ready":
        raise RuntimeError("sandbox_err_off")
    if running():
        raise RuntimeError("sandbox_err_running")  # Windows allows one sandbox at a time
    _clean_old()
    folder = WORK_DIR / uuid.uuid4().hex
    share = folder / "share"
    share.mkdir(parents=True)
    shutil.copy2(src, share / src.name)
    inside_file = f"{INSIDE}\\{src.name}"
    config = f"""<Configuration>
  <Networking>{"Enable" if internet else "Disable"}</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{escape(str(share))}</HostFolder>
      <SandboxFolder>{escape(INSIDE)}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe "{escape(inside_file)}"</Command>
  </LogonCommand>
</Configuration>
"""
    wsb = folder / "open.wsb"
    wsb.write_text(config, encoding="utf-8")
    os.startfile(str(wsb))
    return wsb


def _clean_old():
    """Removes copies from earlier sandbox sessions (over a day old)."""
    if not WORK_DIR.is_dir():
        return
    for old in WORK_DIR.iterdir():
        try:
            if time.time() - old.stat().st_mtime > 86400:
                shutil.rmtree(old, ignore_errors=True)
        except OSError:
            pass


def turn_on():
    """Turns on the Windows Sandbox feature (admin prompt). A restart finishes it."""
    from . import elevate

    elevate.run("sandbox", "enable")


def elevated(args: list[str]):
    if args != ["enable"]:
        raise RuntimeError("bad sandbox action")
    result = subprocess.run(["dism.exe", "/Online", "/Enable-Feature", "/FeatureName:Containers-DisposableClientVM",
                             "/All", "/NoRestart"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
    # 3010: done, restart needed
    if result.returncode not in (0, 3010):
        lines = [l.strip() for l in (result.stdout or "").splitlines() if l.strip()]
        raise RuntimeError(lines[-1] if lines else f"DISM error {result.returncode}")
