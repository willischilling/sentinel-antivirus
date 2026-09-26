"""Creates a Windows .lnk shortcut via a throwaway VBScript (no pywin32 dependency)."""
import subprocess
import tempfile
from pathlib import Path


def create_shortcut(shortcut_path: Path, target: Path, working_dir: Path, icon: Path, description: str = ""):
    shortcut_path.parent.mkdir(parents=True, exist_ok=True)
    vbs = f'''
Set oWS = WScript.CreateObject("WScript.Shell")
Set oLink = oWS.CreateShortcut("{shortcut_path}")
oLink.TargetPath = "{target}"
oLink.WorkingDirectory = "{working_dir}"
oLink.IconLocation = "{icon}"
oLink.Description = "{description}"
oLink.Save
'''
    with tempfile.NamedTemporaryFile("w", suffix=".vbs", delete=False) as f:
        f.write(vbs)
        vbs_path = f.name
    try:
        subprocess.run(["cscript", "//nologo", vbs_path], check=True, capture_output=True)
    finally:
        Path(vbs_path).unlink(missing_ok=True)
