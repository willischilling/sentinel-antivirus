"""Blocks websites on this PC by writing them into Windows' hosts file, so every
browser and app is covered. Only ever rewrites this program's own clearly
marked block; it never touches any other line in the file.
"""
import json
import os
import subprocess

HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "drivers", "etc", "hosts")
BEGIN = "# >>> Home Network Manager >>>"
END = "# <<< Home Network Manager <<<"
CREATE_NO_WINDOW = 0x08000000


def clean_domain(raw: str) -> str:
    """'https://www.Example.com/path' -> 'example.com'."""
    d = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split("?")[0]
    if d.startswith("www."):
        d = d[4:]
    return d if "." in d and " " not in d else ""


def current_domains() -> set[str]:
    """Base domains currently in this program's hosts block (read-only)."""
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return set()
    if BEGIN not in text or END not in text:
        return set()
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    found = set()
    for line in block.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0] == "0.0.0.0":
            host = parts[1][4:] if parts[1].startswith("www.") else parts[1]
            if host:
                found.add(host)
    return found


def _strip_block(text: str) -> str:
    while BEGIN in text and END in text:
        before, _, rest = text.partition(BEGIN)
        _, _, after = rest.partition(END)
        text = before.rstrip("\n") + ("\n" + after.lstrip("\n") if after.strip() else "\n")
    return text


# ------------------------------------------------------- admin side --------
def elevated(action: str, args: list[str]):
    """Admin side: rewrite only our marked block to hold exactly these domains."""
    if action != "set":
        raise RuntimeError(f"unknown hosts action {action!r}")
    domains = [d for d in (clean_domain(x) for x in json.loads(args[0] or "[]")) if d]
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""
    kept = _strip_block(text)
    if domains:
        lines = [BEGIN, "# Added by Home Network Manager. Edit these in the app, not here."]
        for d in domains:
            lines.append(f"0.0.0.0 {d}")
            lines.append(f"0.0.0.0 www.{d}")
        lines.append(END)
        block = "\n".join(lines)
        new = (kept.rstrip() + "\n\n" + block + "\n") if kept.strip() else (block + "\n")
    else:
        new = kept if (not kept or kept.endswith("\n")) else kept + "\n"
    with open(HOSTS, "w", encoding="utf-8") as fh:
        fh.write(new)
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, stdin=subprocess.DEVNULL,
                       creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass
