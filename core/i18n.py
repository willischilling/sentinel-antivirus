"""Translations for the app, background agent, installer and uninstaller.

Deliberately has no imports from the rest of the app, so the installer and
uninstaller can bundle it on its own.
"""
import sys
from datetime import datetime

from .translations import STRINGS

LANGUAGES = {  # code -> name in that language
    "en": "English",
    "zh": "简体中文",
    "hi": "हिन्दी",
    "es": "Español",
    "fr": "Français",
}
ENGLISH_NAMES = {"en": "English", "zh": "Chinese", "hi": "Hindi", "es": "Spanish", "fr": "French"}
# Windows primary language IDs (low 10 bits of a LANGID).
_WINDOWS_LANG_IDS = {0x09: "en", 0x04: "zh", 0x39: "hi", 0x0A: "es", 0x0C: "fr"}

_current = "en"


def system_default() -> str:
    """The Windows display language, if it's one we support."""
    if sys.platform == "win32":
        try:
            import ctypes

            lang_id = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            return _WINDOWS_LANG_IDS.get(lang_id & 0x3FF, "en")
        except (AttributeError, OSError):
            pass
    return "en"


def set_language(code: str | None):
    global _current
    _current = code if code in LANGUAGES else system_default()


def current() -> str:
    return _current


def t(key: str, **values) -> str:
    text = STRINGS.get(_current, {}).get(key)
    if text is None:
        text = STRINGS["en"].get(key, key)
    return text.format(**values) if values else text


def plural(key: str, n: int, **values) -> str:
    """Picks key_one / key_other using the language's plural rule."""
    if _current == "zh":
        form = "other"  # Chinese has no grammatical plural
    elif _current == "fr":
        form = "one" if n in (0, 1) else "other"
    else:
        form = "one" if n == 1 else "other"
    return t(f"{key}_{form}", n=number(n), **values)


def number(n: int) -> str:
    """Thousands grouping in the local style."""
    grouped = f"{n:,}"
    if _current == "fr":
        return grouped.replace(",", " ")  # narrow no-break space
    if _current == "es":
        return grouped.replace(",", ".")
    return grouped


def time_of_day(moment: datetime) -> str:
    if _current == "en":
        return moment.strftime("%I:%M %p").lstrip("0")
    return moment.strftime("%H:%M")


def duration(seconds: int) -> str:
    """'45s' / '10m 11s' / '1h 5m', in the current language."""
    minutes, secs = divmod(max(0, int(seconds)), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return t("duration_hm", h=hours, m=minutes)
    if minutes:
        return t("duration_ms", m=minutes, s=secs)
    return t("duration_s", s=secs)


def relative(moment: datetime) -> str:
    """'Today, 7:28 PM' / 'Yesterday, ...' / a date, in the current language."""
    now = datetime.now(moment.tzinfo)
    clock = time_of_day(moment)
    days = (now.date() - moment.date()).days
    if days == 0:
        return t("today_at", time=clock)
    if days == 1:
        return t("yesterday_at", time=clock)
    if days == -1:
        return t("tomorrow_at", time=clock)
    return moment.strftime(t("date_format")) + " " + clock
