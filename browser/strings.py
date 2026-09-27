"""The browser's text in the current language, for its HTML pages (they get it as JSON)."""
from core.i18n import t
from core.translations import EN

PREFIXES = ("brw_", "page_", "scam_")


def table() -> dict[str, str]:
    return {key: t(key) for key in EN if key.startswith(PREFIXES)}
