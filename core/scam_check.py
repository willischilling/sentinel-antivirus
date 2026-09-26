"""Built-in scam checks for Ask Sentinel: fast, offline, no AI.

Looks at every link in a message (known phishing/malware lists, brand
look-alikes, disguised characters, shorteners...) and at the wording
(gift cards, passwords and codes, prizes, remote access...). The findings
are shown as-is and also handed to the AI as facts, so a small local model
doesn't have to guess.
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import link_intel
from .translations import EN


@dataclass
class Finding:
    level: str          # "bad", "warn", "good" or "info"
    key: str            # translation key
    values: dict = field(default_factory=dict)

    def english(self) -> str:
        return EN[self.key].format(**self.values)


@dataclass
class Report:
    findings: list[Finding]
    links: list[str]

    @property
    def verdict(self) -> str | None:
        """'scam', 'suspicious', 'caution', 'safe' or None (nothing to go on)."""
        levels = [f.level for f in self.findings]
        if "bad" in levels:
            return "scam"
        if levels.count("warn") >= 2:
            return "suspicious"
        if "warn" in levels:
            return "caution"
        if "good" in levels:
            return "safe"
        return None


# Brand name -> domains it really uses. A brand name in any other domain is a red flag.
BRANDS = {
    "paypal": ["paypal.com", "paypal.me"], "apple": ["apple.com", "icloud.com"], "icloud": ["icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "windows.com"],
    "outlook": ["outlook.com", "live.com", "office.com"], "office365": ["office.com", "microsoft.com"],
    "google": ["google.com", "youtube.com", "gmail.com", "goo.gl", "g.co"], "gmail": ["gmail.com", "google.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.in", "amzn.to"],
    "netflix": ["netflix.com"], "roblox": ["roblox.com", "rbxcdn.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com", "discord.media"],
    "steam": ["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    "steamcommunity": ["steamcommunity.com"], "epicgames": ["epicgames.com"], "fortnite": ["fortnite.com", "epicgames.com"],
    "usps": ["usps.com"], "fedex": ["fedex.com"], "dhl": ["dhl.com", "dhl.de"],
    "facebook": ["facebook.com", "fb.com", "meta.com"], "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com", "wa.me"], "tiktok": ["tiktok.com"], "snapchat": ["snapchat.com"],
    "coinbase": ["coinbase.com"], "binance": ["binance.com"], "metamask": ["metamask.io"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "irs": ["irs.gov"], "venmo": ["venmo.com"], "cashapp": ["cash.app"], "zelle": ["zellepay.com"],
    "ebay": ["ebay.com"], "walmart": ["walmart.com"], "minecraft": ["minecraft.net"], "xbox": ["xbox.com"],
    "playstation": ["playstation.com"], "spotify": ["spotify.com"], "linkedin": ["linkedin.com"],
    "twitter": ["twitter.com", "x.com"], "telegram": ["telegram.org", "t.me"], "chatgpt": ["chatgpt.com", "openai.com"],
}
NAMES = {"usps": "USPS", "paypal": "PayPal", "irs": "IRS", "dhl": "DHL", "fedex": "FedEx", "tiktok": "TikTok",
         "whatsapp": "WhatsApp", "linkedin": "LinkedIn", "playstation": "PlayStation", "epicgames": "Epic Games",
         "bankofamerica": "Bank of America", "wellsfargo": "Wells Fargo", "cashapp": "Cash App",
         "metamask": "MetaMask", "chatgpt": "ChatGPT", "icloud": "iCloud", "steamcommunity": "Steam",
         "office365": "Microsoft 365", "ebay": "eBay", "twitter": "X (Twitter)"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
              "ow.ly", "rebrand.ly", "s.id", "t.ly", "v.gd", "shorte.st", "adf.ly", "bitly.com"}
CHEAP_TLDS = {"xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "icu", "cyou", "rest", "sbs", "zip", "mov",
              "buzz", "monster", "cam", "lol", "quest", "cfd", "bond", "win", "loan", "work", "support", "live",
              "online", "site", "store", "fun", "beauty", "hair", "ink"}
TWO_PART_SUFFIXES = {"co.uk", "com.au", "co.jp", "co.in", "com.br", "co.nz", "com.mx", "co.za", "org.uk", "gov.uk"}
RISKY_DOWNLOADS = (".exe", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".apk", ".hta", ".lnk",
                   ".iso", ".img")
LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})

URL_RE = re.compile(
    r"(?i)\b(?:https?://[^\s<>\"'`]+|(?:www\.)?(?:[a-z0-9-]+\.)+(?:com|net|org|io|co|me|gg|app|dev|info|biz|us|uk|"
    + "|".join(sorted(CHEAP_TLDS)) + r"|ru|cn|in|de|fr|br|to|ly|ms|at|id|tv|cc|ws|pw|gov|edu)(?::\d+)?(?:/[^\s<>\"'`]*)?)")

TEXT_RULES = [
    ("bad", "scam_gift_cards", r"gift ?cards?|itunes card|google play card|steam (gift )?card|apple card codes?"),
    ("bad", "scam_prize", r"you('ve| have)? won|\bwinner\b|free robux|free v-?bucks|free nitro|claim your (prize|reward)"
                          r"|giveaway|double your (money|crypto|bitcoin)"),
    ("bad", "scam_remote", r"anydesk|teamviewer|ultraviewer|quick ?assist|remote access|screen ?connect"),
    ("bad", "scam_support", r"(microsoft|apple|windows|amazon) (tech )?support|call (this|the) number"
                            r"|your (computer|pc|device) (is|has been) (infected|hacked|locked)"),
    ("warn", "scam_secrets", r"password|verification code|2fa|one[- ]time (pass)?code|\botp\b|security code"
                             r"|seed phrase|recovery phrase|private key|login details"),
    ("warn", "scam_urgency", r"urgent|immediately|within (24|48) hours|act now|right now|suspended|final notice"
                             r"|last chance|will be (closed|deleted|locked)|expires? (today|soon)"),
    ("warn", "scam_payment", r"bitcoin|\bcrypto\b|\busdt\b|wire transfer|western union|moneygram|zelle|cash ?app"),
]


def extract_links(text: str) -> list[str]:
    seen, links = set(), []
    for match in URL_RE.finditer(text):
        link = match.group(0).rstrip(".,;:!?)]}'\"")
        if "@" in link.split("/")[0] and "://" not in link:
            continue  # an email address
        if link.lower() not in seen:
            seen.add(link.lower())
            links.append(link)
    return links


def registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _near(a: str, b: str) -> bool:
    """One typo apart (swap, extra, missing or wrong letter)."""
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def check_link(link: str) -> list[Finding]:
    url = link if "://" in link else "http://" + link
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    shown = host or link
    if not host:
        return []
    findings = []
    source = link_intel.lookup(url)
    if source:
        findings.append(Finding("bad", "scam_listed", {"host": shown, "source": source}))
    if "@" in parts.netloc:
        findings.append(Finding("bad", "scam_at_trick", {"host": shown}))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(Finding("bad", "scam_punycode", {"host": shown}))
    if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", host):
        findings.append(Finding("warn", "scam_ip", {"host": shown}))
    if host in SHORTENERS:
        findings.append(Finding("warn", "scam_shortener", {"host": shown}))
    if parts.path.lower().endswith(RISKY_DOWNLOADS):
        findings.append(Finding("warn", "scam_download", {"host": shown, "file": parts.path.rsplit("/", 1)[-1]}))

    if host in link_intel.SHARED_HOSTS and host not in SHORTENERS:
        # Anyone can publish on these, so the brand says nothing about the page.
        findings.append(Finding("info", "scam_shared", {"host": shown}))
        return findings
    domain = registrable(host)
    tokens = [tok for tok in re.split(r"[.\-_]", host) if tok]
    for brand, official in BRANDS.items():
        if domain in official or any(host.endswith("." + d) for d in official):
            if brand in tokens or domain.split(".")[0] == brand:
                findings.append(Finding("good", "scam_official", {"host": shown, "brand": NAMES.get(brand, brand.capitalize())}))
                break
            continue
        glued = domain.split(".")[0].replace("-", "")  # "paypalsecure" in paypalsecure-login.com
        if brand in tokens or (len(brand) >= 6 and brand in glued):
            findings.append(Finding("bad", "scam_brand", {"host": shown, "brand": NAMES.get(brand, brand.capitalize()),
                                                          "official": official[0]}))
            break
        if any(len(tok) >= 4 and (tok.translate(LOOKALIKE).replace("rn", "m") == brand or _near(tok, brand))
               for tok in tokens if tok not in BRANDS):
            findings.append(Finding("bad", "scam_lookalike", {"host": shown, "brand": NAMES.get(brand, brand.capitalize()),
                                                              "official": official[0]}))
            break
    if host.rsplit(".", 1)[-1] in CHEAP_TLDS and not any(f.level == "good" for f in findings):
        findings.append(Finding("warn", "scam_cheap_tld", {"host": shown, "tld": "." + host.rsplit(".", 1)[-1]}))
    return findings


def analyze(text: str) -> Report:
    links = extract_links(text)
    findings = []
    for link in links[:10]:
        findings += check_link(link)
    lowered = text.lower()
    for level, key, pattern in TEXT_RULES:
        if re.search(pattern, lowered):
            findings.append(Finding(level, key))
    if links and not link_intel.available():
        findings.append(Finding("info", "scam_lists_missing"))
    return Report(findings, links)
