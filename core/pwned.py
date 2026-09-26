"""Password leak check, using Have I Been Pwned's free Pwned Passwords service.

The password is hashed (SHA-1) on this PC and only the first 5 characters of
that hash are sent; the service answers with every leaked hash that starts
the same way (hundreds of them, padded with fake ones), and the match is
found here. So neither the password nor its full hash ever leaves the PC,
and nothing is saved. https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib
import urllib.request

RANGE_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "Sentinel-Antivirus/1.0"


def times_leaked(password: str) -> int:
    """How many times this password appears in known data breaches (0 if never).
    Raises OSError if the service can't be reached."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(RANGE_URL + prefix,
                                     headers={"User-Agent": USER_AGENT, "Add-Padding": "true"})
    with urllib.request.urlopen(request, timeout=15) as response:
        body = response.read().decode("utf-8", "replace")
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip() or 0)  # padding entries have a count of 0
    return 0
