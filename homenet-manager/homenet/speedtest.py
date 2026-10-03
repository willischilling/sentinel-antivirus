"""A quick, approximate internet speed check: download throughput and latency.
Uses Cloudflare's public speed endpoints. No account or extra packages needed.
"""
import socket
import time
import urllib.request

DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
PING_HOST = ("1.1.1.1", 443)
USER_AGENT = "HomeNetManager/1.0"


def ping(count: int = 4) -> float | None:
    """Median TCP-connect latency to 1.1.1.1:443, in milliseconds."""
    times = []
    for _ in range(count):
        start = time.perf_counter()
        try:
            with socket.create_connection(PING_HOST, timeout=3):
                times.append((time.perf_counter() - start) * 1000)
        except OSError:
            pass
    if not times:
        return None
    times.sort()
    return round(times[len(times) // 2], 1)


def download(max_seconds: float = 6.0, size_mb: int = 40) -> float | None:
    """Approximate download speed in megabits per second."""
    req = urllib.request.Request(DOWN_URL.format(n=size_mb * 1024 * 1024),
                                 headers={"User-Agent": USER_AGENT})
    start = time.perf_counter()
    got = 0
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                got += len(chunk)
                if time.perf_counter() - start >= max_seconds:
                    break
    except OSError:
        return None
    elapsed = time.perf_counter() - start
    if elapsed <= 0 or got == 0:
        return None
    return round((got * 8) / elapsed / 1_000_000, 1)


def run(progress=None) -> dict:
    """Returns {"ping": ms|None, "down": mbps|None}."""
    if progress:
        progress("Measuring latency…")
    p = ping()
    if progress:
        progress("Measuring download speed…")
    d = download()
    return {"ping": p, "down": d}
