"""Per-user scan limits.

Three limits, all sliding windows:

  * scans per hour
  * scans per day
  * distinct domains scanned per day. This is the abuse signal: someone testing
    their own site scans the same domain over and over, someone probing the
    internet scans many unrelated ones. Repeat scans of one domain do not
    count against this limit.

The email in a scan request is self-reported, so limits keyed only on it are
bypassed by typing a different address. Every limit is therefore applied to
the email AND to the client IP, and a request must fit under both.

State lives in this process's memory: it resets on restart and is not shared
between workers. Swap the storage (Redis, a database) before running more than
one process; check_and_record() is the only method callers use.
"""

import ipaddress
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlsplit

HOUR = 3600
DAY = 86400

# Second-level labels that make "example.co.uk" one registrable domain, not "co.uk".
# A heuristic standing in for the Public Suffix List (add `tldextract` to make it exact).
_SECOND_LEVEL_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "ed", "gob"}

# Hosts where every customer gets a subdomain of the same name. "a.nip.io" and
# "b.nip.io" are unrelated sites, so the registrable domain is one label more.
# (Also a stand-in for the Public Suffix List's private section.)
_SHARED_HOSTING_SUFFIXES = {
    "nip.io", "sslip.io", "xip.io", "traefik.me", "github.io", "gitlab.io",
    "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
    "web.app", "firebaseapp.com", "azurewebsites.net", "cloudfront.net",
    "onrender.com", "lovable.app", "lovableproject.com", "fly.dev",
    "ngrok.io", "ngrok-free.app", "repl.co", "glitch.me",
}

_SWEEP_INTERVAL = 600


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    # Internal only: for logs. Which limit tripped tells a caller what to work around.
    reason: str = ""
    retry_after_seconds: int = 0


def registrable_domain(url: str) -> str:
    """'https://app.example.co.uk/x' -> 'example.co.uk'; IP literals are returned as-is."""
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2 or host.replace(".", "").isdigit() or ":" in host:
        return host
    for suffix in _SHARED_HOSTING_SUFFIXES:
        if host.endswith("." + suffix):
            depth = suffix.count(".") + 2  # the suffix's labels plus the customer's
            return ".".join(labels[-depth:])
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _ip_bucket(ip: str) -> str:
    """The unit an IP limit applies to. An IPv6 customer normally holds a whole
    /64 (2^64 addresses), so limiting single addresses would let one client
    rotate through them for free; limit the /64 instead."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip or "unknown"
    if address.version == 6:
        if address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network(f"{address}/64", strict=False))
    return str(address)


class ScanRateLimiter:
    def __init__(
        self,
        max_per_hour: int = 3,
        max_per_day: int = 10,
        max_distinct_domains_per_day: int = 5,
        clock=time.time,
    ):
        self.max_per_hour = max_per_hour
        self.max_per_day = max_per_day
        self.max_distinct_domains_per_day = max_distinct_domains_per_day
        self._clock = clock
        self._lock = threading.Lock()
        # limiter key -> deque of (timestamp, domain), oldest first
        self._events: dict[str, deque] = {}
        self._last_sweep = clock()

    @classmethod
    def from_env(cls) -> "ScanRateLimiter":
        return cls(
            max_per_hour=int(os.getenv("SCAN_LIMIT_PER_HOUR", 3)),
            max_per_day=int(os.getenv("SCAN_LIMIT_PER_DAY", 10)),
            max_distinct_domains_per_day=int(os.getenv("SCAN_LIMIT_DOMAINS_PER_DAY", 5)),
        )

    def check_and_record(
        self, *, user_email: str, client_ip: str, target_url: str
    ) -> RateLimitResult:
        """Check every limit and, if the scan is allowed, count it. One atomic step."""
        domain = registrable_domain(target_url)
        keys = (f"email:{user_email.strip().lower()}", f"ip:{_ip_bucket(client_ip)}")

        with self._lock:
            now = self._clock()
            self._sweep(now)

            denials = []
            for key in keys:
                events = self._prune(key, now)
                denial = self._check_one(key, events, domain, now)
                if denial:
                    denials.append(denial)
            if denials:
                return max(denials, key=lambda d: d.retry_after_seconds)

            for key in keys:
                self._events.setdefault(key, deque()).append((now, domain))
            return RateLimitResult(allowed=True)

    def _check_one(self, key, events, domain, now) -> RateLimitResult | None:
        in_last_hour = [ts for ts, _ in events if ts > now - HOUR]
        if len(in_last_hour) >= self.max_per_hour:
            return self._deny(f"{key}: hourly limit", in_last_hour[0] + HOUR - now)

        if len(events) >= self.max_per_day:
            return self._deny(f"{key}: daily limit", events[0][0] + DAY - now)

        last_seen = {}
        for ts, d in events:
            last_seen[d] = ts
        if domain not in last_seen and len(last_seen) >= self.max_distinct_domains_per_day:
            # Frees up when the least-recently scanned domain ages out of the window.
            return self._deny(
                f"{key}: distinct-domain limit ({len(last_seen)} domains, new: {domain})",
                min(last_seen.values()) + DAY - now,
            )
        return None

    @staticmethod
    def _deny(reason: str, retry_after: float) -> RateLimitResult:
        return RateLimitResult(
            allowed=False, reason=reason, retry_after_seconds=max(1, int(retry_after) + 1)
        )

    def _prune(self, key, now) -> deque:
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and events[0][0] <= now - DAY:
            events.popleft()
        return events

    def _sweep(self, now):
        """Drop keys with no events left in the window so memory stays bounded."""
        if now - self._last_sweep < _SWEEP_INTERVAL:
            return
        self._last_sweep = now
        for key in list(self._events):
            if not self._prune(key, now):
                del self._events[key]
