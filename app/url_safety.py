"""SSRF protection for scan targets.

validate_target_url() is the single gate every target URL must pass before
anything (the browser, garak, a DNS lookup on behalf of a user) touches it.

The result carries an internal `reason` for our own logs. The API layer must
never show that reason to the caller: a specific "blocked because X" message
is a map of which bypasses to try next.

Known limit: this validates at one point in time. A hostile DNS server can
answer differently on the later lookup made by the browser (DNS rebinding).
BrowserGenerator re-validates every request the page makes, which narrows that
window, but the only hard guarantee is network-level egress filtering on the
machine that runs scans.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata endpoints and loopback names. Compared against the hostname
# after lowercasing and stripping a trailing dot ("localhost." is still localhost).
BLOCKED_HOSTNAMES = {
    "localhost",
    "169.254.169.254",
    "metadata.google.internal",
    "fd00:ec2::254",
}

# Ports of common internal services: ssh, telnet, smtp, smb, mysql, postgres,
# redis, elasticsearch, memcached, mongodb.
BLOCKED_PORTS = {22, 23, 25, 445, 3306, 5432, 6379, 9200, 11211, 27017}

_DEFAULT_PORTS = {"http": 80, "https": 443}

_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

# Special-use ranges that Python's flags call "global" but that are not public
# hosts: deprecated site-local IPv6, the 6to4 relay anycast block, the IPv6
# discard prefix, and the documentation prefix.
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("fec0::/10", "192.88.99.0/24", "100::/64", "2001:db8::/32")
]


@dataclass(frozen=True)
class UrlSafetyResult:
    is_safe: bool
    # Internal only: for logs, never for the API response.
    reason: str = ""


def _unsafe(reason: str) -> UrlSafetyResult:
    return UrlSafetyResult(is_safe=False, reason=reason)


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """IPv4 address hidden inside an IPv6 one (mapped, 6to4, Teredo, NAT64)."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]  # (server, client): the client is the target
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _ip_problem(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return why this address is not a public internet address, or None if it is."""
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_ipv4(ip)
        if inner is not None:
            problem = _ip_problem(inner)
            if problem:
                return f"{problem} (embedded in {ip})"
    if str(ip) in BLOCKED_HOSTNAMES:
        return f"{ip} is a blocked metadata address"
    if ip.is_unspecified:
        return f"{ip} is the unspecified address"
    if ip.is_loopback:
        return f"{ip} is loopback"
    if ip.is_link_local:
        return f"{ip} is link-local"
    if ip.is_private:
        return f"{ip} is private"
    if ip.is_reserved:
        return f"{ip} is reserved"
    if ip.is_multicast:
        return f"{ip} is multicast"
    for network in _EXTRA_BLOCKED_NETWORKS:
        if ip.version == network.version and ip in network:
            return f"{ip} is in special-use range {network}"
    # Catches what the flags above miss, e.g. carrier-grade NAT 100.64.0.0/10.
    if not ip.is_global:
        return f"{ip} is not a globally routable address"
    return None


def validate_target_url(url: str) -> UrlSafetyResult:
    """Decide whether `url` is safe to fetch. Does a DNS lookup."""
    if not isinstance(url, str) or not url.strip():
        return _unsafe("empty url")
    url = url.strip()

    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError if out of range or not numeric
    except ValueError as e:
        return _unsafe(f"unparseable url: {e}")

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return _unsafe(f"scheme {scheme!r} not allowed")

    # Credentials in a URL are a classic parser-confusion trick
    # (http://good.com@127.0.0.1/) and never legitimate for a public chat page.
    if parts.username is not None or parts.password is not None:
        return _unsafe("credentials in url")

    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        return _unsafe("no hostname")

    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".localhost"):
        return _unsafe(f"blocked hostname {hostname}")

    effective_port = port if port is not None else _DEFAULT_PORTS[scheme]
    if effective_port in BLOCKED_PORTS:
        return _unsafe(f"blocked port {effective_port}")

    # Resolve with the system resolver, not by parsing the string ourselves.
    # That way exotic literals (2130706433, 0x7f.1, 017700000001) are judged by
    # the address they actually turn into, which is what the browser will connect to.
    try:
        infos = socket.getaddrinfo(
            hostname, effective_port, proto=socket.IPPROTO_TCP
        )
    except (socket.gaierror, UnicodeError):
        return _unsafe(f"hostname {hostname} did not resolve")
    if not infos:
        return _unsafe(f"hostname {hostname} did not resolve")

    # Every address must be public. One private record among public ones is how
    # multi-record rebinding tricks get past a check that looks only at the first.
    for info in infos:
        address = info[4][0].split("%", 1)[0]  # drop IPv6 zone id
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return _unsafe(f"unparseable resolved address {address!r}")
        problem = _ip_problem(ip)
        if problem:
            return _unsafe(f"{hostname} resolves to non-public address: {problem}")

    return UrlSafetyResult(is_safe=True)
