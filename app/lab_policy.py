"""Process-local, startup-configured exceptions for exact lab endpoints.

This registry does not change production URL safety. Callers must check each
destination independently, including any redirect destination.
"""

import re
import socket

from app.url_safety import BLOCKED_PORTS


_targets: tuple[str, ...] = ()
_ENDPOINT = re.compile(
    r"(https?)://(127\.0\.0\.1|\[::1\]):([0-9]+)/([^?#]*)\Z"
)
_ERROR = "Invalid local lab target configuration"


def _parse(url: str) -> tuple[str, int]:
    if not isinstance(url, str) or any(
        ord(char) < 32 or ord(char) == 127 or char.isspace()
        or char in "\\%" for char in url
    ):
        raise ValueError(_ERROR)
    match = _ENDPOINT.fullmatch(url)
    if match is None:
        raise ValueError(_ERROR)
    _, host, port_text, path = match.groups()
    # Limit the spelling as well as the numeric range before converting.
    if len(port_text) > 5:
        raise ValueError(_ERROR)
    port = int(port_text)
    if not 1024 <= port <= 65535 or port in BLOCKED_PORTS:
        raise ValueError(_ERROR)
    if any(segment in (".", "..") for segment in path.split("/")):
        raise ValueError(_ERROR)
    return host.strip("[]"), port


def configure_local_targets(urls: list[str]) -> None:
    """Replace the process-only registry at startup; invalid input changes nothing."""
    if not isinstance(urls, list):
        raise ValueError(_ERROR)
    candidate = tuple(urls)
    for url in candidate:
        _parse(url)
    global _targets
    _targets = candidate


def is_local_target(url: str) -> bool:
    """Return whether the complete URL is explicitly registered."""
    return isinstance(url, str) and url in _targets


def preview_request_allowed(request, url: str) -> bool:
    """Operator-registered exact target, verified loopback preview and origin."""
    from .security import local_preview_allowed, _same_origin
    return (is_local_target(url) and local_preview_allowed(request.scope)
            and _same_origin(request.scope, required=True))


def local_target_address(url: str) -> tuple:
    """Return one getaddrinfo-shaped numeric address for a registered endpoint."""
    if not is_local_target(url):
        raise ValueError(_ERROR)
    host, port = _parse(url)
    if host == "::1":
        family, address = socket.AF_INET6, (host, port, 0, 0)
    else:
        family, address = socket.AF_INET, (host, port)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address


def configured_local_targets() -> list[str]:
    """Return a copy so callers cannot mutate the registry."""
    return list(_targets)
