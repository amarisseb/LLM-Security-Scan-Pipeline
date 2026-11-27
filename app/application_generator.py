"""A bounded JSON-over-HTTPS connector for a customer's AI application.

Requests connect to an already checked numeric address, with TLS identity checked
against the original hostname. No proxy environment, redirects or second DNS
lookup are involved. Secrets and request templates never enter garak config.
"""

import copy
import http.client
import ipaddress
import json
import re
import queue
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit

from garak import _config
from garak.attempt import Message
from garak.generators.base import Generator

from . import lab_policy, url_safety

MAX_BYTES = 1_000_000
MAX_TEMPLATE_BYTES = 65_536
REQUEST_TIMEOUT = 30
SCAN_TIMEOUT = 1800
_DNS_SLOTS = threading.BoundedSemaphore(4)
PROMPT_MARKER = "{{prompt}}"


class ApplicationConfigError(ValueError):
    """Invalid connection configuration; contains no submitted values."""


class ApplicationRequestError(RuntimeError):
    """Transport or response error with a fixed, credential-free message."""


class ApplicationAuthError(ApplicationRequestError):
    pass


def validate_connection(url, template, response_path, token=None):
    try:
        parts = urlsplit(url)
        if ((parts.scheme != "https" and not lab_policy.is_local_target(url)) or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.fragment or parts.query
                or "\\" in url or any(ord(c) <= 32 or ord(c) == 127 for c in url)
                or parts.port == 0):
            raise ValueError()
        parts.hostname.encode("idna")
        if not isinstance(template, dict) or not template:
            raise ValueError()
        encoded = json.dumps(template, ensure_ascii=True, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_TEMPLATE_BYTES:
            raise ValueError()
        if not isinstance(response_path, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", response_path
        ) or len(response_path) > 200:
            raise ValueError()
        if token is not None and (not isinstance(token, str) or not token.strip()
                                  or len(token) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError()
        count = 0

        def walk(value, depth=0):
            nonlocal count
            if depth > 20:
                raise ValueError()
            if isinstance(value, dict):
                for key, child in value.items():
                    if PROMPT_MARKER in str(key):
                        raise ValueError()
                    walk(child, depth + 1)
            elif isinstance(value, list):
                for child in value:
                    walk(child, depth + 1)
            elif isinstance(value, str) and PROMPT_MARKER in value:
                if value != PROMPT_MARKER:
                    raise ValueError()
                count += 1
        walk(template)
        if count == 0:
            raise ValueError()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ApplicationConfigError(
            "Use an HTTPS endpoint without credentials, query or fragment; a JSON object "
            "containing a standalone {{prompt}} value; and a dot-separated response path."
        ) from None


def render_request(template, prompt):
    """Replace JSON values, never interpolate JSON source or execute expressions."""
    if isinstance(template, dict):
        return {key: render_request(value, prompt) for key, value in template.items()}
    if isinstance(template, list):
        return [render_request(value, prompt) for value in template]
    return prompt if template == PROMPT_MARKER else template


def response_text(document, path):
    try:
        value = document
        for part in path.split("."):
            value = value[int(part)] if isinstance(value, list) and part.isdigit() else value[part]
        if not isinstance(value, str) or not value.strip():
            raise ValueError()
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        raise ApplicationRequestError("The response path did not contain a text answer.") from None


def _resolve_public(hostname, port):
    # The OS resolver has no per-call deadline. Run it in a bounded daemon
    # thread so a stalled lookup cannot occupy the single scan worker forever.
    if not _DNS_SLOTS.acquire(blocking=False):
        raise ApplicationRequestError("The application endpoint could not be reached.")
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put((socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), None))
        except Exception:
            result.put((None, True))
        finally:
            _DNS_SLOTS.release()

    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses, error = result.get(timeout=5)
        if error or not addresses:
            raise ValueError()
        for family, kind, protocol, _, address in addresses:
            if family not in (socket.AF_INET, socket.AF_INET6) or url_safety._ip_problem(
                ipaddress.ip_address(address[0].split("%", 1)[0])
            ):
                raise ValueError()
        return addresses[0]
    except (OSError, ValueError, queue.Empty):
        raise ApplicationRequestError("The application endpoint could not be reached.") from None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._address = address
        self._active_socket = None

    def abort(self):
        active = self._active_socket
        if active:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            active.close()

    def connect(self):
        family, kind, protocol, _, address = self._address
        raw = socket.socket(family, kind, protocol)
        self._active_socket = raw
        try:
            raw.settimeout(self.timeout)
            raw.connect(address)  # numeric sockaddr from the validated lookup
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            self._active_socket = self.sock
            self.sock.do_handshake()
        except BaseException:
            raw.close()
            raise


class _PinnedLocalHTTPConnection(http.client.HTTPConnection):
    """Plain HTTP is available only for a registered numeric loopback target."""

    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address
        self._active_socket = None

    abort = _PinnedHTTPSConnection.abort

    def connect(self):
        family, kind, protocol, _, address = self._address
        raw = socket.socket(family, kind, protocol)
        self._active_socket = raw
        try:
            raw.settimeout(self.timeout)
            raw.connect(address)
            self.sock = raw
        except BaseException:
            raw.close()
            raise


def post_json(url, payload, token=None):
    """One bounded POST. A redirect is an error, never an instruction to fetch."""
    connection = None
    watchdog = None
    try:
        parts = urlsplit(url)
        hostname = parts.hostname.encode("idna").decode("ascii")
        port = parts.port or 443
        local = lab_policy.is_local_target(url)
        if not local and (parts.scheme != "https" or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment or port in url_safety.BLOCKED_PORTS
                or hostname.rstrip(".").lower() in url_safety.BLOCKED_HOSTNAMES
                or hostname.rstrip(".").lower().endswith(".localhost")):
            raise ApplicationRequestError("The application endpoint could not be reached.")
        deadline = time.monotonic() + REQUEST_TIMEOUT
        address = lab_policy.local_target_address(url) if local else _resolve_public(hostname, port)
        remaining = max(0.01, deadline - time.monotonic())
        connection_class = _PinnedLocalHTTPConnection if local and parts.scheme == "http" else _PinnedHTTPSConnection
        connection = connection_class(hostname, port, address, remaining)
        # Socket timeouts alone only bound inactivity. Force shutdown at the
        # wall-clock deadline even if a target trickles response-header bytes.
        watchdog = threading.Timer(remaining, connection.abort)
        watchdog.daemon = True
        watchdog.start()
        headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
        if token:
            headers["Authorization"] = "Bearer " + token
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(body) > MAX_BYTES:
            raise ApplicationRequestError("The application request exceeded the size limit.")
        connection.request("POST", parts.path or "/", body=body, headers=headers)
        tls_socket = connection.sock
        tls_socket.settimeout(max(0.01, deadline - time.monotonic()))
        response = connection.getresponse()
        if response.status in (401, 403):
            raise ApplicationAuthError("The application rejected the supplied credentials.")
        if response.status < 200 or response.status >= 300:
            raise ApplicationRequestError("The application returned an unsuccessful response.")
        if "json" not in response.getheader("Content-Type", "").lower():
            raise ApplicationRequestError("The application did not return JSON.")
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            tls_socket.settimeout(remaining)
            chunk = response.read1(min(65_536, MAX_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BYTES:
                raise ApplicationRequestError("The application response exceeded the size limit.")
        return json.loads(b"".join(chunks))
    except ApplicationRequestError:
        raise
    except (OSError, ValueError, TypeError, http.client.HTTPException, RecursionError):
        raise ApplicationRequestError("The application request failed or timed out.") from None
    finally:
        if watchdog:
            watchdog.cancel()
        if connection:
            connection.close()


class ApplicationGenerator(Generator):
    """Test the text behavior of an AI application through its JSON API."""

    __module__ = "garak.generators.application"
    generator_family_name = "application"
    parallel_capable = False
    supports_multiple_generations = False
    _unsafe_attributes = ["_token", "_template"]

    def __init__(self, url, template, answer_path, token=None, config_root=_config):
        validate_connection(url, template, answer_path, token)
        super().__init__("AI application", config_root=config_root)
        self._url = url
        self._template = copy.deepcopy(template)
        self._answer_path = answer_path
        self._token = token
        self._started = time.monotonic()

    def _call_model(self, prompt, generations_this_call=1):
        if time.monotonic() - self._started > SCAN_TIMEOUT:
            raise ApplicationRequestError("The application scan exceeded the time limit.")
        message = prompt.last_message("user").text
        payload = render_request(self._template, message)
        value = response_text(post_json(self._url, payload, self._token), self._answer_path)
        if self._token:
            value = value.replace(self._token, "[credential redacted]")
        return [Message(text=value[:20_000])]

    def close(self):
        self._token = None
        self._template = None


DEFAULT_CLASS = "ApplicationGenerator"
sys.modules.setdefault("garak.generators.application", sys.modules[__name__])
