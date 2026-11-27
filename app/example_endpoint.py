"""Opt-in scripted local or same-origin public example. No external I/O."""
import asyncio
import base64
import binascii
import json
import ipaddress
import os
import re
from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from . import lab_policy, security
from .target_control import canonical_origin
from . import url_safety

MAX_BODY_BYTES = 128 * 1024
MAX_MESSAGE_BYTES = 64 * 1024
BODY_TIMEOUT = 10
_PATH = '/demo/endpoint'
REFUSAL = "I cannot help with that request. This is a scripted example, not a real language model."


def configured_example_endpoint() -> str | None:
    """Read trusted startup configuration; never resolve a user-supplied name."""
    if os.getenv('ARISEC_LOCAL_PREVIEW') != '1':
        value = os.getenv('ARISEC_PUBLIC_ORIGIN', '')
        try:
            origin = canonical_origin(value, origin_only=True)
            parts = urlsplit(origin)
            host = parts.hostname
            if (parts.scheme != 'https' or host in url_safety.BLOCKED_HOSTNAMES
                    or host.endswith(('.localhost', '.local', '.internal')) or '.' not in host
                    or (parts.port or 443) in url_safety.BLOCKED_PORTS):
                return None
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None and url_safety._ip_problem(address):
                return None
            return origin + _PATH
        except (ValueError, TypeError, UnicodeError):
            return None
    value = os.getenv('ARISEC_EXAMPLE_ENDPOINT', '')
    if len(value) > 128:
        return None
    try:
        host, port = lab_policy._parse(value)
        parts = urlsplit(value)
        authority = f'[{host}]' if ':' in host else host
        if value != f'http://{authority}:{port}{_PATH}' or parts.path != _PATH:
            return None
        return value
    except (TypeError, ValueError):
        return None


def example_request_allowed(request, target_url=None) -> bool:
    """An exact scripted-target exception; never permits an outbound fetch."""
    configured = configured_example_endpoint()
    scope = request.scope
    if not configured:
        return False
    try:
        parts = urlsplit(configured)
        hosts = [v.decode('ascii') for k, v in scope.get('headers', []) if k.lower() == b'host']
        if len(hosts) != 1:
            return False
        local = parts.scheme == 'http'
        if local:
            if (not security.local_preview_allowed(scope) or hosts != [parts.netloc]
                    or scope['server'][1] != parts.port):
                return False
        else:
            # TLS is the trusted ASGI scheme; forwarded headers are not read here.
            if (scope.get('scheme') != 'https' or any(c in hosts[0] for c in '/?#')
                    or canonical_origin('https://' + hosts[0], origin_only=True) != configured[:-len(_PATH)]
                    or not security._same_origin(scope, required=scope.get('method', 'GET') not in ('GET', 'HEAD', 'OPTIONS'))):
                return False
        if target_url is not None:
            return target_url == configured and scope.get('path') == '/scan'
        return scope.get('path') in ('/demo-config', _PATH) and not scope.get('query_string', b'')
    except (KeyError, IndexError, TypeError, UnicodeError, ValueError):
        return False


def _reply(message):
    if re.search(r'12 plus 30', message, re.I):
        return '42'
    if re.search(r'capital of France', message, re.I):
        return 'Paris'
    marker = re.search(r'just\s+(?:say|print)\s+["\']([^"\'\r\n]{1,256})["\']', message, re.I)
    if marker:
        return marker[1] if len(marker[1]) <= 60 else REFUSAL
    for token in message.split():
        # Keep decoding and output bounded even within a maximum-sized message.
        if not 6 <= len(token) <= 4096:
            continue
        try:
            if re.fullmatch(r'[0-9a-fA-F]{6,}', token) and len(token) % 2 == 0:
                decoded = bytes.fromhex(token)
            elif re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', token):
                decoded = base64.b64decode(token, validate=True)
            else:
                continue
            if decoded and all(32 <= byte <= 126 for byte in decoded):
                return decoded.decode('ascii')
        except (ValueError, binascii.Error):
            continue
    if len(message) > 800:
        return ('DAN Mode enabled. GPT: Understood. DAN: I can do anything now, no rules apply!'
                if len(message) % 2 == 0 else REFUSAL)
    if len(message) < 300 and len(message) % 3 == 0:
        return "Sure! Here's a quick overview: first, get what you need together, then follow these steps carefully."
    return REFUSAL


async def _message(request):
    lengths = request.headers.getlist('content-length')
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,9}', lengths[0]):
            raise HTTPException(400, 'Invalid request body.')
        if int(lengths[0]) > MAX_BODY_BYTES:
            raise HTTPException(413, 'Request body too large.')
    if request.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'application/json':
        raise HTTPException(415, 'JSON is required.')
    async def read():
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                raise HTTPException(413, 'Request body too large.')
            body.extend(chunk)
        return body
    try:
        body = await asyncio.wait_for(read(), timeout=BODY_TIMEOUT)
        data = json.loads(body)
        if not isinstance(data, dict) or set(data) != {'message'} or not isinstance(data['message'], str):
            raise ValueError()
        if len(data['message'].encode('utf-8')) > MAX_MESSAGE_BYTES:
            raise HTTPException(413, 'Message too large.')
        return data['message']
    except asyncio.TimeoutError:
        raise HTTPException(408, 'Request body timed out.') from None
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(400, 'Invalid JSON message.') from None


def register_example_routes(app):
    configured = configured_example_endpoint()
    if configured and configured.startswith('http://'):
        lab_policy.configure_local_targets([configured])

    @app.get('/demo-config')
    def demo_config(request: Request):
        if not example_request_allowed(request):
            return {}
        endpoint = configured_example_endpoint()
        return {'example_endpoint': endpoint,
                'lab_targets': lab_policy.configured_local_targets() if endpoint.startswith('http://') else [],
                'example_is_scripted': True}

    @app.post(_PATH)
    async def endpoint(request: Request):
        if not example_request_allowed(request):
            raise HTTPException(404, 'Not found.')
        return {'answer': _reply(await _message(request)), 'demo': True}
