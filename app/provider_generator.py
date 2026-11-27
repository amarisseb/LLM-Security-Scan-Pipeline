"""Isolated direct-provider transport implementing garak's Generator contract.

Deliberately bypass LiteLLM: its callbacks, aliases, cached clients and globals
can override explicit parameters or export credentials. No process state is
changed here. Only public metadata belongs in garak's serialized configuration.
"""

import json
import re
import sys
import time
from types import MappingProxyType

import httpx
from garak.attempt import Message
from garak.exception import BadGeneratorException
from garak.generators.base import Generator


PROVIDER_API_BASES = MappingProxyType({
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "cohere": "https://api.cohere.ai/v2",
})
REQUEST_TIMEOUT_SECONDS = 30.0
SCAN_TIMEOUT_SECONDS = 900.0
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576


def _read_response(response):
    """Bound bytes before JSON parsing; do not accept compressed responses.

    Streaming prevents HTTPX eagerly buffering an unbounded successful body.
    These are size limits, not an absolute deadline: a blocking read still uses
    HTTPX's inactivity timeout and scan wall-clock checks remain cooperative.
    """
    if response.headers.get("content-encoding", "identity").lower() != "identity":
        raise ValueError("unsupported response encoding")
    length = response.headers.get("content-length")
    if length is not None and (int(length) < 0 or int(length) > MAX_RESPONSE_BYTES):
        raise ValueError("response size limit exceeded")
    chunks, size = [], 0
    for chunk in response.iter_bytes(chunk_size=65_536):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise ValueError("response size limit exceeded")
        chunks.append(chunk)
    return json.loads(b"".join(chunks))


def validate_target(provider, model, api_key):
    if provider not in PROVIDER_API_BASES:
        raise ValueError("unsupported provider")
    # No provider prefixes, URLs, paths, queries, whitespace or env references.
    if not isinstance(model, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", model
    ) or ".." in model:
        raise ValueError("expected a plain provider model id")
    if not isinstance(api_key, str) or not api_key or len(api_key) > 8192 or any(
        ord(c) < 33 or ord(c) > 126 for c in api_key
    ):
        raise ValueError("invalid API key")


class ProviderGenerator(Generator):
    """Direct HTTPS provider generator with runtime-only credentials."""

    __module__ = "garak.generators.direct_provider"
    generator_family_name = "Direct provider"
    _supported_params = ("name",)
    parallel_capable = False
    supports_multiple_generations = False
    _unsafe_attributes = ["_api_key", "_client"]

    def __init__(self, provider, model, api_key):
        validate_target(provider, model, api_key)
        super().__init__(name=f"{provider}/{model}")
        self.custom_llm_provider = provider
        self.api_base = PROVIDER_API_BASES[provider]
        self._model = model
        self.parallel_requests = 1
        self._deadline = time.monotonic() + SCAN_TIMEOUT_SECONDS
        self._api_key = api_key
        # Ignore proxy/CA environment settings, don't follow credential-bearing
        # redirects, and don't inherit any SDK/LiteLLM client or retry policy.
        self._client = httpx.Client(
            trust_env=False, follow_redirects=False,
            transport=httpx.HTTPTransport(retries=0, trust_env=False),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

    def check_deadline(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise BadGeneratorException("provider scan time budget exceeded")
        return remaining

    def _call_model(self, prompt, generations_this_call=1):
        timeout = min(REQUEST_TIMEOUT_SECONDS, self.check_deadline())
        failure = None
        try:
            messages = self._conversation_to_list(prompt)
            body = {"model": self._model, "messages": messages, "max_tokens": 150}
            headers = {"Authorization": f"Bearer {self._api_key}"}
            path = "/chat/completions"
            if self.custom_llm_provider == "anthropic":
                path = "/messages"
                headers = {"x-api-key": self._api_key, "anthropic-version": "2023-06-01"}
                system = [m["content"] for m in messages if m["role"] == "system"]
                body["messages"] = [m for m in messages if m["role"] != "system"]
                if system:
                    body["system"] = "\n".join(system)
            elif self.custom_llm_provider == "cohere":
                path = "/chat"
            encoded = json.dumps(body, ensure_ascii=True, allow_nan=False).encode("utf-8")
            if len(encoded) > MAX_REQUEST_BYTES:
                raise ValueError("request size limit exceeded")
            headers.update({"Content-Type": "application/json", "Accept": "application/json",
                            "Accept-Encoding": "identity"})
            with self._client.stream(
                "POST", self.api_base + path, headers=headers, content=encoded, timeout=timeout
            ) as response:
                if response.status_code in (401, 403):
                    failure = "auth"
                elif not 200 <= response.status_code < 300:
                    failure = "request"
                else:
                    data = _read_response(response)
            if failure is None:
                if self.custom_llm_provider == "anthropic":
                    text = "".join(b["text"] for b in data["content"] if b["type"] == "text")
                elif self.custom_llm_provider == "cohere":
                    text = "".join(b["text"] for b in data["message"]["content"] if b["type"] == "text")
                else:
                    text = data["choices"][0]["message"]["content"]
                if not isinstance(text, str):
                    failure = "response"
        except Exception:
            # Never log, chain, format or propagate transport/decoder exceptions:
            # they can carry headers, echoed keys, prompts and response bodies.
            failure = "request"
        self.check_deadline()
        # Raise outside the handler so even __context__ cannot expose a key.
        if failure == "auth":
            from .run_scan import ApiAuthError

            raise ApiAuthError("provider rejected the API key")
        if failure:
            raise BadGeneratorException("provider request failed")
        return [Message(text.replace(self._api_key, "[credential redacted]"))]

    def close(self):
        self._api_key = None
        self._client.close()


# garak uses the module path to emit standard plugin-cache report entries.
DEFAULT_CLASS = "ProviderGenerator"
sys.modules.setdefault("garak.generators.direct_provider", sys.modules[__name__])
