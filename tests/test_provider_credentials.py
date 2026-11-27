"""Provider requests use a real HTTPX client with a stubbed wire transport only."""
import json
import logging
import os
import socket
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

# Avoid garak opening its default user-home log during standalone unittest runs.
logging.getLogger().addHandler(logging.NullHandler())

import httpx
from garak import _config
from garak.attempt import Conversation, Message, Turn
from garak.exception import BadGeneratorException
from app import run_scan
from app import provider_generator as pg

USER_KEY = "user-private-test-credential"
HOST_KEY = "host-private-test-credential"
MODELS = {"openai": "gpt-4o-mini", "anthropic": "claude-sonnet-4-5",
          "groq": "llama-3.3-70b-versatile", "mistral": "mistral-small-latest",
          "cohere": "command-r-plus"}
URLS = {"openai": "https://api.openai.com/v1/chat/completions",
        "anthropic": "https://api.anthropic.com/v1/messages",
        "groq": "https://api.groq.com/openai/v1/chat/completions",
        "mistral": "https://api.mistral.ai/v1/chat/completions",
        "cohere": "https://api.cohere.ai/v2/chat"}


def prompt():
    return Conversation([Turn("user", Message("hello"))])


def answer(provider, text="safe reply"):
    if provider == "anthropic":
        return {"content": [{"type": "text", "text": text}]}
    if provider == "cohere":
        return {"message": {"content": [{"type": "text", "text": text}]}}
    return {"choices": [{"message": {"content": text}}]}


class ProviderCredentialTests(unittest.TestCase):
    def setUp(self):
        # Fail closed if a regression ever bypasses the stubbed wire transport.
        network = patch.object(socket.socket, "connect", side_effect=AssertionError("network disabled in tests"))
        network.start()
        self.addCleanup(network.stop)
        run_scan._make_output_encoding_safe()
        run_scan._reset_garak_state()
        _config.load_base_config()

    def generator(self, provider, handler):
        wire = patch.object(pg.httpx, "HTTPTransport", return_value=httpx.MockTransport(handler))
        factory = wire.start()
        self.addCleanup(wire.stop)
        generator = pg.ProviderGenerator(provider, MODELS[provider], USER_KEY)
        self.addCleanup(generator.close)
        factory.assert_called_once_with(retries=0, trust_env=False)
        return generator

    def test_user_credentials_and_fixed_endpoint_win_over_ambient_state(self):
        with patch.dict(os.environ, {"LITELLM_LOCAL_MODEL_COST_MAP": "True"}):
            import litellm
        ambient = {name: HOST_KEY for name in run_scan.PROVIDER_API_KEY_ENV_VAR.values()}
        ambient.update({"OPENAI_BASE_URL": "http://127.0.0.1:9999",
                        "OPENAI_API_BASE": "http://127.0.0.1:9999",
                        "ANTHROPIC_BASE_URL": "http://127.0.0.1:9999",
                        "GROQ_API_BASE": "http://127.0.0.1:9999",
                        "MISTRAL_API_BASE": "http://127.0.0.1:9999",
                        "COHERE_API_BASE": "http://127.0.0.1:9999",
                        "HTTPS_PROXY": "http://127.0.0.1:9999"})
        with patch.dict(os.environ, ambient), patch.multiple(
            litellm, api_key=HOST_KEY, openai_key=HOST_KEY,
            api_base="http://127.0.0.1:9999", num_retries=999,
            model_alias_map={model: "openrouter/evil" for model in MODELS.values()},
        ), patch.object(litellm, "completion", side_effect=AssertionError("must bypass globals")):
            for provider in MODELS:
                with self.subTest(provider=provider):
                    requests = []
                    def handle(request):
                        requests.append(request)
                        self.assertEqual(str(request.url), URLS[provider])
                        self.assertEqual(json.loads(request.content)["model"], MODELS[provider])
                        header = "x-api-key" if provider == "anthropic" else "authorization"
                        expected = USER_KEY if provider == "anthropic" else "Bearer " + USER_KEY
                        self.assertEqual(request.headers[header], expected)
                        self.assertNotIn(HOST_KEY, str(request.headers))
                        for value in request.extensions["timeout"].values():
                            self.assertGreater(value, 0)
                            self.assertLessEqual(value, 30)
                        return httpx.Response(200, json=answer(provider))
                    generator = self.generator(provider, handle)
                    self.assertEqual(generator.generate(prompt())[0].text, "safe reply")
                    self.assertEqual(len(requests), 1)
                    self.assertFalse(generator._client._trust_env)
                    self.assertFalse(generator._client.follow_redirects)
                    self.assertNotIn(USER_KEY, repr(generator.__getstate__()))
                    for name, value in ambient.items():
                        self.assertEqual(os.environ[name], value)

    def test_routing_inputs_rejected_before_transport_or_output(self):
        for model in ["openai/gpt-4o", "https://evil/a", "../x", "a..b", "x?key=y",
                      "x#evil", "x@y", "x:y", "x\\y", " x", "x\n", "", "os.environ/KEY", "x%2fy"]:
            with self.subTest(model=model), patch.object(pg.httpx, "Client") as client:
                with self.assertRaisesRegex(ValueError, "plain provider model id"):
                    run_scan.run_api_scan("openai", model, USER_KEY, "unused-output")
                client.assert_not_called()
        with self.assertRaises(run_scan.UnsupportedProvider):
            run_scan.run_api_scan("evil", "model", USER_KEY, "unused-output")
        for key in ["", "\nsecret", " key", None]:
            with self.assertRaisesRegex(ValueError, "invalid API key"):
                pg.validate_target("openai", "model", key)

    def test_failures_never_expose_raw_exception_or_body_and_never_retry(self):
        for mode in ["transport", "auth", "forbidden", "server", "redirect", "malformed"]:
            with self.subTest(mode=mode):
                calls = []
                def handle(request):
                    calls.append(request)
                    if mode == "transport":
                        raise httpx.ReadTimeout(USER_KEY, request=request)
                    if mode == "malformed":
                        return httpx.Response(200, text=USER_KEY)
                    status = {"auth": 401, "forbidden": 403, "server": 503, "redirect": 307}[mode]
                    return httpx.Response(status, text=USER_KEY, headers={"location": "https://evil.test"})
                generator = self.generator("openai", handle)
                error = run_scan.ApiAuthError if mode in ("auth", "forbidden") else BadGeneratorException
                with self.assertLogs(level="DEBUG") as logs:
                    # A sentinel ensures assertLogs works when there are no transport logs.
                    logging.debug("provider failure test")
                    with self.assertRaises(error) as caught:
                        generator.generate(prompt())
                self.assertEqual(len(calls), 1)
                self.assertIsNone(caught.exception.__context__)
                self.assertIsNone(caught.exception.__cause__)
                rendered = "".join(traceback.format_exception(caught.exception)) + str(logs.output)
                self.assertNotIn(USER_KEY, rendered)

    def test_successful_echo_is_redacted_for_every_provider(self):
        for provider in MODELS:
            with self.subTest(provider=provider):
                generator = self.generator(provider, lambda request: httpx.Response(
                    200, json=answer(provider, USER_KEY + " reply " + USER_KEY)))
                self.assertEqual(generator.generate(prompt())[0].text,
                                 "[credential redacted] reply [credential redacted]")

    def test_request_size_cap_is_applied_to_encoded_json_before_sending(self):
        calls = []
        generator = self.generator("openai", lambda request: calls.append(request))
        large = Conversation([Turn("user", Message("\N{SNOWMAN}" * 100))])
        with patch.object(pg, "MAX_REQUEST_BYTES", 256):
            with self.assertRaisesRegex(BadGeneratorException, "provider request failed") as caught:
                generator.generate(large)
        self.assertEqual(calls, [])
        self.assertIsNone(caught.exception.__context__)

    def test_response_size_cap_streaming_encodings_and_auth_without_body_read(self):
        class Body(httpx.SyncByteStream):
            def __init__(self):
                self.reads = 0
                self.closed = False
            def __iter__(self):
                for _ in range(100):
                    self.reads += 1
                    yield b"x" * 65_536
            def close(self):
                self.closed = True
        for mode in ("chunked", "false_length", "large_length", "gzip", "auth"):
            with self.subTest(mode=mode):
                stream = Body()
                headers = {"false_length": {"content-length": "1"},
                           "large_length": {"content-length": "999999999"},
                           "gzip": {"content-encoding": "gzip"}}.get(mode, {})
                generator = self.generator("openai", lambda request: httpx.Response(
                    401 if mode == "auth" else 200, headers=headers, stream=stream))
                error = run_scan.ApiAuthError if mode == "auth" else BadGeneratorException
                with patch.object(pg, "MAX_RESPONSE_BYTES", 65_536):
                    with self.assertRaises(error) as caught:
                        generator.generate(prompt())
                self.assertTrue(stream.closed)
                self.assertEqual(stream.reads, 2 if mode in ("chunked", "false_length") else 0)
                self.assertIsNone(caught.exception.__context__)

    def test_response_exact_size_limit_is_accepted(self):
        encoded = json.dumps(answer("openai")).encode()
        generator = self.generator("openai", lambda request: httpx.Response(200, content=encoded))
        with patch.object(pg, "MAX_RESPONSE_BYTES", len(encoded)):
            self.assertEqual(generator.generate(prompt())[0].text, "safe reply")

    def test_scan_budget_checked_before_and_after_request(self):
        calls = []
        def handle(request):
            calls.append(request)
            return httpx.Response(200, json=answer("openai"))
        generator = self.generator("openai", handle)
        generator._deadline = 10
        with patch.object(pg.time, "monotonic", return_value=11):
            with self.assertRaisesRegex(BadGeneratorException, "time budget"):
                generator.generate(prompt())
        self.assertEqual(calls, [])
        with patch.object(pg.time, "monotonic", side_effect=[9, 11]):
            with self.assertRaisesRegex(BadGeneratorException, "time budget"):
                generator.generate(prompt())
        self.assertEqual(calls[0].extensions["timeout"]["read"], 1)

    def test_repeated_generations_and_new_scan_keep_credentials_isolated(self):
        seen = []
        def handle(request):
            seen.append(request.headers["authorization"])
            return httpx.Response(200, json=answer("openai"))
        first = self.generator("openai", handle)
        self.assertEqual(len(first.generate(prompt(), generations_this_call=2)), 2)
        first.close()
        with patch.object(pg.httpx, "HTTPTransport", return_value=httpx.MockTransport(handle)):
            second = pg.ProviderGenerator("openai", MODELS["openai"], "second-test-key")
            try:
                second.generate(prompt())
            finally:
                second.close()
        self.assertEqual(seen, ["Bearer " + USER_KEY, "Bearer " + USER_KEY, "Bearer second-test-key"])

    def test_probe_boundary_budget_and_progress_failure_are_safe(self):
        from types import SimpleNamespace
        checks = []
        def deadline():
            checks.append(True)
            if len(checks) == 2:
                raise BadGeneratorException("provider scan time budget exceeded")
        def progress(*args):
            raise RuntimeError(USER_KEY)
        loader = run_scan._capping_loader(
            lambda *a: SimpleNamespace(prompts=["hello"]), 1, progress,
            check_deadline=deadline,
        )
        with self.assertLogs(run_scan.logger, level="ERROR") as logs:
            with self.assertRaisesRegex(BadGeneratorException, "time budget"):
                loader("probes.test")
        self.assertNotIn(USER_KEY, str(logs.output))
        self.assertEqual(len(checks), 2)

    def test_standard_garak_report_contains_no_credentials_and_closes_generator(self):
        for fail in [False, True]:
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                def handle(request):
                    return httpx.Response(401, text=USER_KEY) if fail else httpx.Response(200, json=answer("openai"))
                instances = []
                original = pg.ProviderGenerator.close
                def close(generator):
                    instances.append(generator)
                    return original(generator)
                def harness(generator, *args):
                    outputs = generator.generate(prompt())
                    _config.transient.reportfile.write(json.dumps({"entry_type": "attempt", "outputs": [outputs[0].text]}) + "\n")
                with patch.object(pg.httpx, "HTTPTransport", return_value=httpx.MockTransport(handle)), \
                     patch.object(pg.ProviderGenerator, "close", close), \
                     patch.object(run_scan._config, "parse_plugin_spec", return_value=(["test"], [])), \
                     patch.object(run_scan.command, "probewise_run", side_effect=harness), \
                     patch.object(run_scan.command, "write_report_digest"):
                    if fail:
                        with self.assertRaises(run_scan.ApiAuthError):
                            run_scan.run_api_scan("openai", MODELS["openai"], USER_KEY, directory)
                    else:
                        path = run_scan.run_api_scan("openai", MODELS["openai"], USER_KEY, directory)
                        self.assertTrue(path.exists())
                reports = list(Path(directory).glob("*.report.jsonl"))
                self.assertEqual(len(reports), 1)
                serialized = reports[0].read_text(encoding="utf-8")
                self.assertNotIn(USER_KEY, serialized)
                rows = [json.loads(line) for line in serialized.splitlines()]
                self.assertEqual(rows[0]["entry_type"], "start_run setup")
                self.assertEqual(rows[1]["entry_type"], "init")
                self.assertEqual(rows[0]["plugins.target_name"], "openai/" + MODELS["openai"])
                if not fail:
                    self.assertEqual(rows[-1]["entry_type"], "completion")
                self.assertTrue(_config.transient.reportfile.closed)
                self.assertEqual(len(instances), 1)
                self.assertIsNone(instances[0]._api_key)
                self.assertTrue(instances[0]._client.is_closed)

    def test_real_garak_harness_writes_attempts_evaluations_and_digest(self):
        requests = []
        def handle(request):
            requests.append(request)
            self.assertEqual(request.headers["authorization"], "Bearer " + USER_KEY)
            return httpx.Response(200, json=answer("openai", "echo " + USER_KEY))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(pg.httpx, "HTTPTransport", return_value=httpx.MockTransport(handle)), \
             patch.object(run_scan, "PROBES", ["test.Test"]):
            path = run_scan.run_api_scan("openai", MODELS["openai"], USER_KEY, directory)
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            kinds = {row["entry_type"] for row in rows}
            self.assertTrue({"start_run setup", "init", "attempt", "eval", "completion"} <= kinds)
            self.assertTrue(requests)
            self.assertIn("[credential redacted]", path.read_text(encoding="utf-8"))
            for file in Path(directory).rglob("*"):
                if file.is_file():
                    self.assertNotIn(USER_KEY.encode(), file.read_bytes())


if __name__ == "__main__":
    unittest.main()
