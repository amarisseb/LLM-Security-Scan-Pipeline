"""Application mapping and egress tests; no external requests or paid models."""

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from garak import _config
from garak.attempt import Conversation, Message, Turn

from app import application_generator as connector
from app import application_scan, run_scan


PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
SECRET = "test-bearer-NEVER-WRITE-THIS"


class ApplicationMappingTests(unittest.TestCase):
    def test_prompt_substitution_cannot_break_json(self):
        prompt = '\"}, "admin": true, "x":"\\\n{{prompt}}'
        payload = connector.render_request({"data": [{"text": "{{prompt}}"}], "policy": "summarize only"}, prompt)
        self.assertEqual(json.loads(json.dumps(payload))["data"][0]["text"], prompt)
        self.assertEqual(payload["policy"], "summarize only")
        self.assertNotIn("admin", payload)

    def test_invalid_config_is_rejected(self):
        for url, template, path in [
            ("http://example.com", {"text": "{{prompt}}"}, "answer"),
            ("https://u:p@example.com", {"text": "{{prompt}}"}, "answer"),
            ("https://example.com?token=secret", {"text": "{{prompt}}"}, "answer"),
            ("https://example.com/#part", {"text": "{{prompt}}"}, "answer"),
            ("https://example.com", {"text": "prefix {{prompt}}"}, "answer"),
            ("https://example.com", {"text": "no substitution"}, "answer"),
            ("https://example.com", {"text": "{{prompt}}"}, "x[eval()]"),
        ]:
            with self.subTest(url=url, template=template, path=path):
                with self.assertRaises(connector.ApplicationConfigError):
                    connector.validate_connection(url, template, path)

    def test_list_response_path_and_type_failures(self):
        self.assertEqual(connector.response_text({"choices": [{"message": {"content": "answer"}}]},
                                                 "choices.0.message.content"), "answer")
        for data in [{"answer": {}}, {"answer": ""}, {"wrong": "text"}]:
            with self.assertRaises(connector.ApplicationRequestError):
                connector.response_text(data, "answer")

    def test_header_injection_is_rejected(self):
        with self.assertRaises(connector.ApplicationConfigError):
            connector.validate_connection("https://example.com", {"q": "{{prompt}}"}, "answer", "secret\r\nX: y")

    def test_mixed_public_and_private_dns_blocks_every_connection(self):
        private = (*PUBLIC[:4], ("127.0.0.1", 443))
        with patch.object(socket, "getaddrinfo", return_value=[PUBLIC, private]):
            with self.assertRaises(connector.ApplicationRequestError):
                connector._resolve_public("example.com", 443)

    def test_numeric_sockaddr_is_pinned_and_tls_uses_original_name(self):
        with patch.object(connector.ssl, "create_default_context") as context_factory:
            context = context_factory.return_value
            conn = connector._PinnedHTTPSConnection("example.com", 443, PUBLIC, 2)
            with patch.object(connector.socket, "socket") as socket_factory:
                conn.connect()
                socket_factory.return_value.connect.assert_called_once_with(PUBLIC[4])
                context.wrap_socket.assert_called_once_with(socket_factory.return_value, server_hostname="example.com", do_handshake_on_connect=False)

    def test_redirect_is_never_followed_and_auth_does_not_leak(self):
        with patch.object(connector.url_safety, "validate_target_url") as validate, \
                patch.object(connector, "_resolve_public", return_value=PUBLIC), \
                patch.object(connector, "_PinnedHTTPSConnection") as factory:
            validate.return_value.is_safe = True
            conn = factory.return_value
            conn.getresponse.return_value.status = 302
            with self.assertRaises(connector.ApplicationRequestError) as raised:
                connector.post_json("https://example.com/ai", {"q": "hello"}, SECRET)
            self.assertNotIn(SECRET, str(raised.exception))
            factory.assert_called_once()
            conn.request.assert_called_once()
            self.assertEqual(conn.request.call_args.kwargs["headers"]["Authorization"], "Bearer " + SECRET)
            conn.close.assert_called_once()

    def test_transport_exception_does_not_include_secret(self):
        with patch.object(connector.url_safety, "validate_target_url") as validate, \
                patch.object(connector, "_resolve_public", return_value=PUBLIC), \
                patch.object(connector, "_PinnedHTTPSConnection") as factory:
            validate.return_value.is_safe = True
            factory.return_value.request.side_effect = OSError("token=" + SECRET)
            with self.assertRaises(connector.ApplicationRequestError) as raised:
                connector.post_json("https://example.com/ai", {"q": "hello"}, SECRET)
            self.assertNotIn(SECRET, str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_generator_uses_application_mapping_and_redacts_reflected_token(self):
        _config.load_base_config()
        gen = connector.ApplicationGenerator("https://example.com/ai", {"document": "{{prompt}}", "mode": "summary"}, "answer", SECRET)
        with patch.object(connector, "post_json", return_value={"answer": "oops " + SECRET}) as post:
            output = gen._call_model(Conversation([Turn("user", Message(text="attack"))]))
            self.assertEqual(post.call_args.args[1], {"document": "attack", "mode": "summary"})
            self.assertNotIn(SECRET, output[0].text)
        gen.close()
        self.assertIsNone(gen._token)

    def test_real_garak_pipeline_writes_standard_report_without_key_or_template(self):
        # Run garak's actual harness/evaluator with its offline test probe; only
        # the remote application's transport is mocked. No LLM API call occurs.
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(run_scan, "PROBES", ["test.Test"]), \
                patch.object(connector, "post_json", return_value={"result": "I'm sorry, I cannot comply."}):
            report = application_scan.run_application_scan(
                "https://example.com/ai", {"message": "{{prompt}}", "private_context": "TEMPLATE-SENTINEL"},
                "result", SECRET, tmp,
            )
            text = report.read_text(encoding="utf-8")
            self.assertTrue(any(json.loads(line).get("entry_type") == "eval" for line in text.splitlines()))
            for file in Path(tmp).rglob("*"):
                if file.is_file():
                    self.assertNotIn(SECRET.encode(), file.read_bytes())
                    self.assertNotIn(b"TEMPLATE-SENTINEL", file.read_bytes())


if __name__ == "__main__":
    unittest.main()
