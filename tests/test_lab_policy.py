"""Exact lab allowlisting requires no network access or scanner imports."""

import importlib
import os
from types import SimpleNamespace
import socket
import unittest
from unittest.mock import patch

from app import lab_policy as policy
from app.url_safety import BLOCKED_PORTS


URL = "http://127.0.0.1:3001/api/v1/workspace/lab/chat"


class LabPolicyTests(unittest.TestCase):
    def test_preview_exception_requires_exact_target_origin_and_loopback(self):
        policy.configure_local_targets([URL])
        scope = {'scheme':'http', 'client':('127.0.0.1',1234), 'server':('127.0.0.1',63820),
                 'headers':[(b'host',b'127.0.0.1:63820'),(b'origin',b'http://127.0.0.1:63820')]}
        with patch.dict(os.environ, {'ARISEC_LOCAL_PREVIEW':'1'}):
            self.assertTrue(policy.preview_request_allowed(SimpleNamespace(scope=scope),URL))
            self.assertFalse(policy.preview_request_allowed(SimpleNamespace(scope=scope),URL+'/other'))
            self.assertFalse(policy.preview_request_allowed(SimpleNamespace(scope={**scope,'client':('203.0.113.4',1234)}),URL))
            self.assertFalse(policy.preview_request_allowed(SimpleNamespace(scope={**scope,'headers':[(b'host',b'127.0.0.1:63820')]}),URL))
        with patch.dict(os.environ, {'ARISEC_LOCAL_PREVIEW':'0'}):
            self.assertFalse(policy.preview_request_allowed(SimpleNamespace(scope=scope),URL))

    def setUp(self):
        policy.configure_local_targets([])
        self.addCleanup(policy.configure_local_targets, [])

    def test_default_empty(self):
        importlib.reload(policy)
        self.assertEqual(policy.configured_local_targets(), [])
        self.assertIsInstance(policy._targets, tuple)
        self.assertFalse(policy.is_local_target(URL))

    def test_exact_endpoint_only(self):
        policy.configure_local_targets([URL])
        self.assertTrue(policy.is_local_target(URL))
        for other in (
            URL + "/", URL + "/child", URL + "?", URL + "#",
            URL.replace("/chat", "/chats"),
            URL.replace("3001", "3002"), URL.replace("http:", "https:"),
            URL.replace("127.0.0.1", "127.0.0.2"),
            URL.replace("127.0.0.1", "localhost"),
            URL.replace("/lab/", "/LAB/"), None, [],
        ):
            with self.subTest(other=other):
                self.assertFalse(policy.is_local_target(other))
                with self.assertRaisesRegex(ValueError, "^Invalid local lab target configuration$"):
                    policy.local_target_address(other)

    def test_numeric_addresses_without_resolution(self):
        ipv6 = "https://[::1]:8443/"
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("no DNS")):
            policy.configure_local_targets([URL, ipv6])
            self.assertEqual(policy.local_target_address(URL), (
                socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                "", ("127.0.0.1", 3001)))
            self.assertEqual(policy.local_target_address(ipv6), (
                socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP,
                "", ("::1", 8443, 0, 0)))

    def test_invalid_configuration_is_atomic_and_generic(self):
        invalid = [
            "http://169.254.169.254:8080/latest/meta-data/",
            "http://metadata.google.internal:8080/",
            "http://[fd00:ec2::254]:8080/",
            "http://localhost:8080/", "http://localhost.:8080/",
            "http://127.0.0.2:8080/", "http://10.0.0.1:8080/",
            "http://example.com:8080/", "http://0.0.0.0:8080/",
            "http://[::ffff:127.0.0.1]:8080/",
            "http://2130706433:8080/", "http://127.1:8080/",
            "http://127.0.0.1/", "http://127.0.0.1:8080",
            "http://127.0.0.1:1023/", "http://127.0.0.1:65536/",
            "http://127.0.0.1:+8080/", "ftp://127.0.0.1:8080/",
            "http://secret:password@127.0.0.1:8080/",
            URL + "?secret=password", URL + "#secret", URL + "?", URL + "#",
            URL + "/./x", URL + "/../x", URL + "/..",
            URL + "/%2e%2e", URL + "%2f", URL + "%25",
            URL + "\\x", " " + URL, URL + "\n", URL + "\t",
            URL + "\x00", URL + "\x7f", URL + "\u00a0",
            None, 123,
        ]
        invalid.extend(f"http://127.0.0.1:{port}/" for port in BLOCKED_PORTS)
        policy.configure_local_targets([URL])
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ValueError) as caught:
                    policy.configure_local_targets([URL, url])
                self.assertEqual(str(caught.exception), "Invalid local lab target configuration")
                self.assertEqual(policy.configured_local_targets(), [URL])

    def test_registry_copies_replacement_and_clear(self):
        urls = [URL]
        policy.configure_local_targets(urls)
        urls.clear()
        policy.configured_local_targets().clear()
        self.assertEqual(policy.configured_local_targets(), [URL])
        replacement = "https://[::1]:65535/endpoint"
        policy.configure_local_targets([replacement])
        self.assertFalse(policy.is_local_target(URL))
        policy.configure_local_targets([])
        self.assertFalse(policy.is_local_target(replacement))

    def test_no_ambient_enabling_or_redirect_permission(self):
        with patch.dict("os.environ", {"LOCAL_LAB_TARGETS": URL}):
            importlib.reload(policy)
            self.assertFalse(policy.is_local_target(URL))
        policy.configure_local_targets([URL])
        self.assertFalse(policy.is_local_target("http://127.0.0.1:3001/redirected"))

    def test_requires_list(self):
        for value in (URL, (URL,), None, {URL}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.configure_local_targets(value)


if __name__ == "__main__":
    unittest.main()
