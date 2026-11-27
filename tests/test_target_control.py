import unittest
from unittest.mock import patch
from fastapi import HTTPException
from app.target_control import canonical_origin, require_target_control


class TargetControlTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(canonical_origin('https://EXAMPLE.com:443/chat?q=1'), 'https://example.com')
        self.assertEqual(canonical_origin('https://bücher.example/'), 'https://xn--bcher-kva.example')
        self.assertEqual(canonical_origin('http://[::1]:80/path'), 'http://[::1]')

    def test_reject_ambiguous_origins(self):
        for url in ['https://u:p@example.com', 'https://example.com/#x', 'https://example.com/#', 'https://example.com\\evil', ' https://example.com', 'https://example.com\n', '//example.com', 'ftp://example.com', 'https://example.com:', 'https://example.com:99999', 'https://example.com.', 'https://bad_host.com', 'https://[fe80::1%25eth0]']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                canonical_origin(url)

    def test_exact_grant_and_no_network(self):
        principal = dict(id='pilot', email='p@example.com', allowed_origins=['https://example.com'], local_demo=False)
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS forbidden')):
            require_target_control(principal, 'https://EXAMPLE.com:443/chat')
            for url in ['https://sub.example.com', 'https://example.com.evil', 'http://example.com', 'https://example.com:444', 'https://example.com/#fragment']:
                with self.subTest(url=url), self.assertRaises(HTTPException) as error:
                    require_target_control(principal, url)
                self.assertEqual(error.exception.status_code, 403)
                self.assertEqual(error.exception.detail, 'Target not approved.')

    def test_no_implicit_demo_or_email_grants(self):
        for principal in [{}, dict(email='owner@example.com'), dict(local_demo=True, allowed_origins=[]), dict(allowed_origins='https://example.com')]:
            with self.assertRaises(HTTPException):
                require_target_control(principal, 'https://example.com')
