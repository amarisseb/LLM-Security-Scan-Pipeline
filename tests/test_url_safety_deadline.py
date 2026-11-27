import socket
import threading
import time
import unittest
from unittest.mock import patch
from app import url_safety


class ResolverDeadlineTests(unittest.TestCase):
    def test_stalled_resolver_has_bounded_wait_and_thread_count(self):
        release, entered = threading.Event(), threading.Event()
        slots = threading.BoundedSemaphore(1)
        def stalled(*args, **kwargs):
            entered.set()
            release.wait(2)
            return []
        try:
            with patch.object(url_safety, "DNS_TIMEOUT_SECONDS", 0.05), \
                 patch.object(url_safety, "_DNS_SLOTS", slots), \
                 patch.object(socket, "getaddrinfo", stalled):
                start = time.monotonic()
                self.assertFalse(url_safety.validate_target_url("https://example.com").is_safe)
                self.assertTrue(entered.is_set())
                self.assertLess(time.monotonic() - start, 0.8)
                self.assertFalse(slots.acquire(blocking=False))
                self.assertFalse(url_safety.validate_target_url("https://example.org").is_safe)
        finally:
            release.set()

    def test_any_private_record_rejects_hostname(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))
                   for ip in ('93.184.216.34', '169.254.169.254')]
        with patch.object(socket, "getaddrinfo", return_value=records):
            self.assertFalse(url_safety.validate_target_url('https://example.com').is_safe)
