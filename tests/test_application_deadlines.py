"""Independent offline QA; no real sockets, DNS, or providers."""
import io
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from app import application_generator as c

PUBLIC = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('93.184.216.34', 443))


class Trickle(io.RawIOBase):
    def __init__(self, stopped, data):
        self.stopped, self.data, self.offset = stopped, data, 0

    def readable(self):
        return True

    def readinto(self, target):
        if self.stopped.wait(.01):
            raise OSError('watchdog shutdown')
        if self.offset == len(self.data):
            return 0
        target[0] = self.data[self.offset]
        self.offset += 1
        return 1


class DeadlineQA(unittest.TestCase):
    def exercise_transport(self, data=None, handshake=False):
        stopped = threading.Event()
        raw = MagicMock()
        tls = MagicMock()
        tls.shutdown.side_effect = lambda *_: stopped.set()
        raw.shutdown.side_effect = lambda *_: stopped.set()
        if handshake:
            def stalled_handshake():
                if not stopped.wait(2):
                    raise AssertionError('watchdog failed to interrupt handshake')
                raise OSError('aborted handshake')
            tls.do_handshake.side_effect = stalled_handshake
        else:
            tls.makefile.side_effect = lambda *_: io.BufferedReader(Trickle(stopped, data))
        context = MagicMock()
        context.wrap_socket.return_value = tls
        started = time.monotonic()
        with patch.object(c, 'REQUEST_TIMEOUT', .15), patch.object(c, '_resolve_public', return_value=PUBLIC), patch.object(c.socket, 'socket', return_value=raw), patch.object(c.ssl, 'create_default_context', return_value=context), patch.object(c.url_safety, 'validate_target_url', side_effect=AssertionError('unbounded DNS gate called')):
            with self.assertRaises(c.ApplicationRequestError) as caught:
                c.post_json('https://example.com:8443/ai', {'q': 'hello'})
        elapsed = time.monotonic() - started
        self.assertTrue(stopped.is_set())
        self.assertLess(elapsed, .8)
        raw.connect.assert_called_once_with(PUBLIC[4])
        context.wrap_socket.assert_called_once_with(raw, server_hostname='example.com', do_handshake_on_connect=False)
        print('transport elapsed:', round(elapsed, 3))

    def test_real_httpresponse_header_trickle(self):
        self.exercise_transport(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}')

    def test_real_httpresponse_body_trickle(self):
        # Headers arrive immediately; only the body trickles.
        original = Trickle.readinto
        def body_only(stream, target):
            boundary = stream.data.index(b'\r\n\r\n') + 4
            if stream.offset < boundary:
                n = min(len(target), boundary - stream.offset)
                target[:n] = stream.data[stream.offset:stream.offset+n]
                stream.offset += n
                return n
            return original(stream, target)
        with patch.object(Trickle, 'readinto', body_only):
            self.exercise_transport(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1000;' + b'x'*1000 + b'\r\n')

    def test_tls_handshake_shutdown(self):
        self.exercise_transport(handshake=True)

    def test_dns_four_daemons_timeout_and_slot_recovery(self):
        release = threading.Event()
        entered = threading.Condition()
        resolvers = []
        errors = []
        def blocked_dns(*args, **kwargs):
            with entered:
                resolvers.append(threading.current_thread())
                entered.notify_all()
            release.wait(8)
            return [PUBLIC]
        def lookup():
            try:
                c._resolve_public('example.com', 443)
            except c.ApplicationRequestError:
                errors.append(True)
        slots = threading.BoundedSemaphore(4)
        with patch.object(c, '_DNS_SLOTS', slots), patch.object(c.socket, 'getaddrinfo', side_effect=blocked_dns):
            workers = [threading.Thread(target=lookup) for _ in range(4)]
            started = time.monotonic()
            try:
                for worker in workers:
                    worker.start()
                with entered:
                    self.assertTrue(entered.wait_for(lambda: len(resolvers) == 4, timeout=2))
                fifth = time.monotonic()
                with self.assertRaises(c.ApplicationRequestError):
                    c._resolve_public('example.com', 443)
                self.assertLess(time.monotonic() - fifth, .2)
                for worker in workers:
                    worker.join(6)
                self.assertEqual(len(errors), 4)
                self.assertTrue(all(not worker.is_alive() for worker in workers))
                self.assertTrue(all(worker.daemon for worker in resolvers))
                self.assertEqual(len(resolvers), 4)
                self.assertLess(time.monotonic() - started, 6)
                print('DNS timeout elapsed:', round(time.monotonic() - started, 3))
            finally:
                release.set()
                for worker in resolvers:
                    worker.join(1)
            with patch.object(c.socket, 'getaddrinfo', return_value=[PUBLIC]):
                self.assertEqual(c._resolve_public('example.com', 443), PUBLIC)


if __name__ == '__main__':
    unittest.main(verbosity=2)
