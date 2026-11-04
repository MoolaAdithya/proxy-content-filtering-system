#!/usr/bin/env python3
"""Focused tests for HTTP framing and safety checks in proxy.py."""
import unittest

import proxy


class FakeSocket:
    def __init__(self, payload, split=65536):
        self.payload = payload
        self.split = split

    def recv(self, size):
        if not self.payload:
            return b''
        n = min(size, self.split, len(self.payload))
        out, self.payload = self.payload[:n], self.payload[n:]
        return out


class ProxyHTTPTests(unittest.TestCase):
    def test_content_length_body(self):
        raw = (b'POST /checkout HTTP/1.1\r\nHost: lab\r\n'
               b'Content-Length: 4\r\n\r\ndata')
        head, body = proxy.read_request(FakeSocket(raw, split=3))
        self.assertIn(b'POST /checkout', head)
        self.assertEqual(body, b'data')

    def test_chunked_body_is_decoded(self):
        raw = (b'POST /checkout HTTP/1.1\r\nHost: lab\r\n'
               b'Transfer-Encoding: chunked\r\n\r\n'
               b'4;ext=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n')
        head, body = proxy.read_request(FakeSocket(raw, split=2))
        self.assertIn(b'Transfer-Encoding: chunked', head)
        self.assertEqual(body, b'data')
        forwarded = proxy.rewrite_head(head, len(body))
        self.assertNotIn(b'Transfer-Encoding', forwarded)
        self.assertIn(b'Content-Length: 4', forwarded)

    def test_conflicting_content_lengths_rejected(self):
        raw = (b'POST / HTTP/1.1\r\nHost: lab\r\n'
               b'Content-Length: 2\r\nContent-Length: 3\r\n\r\nabc')
        with self.assertRaises(proxy.RequestReadError) as ctx:
            proxy.read_request(FakeSocket(raw))
        self.assertEqual(ctx.exception.status, 400)

    def test_duplicate_content_length_rejected(self):
        raw = (b'POST / HTTP/1.1\r\nHost: lab\r\n'
               b'Content-Length: 3\r\nContent-Length: 3\r\n\r\nabc')
        with self.assertRaises(proxy.RequestReadError) as ctx:
            proxy.read_request(FakeSocket(raw))
        self.assertEqual(ctx.exception.status, 400)

    def test_content_length_and_transfer_encoding_rejected(self):
        raw = (b'POST / HTTP/1.1\r\nHost: lab\r\nContent-Length: 4\r\n'
               b'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n')
        with self.assertRaises(proxy.RequestReadError) as ctx:
            proxy.read_request(FakeSocket(raw))
        self.assertEqual(ctx.exception.status, 400)

    def test_oversized_body_rejected(self):
        raw = (b'POST / HTTP/1.1\r\nHost: lab\r\nContent-Length: '
               + str(proxy.MAX_BODY_BYTES + 1).encode() + b'\r\n\r\n')
        with self.assertRaises(proxy.RequestReadError) as ctx:
            proxy.read_request(FakeSocket(raw))
        self.assertEqual(ctx.exception.status, 413)

    def test_malformed_header_rejected(self):
        raw = b'GET / HTTP/1.1\r\nBad Header\r\n\r\n'
        with self.assertRaises(proxy.RequestReadError) as ctx:
            proxy.read_request(FakeSocket(raw))
        self.assertEqual(ctx.exception.status, 400)


if __name__ == '__main__':
    unittest.main(verbosity=2)
