#!/usr/bin/env python3
"""Member 1 client: sends HTTP requests through the proxy and prints the result.

Examples (run on h1 in Mininet, proxy on h2):
  python3 client.py --proxy 10.0.0.2:8888 /
  python3 client.py --proxy 10.0.0.2:8888 /forbidden
  python3 client.py --proxy 10.0.0.2:8888 --host blocked.example /
  python3 client.py --proxy 10.0.0.2:8888 --method DELETE /
  python3 client.py --proxy 10.0.0.2:8888 --count 30 /
  python3 client.py --proxy 10.0.0.3:9002 --timeout 3 /      # static SDN drop -> ERROR timed out
"""
import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def request(proxy, method, path, host, timeout=5, raw=None):
    h, p = proxy.split(':')
    t0 = time.time()
    try:
        s = socket.create_connection((h, int(p)), timeout=timeout)
        if raw is not None:
            s.sendall((raw + '\r\n\r\n').encode())
        else:
            s.sendall(('%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'
                       % (method, path, host or h)).encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
    except OSError as e:
        return 'ERROR %s' % e, '', (time.time() - t0) * 1000
    head, _, body = data.partition(b'\r\n\r\n')
    status = head.split(b'\r\n')[0].decode(errors='ignore') if head else 'EMPTY RESPONSE'
    return status, body.decode(errors='ignore').strip(), (time.time() - t0) * 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path', nargs='?', default='/')
    ap.add_argument('--proxy', default='127.0.0.1:8888')
    ap.add_argument('--method', default='GET')
    ap.add_argument('--host', default=None, help='Host header to send')
    ap.add_argument('--count', type=int, default=1, help='concurrent requests')
    ap.add_argument('--raw', default=None, help='send this literal text as the request (for malformed-request tests)')
    ap.add_argument('--timeout', type=float, default=5, help='socket timeout in seconds')
    a = ap.parse_args()
    if a.count == 1:
        status, body, ms = request(a.proxy, a.method, a.path, a.host, a.timeout, a.raw)
        print('%s  (%.1f ms)\n%s' % (status, ms, body))
    else:
        with ThreadPoolExecutor(a.count) as ex:
            res = list(ex.map(lambda _: request(a.proxy, a.method, a.path, a.host, a.timeout, a.raw), range(a.count)))
        counts = {}
        for status, _, _ in res:
            counts[status] = counts.get(status, 0) + 1
        for status, n in counts.items():
            print('%d x %s' % (n, status))
        print('average latency: %.1f ms' % (sum(r[2] for r in res) / len(res)))


if __name__ == '__main__':
    main()
