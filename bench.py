#!/usr/bin/env python3
"""Load generator for Project 28 (runs on h1 / h4 inside Mininet, or on localhost).

Latency / throughput (closed loop: N clients, each sends requests one after another)
  python3 bench.py --target 10.0.0.2:8888 --clients 10 --requests 20
  python3 bench.py --target 10.0.0.3:80   --clients 10 --duration 8

Attack flood (open loop: a fixed number of requests per second, many violate the policy)
  python3 bench.py --mode flood --target 10.0.0.2:8888 --rate 100 --duration 10 --path /malware

The last line printed is a single JSON object with the measurements.
"""
import argparse
import json
import socket
import threading
import time


def one_request(target, path, timeout):
    """Return (status_text, latency_ms). status_text is 'ERR:<reason>' on failure."""
    host, port = target.split(':')
    t0 = time.time()
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'
                   % (path, host)).encode())
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
    except OSError as e:
        return 'ERR:%s' % (str(e) or e.__class__.__name__), (time.time() - t0) * 1000
    line = data.split(b'\r\n', 1)[0].decode(errors='ignore')
    parts = line.split()
    code = parts[1] if len(parts) >= 2 else 'EMPTY'
    return code, (time.time() - t0) * 1000


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(round(pct / 100.0 * (len(values) - 1))))]


def run_latency(a):
    lats, codes, lock = [], {}, threading.Lock()
    stop_at = time.time() + a.duration if a.duration else None

    def worker():
        n = 0
        while True:
            if stop_at is not None:
                if time.time() >= stop_at:
                    break
            elif n >= a.requests:
                break
            code, ms = one_request(a.target, a.path, a.timeout)
            with lock:
                codes[code] = codes.get(code, 0) + 1
                if code == '200':
                    lats.append(ms)
            n += 1

    t0 = time.time()
    threads = [threading.Thread(target=worker) for _ in range(a.clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    total = sum(codes.values())
    ok = codes.get('200', 0)
    return {'mode': 'latency', 'target': a.target, 'clients': a.clients,
            'total': total, 'ok': ok, 'errors': total - ok, 'codes': codes,
            'avg_ms': round(sum(lats) / len(lats), 2) if lats else 0.0,
            'p50_ms': round(percentile(lats, 50), 2),
            'p95_ms': round(percentile(lats, 95), 2),
            'throughput_rps': round(ok / elapsed, 2) if elapsed else 0.0,
            'duration_s': round(elapsed, 2)}


def run_flood(a):
    codes, lock, threads = {}, threading.Lock(), []

    def fire():
        code, _ = one_request(a.target, a.path, a.timeout)
        if code.startswith('ERR:'):
            code = 'timeout/dropped' if 'timed out' in code else 'error'
        with lock:
            codes[code] = codes.get(code, 0) + 1

    sent = 0
    t0 = time.time()
    interval = 1.0 / a.rate
    total = int(a.rate * a.duration)
    while sent < total:
        due = t0 + sent * interval
        now = time.time()
        if due > now:
            time.sleep(due - now)
        t = threading.Thread(target=fire)
        t.start()
        threads.append(t)
        sent += 1
    for t in threads:
        t.join(a.timeout + 2)
    return {'mode': 'flood', 'target': a.target, 'rate_rps': a.rate,
            'sent': sent, 'codes': codes,
            'got_403': codes.get('403', 0),
            'dropped_or_timeout': codes.get('timeout/dropped', 0),
            'duration_s': round(time.time() - t0, 2)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['latency', 'flood'], default='latency')
    ap.add_argument('--target', required=True, help='host:port (proxy or backend)')
    ap.add_argument('--path', default='/')
    ap.add_argument('--clients', type=int, default=1)
    ap.add_argument('--requests', type=int, default=20, help='per client (latency mode)')
    ap.add_argument('--duration', type=float, default=0, help='seconds')
    ap.add_argument('--rate', type=float, default=20, help='requests/second (flood mode)')
    ap.add_argument('--timeout', type=float, default=5)
    a = ap.parse_args()
    if a.mode == 'flood':
        a.duration = a.duration or 10
        a.timeout = min(a.timeout, 1.0)
        result = run_flood(a)
    else:
        result = run_latency(a)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
