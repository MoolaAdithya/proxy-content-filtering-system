#!/usr/bin/env python3
"""
Concurrent TCP content-filtering proxy (Project 28)  -  Socket & Application Layer.

What it does
  * Accepts many clients at once (one thread per connection).
  * Parses each HTTP request: method, target (also absolute http://host:port/ form),
    headers, body. The URL is decoded and normalised so tricks like "/%6Dalware",
    "/MALWARE" or "/public/../admin" cannot slip past the filter.
  * Checks the request against the ordered rules in policy.json (see rules.py):
    source IP / subnet, destination port, method, exact or wildcard host, path,
    query, whole-word keywords, User-Agent, headers, body content, size, time and
    request rate. The FIRST matching rule decides; every decision records the rule
    id and the exact condition that matched. The file is re-read automatically
    when it changes, so the policy can be changed at runtime (also from the dashboard).
  * Allowed requests are forwarded to the backend and the response is relayed.
  * Blocked requests get HTTP 403 (header X-Filter-Rule names the rule).
    Each block adds strikes (1 for low/medium, 2 for high, 3 for critical rules);
    when a client reaches strike_limit within strike_window seconds and SDN is
    enabled, the controller is asked to DROP that client at the switch.
  * Human-readable log  -> proxy.log    (PERMITTED / BLOCKED / STRIKE ... lines)
    Machine-readable log -> events.jsonl (one JSON object per request, read by dashboard.py)

Environment variables
  PROXY_HOST (0.0.0.0)  PROXY_PORT (8888)
  BACKEND_HOST (10.0.0.3)  BACKEND_PORT (80)
  SDN_ENABLED (1)  SDN_URL (http://10.0.0.254:8080/policy/block)
  POLICY_FILE (policy.json)  LOG_FILE (proxy.log)  EVENTS_FILE (events.jsonl)
  SIMULATE_CLIENTS (0)  demo mode WITHOUT Mininet only: trust the X-Simulated-Client
                        header as the client IP so one PC can play several clients.
"""
import json
import os
import socket
import threading
import time
import urllib.request

import rules

PROXY_HOST = os.environ.get('PROXY_HOST', '0.0.0.0')
PROXY_PORT = int(os.environ.get('PROXY_PORT', '8888'))
BACKEND = (os.environ.get('BACKEND_HOST', '10.0.0.3'), int(os.environ.get('BACKEND_PORT', '80')))
SDN_ENABLED = os.environ.get('SDN_ENABLED', '1') == '1'
SDN_URL = os.environ.get('SDN_URL', 'http://10.0.0.254:8080/policy/block')
POLICY_FILE = os.environ.get('POLICY_FILE', 'policy.json')
LOG_FILE = os.environ.get('LOG_FILE', 'proxy.log')
EVENTS_FILE = os.environ.get('EVENTS_FILE', 'events.jsonl')
SIMULATE = os.environ.get('SIMULATE_CLIENTS', '0') == '1'

DEFAULT_POLICY = {
    'default_action': 'allow',
    'rules': [],
    'block_client_on_violation': True,
    'block_duration': 300,
    'strike_limit': 3,
    'strike_window': 60,
}

_policy = dict(DEFAULT_POLICY)
_engine = rules.Engine(_policy)
_policy_mtime = None
_policy_lock = threading.Lock()
_log_lock = threading.Lock()
_event_lock = threading.Lock()
_strikes = {}
_strike_lock = threading.Lock()


def log(line):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with _log_lock:
        with open(LOG_FILE, 'a') as f:
            f.write('%s %s\n' % (stamp, line))
    print(line, flush=True)


def event(**fields):
    """Append one structured event (JSON line) for the dashboard."""
    fields.setdefault('ts', time.time())
    line = json.dumps(fields, separators=(',', ':'))
    with _event_lock:
        try:
            with open(EVENTS_FILE, 'a') as f:
                f.write(line + '\n')
        except OSError:
            pass


def get_policy():
    """Current (policy, engine); reloaded automatically when the file changes."""
    global _policy, _engine, _policy_mtime
    try:
        mtime = os.path.getmtime(POLICY_FILE)
    except OSError:
        return _policy, _engine
    with _policy_lock:
        if mtime != _policy_mtime:
            _policy_mtime = mtime
            try:
                with open(POLICY_FILE) as f:
                    loaded = json.load(f)
                policy = dict(DEFAULT_POLICY, **loaded)
                engine = rules.Engine(policy)
                _policy, _engine = policy, engine
                log('POLICY_RELOADED rules=%d default=%s' % (len(engine.rules), engine.default))
                for err in engine.errors:
                    log('POLICY_WARNING %s' % err)
                event(type='policy', rules=len(engine.rules), errors=engine.errors)
            except (OSError, ValueError) as e:
                log('POLICY_ERROR %s (keeping previous policy)' % e)
    return _policy, _engine


class RequestReadError(Exception):
    """A client request is malformed or exceeds configured safety limits."""
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


MAX_HEADER_BYTES = 65536
MAX_BODY_BYTES = 2 * 1024 * 1024


def read_request(sock):
    """Read one HTTP/1.x request, decoding chunked bodies for policy inspection.

    The proxy closes each client connection after one request.  Chunked request
    bodies are de-framed here and later forwarded with a fresh Content-Length,
    so filtering and the backend see the same entity body.
    """
    buffer = bytearray()

    def receive():
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            raise RequestReadError(408, 'Timed out while reading the request.')
        if not chunk:
            raise RequestReadError(400, 'Unexpected end of request.')
        buffer.extend(chunk)

    def take_until(marker, limit, label):
        while True:
            pos = buffer.find(marker)
            if pos >= 0:
                value = bytes(buffer[:pos])
                del buffer[:pos + len(marker)]
                return value
            if len(buffer) > limit:
                raise RequestReadError(431 if label == 'headers' else 400,
                                       '%s exceeds the permitted size.' % label.capitalize())
            receive()

    def take_exact(length):
        while len(buffer) < length:
            receive()
        value = bytes(buffer[:length])
        del buffer[:length]
        return value

    # Header terminator is bounded independently from body size.
    while b'\r\n\r\n' not in buffer:
        if len(buffer) > MAX_HEADER_BYTES:
            raise RequestReadError(431, 'Request headers are too large.')
        try:
            receive()
        except RequestReadError:
            if not buffer:
                return b'', b''
            raise
    head, _, remainder = bytes(buffer).partition(b'\r\n\r\n')
    buffer[:] = remainder
    if len(head) > MAX_HEADER_BYTES:
        raise RequestReadError(431, 'Request headers are too large.')

    lines = head.split(b'\r\n')
    if not lines or len(lines[0].split()) != 3:
        raise RequestReadError(400, 'Malformed request line.')

    content_lengths = []
    transfer_encodings = []
    host_headers = 0
    for line in lines[1:]:
        if not line or line[:1] in (b' ', b'\t') or b':' not in line:
            raise RequestReadError(400, 'Malformed request header.')
        name, value = line.split(b':', 1)
        name = name.strip().lower()
        value = value.strip()
        if name == b'host':
            host_headers += 1
        elif name == b'content-length':
            try:
                content_lengths.append(int(value))
            except ValueError:
                raise RequestReadError(400, 'Invalid Content-Length.')
        elif name == b'transfer-encoding':
            transfer_encodings.extend(x.strip().lower() for x in value.split(b','))

    if any(n < 0 for n in content_lengths):
        raise RequestReadError(400, 'Invalid Content-Length.')
    if len(content_lengths) > 1:
        raise RequestReadError(400, 'Duplicate Content-Length headers are not accepted.')
    if host_headers > 1:
        raise RequestReadError(400, 'Duplicate Host headers are not accepted.')
    if content_lengths and transfer_encodings:
        raise RequestReadError(400, 'Content-Length with Transfer-Encoding is not accepted.')
    if transfer_encodings and transfer_encodings != [b'chunked']:
        raise RequestReadError(501, 'Unsupported Transfer-Encoding.')

    body = bytearray()
    if transfer_encodings == [b'chunked']:
        while True:
            size_line = take_until(b'\r\n', 8192, 'chunk-size line')
            size_token = size_line.split(b';', 1)[0].strip()
            try:
                size = int(size_token, 16)
            except ValueError:
                raise RequestReadError(400, 'Invalid chunk size.')
            if size < 0 or size > MAX_BODY_BYTES - len(body):
                raise RequestReadError(413, 'Request body is too large.')
            if size == 0:
                # Consume optional trailers through the terminating empty line.
                trailer_bytes = 0
                while True:
                    trailer = take_until(b'\r\n', 8192, 'chunk trailer')
                    trailer_bytes += len(trailer) + 2
                    if trailer_bytes > 16384:
                        raise RequestReadError(400, 'Chunk trailers are too large.')
                    if not trailer:
                        break
                    if b':' not in trailer or trailer[:1] in (b' ', b'\t'):
                        raise RequestReadError(400, 'Malformed chunk trailer.')
                break
            body.extend(take_exact(size))
            if take_exact(2) != b'\r\n':
                raise RequestReadError(400, 'Malformed chunk terminator.')
    elif content_lengths:
        length = content_lengths[0]
        if length > MAX_BODY_BYTES:
            raise RequestReadError(413, 'Request body is too large.')
        body.extend(take_exact(length))

    return head, bytes(body)


def parse_request(head):
    """Return (method, target, version, headers_dict) or None if malformed."""
    lines = head.decode('utf-8', errors='ignore').split('\r\n')
    parts = lines[0].split()
    if len(parts) != 3 or not parts[2].upper().startswith('HTTP/'):
        return None
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    return parts[0].upper(), parts[1], parts[2], headers


def add_strike(ip, weight):
    """Record a violation worth `weight` strikes; return (count, limit, should_block)."""
    p, _ = get_policy()
    now = time.time()
    with _strike_lock:
        hits = [t for t in _strikes.get(ip, []) if now - t < p['strike_window']]
        hits.extend([now] * max(weight, 1))
        limit = p['strike_limit']
        if len(hits) >= limit:
            _strikes.pop(ip, None)
            return len(hits), limit, True
        _strikes[ip] = hits
        return len(hits), limit, False


def rewrite_head(head, body_length=0):
    """Remove hop-by-hop/framing headers and forward a normalized body length."""
    lines = head.split(b'\r\n')
    kept = [l for l in lines if not l.lower().startswith((
        b'connection:', b'proxy-connection:', b'x-simulated-client:',
        b'transfer-encoding:', b'content-length:', b'trailer:'))]
    kept.append(('Content-Length: %d' % body_length).encode('ascii'))
    kept.append(b'Connection: close')
    return b'\r\n'.join(kept)


def sdn_block(ip, reason):
    duration = get_policy()[0]['block_duration']
    payload = json.dumps({'ip': ip, 'duration': duration, 'reason': reason}).encode()
    req = urllib.request.Request(SDN_URL, data=payload,
                                 headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=2).read()
        log('SDN_BLOCK_REQUESTED ip=%s duration=%ss' % (ip, duration))
        event(type='sdn', action='block', ip=ip, duration=duration, reason=reason, ok=True)
    except Exception as e:
        log('SDN_BLOCK_FAILED ip=%s error=%s' % (ip, e))
        event(type='sdn', action='block', ip=ip, duration=duration, reason=reason, ok=False, error=str(e))


def respond(client, status, text, rule_id=None):
    body = (text + '\n').encode()
    extra = 'X-Filter-Rule: %s\r\n' % rule_id if rule_id else ''
    client.sendall(('HTTP/1.1 %s\r\nContent-Type: text/plain\r\n%s'
                    'Content-Length: %d\r\nConnection: close\r\n\r\n'
                    % (status, extra, len(body))).encode() + body)


STATUS_TEXT = {400: 'Bad Request', 403: 'Forbidden', 408: 'Request Timeout',
               413: 'Payload Too Large', 431: 'Request Header Fields Too Large',
               429: 'Too Many Requests', 451: 'Unavailable For Legal Reasons',
               501: 'Not Implemented'}


def handle_client(client, addr):
    t0 = time.time()
    ip, cport = addr[0], addr[1]
    try:
        client.settimeout(10)
        try:
            head, body = read_request(client)
        except RequestReadError as exc:
            code = exc.status
            phrase = STATUS_TEXT.get(code, 'Request Error')
            respond(client, '%d %s' % (code, phrase), str(exc))
            log('BAD_REQUEST client=%s status=%d error=%s' % (ip, code, exc))
            event(type='request', client_ip=ip, client_port=cport, decision='bad_request',
                  status=code, error=str(exc), proxy_ms=round((time.time() - t0) * 1000, 2))
            return
        if not head:
            return
        parsed = parse_request(head)
        if parsed is None:
            respond(client, '400 Bad Request', 'Malformed request.')
            log('BAD_REQUEST client=%s' % ip)
            event(type='request', client_ip=ip, client_port=cport, decision='bad_request', status=400,
                  method='?', host='', dst_port=0, path='', rule_id=None, rule_name='malformed HTTP',
                  category='malformed', severity='low', why=['request line is not valid HTTP'],
                  proxy_ms=round((time.time() - t0) * 1000, 2))
            return
        method, target, _version, headers = parsed
        if SIMULATE and headers.get('x-simulated-client'):
            ip = headers['x-simulated-client'].strip()
        policy, engine = get_policy()
        req = rules.build_request(method, target, headers, body, ip, cport)
        d = engine.evaluate(req)
        request_line = '%s %s' % (method, target)
        base = dict(type='request', client_ip=ip, client_port=cport, method=method,
                    host=req['host'], dst_port=req['dst_port'], path=target[:300],
                    rule_id=d['rule_id'], rule_name=d['rule_name'], category=d['category'],
                    severity=d['severity'], why=d['why'], ua=req['user_agent'][:120],
                    req_bytes=len(head) + len(body))

        if d['action'] == 'deny':
            code = d['status']
            respond(client, '%d %s' % (code, STATUS_TEXT.get(code, 'Forbidden')),
                    'Access denied by proxy content filter (rule %s: %s).' % (d['rule_id'], d['rule_name']),
                    d['rule_id'])
            proxy_ms = (time.time() - t0) * 1000
            log('BLOCKED client=%s:%d request="%s" rule=%s reason="%s" proxy_ms=%.2f'
                % (ip, cport, request_line, d['rule_id'], '; '.join(d['why']), proxy_ms))
            count, limit, should_block = add_strike(ip, d['weight'])
            log('STRIKE client=%s count=%d/%d (+%d)' % (ip, count, limit, d['weight']))
            sdn = bool(should_block and SDN_ENABLED and policy['block_client_on_violation'])
            event(decision='blocked', status=code, strikes=count, strike_limit=limit,
                  escalated=sdn, proxy_ms=round(proxy_ms, 2), **base)
            if sdn:
                threading.Thread(target=sdn_block,
                                 args=(ip, '%d strikes, last: %s (%s)' % (count, d['rule_name'], d['rule_id'])),
                                 daemon=True).start()
            return

        try:
            backend = socket.create_connection(BACKEND, timeout=5)
        except OSError as e:
            respond(client, '502 Bad Gateway', 'Backend unavailable.')
            log('BACKEND_ERROR client=%s request="%s" error=%s' % (ip, request_line, e))
            event(decision='error', status=502, proxy_ms=round((time.time() - t0) * 1000, 2),
                  error=str(e), **base)
            return
        t_backend = time.time()
        backend.sendall(rewrite_head(head, len(body)) + b'\r\n\r\n' + body)
        resp_bytes, status = 0, 0
        while True:
            chunk = backend.recv(4096)
            if not chunk:
                break
            if not resp_bytes:
                try:
                    status = int(chunk.split(b' ', 2)[1])
                except (IndexError, ValueError):
                    status = 0
            resp_bytes += len(chunk)
            client.sendall(chunk)
        backend.close()
        total = (time.time() - t0) * 1000
        backend_ms = (time.time() - t_backend) * 1000
        flagged = d['action'] == 'monitor'
        log('PERMITTED client=%s:%d request="%s" rule=%s%s proxy_ms=%.2f backend_ms=%.2f overhead_ms=%.2f'
            % (ip, cport, request_line, d['rule_id'] or '-', ' FLAGGED' if flagged else '',
               total, backend_ms, total - backend_ms))
        event(decision='monitored' if flagged else 'allowed', status=status, proxy_ms=round(total, 2),
              backend_ms=round(backend_ms, 2), overhead_ms=round(total - backend_ms, 2),
              resp_bytes=resp_bytes, **base)
    except Exception as e:
        log('ERROR client=%s error=%s' % (ip, e))
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    get_policy()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((PROXY_HOST, PROXY_PORT))
    server.listen(256)
    log('PROXY_STARTED listen=%s:%d backend=%s:%d sdn=%s%s'
        % (PROXY_HOST, PROXY_PORT, BACKEND[0], BACKEND[1], SDN_URL if SDN_ENABLED else 'disabled',
           ' SIMULATE_CLIENTS' if SIMULATE else ''))
    event(type='start', listen='%s:%d' % (PROXY_HOST, PROXY_PORT), sdn=SDN_ENABLED)
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()


if __name__ == '__main__':
    main()
