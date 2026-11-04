#!/usr/bin/env python3
"""Traffic generator used by the dashboard (can also be run by hand).

Runs a batch of HTTP requests through the proxy, or a TCP port probe, and prints
ONE JSON line with the results. In lab mode the dashboard starts this script
inside a Mininet host (h1 / h4) so the traffic really comes from that host's IP.

  python3 traffic.py '{"target": "10.0.0.2:8888", "requests": [{"path": "/malware"}], "repeat": 3}'
  python3 traffic.py '{"probe": {"ip": "10.0.0.3", "ports": [22, 80, 9002]}}'
"""
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# Ready-made demo scenarios shown as buttons in the dashboard's Traffic Lab.
SCENARIOS = [
    {'id': 'normal', 'name': 'Normal browsing', 'icon': 'globe', 'from': 'h1',
     'desc': 'Ordinary pages, an API call and a login - should all pass.',
     'requests': [{'path': '/'}, {'path': '/news'}, {'path': '/products/malwarebytes'},
                  {'path': '/images/logo.png'}, {'path': '/api/items?page=2'},
                  {'method': 'POST', 'path': '/login', 'body': 'user=alice'},
                  {'path': '/health'}, {'method': 'HEAD', 'path': '/'}]},
    {'id': 'malware', 'name': 'Malware downloads', 'icon': 'bug', 'from': 'h4',
     'desc': 'Executables and malware words, including URL-encoded evasions.',
     'requests': [{'path': '/downloads/setup.exe'}, {'path': '/files/invoice.pdf.scr'},
                  {'path': '/malware'}, {'path': '/%6Dalware'}, {'path': '/get/RANSOMWARE.zip'}]},
    {'id': 'sqli', 'name': 'SQL injection', 'icon': 'database', 'from': 'h4',
     'desc': 'Classic injection payloads in the query string.',
     'requests': [{'path': "/product?id=1' OR '1'='1"},
                  {'path': '/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users'},
                  {'path': '/item?id=5;DROP TABLE orders'}]},
    {'id': 'traversal', 'name': 'Path traversal & XSS', 'icon': 'folder', 'from': 'h4',
     'desc': 'Reading system files and script injection, plain and encoded.',
     'requests': [{'path': '/../../etc/passwd'}, {'path': '/%2e%2e/%2e%2e/etc/shadow'},
                  {'path': '/comment?text=<script>alert(1)</script>'}]},
    {'id': 'scanner', 'name': 'Hacking tool scan', 'icon': 'radar', 'from': 'h4',
     'desc': 'Requests that identify themselves as sqlmap / nikto.',
     'requests': [{'path': '/', 'ua': 'sqlmap/1.7.2#stable'}, {'path': '/robots.txt', 'ua': 'Mozilla/5.00 (Nikto/2.5.0)'}]},
    {'id': 'sites', 'name': 'Blocked websites', 'icon': 'ban', 'from': 'h1',
     'desc': 'Social media and blocked domains, exact host and subdomains.',
     'requests': [{'path': '/', 'host': 'www.facebook.com'}, {'path': '/reels', 'host': 'instagram.com'},
                  {'path': '/', 'host': 'blocked.example'}, {'path': '/', 'host': 'notblocked.example'},
                  {'path': '/casino/offers'}]},
    {'id': 'admin', 'name': 'Admin area access', 'icon': 'lock', 'from': 'h4',
     'desc': 'Only 10.0.0.1 may open /admin. Try it from h1 and from h4.',
     'requests': [{'path': '/admin'}, {'path': '/admin/users'}, {'path': '//%41DMIN/settings'}]},
    {'id': 'ports', 'name': 'Restricted ports', 'icon': 'plug', 'from': 'h1',
     'desc': 'Requests aimed at SSH, MySQL and RDP ports via the Host header.',
     'requests': [{'path': '/', 'host': '10.0.0.3:22'}, {'path': '/', 'host': '10.0.0.3:3306'},
                  {'path': '/', 'host': '10.0.0.3:3389'}, {'path': '/', 'host': '10.0.0.3:8080'}]},
    {'id': 'dlp', 'name': 'Data leak (DLP)', 'icon': 'card', 'from': 'h1',
     'desc': 'A card number in a POST body is stopped; a normal order passes.',
     'requests': [{'method': 'POST', 'path': '/checkout', 'body': 'name=Ravi&card=4111 1111 1111 1111'},
                  {'method': 'POST', 'path': '/checkout', 'body': 'item=42&qty=1'}]},
    {'id': 'methods', 'name': 'Disallowed methods', 'icon': 'x', 'from': 'h1',
     'desc': 'PUT, DELETE and TRACE are outside the method whitelist.',
     'requests': [{'method': 'PUT', 'path': '/files/a.txt', 'body': 'x'},
                  {'method': 'DELETE', 'path': '/users/7'}, {'method': 'TRACE', 'path': '/'}]},
    {'id': 'attack', 'name': 'Escalation to SDN block', 'icon': 'bolt', 'from': 'h4',
     'desc': 'Repeated violations -> strikes -> the switch drops the attacker.',
     'requests': [{'path': '/malware'}, {'path': '/downloads/tool.exe'}, {'path': '/forbidden'},
                  {'path': '/'}, {'path': '/'}]},
    {'id': 'flood', 'name': 'Request flood', 'icon': 'wave', 'from': 'h4', 'repeat': 40, 'concurrency': 20,
     'desc': '40 fast requests. Enable rule R16 (rate limit) first to see it trip.',
     'requests': [{'path': '/'}]},
]


def send(target, method='GET', path='/', host=None, ua=None, body='', timeout=2.0, sim_ip=None, headers=None):
    """One HTTP request through the proxy. Returns a small result dict."""
    h, p = target.split(':')
    body_b = body.encode() if isinstance(body, str) else (body or b'')
    wire_path = path.replace(' ', '%20') or '/'          # spaces would break the request line
    lines = ['%s %s HTTP/1.1' % (method.upper(), wire_path), 'Host: %s' % (host or target),
             'User-Agent: %s' % (ua or 'p28-traffic/1.0'), 'Connection: close']
    if sim_ip:
        lines.append('X-Simulated-Client: %s' % sim_ip)
    for k, v in (headers or {}).items():
        lines.append('%s: %s' % (k, v))
    if body_b:
        lines += ['Content-Type: application/x-www-form-urlencoded', 'Content-Length: %d' % len(body_b)]
    raw = ('\r\n'.join(lines) + '\r\n\r\n').encode() + body_b
    t0 = time.time()
    res = {'method': method.upper(), 'path': path, 'host': host or '', 'code': 0, 'status': '', 'rule': None}
    try:
        s = socket.create_connection((h, int(p)), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(raw)
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        head = data.split(b'\r\n\r\n', 1)[0].decode(errors='ignore').split('\r\n')
        parts = head[0].split(' ', 2)
        res['code'] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        res['status'] = head[0]
        for line in head[1:]:
            if line.lower().startswith('x-filter-rule:'):
                res['rule'] = line.split(':', 1)[1].strip()
    except socket.timeout:
        res['status'] = 'TIMEOUT (no reply - dropped by the SDN switch?)'
        res['error'] = 'timeout'
    except OSError as e:
        res['status'] = 'ERROR %s' % e
        res['error'] = str(e)
    res['ms'] = round((time.time() - t0) * 1000, 1)
    return res


def probe(ip, port, timeout=1.0):
    """TCP connect test: open / closed (RST) / filtered (no answer = dropped)."""
    t0 = time.time()
    try:
        s = socket.create_connection((ip, int(port)), timeout=timeout)
        s.close()
        state = 'open'
    except socket.timeout:
        state = 'filtered'
    except ConnectionRefusedError:
        state = 'closed'
    except OSError as e:
        state = 'error: %s' % e
    return {'ip': ip, 'port': int(port), 'state': state, 'ms': round((time.time() - t0) * 1000, 1)}


def run(spec):
    if 'probe' in spec:
        pr = spec['probe']
        ports = [int(x) for x in pr['ports']][:64]
        with ThreadPoolExecutor(min(len(ports), 32) or 1) as ex:
            out = list(ex.map(lambda port: probe(pr['ip'], port, pr.get('timeout', 1.0)), ports))
        return {'probes': out}
    reqs = spec.get('requests') or [{}]
    jobs = []
    for _ in range(max(1, min(int(spec.get('repeat', 1)), 500))):
        jobs.extend(reqs)
    conc = max(1, min(int(spec.get('concurrency', 1)), 50))
    target = spec.get('target', '127.0.0.1:8888')
    timeout = float(spec.get('timeout', 2.0))
    sim = spec.get('sim_ip')

    def go(r):
        return send(target, r.get('method', 'GET'), r.get('path', '/'), r.get('host'), r.get('ua'),
                    r.get('body', ''), timeout, sim, r.get('headers'))
    if conc == 1:
        out = []
        for r in jobs:
            out.append(go(r))
            if spec.get('gap'):
                time.sleep(float(spec['gap']))
    else:
        with ThreadPoolExecutor(conc) as ex:
            out = list(ex.map(go, jobs))
    return {'results': out}


if __name__ == '__main__':
    print(json.dumps(run(json.loads(sys.argv[1]))), flush=True)
