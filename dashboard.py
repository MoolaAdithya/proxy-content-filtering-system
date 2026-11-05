#!/usr/bin/env python3
"""
Web dashboard for Project 28  -  live analytics, traffic generator, rule editor, SDN control.

Open http://localhost:5000 in a browser.

Two ways to run it
  1. Lab mode (recommended, real Mininet + SDN):   sudo python3 lab.py
     lab.py builds the network, starts backend + proxy and this dashboard. Traffic you
     send from the UI is generated INSIDE h1 / h4, so it carries their real IPs and
     the SDN switch can block them.
  2. Standalone (any laptop, no Mininet, no root): python3 dashboard.py --standalone
     Starts a backend and the proxy on 127.0.0.1. The proxy runs with SIMULATE_CLIENTS=1
     so the UI can label requests as coming from 10.0.0.1 / 10.0.0.4. The SDN panel
     works only if the controller is running.

What it reads / talks to
  * events.jsonl         - one JSON line per proxy decision (written by proxy.py)
  * policy.json          - rules; saving from the UI rewrites it and the proxy reloads it live
  * controller REST API  - /policy/status, /policy/stats, block / unblock calls

Only the Python standard library is used.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import rules
import traffic

HERE = os.path.dirname(os.path.abspath(__file__))
UI_FILE = os.path.join(HERE, 'ui', 'index.html')


# ============================================================== policy changes
SETTING_LABELS = {'default_action': 'Default action', 'strike_limit': 'Strike limit',
                  'strike_window': 'Strike window (s)', 'block_duration': 'SDN block duration (s)',
                  'block_client_on_violation': 'Escalate to SDN block'}
DECISION_OF = {'deny': 'blocked', 'allow': 'allowed', 'monitor': 'allowed'}


def _short(v, n=60):
    s = ', '.join(map(str, v)) if isinstance(v, list) else json.dumps(v) if isinstance(v, dict) else str(v)
    return s if len(s) <= n else s[:n - 1] + '…'


def diff_policy(old, new):
    """Human-readable list of what changed between two policy dicts + the rule IDs involved."""
    items, ids = [], set()
    for k, label in SETTING_LABELS.items():
        if old.get(k) != new.get(k):
            items.append('%s: %s → %s' % (label, old.get(k), new.get(k)))
            ids.add('*settings')
    o = {r.get('id'): r for r in rules.legacy_rules(old) + list(old.get('rules', []))}
    n = {r.get('id'): r for r in rules.legacy_rules(new) + list(new.get('rules', []))}
    for rid, r in n.items():
        name = r.get('name', '')
        if rid not in o:
            items.append('%s "%s" added (%s)' % (rid, name, r.get('action', 'deny').upper()))
            ids.add(rid)
            continue
        p = o[rid]
        if p.get('enabled', True) != r.get('enabled', True):
            items.append('%s "%s" %s' % (rid, name, 'ENABLED' if r.get('enabled', True) else 'DISABLED'))
            ids.add(rid)
        if (p.get('hit_limit') or 0) != (r.get('hit_limit') or 0):
            items.append('%s "%s" block after hits: %s → %s' % (rid, name, p.get('hit_limit') or 'off', r.get('hit_limit') or 'off'))
        if p.get('action', 'deny') != r.get('action', 'deny'):
            items.append('%s action %s → %s' % (rid, p.get('action', 'deny').upper(), r.get('action', 'deny').upper()))
            ids.add(rid)
        pm, rm = p.get('match', {}), r.get('match', {})
        for key in sorted(set(pm) | set(rm)):
            if pm.get(key) != rm.get(key):
                items.append('%s %s: %s → %s' % (rid, key, _short(pm.get(key, '–')), _short(rm.get(key, '–'))))
                ids.add(rid)
        if p.get('name') != r.get('name') and rid not in ids:
            items.append('%s renamed to "%s"' % (rid, name))
    for rid, r in o.items():
        if rid not in n:
            items.append('%s "%s" deleted' % (rid, r.get('name', '')))
            ids.add(rid)
    if not items and [r.get('id') for r in old.get('rules', [])] != [r.get('id') for r in new.get('rules', [])]:
        items.append('Rule order changed')
        ids.add('*order')
    return items, ids


class PolicyWatch:
    """Watches policy.json. When it changes while traffic is flowing, every later request is
    replayed against the PREVIOUS policy; if the verdict differs, the request is tagged with
    the change that caused it ("blocked now because R09 was enabled")."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.policy, self.mtime = None, None
        self.changes = deque(maxlen=25)
        self.next_id = 1
        self.check()

    def clear(self):
        with self.lock:
            self.changes.clear()

    def check(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        with self.lock:
            if mtime == self.mtime:
                return
            try:
                with open(self.path) as f:
                    new = json.load(f)
            except (OSError, ValueError):
                return                                      # half-written file: try again next poll
            self.mtime = mtime
            old, self.policy = self.policy, new
            if old is None:
                return
            items, ids = diff_policy(old, new)
            if not items:
                return
            try:
                old_engine = rules.Engine(old)
            except Exception:
                old_engine = None
            self.changes.appendleft({'id': self.next_id, 'ts': mtime, 'items': items, 'rule_ids': sorted(ids),
                                     'newly_blocked': 0, 'newly_allowed': 0, 'examples': [],
                                     '_engine': old_engine, '_ids': ids})
            self.next_id += 1

    def annotate(self, e):
        """Tag request event e if its verdict is different from what the old policy would give."""
        if not self.changes or e.get('decision') not in ('allowed', 'monitored', 'blocked', 'error'):
            return
        ch = self.changes[0]
        if ch['_engine'] is None or e.get('ts', 0) < ch['ts']:
            return
        host = e.get('host') or 'site.local'
        if e.get('dst_port') and e['dst_port'] != 80:
            host += ':%d' % e['dst_port']
        hdr = {'Host': host}
        if e.get('ua'):
            hdr['User-Agent'] = e['ua']
        try:
            req = rules.build_request(e.get('method', 'GET'), e.get('path') or '/', hdr, b'',
                                      e.get('client_ip', ''), e.get('client_port', 0))
            old = ch['_engine'].evaluate(req)
        except Exception:
            return
        before = DECISION_OF.get(old['action'], 'allowed')
        now = 'blocked' if e['decision'] == 'blocked' else 'allowed'
        if before == now:
            return
        ids = ch['_ids']
        caused = (e.get('rule_id') in ids or old.get('rule_id') in ids or '*settings' in ids or '*order' in ids)
        if not caused:
            return                                          # e.g. a rate limit, unrelated to the edit
        if now == 'blocked':
            ch['newly_blocked'] += 1
            text = 'BLOCKED by %s "%s" because the rules were changed. Before the change it was ALLOWED.' % (
                e.get('rule_id') or 'default', e.get('rule_name', ''))
        else:
            ch['newly_allowed'] += 1
            text = 'ALLOWED now because the rules were changed. Before the change %s "%s" BLOCKED it.' % (
                old.get('rule_id') or 'default', old.get('rule_name', ''))
        e['rule_change'] = {'change_id': ch['id'], 'before': before, 'after': now, 'text': text,
                            'old_rule': old.get('rule_id'), 'change': ch['items'][:3]}
        ch['examples'] = ([{'ts': e.get('ts'), 'ip': e.get('client_ip'), 'method': e.get('method'),
                            'path': e.get('path'), 'host': e.get('host'), 'after': now, 'before': before,
                            'rule': e.get('rule_id') if now == 'blocked' else old.get('rule_id')}]
                          + ch['examples'])[:6]

    def public(self):
        with self.lock:
            return [{k: v for k, v in c.items() if not k.startswith('_')} for c in self.changes]


# =================================================================== analytics
class Analytics:
    """Tails events.jsonl and keeps running aggregates for the UI."""

    def __init__(self, path, watch=None):
        self.path = path
        self.watch = watch
        self.lock = threading.Lock()
        self.reset_state()

    def reset_state(self):
        self.offset = 0
        self.next_id = 1
        self.events = deque(maxlen=3000)
        self.totals = Counter()
        self.timeline = {}                     # second -> Counter(decision)
        self.by_ip = {}
        self.by_port = {}
        self.by_host = {}
        self.by_rule = {}
        self.by_category = Counter()
        self.latency = deque(maxlen=600)
        self.sdn_events = deque(maxlen=50)
        self.started = time.time()

    def clear(self):
        with self.lock:
            try:
                open(self.path, 'w').close()
            except OSError:
                pass
            self.reset_state()
        if self.watch:
            self.watch.clear()

    def poll(self):
        if self.watch:
            self.watch.check()            # notice rule edits BEFORE reading the requests they affect
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return
        with self.lock:
            if size < self.offset:              # file was truncated / replaced
                self.reset_state()
            if size == self.offset:
                return
            with open(self.path, 'r', errors='ignore') as f:
                f.seek(self.offset)
                chunk = f.read()
            # only consume complete lines
            end = chunk.rfind('\n') + 1
            self.offset += len(chunk[:end].encode())
            for line in chunk[:end].splitlines():
                try:
                    self._add(json.loads(line))
                except ValueError:
                    continue

    def _add(self, e):
        e['id'] = self.next_id
        self.next_id += 1
        kind = e.get('type')
        if kind == 'sdn':
            self.sdn_events.appendleft(e)
            self.events.append(e)
            return
        if kind != 'request':
            return
        d = e.get('decision', 'error')
        if self.watch:
            self.watch.annotate(e)
            if e.get('rule_change'):
                self.totals['rule_changed'] += 1
        self.events.append(e)
        self.totals['requests'] += 1
        self.totals[d] += 1
        sec = int(e.get('ts', time.time()))
        self.timeline.setdefault(sec, Counter())[d] += 1
        if len(self.timeline) > 1200:
            for k in sorted(self.timeline)[:200]:
                del self.timeline[k]
        blocked = d in ('blocked', 'bad_request')
        ip = e.get('client_ip', '?')
        s = self.by_ip.setdefault(ip, {'ip': ip, 'total': 0, 'blocked': 0, 'monitored': 0,
                                       'reasons': Counter(), 'ports': deque(maxlen=6),
                                       'last': 0, 'strikes': 0, 'escalated': 0})
        s['total'] += 1
        s['last'] = e.get('ts', 0)
        s['ports'].append(e.get('client_port'))
        if d == 'monitored':
            s['monitored'] += 1
        if blocked:
            s['blocked'] += 1
            s['reasons'][e.get('rule_id') or e.get('category')] += 1
            s['strikes'] = e.get('strikes', s['strikes'])
            if e.get('escalated'):
                s['escalated'] += 1
        port = e.get('dst_port') or 0
        p = self.by_port.setdefault(port, {'port': port, 'total': 0, 'blocked': 0})
        p['total'] += 1
        p['blocked'] += blocked
        host = e.get('host') or '(none)'
        h = self.by_host.setdefault(host, {'host': host, 'total': 0, 'blocked': 0})
        h['total'] += 1
        h['blocked'] += blocked
        if e.get('rule_id'):
            r = self.by_rule.setdefault(e['rule_id'], {'id': e['rule_id'], 'name': e.get('rule_name', ''),
                                                       'category': e.get('category', ''), 'hits': 0,
                                                       'decision': d})
            r['hits'] += 1
        if blocked:
            self.by_category[e.get('category') or 'other'] += 1
        if d in ('allowed', 'monitored') and e.get('overhead_ms') is not None:
            self.latency.append(e['overhead_ms'])

    def summary(self, window=300, bucket=5):
        self.poll()
        with self.lock:
            now = int(time.time())
            start = now - window
            buckets = []
            for b in range(start - start % bucket, now + 1, bucket):
                c = Counter()
                for sec in range(b, b + bucket):
                    c.update(self.timeline.get(sec, {}))
                buckets.append({'t': b, 'allowed': c['allowed'], 'monitored': c['monitored'],
                                'blocked': c['blocked'] + c['bad_request'], 'error': c['error']})
            lat = sorted(self.latency)
            ips = []
            for s in self.by_ip.values():
                ips.append({'ip': s['ip'], 'total': s['total'], 'blocked': s['blocked'],
                            'monitored': s['monitored'], 'last': s['last'],
                            'top_reasons': s['reasons'].most_common(3),
                            'recent_ports': [x for x in s['ports'] if x],
                            'strikes': s['strikes'], 'escalated': s['escalated']})
            ips.sort(key=lambda x: (-x['blocked'], -x['total']))
            last60 = sum(sum(self.timeline.get(s, {}).values()) for s in range(now - 60, now + 1))
            return {
                'totals': dict(self.totals),
                'rate_per_min': last60,
                'timeline': buckets, 'bucket': bucket,
                'by_ip': ips[:50],
                'by_port': sorted(self.by_port.values(), key=lambda x: (-x['blocked'], -x['total']))[:15],
                'by_host': sorted(self.by_host.values(), key=lambda x: (-x['blocked'], -x['total']))[:15],
                'by_rule': sorted(self.by_rule.values(), key=lambda x: -x['hits'])[:20],
                'by_category': self.by_category.most_common(),
                'latency': {'avg': round(sum(lat) / len(lat), 2) if lat else None,
                            'p95': lat[int(0.95 * (len(lat) - 1))] if lat else None,
                            'n': len(lat)},
                'sdn_events': list(self.sdn_events)[:20],
                'policy_changes': self.watch.public() if self.watch else [],
                'last_id': self.next_id - 1,
            }

    def since(self, after, limit=300):
        self.poll()
        with self.lock:
            out = [e for e in self.events if e['id'] > after]
        return out[-limit:]


# ===================================================================== backends
class Controller:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.cache = {}

    def call(self, path, data=None, timeout=1.5):
        req = urllib.request.Request(self.url + path,
                                     data=json.dumps(data).encode() if data is not None else None,
                                     headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode() or '{}')
            except ValueError:
                return e.code, {'error': str(e)}
        except Exception as e:
            return 0, {'error': 'controller unreachable: %s' % e}

    def cached(self, path, ttl=1.0):
        hit = self.cache.get(path)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        code, body = self.call(path, timeout=0.8)
        val = body if code == 200 else None
        self.cache[path] = (time.time(), val)
        return val


class App:
    def __init__(self, args, hosts):
        self.args = args
        self.hosts = hosts            # name -> {"ip", "role", "run": callable(spec) -> dict}
        self.watch = PolicyWatch(args.policy)
        self.analytics = Analytics(args.events, self.watch)
        self.ctl = Controller(args.controller)
        self.policy_lock = threading.Lock()
        # Traffic Lab mix: one request from every scenario in turn (round robin), so any
        # number of requests always covers all scenarios.
        self.mix = []
        longest = max(len(s['requests']) for s in traffic.SCENARIOS)
        for i in range(longest):
            for s in traffic.SCENARIOS:
                if i < len(s['requests']):
                    self.mix.append((s, s['requests'][i]))

    # ------------------------------------------------------------- policy
    def read_policy(self):
        with open(self.args.policy) as f:
            return json.load(f)

    def write_policy(self, policy):
        errors = rules.validate_policy(policy)
        if errors:
            return False, errors
        with self.policy_lock:
            tmp = self.args.policy + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(policy, f, indent=2)
                f.write('\n')
            os.replace(tmp, self.args.policy)
        return True, []

    # ------------------------------------------------------------ traffic
    def run_traffic(self, data):
        src = data.get('from', 'h1')
        host = self.hosts.get(src)
        if not host:
            return {'error': 'unknown source host %s' % src}
        if 'probe' in data:
            spec = {'probe': data['probe']}
        else:
            if data.get('scenario'):
                sc = next((s for s in traffic.SCENARIOS if s['id'] == data['scenario']), None)
                if not sc:
                    return {'error': 'unknown scenario'}
                spec = {'requests': sc['requests'], 'repeat': sc.get('repeat', 1),
                        'concurrency': sc.get('concurrency', 1)}
            else:
                req = {k: data[k] for k in ('method', 'path', 'host', 'ua', 'body') if data.get(k)}
                spec = {'requests': [req], 'repeat': int(data.get('count', 1)),
                        'concurrency': int(data.get('concurrency', 1))}
            spec['target'] = self.args.proxy
            spec['timeout'] = 1.5
        res = host['run'](spec)
        res['from'] = src
        res['from_ip'] = host['ip']
        return res

    @staticmethod
    def outcome(r):
        if r.get('error'):
            return 'dropped' if r['error'] == 'timeout' else 'error'
        c = r.get('code', 0)
        if c in (403, 451):
            return 'blocked'
        if c == 429:
            return 'ratelimited'
        if c == 400:
            return 'bad'
        if c >= 500 or c == 0:
            return 'error'
        return 'allowed'

    def run_blast(self, data):
        """Send requests number offset .. offset+count-1 of the all-scenario mix."""
        offset = max(0, int(data.get('offset', 0)))
        count = max(1, min(int(data.get('count', 10)), 200))
        jobs = [self.mix[(offset + i) % len(self.mix)] for i in range(count)]
        first = next(iter(self.hosts))
        try:
            engine = rules.Engine(self.read_policy())
        except Exception:
            engine = None
        sim = {'h1': '10.0.0.1', 'h4': '10.0.0.4'}

        def expected(src, req):
            if engine is None:
                return None
            h = {'Host': req.get('host') or self.args.proxy}
            if req.get('ua'):
                h['User-Agent'] = req['ua']
            ip = self.hosts[src]['ip'] if src in self.hosts else sim.get(src, '')
            d = engine.evaluate(rules.build_request(req.get('method', 'GET'), (req.get('path') or '/').replace(' ', '%20'),
                                                    h, (req.get('body') or '').encode(), ip))
            return ('block' if d['action'] == 'deny' else 'allow'), d.get('rule_id')
        groups = {}
        for idx, (sc, req) in enumerate(jobs):
            src = sc.get('from') if sc.get('from') in self.hosts else first
            groups.setdefault(src, []).append((idx, sc, req))
        out = [None] * len(jobs)
        exps = []
        for sc, req in jobs:
            src = sc.get('from') if sc.get('from') in self.hosts else first
            try:
                exps.append(expected(src, req))
            except Exception:
                exps.append(None)
        sdn_ips = set()

        def worker(src, items):
            host = self.hosts[src]
            spec = {'requests': [req for _, _, req in items], 'repeat': 1, 'target': self.args.proxy,
                    'concurrency': min(10, len(items)), 'timeout': 1.5}
            try:
                res = host['run'](spec)
            except Exception as e:                       # one host failing must not kill the batch
                res = {'error': str(e)}
            got = res.get('results') or []
            for k, (idx, sc, req) in enumerate(items):
                r = got[k] if k < len(got) else {'method': req.get('method', 'GET'), 'path': req.get('path', '/'),
                                                 'host': req.get('host', ''), 'code': 0,
                                                 'error': res.get('error', 'no result')}
                r.update(scenario=sc['id'], scenario_name=sc['name'], icon=sc.get('icon'), src=src,
                         src_ip=host['ip'], n=offset + idx + 1)
                r['outcome'] = self.outcome(r)
                exp = exps[idx]
                r['expected'], r['expected_rule'] = exp if exp else (None, None)
                o = r['outcome']
                if r['expected'] is None:
                    r['correct'] = None
                elif o == 'dropped':                     # SDN switch dropped it: right if it was meant to be
                    r['correct'] = r['expected'] == 'block' or host['ip'] in sdn_ips   # blocked, or the host is cut off
                elif o in ('blocked', 'ratelimited', 'bad'):
                    r['correct'] = r['expected'] == 'block'
                elif o == 'allowed':
                    r['correct'] = r['expected'] == 'allow'
                else:
                    r['correct'] = False                 # 502 / connection error
                out[idx] = r
        threads = [threading.Thread(target=worker, args=g) for g in groups.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if any(r and r['outcome'] == 'dropped' for r in out):
            st = self.ctl.cached('/policy/status', ttl=0.5) or {}
            sdn_ips.update((st.get('blocked_ips') or {}).keys())
            for r in out:
                if r and r['outcome'] == 'dropped' and r['src_ip'] in sdn_ips:
                    r['correct'] = True
        return {'results': out}

    def info(self):
        return {'mode': self.args.mode, 'proxy': self.args.proxy, 'controller': self.args.controller,
                'hosts': [{'name': n, 'ip': h['ip'], 'role': h['role']} for n, h in self.hosts.items()],
                'probe_target': self.args.probe_target,
                'scenarios': [dict({k: s.get(k) for k in ('id', 'name', 'desc', 'icon', 'from')},
                                   n=len(s['requests'])) for s in traffic.SCENARIOS],
                'mix_size': len(self.mix)}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def _send(self, code, obj, ctype='application/json'):
            body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def _json(self):
            n = int(self.headers.get('Content-Length', 0) or 0)
            raw = self.rfile.read(n).decode('utf-8', 'ignore') if n else ''
            return json.loads(raw) if raw.strip() else {}

        def do_GET(self):
            path, _, query = self.path.partition('?')
            q = dict(x.split('=', 1) for x in query.split('&') if '=' in x)
            if path in ('/', '/index.html'):
                with open(UI_FILE, 'rb') as f:
                    return self._send(200, f.read(), 'text/html; charset=utf-8')
            if path == '/api/info':
                return self._send(200, app.info())
            if path == '/api/summary':
                s = app.analytics.summary()
                s['sdn'] = app.ctl.cached('/policy/status')
                s['sdn_stats'] = app.ctl.cached('/policy/stats')
                return self._send(200, s)
            if path == '/api/events':
                return self._send(200, app.analytics.since(int(q.get('after', 0) or 0)))
            if path == '/api/policy':
                try:
                    p = app.read_policy()
                except (OSError, ValueError) as e:
                    return self._send(500, {'error': str(e)})
                eng = rules.Engine(p)
                return self._send(200, {'policy': p, 'legacy': rules.legacy_rules(p),
                                        'errors': rules.validate_policy(p) + eng.errors})
            return self._send(404, {'error': 'not found'})

        def do_POST(self):
            try:
                data = self._json()
            except ValueError:
                return self._send(400, {'error': 'invalid JSON'})
            path = self.path.split('?')[0]
            try:
                if path == '/api/policy':
                    ok, errors = app.write_policy(data)
                    return self._send(200 if ok else 422, {'ok': ok, 'errors': errors})
                if path == '/api/test':
                    p = data.get('policy') or app.read_policy()
                    eng = rules.Engine(p)
                    hdr = {'Host': data.get('host') or 'site.local'}
                    if data.get('ua'):
                        hdr['User-Agent'] = data['ua']
                    req = rules.build_request(data.get('method', 'GET'), data.get('path', '/'), hdr,
                                              (data.get('body') or '').encode(), data.get('ip', '10.0.0.1'))
                    d = eng.evaluate(req)
                    d['normalised'] = {k: req[k] for k in ('method', 'host', 'dst_port', 'path', 'path_norm',
                                                           'query', 'encoded')}
                    return self._send(200, d)
                if path == '/api/send':
                    return self._send(200, app.run_traffic(data))
                if path == '/api/blast':
                    return self._send(200, app.run_blast(data))
                if path == '/api/reset':
                    app.analytics.clear()
                    return self._send(200, {'ok': True})
                if path.startswith('/api/sdn/'):
                    action = path.rsplit('/', 1)[1]
                    if action not in ('block', 'unblock', 'port_block', 'port_unblock'):
                        return self._send(404, {'error': 'unknown action'})
                    code, body = app.ctl.call('/policy/' + action, data, timeout=3)
                    app.ctl.cache.clear()
                    return self._send(200, dict(body, http=code))
            except Exception as e:                       # never kill the dashboard
                return self._send(500, {'error': '%s: %s' % (e.__class__.__name__, e)})
            return self._send(404, {'error': 'not found'})

        def log_message(self, fmt, *args):
            pass

    return Handler


def serve(args, hosts, block=True):
    app = App(args, hosts)
    server = ThreadingHTTPServer((args.listen, args.port), make_handler(app))
    server.daemon_threads = True
    print('*** Dashboard: http://localhost:%d   (mode: %s)' % (args.port, args.mode), flush=True)
    if block:
        server.serve_forever()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def local_runner(sim_ip=None):
    def run(spec):
        if sim_ip and 'probe' not in spec:
            spec = dict(spec, sim_ip=sim_ip)
        return traffic.run(spec)
    return run


def parser():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--listen', default='0.0.0.0')
    ap.add_argument('--events', default=os.path.join(HERE, 'events.jsonl'))
    ap.add_argument('--policy', default=os.path.join(HERE, 'policy.json'))
    ap.add_argument('--controller', default='http://127.0.0.1:8080')
    ap.add_argument('--proxy', default='10.0.0.2:8888', help='proxy address used by generated traffic')
    ap.add_argument('--probe-target', default='10.0.0.3')
    ap.add_argument('--standalone', action='store_true',
                    help='no Mininet: start backend + proxy on 127.0.0.1 and simulate client IPs')
    return ap


def main():
    args = parser().parse_args()
    if args.standalone:
        args.mode = 'standalone'
        args.proxy = '127.0.0.1:8888'
        args.probe_target = '127.0.0.1'
        env = dict(os.environ, PROXY_HOST='127.0.0.1', PROXY_PORT='8888', BACKEND_HOST='127.0.0.1',
                   BACKEND_PORT='8081', SIMULATE_CLIENTS='1', SDN_URL=args.controller + '/policy/block',
                   EVENTS_FILE=args.events, POLICY_FILE=args.policy,
                   LOG_FILE=os.path.join(HERE, 'proxy.log'))
        procs = [subprocess.Popen([sys.executable, os.path.join(HERE, 'service.py'), '8081'], cwd=HERE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
                 subprocess.Popen([sys.executable, os.path.join(HERE, 'proxy.py')], cwd=HERE, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        time.sleep(0.8)
        hosts = {'h1': {'ip': '10.0.0.1', 'role': 'normal client (simulated)', 'run': local_runner('10.0.0.1')},
                 'h4': {'ip': '10.0.0.4', 'role': 'attacker (simulated)', 'run': local_runner('10.0.0.4')}}
        try:
            serve(args, hosts)
        finally:
            for p in procs:
                p.terminate()
    else:
        # plain mode: dashboard on the Ubuntu PC next to topology.py; traffic leaves from this PC
        args.mode = 'root'
        hosts = {'pc': {'ip': '10.0.0.254', 'role': 'this PC (protected, never SDN-blocked)',
                        'run': local_runner()}}
        serve(args, hosts)


if __name__ == '__main__':
    main()
