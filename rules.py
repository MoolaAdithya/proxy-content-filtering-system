#!/usr/bin/env python3
"""
Precise rule engine for the Project 28 filtering proxy.

Why this exists
  The first version blocked a request when a banned word appeared *anywhere* in
  the URL (plain substring check). That is imprecise in both directions:
    * false positives  - "/products/malwarebytes" was blocked because it contains "malware"
    * false negatives  - "/%6Dalware" or "/MAL%57ARE" slipped through (URL-encoding tricks)
  It also could not say *who* (IP / subnet), *where* (destination port, exact host)
  or *what part* of the request (path, query, header, body) a rule is about.

How a policy is evaluated
  * policy["rules"] is an ordered list. The FIRST enabled rule whose conditions
    ALL match decides the request (like a firewall ACL). If no rule matches,
    policy["default_action"] is used ("allow" by default).
  * Inside one condition a list means OR, e.g. "method": ["PUT", "DELETE"].
  * Every decision carries an explanation: the rule id/name and the exact
    conditions that matched (e.g.  path ~ /\\.(exe|msi)$/ matched "setup.exe").

Rule format
  {
    "id": "R03", "name": "Executable downloads", "enabled": true,
    "action": "deny",            # deny | allow | monitor (allow, but log as suspicious)
    "category": "malware",       # free text used for the analytics charts
    "severity": "high",          # low | medium | high | critical -> strike weight 1/1/2/3
    "strike_weight": 2,          # optional, overrides the severity default
    "match": { ...conditions... }
  }

Conditions (all optional, all must hold)
  src_ip            ["10.0.0.4", "10.0.0.0/24"]   client address or subnet
  src_ip_not        ["10.0.0.1"]                  everyone EXCEPT these
  dst_port          [22, "8000-8999"]             port from the Host header / absolute URL
  method            ["DELETE", "PUT"]
  method_not        ["GET", "HEAD", "POST"]       anything not in this list (method whitelist)
  host              ["facebook.com", "*.facebook.com", ".example.org"]
                       exact | subdomains only | domain + all subdomains
  path_exact        ["/admin"]                    after decoding and resolving ../
  path_prefix       ["/admin/", "/internal"]      after decoding and resolving ../
  path_regex        "\\.(exe|msi|bat)$"            on the decoded path (../ kept)
  query_regex       "union\\s+select"             on the decoded query string
  url_regex         "..."                         on decoded path + "?" + query
  keywords          ["malware", "casino"]         WHOLE words in decoded host+path+query
  user_agent_regex  "sqlmap|nikto"
  header_regex      {"Referer": "evil\\.com"}
  body_regex        "\\b\\d{4}[ -]?\\d{4}[ -]?\\d{4}[ -]?\\d{4}\\b"
  body_larger_than  10000                         bytes
  content_type      ["application/x-msdownload"]  request Content-Type prefix
  hours             ["09:00-18:00"]               only during these local times
  rate_limit        {"requests": 20, "seconds": 10}  per client IP, sliding window

All regexes are case-insensitive.
"""
import ipaddress
import posixpath
import re
import threading
import time
from collections import deque
from urllib.parse import unquote_plus

ACTIONS = ('deny', 'allow', 'monitor')
SEVERITY_WEIGHT = {'low': 1, 'medium': 1, 'high': 2, 'critical': 3}
CONDITION_KEYS = (
    'src_ip', 'src_ip_not', 'dst_port', 'method', 'method_not', 'host',
    'path_exact', 'path_prefix', 'path_regex', 'query_regex', 'url_regex',
    'keywords', 'user_agent_regex', 'header_regex', 'body_regex',
    'body_larger_than', 'content_type', 'hours', 'rate_limit')

# ----------------------------------------------------------------- parsing


def decode(text, rounds=3):
    """URL-decode repeatedly (catches double encoding like %252e). Returns (decoded, was_encoded)."""
    out = text
    for _ in range(rounds):
        nxt = unquote_plus(out)
        if nxt == out:
            break
        out = nxt
    out = out.replace('\x00', '').replace('\\', '/')
    return out, out != text


def build_request(method, target, headers, body=b'', client_ip='', client_port=0):
    """Normalise one HTTP request into the dict the rules work on."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    raw_target = target
    host_hdr = headers.get('host', '')
    scheme_port = 80
    # absolute-form target used by forward proxies: GET http://host:port/path HTTP/1.1
    m = re.match(r'^(https?)://([^/?#]+)(.*)$', target, re.I)
    if m:
        scheme_port = 443 if m.group(1).lower() == 'https' else 80
        host_hdr = m.group(2)
        target = m.group(3) or '/'
    host, _, port = host_hdr.strip().lower().partition(':')
    try:
        dst_port = int(port) if port else scheme_port
    except ValueError:
        dst_port = scheme_port
    path_raw, _, query_raw = target.partition('?')
    path_dec, enc1 = decode(path_raw)
    query_dec, enc2 = decode(query_raw)
    path_dec = re.sub(r'/{2,}', '/', path_dec) or '/'
    path_norm = posixpath.normpath(path_dec) if path_dec.startswith('/') else '/' + path_dec
    if path_dec.endswith('/') and path_norm != '/':
        path_norm += '/'
    if path_norm.startswith('//'):
        path_norm = '/' + path_norm.lstrip('/')
    return {
        'client_ip': client_ip, 'client_port': client_port,
        'method': method.upper(), 'raw_target': raw_target,
        'host': host.rstrip('.'), 'dst_port': dst_port,
        'path': path_dec, 'path_norm': path_norm, 'query': query_dec,
        'encoded': enc1 or enc2,
        'headers': headers, 'body': body or b'',
        'user_agent': headers.get('user-agent', ''),
        'content_type': headers.get('content-type', ''),
    }


# --------------------------------------------------------------- compiling


def _rx(pattern):
    return re.compile(pattern, re.I)


def _ports(values):
    out = []
    for v in values:
        s = str(v).strip()
        if '-' in s:
            a, b = s.split('-', 1)
            a, b = int(a), int(b)
        else:
            a = b = int(s)
        if not (0 < a <= b < 65536):
            raise ValueError('bad port %r' % v)
        out.append((a, b))
    return out


def _hours(values):
    out = []
    for v in values:
        a, b = v.split('-')
        ha, ma = [int(x) for x in a.strip().split(':')]
        hb, mb = [int(x) for x in b.strip().split(':')]
        out.append((ha * 60 + ma, hb * 60 + mb, v))
    return out


def _as_list(v):
    return v if isinstance(v, list) else [v]


def compile_rule(rule):
    """Turn a rule dict into a list of (key, test_function). Raises ValueError on bad input."""
    m = rule.get('match') or {}
    unknown = set(m) - set(CONDITION_KEYS)
    if unknown:
        raise ValueError('unknown condition(s): %s' % ', '.join(sorted(unknown)))
    if rule.get('action', 'deny') not in ACTIONS:
        raise ValueError('action must be one of %s' % '/'.join(ACTIONS))
    tests = []

    def add(key, fn):
        tests.append((key, fn))

    if 'src_ip' in m:
        nets = [ipaddress.ip_network(x, strict=False) for x in _as_list(m['src_ip'])]

        def t(r, nets=nets):
            try:
                a = ipaddress.ip_address(r['client_ip'])
            except ValueError:
                return None
            for n in nets:
                if a in n:
                    return 'source %s in %s' % (a, n)
        add('src_ip', t)
    if 'src_ip_not' in m:
        nets = [ipaddress.ip_network(x, strict=False) for x in _as_list(m['src_ip_not'])]

        def t(r, nets=nets):
            try:
                a = ipaddress.ip_address(r['client_ip'])
            except ValueError:
                return 'source %s is not an IP' % r['client_ip']
            if not any(a in n for n in nets):
                return 'source %s not in [%s]' % (a, ', '.join(map(str, nets)))
        add('src_ip_not', t)
    if 'dst_port' in m:
        ranges = _ports(_as_list(m['dst_port']))

        def t(r, ranges=ranges):
            p = r['dst_port']
            for a, b in ranges:
                if a <= p <= b:
                    return 'destination port %d in %s' % (p, a if a == b else '%d-%d' % (a, b))
        add('dst_port', t)
    if 'method' in m:
        ms = {x.upper() for x in _as_list(m['method'])}
        add('method', lambda r, ms=ms: 'method %s' % r['method'] if r['method'] in ms else None)
    if 'method_not' in m:
        ms = {x.upper() for x in _as_list(m['method_not'])}
        add('method_not', lambda r, ms=ms: ('method %s not in allowed [%s]' % (r['method'], ', '.join(sorted(ms))))
            if r['method'] not in ms else None)
    if 'host' in m:
        pats = [h.lower().strip() for h in _as_list(m['host'])]

        def t(r, pats=pats):
            h = r['host']
            for p in pats:
                if p.startswith('*.'):
                    if h.endswith(p[1:]) and h != p[2:]:
                        return 'host %s is a subdomain of %s' % (h, p[2:])
                elif p.startswith('.'):
                    if h == p[1:] or h.endswith(p):
                        return 'host %s is %s or a subdomain' % (h, p[1:])
                elif h == p:
                    return 'host %s' % h
        add('host', t)
    if 'path_exact' in m:
        ps = [p.lower().rstrip('/') or '/' for p in _as_list(m['path_exact'])]
        add('path_exact', lambda r, ps=ps: 'path %s' % r['path_norm']
            if (r['path_norm'].lower().rstrip('/') or '/') in ps else None)
    if 'path_prefix' in m:
        ps = [p.lower() for p in _as_list(m['path_prefix'])]

        def t(r, ps=ps):
            low = r['path_norm'].lower()
            for p in ps:
                if low.startswith(p):
                    return 'path %s starts with %s' % (r['path_norm'], p)
        add('path_prefix', t)
    for key, field in (('path_regex', 'path'), ('query_regex', 'query'), ('user_agent_regex', 'user_agent')):
        if key in m:
            rx = _rx(m[key])

            def t(r, rx=rx, field=field, label=key.replace('_regex', '').replace('_', '-')):
                hit = rx.search(r[field])
                if hit:
                    return '%s ~ /%s/ matched "%s"' % (label, rx.pattern, hit.group(0)[:60])
            add(key, t)
    if 'url_regex' in m:
        rx = _rx(m['url_regex'])

        def t(r, rx=rx):
            url = r['path'] + ('?' + r['query'] if r['query'] else '')
            hit = rx.search(url)
            if hit:
                return 'url ~ /%s/ matched "%s"' % (rx.pattern, hit.group(0)[:60])
        add('url_regex', t)
    if 'keywords' in m:
        words = [w for w in _as_list(m['keywords']) if w]
        rx = _rx(r'(?<![a-z0-9])(%s)(?![a-z0-9])' % '|'.join(re.escape(w.lower()) for w in words)) if words else None

        def t(r, rx=rx):
            if rx is None:
                return None
            hay = '%s %s %s' % (r['host'], r['path'], r['query'])
            hit = rx.search(hay)
            if hit:
                return 'whole word "%s"%s' % (hit.group(1), ' (after URL-decoding)' if r['encoded'] else '')
        add('keywords', t)
    if 'header_regex' in m:
        hx = {k.lower(): _rx(v) for k, v in m['header_regex'].items()}

        def t(r, hx=hx):
            for k, rx in hx.items():
                hit = rx.search(r['headers'].get(k, ''))
                if not hit:
                    return None
            return 'header(s) %s matched' % ', '.join(hx)
        add('header_regex', t)
    if 'body_regex' in m:
        rx = _rx(m['body_regex'])

        def t(r, rx=rx):
            hit = rx.search(r['body'].decode('utf-8', 'ignore'))
            if hit:
                s = hit.group(0)
                return 'body ~ /%s/ matched "%s"' % (rx.pattern, (s[:4] + '…') if len(s) > 8 else s)
        add('body_regex', t)
    if 'body_larger_than' in m:
        lim = int(m['body_larger_than'])
        add('body_larger_than', lambda r, lim=lim: 'body %d bytes > %d' % (len(r['body']), lim)
            if len(r['body']) > lim else None)
    if 'content_type' in m:
        cts = [c.lower() for c in _as_list(m['content_type'])]
        add('content_type', lambda r, cts=cts: 'content-type %s' % r['content_type']
            if any(r['content_type'].lower().startswith(c) for c in cts) else None)
    if 'hours' in m:
        windows = _hours(_as_list(m['hours']))

        def t(r, windows=windows):
            lt = time.localtime()
            now = lt.tm_hour * 60 + lt.tm_min
            for a, b, label in windows:
                inside = a <= now < b if a <= b else (now >= a or now < b)
                if inside:
                    return 'time %02d:%02d inside %s' % (lt.tm_hour, lt.tm_min, label)
        add('hours', t)
    if 'rate_limit' in m:      # always evaluated last (it counts requests)
        n = int(m['rate_limit']['requests'])
        sec = float(m['rate_limit']['seconds'])
        rid = rule.get('id', '?')
        add('rate_limit', lambda r, n=n, sec=sec, rid=rid: _RATE.hit(rid, r['client_ip'], n, sec))
    if not tests:
        raise ValueError('rule has no conditions')
    return tests


class _RateTracker:
    """Sliding-window counters per (rule, client). Survives policy reloads."""

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = {}

    def hit(self, rule_id, ip, limit, seconds):
        now = time.time()
        with self.lock:
            q = self.hits.setdefault((rule_id, ip), deque())
            q.append(now)
            while q and now - q[0] > seconds:
                q.popleft()
            if len(q) > limit:
                return '%d requests in %ss > limit %d' % (len(q), int(seconds), limit)
        return None

    def reset(self):
        with self.lock:
            self.hits.clear()


_RATE = _RateTracker()


def legacy_rules(policy):
    """Old-style keys (banned_keywords, blocked_hosts, ...) become rules so old configs still work."""
    out = []
    if policy.get('denied_clients'):
        out.append({'id': 'L-CLIENTS', 'name': 'Denied clients (list)', 'category': 'denied-client',
                    'severity': 'medium', 'match': {'src_ip': policy['denied_clients']}})
    if policy.get('allowed_methods'):
        out.append({'id': 'L-METHODS', 'name': 'Method not allowed (list)', 'category': 'method',
                    'severity': 'low', 'match': {'method_not': policy['allowed_methods']}})
    if policy.get('blocked_hosts'):
        out.append({'id': 'L-HOSTS', 'name': 'Blocked hosts (list)', 'category': 'blocked-site',
                    'severity': 'low', 'match': {'host': ['.' + h.lstrip('.') for h in policy['blocked_hosts']]}})
    if policy.get('banned_keywords'):
        out.append({'id': 'L-KEYWORDS', 'name': 'Banned keywords (list)', 'category': 'keyword',
                    'severity': 'low', 'match': {'keywords': policy['banned_keywords']}})
    for r in out:
        r.update(enabled=True, action='deny', legacy=True)
    return out


def validate_policy(policy):
    """Return a list of human-readable problems (empty list = OK)."""
    errors = []
    if not isinstance(policy.get('rules', []), list):
        return ['"rules" must be a list']
    if policy.get('default_action', 'allow') not in ('allow', 'deny'):
        errors.append('default_action must be allow or deny')
    seen = set()
    for i, rule in enumerate(policy.get('rules', [])):
        rid = rule.get('id') or '#%d' % (i + 1)
        if rid in seen:
            errors.append('%s: duplicate id' % rid)
        seen.add(rid)
        try:
            compile_rule(rule)
        except (ValueError, TypeError, KeyError, re.error) as e:
            errors.append('%s: %s' % (rid, e))
    return errors


class Engine:
    """Compiled, ready-to-use policy."""

    def __init__(self, policy):
        self.policy = policy
        self.default = policy.get('default_action', 'allow')
        self.rules = []
        self.errors = []
        for rule in legacy_rules(policy) + list(policy.get('rules', [])):
            if not rule.get('enabled', True):
                continue
            try:
                self.rules.append((rule, compile_rule(rule)))
            except (ValueError, TypeError, KeyError, re.error) as e:
                self.errors.append('%s: %s (rule skipped)' % (rule.get('id', '?'), e))

    def evaluate(self, req):
        """Return a decision dict for a request built with build_request()."""
        for rule, tests in self.rules:
            why = []
            for key, fn in tests:
                res = fn(req)
                if not res:
                    break
                why.append(res)
            else:
                sev = rule.get('severity', 'medium')
                return {
                    'action': rule.get('action', 'deny'),
                    'rule_id': rule.get('id', '?'), 'rule_name': rule.get('name', ''),
                    'category': rule.get('category', 'other'), 'severity': sev,
                    'weight': int(rule.get('strike_weight', SEVERITY_WEIGHT.get(sev, 1))),
                    'status': int(rule.get('response_status', 403)),
                    'why': why,
                }
        return {'action': self.default, 'rule_id': None, 'rule_name': 'default policy',
                'category': 'default', 'severity': 'none', 'weight': 1 if self.default == 'deny' else 0,
                'status': 403 if self.default == 'deny' else 200, 'why': ['no rule matched']}
