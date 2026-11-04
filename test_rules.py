#!/usr/bin/env python3
"""Unit tests for the rule engine (no Mininet, no root needed).

    python3 test_rules.py

Shows the precision gain over the old substring filter:
  * encoded / upper-case evasions are now caught
  * innocent URLs that merely CONTAIN a banned word are no longer blocked
  * every block names the exact rule and condition
"""
import json
import os
import sys

import rules

HERE = os.path.dirname(os.path.abspath(__file__))
POLICY = json.load(open(os.path.join(HERE, 'policy.json')))
ENGINE = rules.Engine(POLICY)


def check(method, target, expect, rule=None, ip='10.0.0.1', headers=None, body=b''):
    h = {'Host': '10.0.0.2:8888'}
    h.update(headers or {})
    req = rules.build_request(method, target, h, body, ip, 40000)
    d = ENGINE.evaluate(req)
    got = 'allow' if d['action'] in ('allow', 'monitor') else 'deny'
    ok = got == expect and (rule is None or d['rule_id'] == rule)
    print('%s  %-6s %-48s %-8s -> %-5s %-4s %s' % ('PASS' if ok else 'FAIL', method, target[:48], ip, got,
                                                 d['rule_id'] or '-', '; '.join(d['why'])))
    return ok


CASES = [
    # (method, target, expected, rule, ip, headers, body)
    ('GET', '/', 'allow', None, '10.0.0.1', None, b''),
    ('GET', '/news', 'allow', None, '10.0.0.4', None, b''),
    ('GET', '/health', 'allow', 'R01', '10.0.0.4', None, b''),
    ('DELETE', '/', 'deny', 'R02', '10.0.0.1', None, b''),
    # keywords: whole words, decoding, case
    ('GET', '/malware', 'deny', 'R09', '10.0.0.1', None, b''),
    ('GET', '/%6Dalware', 'deny', 'R09', '10.0.0.1', None, b''),
    ('GET', '/MAL%2557ARE', 'deny', 'R09', '10.0.0.1', None, b''),
    ('GET', '/blog/anti-malware-tips', 'deny', 'R09', '10.0.0.1', None, b''),
    ('GET', '/products/malwarebytes', 'allow', None, '10.0.0.1', None, b''),
    ('GET', '/travel/forbiddencity', 'allow', None, '10.0.0.1', None, b''),
    ('GET', '/forbidden', 'deny', 'R11', '10.0.0.1', None, b''),
    # file types
    ('GET', '/downloads/setup.exe', 'deny', 'R08', '10.0.0.1', None, b''),
    ('GET', '/docs/exe-format.html', 'allow', None, '10.0.0.1', None, b''),
    # hosts: exact vs subdomains
    ('GET', '/', 'deny', 'R10', '10.0.0.1', {'Host': 'blocked.example'}, b''),
    ('GET', '/', 'deny', 'R10', '10.0.0.1', {'Host': 'www.blocked.example'}, b''),
    ('GET', '/', 'allow', None, '10.0.0.1', {'Host': 'notblocked.example'}, b''),
    ('GET', 'http://m.facebook.com/feed', 'deny', 'R10', '10.0.0.1', None, b''),
    # attacks
    ('GET', "/item?id=1' OR '1'='1", 'deny', 'R03', '10.0.0.4', None, b''),
    ('GET', '/search?q=1%20UNION%20SELECT%20password', 'deny', 'R03', '10.0.0.4', None, b''),
    ('GET', '/%2e%2e/%2e%2e/etc/passwd', 'deny', 'R04', '10.0.0.4', None, b''),
    ('GET', '/q?x=<script>alert(1)</script>', 'deny', 'R05', '10.0.0.4', None, b''),
    ('GET', '/', 'deny', 'R06', '10.0.0.4', {'User-Agent': 'sqlmap/1.7'}, b''),
    # who may reach /admin
    ('GET', '/admin/users', 'allow', None, '10.0.0.1', None, b''),
    ('GET', '/admin/users', 'deny', 'R07', '10.0.0.4', None, b''),
    ('GET', '//%41DMIN/users', 'deny', 'R07', '10.0.0.4', None, b''),
    # destination port from Host header
    ('GET', '/', 'deny', 'R12', '10.0.0.1', {'Host': '10.0.0.3:22'}, b''),
    ('GET', '/', 'deny', 'R12', '10.0.0.1', {'Host': 'db.local:3306'}, b''),
    ('GET', '/', 'allow', None, '10.0.0.1', {'Host': '10.0.0.3:8080'}, b''),
    # body inspection
    ('POST', '/checkout', 'deny', 'R13', '10.0.0.1', None, b'card=4111 1111 1111 1111'),
    ('POST', '/checkout', 'allow', None, '10.0.0.1', None, b'item=42&qty=1'),
    ('POST', '/login', 'allow', 'R15', '10.0.0.1', None, b'user=a'),
]


def main():
    print('Rule engine: %d active rules, errors=%s\n' % (len(ENGINE.rules), ENGINE.errors or 'none'))
    results = [check(m, t, e, r, ip, h, b) for (m, t, e, r, ip, h, b) in CASES]

    # legacy keys still work (run_tests.py adds them at runtime)
    legacy = rules.Engine(dict(POLICY, denied_clients=['10.0.0.1'], banned_keywords=['news']))
    for ip, path, want in (('10.0.0.1', '/', 'deny'), ('10.0.0.4', '/', 'allow'), ('10.0.0.4', '/news', 'deny')):
        d = legacy.evaluate(rules.build_request('GET', path, {'Host': 'x'}, b'', ip))
        ok = (d['action'] == 'deny') == (want == 'deny')
        print('%s  legacy  %-6s %-8s -> %s %s' % ('PASS' if ok else 'FAIL', path, ip, d['action'], d['rule_id']))
        results.append(ok)

    # rate limit
    rl = rules.Engine({'rules': [{'id': 'RL', 'action': 'deny', 'match': {'rate_limit': {'requests': 5, 'seconds': 10}}}]})
    seq = [rl.evaluate(rules.build_request('GET', '/', {}, b'', '10.9.9.9'))['action'] for _ in range(7)]
    ok = seq == ['allow'] * 5 + ['deny'] * 2
    print('%s  rate limit 5/10s -> %s' % ('PASS' if ok else 'FAIL', seq))
    results.append(ok)

    bad = rules.validate_policy({'rules': [{'id': 'X', 'match': {'path_regex': '('}},
                                           {'id': 'Y', 'match': {'src_ip': ['10.0.0.300']}},
                                           {'id': 'Z', 'match': {'colour': 'red'}}]})
    ok = len(bad) == 3
    print('%s  validation catches bad regex / bad IP / unknown key: %s' % ('PASS' if ok else 'FAIL', bad))
    results.append(ok)

    print('\n%d / %d rule tests passed.' % (sum(results), len(results)))
    sys.exit(0 if all(results) else 1)


if __name__ == '__main__':
    main()
