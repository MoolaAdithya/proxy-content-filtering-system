#!/usr/bin/env python3
"""Integration tests for Project 28 (25 checks).

Needs: the controller running (osken-manager controller.py) and root rights.
  sudo mn -c
  sudo python3 run_tests.py

Evidence is written to results/: test_results.txt, proxy_test.log, flows_static.txt,
flows_after_block.txt.
"""
import json
import os
import re
import shutil
import sys
import time

import harness as H

RES = H.RESULTS
LOG = os.path.join(RES, 'proxy_test.log')
TEST_POLICY = os.path.join(RES, 'test_policy.json')
ORIGINAL_POLICY = os.path.join(H.HERE, 'policy.json')

results = []          # (id, text, ok, detail)


def record(tid, text, ok, detail=''):
    results.append((tid, text, ok, detail))
    line = '%s %s %s' % (tid, text, 'PASS' if ok else 'FAIL')
    print(line + ('' if ok or not detail else '\n      -> ' + detail), flush=True)


def set_policy(**changes):
    with open(ORIGINAL_POLICY) as f:
        policy = json.load(f)
    policy.update(changes)
    with open(TEST_POLICY, 'w') as f:
        json.dump(policy, f, indent=2)
    time.sleep(0.3)          # let the file mtime move on; the proxy reloads on the next request


def status_of(out):
    """First line of client output, e.g. 'HTTP/1.1 403 Forbidden  (1.2 ms)'."""
    return out.splitlines()[0] if out else ''


def has(out, code):
    return (' %s ' % code) in status_of(out)


def main():
    H.require_root()
    H.require_controller()
    os.makedirs(RES, exist_ok=True)
    H.reset_controller_state()
    for f in (LOG,):
        if os.path.exists(f):
            os.remove(f)
    set_policy()

    lab = H.Lab()
    try:
        lab.start()
        h = lab.h
        # ------------------------------------------------ network + static SDN
        loss = lab.net.ping([h['h1'], h['h2'], h['h3'], h['h4']], timeout=3)
        record('T01', 'pingall: %d%% packet loss (L2 learning switch)' % loss, loss == 0)

        record('T02', 'proxy host h2 can reach controller REST IP 10.0.0.254:8080',
               lab.rest_ok_from_h2)

        lab.start_service(80)
        lab.start_service(9002)
        out = lab.client('h1', H.BACKEND_ADDR)
        record('T03', 'h1 reaches backend h3:80 directly (200)',
               has(out, 200) and 'hello from backend' in out, out)

        out = lab.client('h1', '10.0.0.3:9002')
        record('T04', 'static SDN rule: h1 -> h3:9002 times out (TCP 9002 dropped)',
               out.startswith('ERROR') and 'timed out' in out, out)

        flows = H.dump_flows()
        open(os.path.join(RES, 'flows_static.txt'), 'w').write(flows)
        m = re.search(r'tp_dst=9002.*?actions=drop', flows)
        pkts = 0
        for line in flows.splitlines():
            if 'tp_dst=9002' in line and 'drop' in line:
                n = re.search(r'n_packets=(\d+)', line)
                pkts = int(n.group(1)) if n else 0
        record('T05', 'flow table has tp_dst=9002 actions=drop with n_packets=%d > 0' % pkts,
               bool(m) and pkts > 0, flows)

        out = lab.client('h3', '127.0.0.1:9002')
        record('T06', 'service on 9002 is alive locally (the timeout is caused by the switch)',
               has(out, 200), out)

        # ----------------------------------------- proxy filtering (SDN disabled)
        lab.start_proxy(False, LOG, TEST_POLICY)
        out = lab.client('h1', H.PROXY_ADDR)
        record('T07', 'proxy permits a normal request (200 + backend body)',
               has(out, 200) and 'hello from backend' in out, out)

        out = lab.client('h1', H.PROXY_ADDR, '/forbidden')
        record('T08', 'banned keyword /forbidden -> 403', has(out, 403), out)

        out = lab.client('h1', H.PROXY_ADDR, '/malware')
        record('T09', 'banned keyword /malware -> 403', has(out, 403), out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--method', 'DELETE')
        record('T10', 'method DELETE not allowed -> 403', has(out, 403), out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--host', 'blocked.example')
        record('T11', 'blocked host blocked.example -> 403', has(out, 403), out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--host', 'www.blocked.example')
        record('T12', 'subdomain of a blocked host -> 403', has(out, 403), out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--raw', '"garbage"')
        record('T13', 'malformed request -> 400 Bad Request', has(out, 400), out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--count', '30')
        record('T14', '30 concurrent clients all get 200',
               '30 x HTTP/1.0 200 OK' in out, out)

        out = lab.client('h1', H.PROXY_ADDR, '/', '--method', 'POST')
        record('T15', 'allowed method POST -> 200', has(out, 200), out)

        before = H.count_log(LOG, 'POLICY_RELOADED')
        pre = lab.client('h1', H.PROXY_ADDR, '/news')
        set_policy(banned_keywords=['forbidden', 'malware', 'socialmedia', 'news'])
        out = lab.client('h1', H.PROXY_ADDR, '/news')
        reloaded = H.count_log(LOG, 'POLICY_RELOADED') > before
        record('T16', 'policy edited at runtime: /news 200 -> 403, no restart, POLICY_RELOADED logged',
               has(pre, 200) and has(out, 403) and reloaded and lab.proxy_alive(),
               'before=%s after=%s reloaded=%s' % (status_of(pre), status_of(out), reloaded))

        set_policy(denied_clients=['10.0.0.1'])
        out1 = lab.client('h1', H.PROXY_ADDR)
        out4 = lab.client('h4', H.PROXY_ADDR)
        record('T17', 'denied_clients: h1 -> 403 while h4 -> 200',
               has(out1, 403) and has(out4, 200), '%s | %s' % (status_of(out1), status_of(out4)))
        set_policy()

        lab.stop_proc('svc80')
        time.sleep(0.5)
        out = lab.client('h1', H.PROXY_ADDR)
        record('T18', 'backend down -> 502 Bad Gateway and proxy keeps running',
               has(out, 502) and lab.proxy_alive(), out)

        lab.start_service(80)
        out = lab.client('h1', H.PROXY_ADDR)
        record('T19', 'backend back up -> proxy serves 200 again', has(out, 200), out)

        text = H.read_from(LOG)
        ok = all(s in text for s in ('PERMITTED', 'BLOCKED', 'proxy_ms=', 'overhead_ms='))
        record('T20', 'proxy.log has PERMITTED/BLOCKED lines with proxy_ms and overhead_ms', ok)

        # ------------------------------------- proxy + SDN dynamic blocking
        set_policy()
        lab.start_proxy(True, LOG, TEST_POLICY)
        H.rest('/policy/unblock', {'ip': '10.0.0.4'})
        ctl_start = H.file_size(H.CONTROLLER_LOG)
        proxy_start = H.file_size(LOG)

        o1 = lab.client('h4', H.PROXY_ADDR, '/', '--method', 'DELETE')
        o2 = lab.client('h4', H.PROXY_ADDR, '/', '--host', 'blocked.example')
        time.sleep(0.5)
        o3 = lab.client('h4', H.PROXY_ADDR)
        _, st = H.rest('/policy/status')
        record('T21', 'two violations are only strikes: h4 still gets 200 (not blocked yet)',
               has(o1, 403) and has(o2, 403) and has(o3, 200)
               and '10.0.0.4' not in st.get('blocked_ips', {}),
               '%s | %s | %s' % (status_of(o1), status_of(o2), status_of(o3)))

        o4 = lab.client('h4', H.PROXY_ADDR, '/malware')
        installed = H.wait_for_text(H.CONTROLLER_LOG, 'SDN_BLOCK_INSTALLED ip=10.0.0.4', 6, ctl_start)
        requested = H.wait_for_text(LOG, 'SDN_BLOCK_REQUESTED ip=10.0.0.4', 3, proxy_start)
        flows = H.dump_flows()
        open(os.path.join(RES, 'flows_after_block.txt'), 'w').write(flows)
        has_flow = any('nw_src=10.0.0.4' in l and 'drop' in l for l in flows.splitlines())
        record('T22', '3rd violation -> 403, SDN_BLOCK_REQUESTED/INSTALLED logged, nw_src=10.0.0.4 actions=drop',
               has(o4, 403) and installed and requested and has_flow,
               'installed=%s requested=%s flow=%s' % (installed, requested, has_flow))

        out = lab.client('h4', H.PROXY_ADDR)
        record('T23', 'blocked attacker h4 times out even for a normal page (dropped at the switch)',
               out.startswith('ERROR') and 'timed out' in out, out)

        out = lab.client('h1', H.PROXY_ADDR)
        record('T24', 'other client h1 is unaffected (200)', has(out, 200), out)

        code, _ = H.rest('/policy/unblock', {'ip': '10.0.0.4'})
        time.sleep(0.5)
        out_h4 = lab.client('h4', H.PROXY_ADDR)
        H.rest('/policy/port_unblock', {'port': 9002})
        time.sleep(0.5)
        out_open = lab.client('h1', '10.0.0.3:9002')
        H.rest('/policy/port_block', {'port': 9002})
        time.sleep(0.5)
        out_shut = lab.client('h1', '10.0.0.3:9002')
        record('T25', 'REST unblock restores h4; port_unblock/port_block toggles TCP 9002',
               code == 200 and has(out_h4, 200) and has(out_open, 200)
               and out_shut.startswith('ERROR') and 'timed out' in out_shut,
               '%s | %s | %s' % (status_of(out_h4), status_of(out_open), out_shut))
    finally:
        try:
            lab.stop()
        except Exception as e:                   # keep going: results are more important
            print('cleanup warning: %s' % e)
        H.reset_controller_state()

    passed = sum(1 for r in results if r[2])
    with open(os.path.join(RES, 'test_results.txt'), 'w') as f:
        for tid, text, ok, detail in results:
            f.write('%s %s %s\n' % (tid, text, 'PASS' if ok else 'FAIL'))
        f.write('\n%d / %d tests passed.\n' % (passed, 25))
    print('\n%d / 25 tests passed. Evidence saved in results/' % passed)
    sys.exit(0 if passed == 25 else 1)


if __name__ == '__main__':
    main()
