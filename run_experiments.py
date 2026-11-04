#!/usr/bin/env python3
"""Performance experiments for Project 28.

  sudo mn -c
  sudo python3 run_experiments.py            # about 4 minutes
  sudo python3 run_experiments.py --quick    # about 2 minutes

Experiment 1 - proxy overhead: h1 -> h3 directly vs h1 -> proxy -> h3,
               link delay 0 / 5 ms, 1 / 10 / 50 concurrent clients.
Experiment 2 - attack flood from h4 (policy-violating requests), 20 / 100 req/s:
               proxy-only filtering (SDN off) vs proxy + SDN blocking.

Output in results/: overhead.csv, attack.csv, results.md, overhead.png, attack.png
"""
import argparse
import csv
import os
import subprocess
import time

import harness as H

RES = H.RESULTS
QUICK = False
DELAYS = (0, 5)


def netem_available():
    """Link delay needs the tc 'netem' qdisc; check it on a throw-away veth pair."""
    cmd = ('ip link add p28tmp0 type veth peer name p28tmp1 && '
           'tc qdisc add dev p28tmp0 root netem delay 1ms')
    ok = subprocess.run(cmd, shell=True, capture_output=True).returncode == 0
    subprocess.run('ip link del p28tmp0', shell=True, capture_output=True)
    return ok


def exp1_overhead():
    rows = []
    reqs = 8 if QUICK else 20
    log = os.path.join(RES, 'exp_overhead_proxy.log')
    for delay in DELAYS:
        print('Experiment 1: link delay %d ms' % delay, flush=True)
        lab = H.Lab(delay_ms=delay)
        try:
            lab.start()
            lab.start_service(80)
            if os.path.exists(log):
                os.remove(log)
            lab.start_proxy(False, log)
            lab.bench('h1', '--target', H.PROXY_ADDR, '--clients', 2, '--requests', 3)   # warm-up
            lab.bench('h1', '--target', H.BACKEND_ADDR, '--clients', 2, '--requests', 3)
            for clients in (1, 10, 50):
                for label, target in (('direct', H.BACKEND_ADDR), ('proxy', H.PROXY_ADDR)):
                    r = lab.bench('h1', '--target', target, '--clients', clients,
                                  '--requests', reqs, '--timeout', 10)
                    rows.append({'delay_ms': delay, 'clients': clients, 'mode': label,
                                 'requests': r['total'], 'errors': r['errors'],
                                 'avg_ms': r['avg_ms'], 'p95_ms': r['p95_ms'],
                                 'throughput_rps': r['throughput_rps']})
                    print('  delay=%dms clients=%-3d %-6s avg=%.1f ms p95=%.1f ms %.0f req/s errors=%d'
                          % (delay, clients, label, r['avg_ms'], r['p95_ms'],
                             r['throughput_rps'], r['errors']), flush=True)
        finally:
            lab.stop()
    with open(os.path.join(RES, 'overhead.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return rows


def exp2_attack():
    rows = []
    duration = 5 if QUICK else 10
    print('Experiment 2: attack flood', flush=True)
    lab = H.Lab()
    try:
        lab.start()
        lab.start_service(80)
        for rate in (20, 100):
            for sdn in (False, True):
                mode = 'proxy_sdn' if sdn else 'proxy_only'
                log = os.path.join(RES, 'exp_attack_%s_%d.log' % (mode, rate))
                if os.path.exists(log):
                    os.remove(log)
                H.rest('/policy/unblock', {'ip': '10.0.0.4'})
                time.sleep(1)
                lab.start_proxy(sdn, log)
                legit = lab.bench_async('h1', '--target', H.PROXY_ADDR, '--clients', 2,
                                        '--duration', duration + 1, '--timeout', 5)
                flood = lab.bench('h4', '--mode', 'flood', '--target', H.PROXY_ADDR,
                                  '--rate', rate, '--duration', duration, '--path', '/malware')
                lg = lab.finish_bench(legit)
                time.sleep(0.5)
                handled = H.count_log(log, 'client=10.0.0.4', 'BLOCKED')
                row = {'mode': mode, 'rate_rps': rate, 'attacker_sent': flood['sent'],
                       'attacker_403': flood['got_403'],
                       'attacker_dropped_by_switch': flood['dropped_or_timeout'],
                       'proxy_handled_attacker': handled,
                       'legit_ok': lg['ok'], 'legit_errors': lg['errors'],
                       'legit_avg_ms': lg['avg_ms'], 'legit_p95_ms': lg['p95_ms']}
                rows.append(row)
                print('  %-10s %3d req/s: sent=%d proxy_handled=%d dropped_by_switch=%d '
                      'legit_avg=%.1f ms legit_errors=%d'
                      % (mode, rate, row['attacker_sent'], handled,
                         row['attacker_dropped_by_switch'], row['legit_avg_ms'],
                         row['legit_errors']), flush=True)
                lab.stop_proc('proxy')
        H.rest('/policy/unblock', {'ip': '10.0.0.4'})
    finally:
        lab.stop()
    with open(os.path.join(RES, 'attack.csv'), 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return rows


def write_report(over, atk):
    def pick(delay, clients, mode):
        return next(r for r in over if r['delay_ms'] == delay and r['clients'] == clients
                    and r['mode'] == mode)

    lines = ['# Project 28 - performance results', '',
             '## Experiment 1: proxy overhead (h1 -> h3 directly vs h1 -> proxy -> h3)', '',
             '| link delay | clients | direct avg (ms) | proxy avg (ms) | overhead (ms) | direct p95 | proxy p95 | direct req/s | proxy req/s | errors |',
             '|---|---|---|---|---|---|---|---|---|---|']
    for delay in DELAYS:
        for clients in (1, 10, 50):
            d, p = pick(delay, clients, 'direct'), pick(delay, clients, 'proxy')
            lines.append('| %d ms | %d | %.1f | %.1f | %.1f | %.1f | %.1f | %.0f | %.0f | %d |'
                         % (delay, clients, d['avg_ms'], p['avg_ms'], p['avg_ms'] - d['avg_ms'],
                            d['p95_ms'], p['p95_ms'], d['throughput_rps'], p['throughput_rps'],
                            d['errors'] + p['errors']))
    if len(DELAYS) < 2:
        lines += ['', '_Note: the 5 ms link-delay runs were skipped because tc netem is not available on this machine._']
    lines += ['', '## Experiment 2: attack flood from h4 (policy-violating requests)', '',
              '| mode | attack rate | attack requests sent | handled by proxy | dropped by switch | legit client avg (ms) | legit p95 (ms) | legit errors |',
              '|---|---|---|---|---|---|---|---|']
    for r in atk:
        lines.append('| %s | %d/s | %d | %d | %d | %.1f | %.1f | %d |'
                     % (r['mode'], r['rate_rps'], r['attacker_sent'], r['proxy_handled_attacker'],
                        r['attacker_dropped_by_switch'], r['legit_avg_ms'], r['legit_p95_ms'],
                        r['legit_errors']))
    lines += ['', '## Reading the results', '',
              '* The proxy adds one extra TCP connection and an HTTP parse per request, so the overhead column '
              'is the cost of filtering; it grows with link delay because the request crosses the network twice.',
              '* With SDN blocking the proxy only sees the first 3 violating requests of the attacker; every '
              'later packet is dropped at the switch ("dropped by switch"), so the proxy does far less work '
              'and the legitimate client is not slowed down by the flood.',
              '* With proxy-only filtering every attack request still reaches the proxy and costs a TCP '
              'connection plus a 403 reply.', '']
    open(os.path.join(RES, 'results.md'), 'w').write('\n'.join(lines))


def draw_graphs(over, atk):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        print('matplotlib not installed - skipping graphs (sudo apt install -y python3-matplotlib)')
        return
    fig, axes = plt.subplots(1, len(DELAYS), figsize=(5 * len(DELAYS), 4), squeeze=False)
    for ax, delay in zip(axes[0], DELAYS):
        clients = [1, 10, 50]
        for mode, off in (('direct', -0.2), ('proxy', 0.2)):
            vals = [next(r['avg_ms'] for r in over if r['delay_ms'] == delay and
                         r['clients'] == c and r['mode'] == mode) for c in clients]
            ax.bar([i + off for i in range(3)], vals, 0.4, label=mode)
        ax.set_xticks(range(3))
        ax.set_xticklabels(clients)
        ax.set_xlabel('concurrent clients')
        ax.set_ylabel('average latency (ms)')
        ax.set_title('link delay %d ms' % delay)
        ax.legend()
    fig.suptitle('Experiment 1: proxy overhead')
    fig.tight_layout()
    fig.savefig(os.path.join(RES, 'overhead.png'), dpi=120)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    rates = sorted({r['rate_rps'] for r in atk})
    for mode, off in (('proxy_only', -0.2), ('proxy_sdn', 0.2)):
        axes[0].bar([i + off for i in range(len(rates))],
                    [next(r['proxy_handled_attacker'] for r in atk
                          if r['mode'] == mode and r['rate_rps'] == x) for x in rates],
                    0.4, label=mode)
        axes[1].bar([i + off for i in range(len(rates))],
                    [next(r['legit_avg_ms'] for r in atk
                          if r['mode'] == mode and r['rate_rps'] == x) for x in rates],
                    0.4, label=mode)
    for ax, title in zip(axes, ('attack requests handled by the proxy',
                                'legitimate client average latency (ms)')):
        ax.set_xticks(range(len(rates)))
        ax.set_xticklabels(['%d req/s' % x for x in rates])
        ax.set_title(title)
        ax.legend()
    fig.suptitle('Experiment 2: attack flood')
    fig.tight_layout()
    fig.savefig(os.path.join(RES, 'attack.png'), dpi=120)
    plt.close(fig)


def main():
    global QUICK
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true', help='shorter runs (about 2 minutes)')
    QUICK = ap.parse_args().quick
    global DELAYS
    H.require_root()
    H.require_controller()
    os.makedirs(RES, exist_ok=True)
    if not netem_available():
        DELAYS = (0,)
        print('WARNING: tc netem is not available in this kernel - skipping the 5 ms link-delay runs.\n'
              '         Fix:  sudo apt install -y linux-modules-extra-$(uname -r)  and run again.', flush=True)
    H.reset_controller_state()
    over = exp1_overhead()
    atk = exp2_attack()
    H.reset_controller_state()
    write_report(over, atk)
    draw_graphs(over, atk)
    print('\nDone. See results/results.md, overhead.csv, attack.csv, overhead.png, attack.png')


if __name__ == '__main__':
    main()
