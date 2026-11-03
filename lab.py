#!/usr/bin/env python3
"""
One-command demo for Project 28: Mininet network + backend + proxy + web dashboard.

  Terminal 1:  osken-manager controller.py
  Terminal 2:  sudo mn -c && sudo python3 lab.py
  Browser:     http://localhost:5000

What it starts
  h3  service.py on :80 (backend) and :9002 (blocked by the static SDN rule)
  h2  proxy.py on :8888 with SDN blocking enabled, writing events.jsonl
  PC  dashboard.py on :5000. Traffic sent from the UI is generated INSIDE h1 or h4
      (python3 traffic.py run with that host's network namespace), so the proxy and the
      switch see the real 10.0.0.1 / 10.0.0.4 addresses.

The usual mininet> prompt stays available (e.g. "h4 curl 10.0.0.2:8888/malware").
Type "exit" to stop everything.
"""
import json
import os
import subprocess
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel, info

import dashboard
import topology

HERE = os.path.dirname(os.path.abspath(__file__))


def host_runner(host):
    """Run traffic.py inside a Mininet host and return its JSON result."""
    def run(spec):
        p = host.popen(['python3', os.path.join(HERE, 'traffic.py'), json.dumps(spec)],
                       cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = p.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            p.kill()
            return {'error': 'traffic generator timed out'}
        try:
            return json.loads(out.decode().strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {'error': 'traffic generator failed: %s' % err.decode(errors='ignore')[-300:]}
    return run


def main():
    setLogLevel('info')
    if os.geteuid() != 0:
        sys.exit('Run with sudo:  sudo python3 lab.py')
    args = dashboard.parser().parse_args()
    args.mode = 'lab'
    events = args.events

    net, root = topology.build_network()
    net.start()
    procs = []
    try:
        net.waitConnected(timeout=20)
        topology.sandbox_fixups(net)
        h1, h2, h3, h4 = (net.get(n) for n in ('h1', 'h2', 'h3', 'h4'))
        h2.cmd('ping -c1 -W1 %s' % topology.ROOT_IP)
        if not topology.rest_reachable(h2):
            info('*** WARNING: controller REST not reachable from h2 - is "osken-manager controller.py" running?\n')
        for port in (80, 9002):
            procs.append(h3.popen(['python3', os.path.join(HERE, 'service.py'), str(port)], cwd=HERE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.5)
        env = dict(os.environ, PROXY_HOST='0.0.0.0', SDN_ENABLED='1', EVENTS_FILE=events,
                   POLICY_FILE=args.policy, LOG_FILE=os.path.join(HERE, 'proxy.log'))
        procs.append(h2.popen(['python3', os.path.join(HERE, 'proxy.py')], cwd=HERE, env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        time.sleep(0.8)
        # warm up MAC learning so the first UI request is not slowed down
        net.ping([h1, h2, h3, h4], timeout=1)
        hosts = {'h1': {'ip': '10.0.0.1', 'role': 'normal client', 'run': host_runner(h1)},
                 'h4': {'ip': '10.0.0.4', 'role': 'attacker', 'run': host_runner(h4)}}
        dashboard.serve(args, hosts, block=False)
        info('*** Lab ready.  Open http://localhost:%d   (type "exit" here to stop)\n' % args.port)
        CLI(net)
    finally:
        for p in procs:
            p.terminate()
        net.stop()
        topology.cleanup_root_link()


if __name__ == '__main__':
    main()
