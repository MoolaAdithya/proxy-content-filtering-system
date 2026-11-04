#!/usr/bin/env python3
"""Shared helpers for run_tests.py and run_experiments.py (Mininet + controller + proxy)."""
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, 'results')
REST = os.environ.get('SDN_REST', 'http://127.0.0.1:8080')
PROXY_ADDR = '10.0.0.2:8888'
BACKEND_ADDR = '10.0.0.3:80'
CONTROLLER_LOG = os.path.join(HERE, 'controller.log')
CLIENT = os.path.join(HERE, 'client.py')
BENCH = os.path.join(HERE, 'bench.py')
PROXY = os.path.join(HERE, 'proxy.py')
SERVICE = os.path.join(HERE, 'service.py')
HOSTS = {'h1': '10.0.0.1', 'h2': '10.0.0.2', 'h3': '10.0.0.3', 'h4': '10.0.0.4'}


def require_root():
    if os.geteuid() != 0:
        sys.exit('Run with sudo, e.g.:  sudo python3 %s' % os.path.basename(sys.argv[0]))


def rest(path, data=None, timeout=3):
    """Call the controller REST API from the Ubuntu PC. Returns (http_code, json_or_text)."""
    req = urllib.request.Request(REST + path,
                                 data=json.dumps(data).encode() if data is not None else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body, code = r.read().decode(), r.status
    except urllib.error.HTTPError as e:
        body, code = e.read().decode(), e.code
    try:
        return code, json.loads(body)
    except ValueError:
        return code, body


def require_controller():
    try:
        rest('/policy/status')
    except Exception:
        sys.exit('Controller REST API not reachable at %s.\n'
                 'Start it first in another terminal:  cd ~/project28 && osken-manager controller.py'
                 % REST)


def reset_controller_state():
    """Remove leftover blocks from earlier runs (keeps the static 9002 rule)."""
    for ip in HOSTS.values():
        rest('/policy/unblock', {'ip': ip})
    rest('/policy/port_block', {'port': 9002})


def dump_flows():
    return subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 's1'],
                          capture_output=True, text=True).stdout


def wait_for_text(path, text, timeout=5, start=0):
    """Wait until `text` appears in file `path` after byte offset `start`."""
    end = time.time() + timeout
    while time.time() < end:
        if text in read_from(path, start):
            return True
        time.sleep(0.2)
    return False


def read_from(path, start=0):
    try:
        with open(path, 'r', errors='ignore') as f:
            f.seek(start)
            return f.read()
    except OSError:
        return ''


def file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


class Lab:
    """One running Mininet network plus the helper processes started on it."""

    def __init__(self, delay_ms=0):
        self.delay_ms = delay_ms
        self.net = None
        self.procs = {}
        self.h = {}

    # ---------------------------------------------------------- network
    def start(self):
        from mininet.log import setLogLevel
        import topology
        setLogLevel('warning')
        self.net, self.root = topology.build_network(self.delay_ms)
        self.net.start()
        self.net.waitConnected(timeout=20)
        topology.sandbox_fixups(self.net)
        self.h = {n: self.net.get(n) for n in HOSTS}
        self.h['h2'].cmd('ping -c1 -W1 %s' % topology.ROOT_IP)
        self.rest_ok_from_h2 = topology.rest_reachable(self.h['h2'])
        end = time.time() + 15            # wait until the controller sees the switch
        while time.time() < end:
            code, st = rest('/policy/status')
            if isinstance(st, dict) and st.get('switches'):
                break
            time.sleep(0.5)

    def stop(self):
        for name in list(self.procs):
            self.stop_proc(name)
        if self.net:
            self.net.stop()
            self.net = None
            import topology
            topology.cleanup_root_link()

    # --------------------------------------------------------- processes
    def _spawn(self, name, host, args, env=None, outfile=None):
        out = open(outfile or os.devnull, 'w')
        proc = self.h[host].popen(args, stdout=out, stderr=subprocess.STDOUT,
                                  env=dict(os.environ, **(env or {})), cwd=HERE)
        self.procs[name] = (proc, out)
        return proc

    def stop_proc(self, name):
        item = self.procs.pop(name, None)
        if not item:
            return
        proc, out = item
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        out.close()

    def start_service(self, port):
        name = 'svc%d' % port
        self.stop_proc(name)
        self._spawn(name, 'h3', ['python3', SERVICE, str(port)],
                    outfile='/tmp/p28_%s.out' % name)
        time.sleep(0.8)

    def start_proxy(self, sdn, log_file, policy_file=None, extra_env=None):
        self.stop_proc('proxy')
        env = {'PROXY_HOST': '0.0.0.0', 'SDN_ENABLED': '1' if sdn else '0',
               'LOG_FILE': log_file}
        if policy_file:
            env['POLICY_FILE'] = policy_file
        env.update(extra_env or {})
        start = file_size(log_file)
        self._spawn('proxy', 'h2', ['python3', PROXY], env=env, outfile='/tmp/p28_proxy.out')
        if not wait_for_text(log_file, 'PROXY_STARTED', 6, start):
            raise RuntimeError('proxy did not start, see /tmp/p28_proxy.out')

    def proxy_alive(self):
        item = self.procs.get('proxy')
        return bool(item and item[0].poll() is None)

    # ------------------------------------------------------------ clients
    def client(self, host, target, path='/', *opts):
        """Run client.py on `host`; returns its text output."""
        cmd = 'python3 %s --proxy %s --timeout 3 %s %s' % (CLIENT, target, ' '.join(opts), path)
        return self.h[host].cmd(cmd).strip()

    def bench(self, host, *args):
        """Run bench.py on `host` and return its JSON result (dict)."""
        out = self.h[host].cmd('python3 %s %s' % (BENCH, ' '.join(str(a) for a in args)))
        return parse_json_line(out)

    def bench_async(self, host, *args):
        """Start bench.py in the background; call finish_bench(proc) to get its result."""
        return self.h[host].popen(['python3', BENCH] + [str(a) for a in args], cwd=HERE)

    @staticmethod
    def finish_bench(proc):
        out, _ = proc.communicate()
        return parse_json_line(out.decode(errors='ignore'))


def parse_json_line(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                return json.loads(line)
            except ValueError:
                pass
    raise RuntimeError('no JSON result in output: %r' % text[-300:])


def count_log(path, *needles):
    """Count lines of `path` that contain every string in needles."""
    n = 0
    for line in read_from(path).splitlines():
        if all(s in line for s in needles):
            n += 1
    return n
