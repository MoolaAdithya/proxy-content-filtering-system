#!/usr/bin/env python3
"""Mininet topology for Project 28.

    h1 10.0.0.1 (normal client) --+
    h4 10.0.0.4 (attacker) -------+-- s1 (OVS, OpenFlow 1.3) --+-- h2 10.0.0.2 (proxy :8888)
    root 10.0.0.254 (Ubuntu PC) --+                            +-- h3 10.0.0.3 (backend :80)

The remote controller (osken-manager controller.py) runs on the Ubuntu PC and
is reached by the switch at 127.0.0.1:6653.  The root namespace has the extra
address 10.0.0.254 on interface root-eth0 so that the proxy on h2 can reach the
controller's REST API at http://10.0.0.254:8080.

  sudo python3 topology.py        # interactive demo (mininet> prompt)
"""
import os
import sys

from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController

ROOT_IP = '10.0.0.254'
REST_URL = 'http://%s:8080/policy/status' % ROOT_IP


def cleanup_root_link():
    """Delete the veth pair that connects the Ubuntu PC to s1 (Mininet does not remove it)."""
    os.system('ip link del root-eth0 >/dev/null 2>&1')


def build_network(delay_ms=0, controller_ip='127.0.0.1', controller_port=6653):
    """Create (but do not start) the network. delay_ms is applied per host link."""
    cleanup_root_link()                       # leftover from a previous run/lab
    sw_opts = {'protocols': 'OpenFlow13'}
    if os.environ.get('MN_DATAPATH') == 'user':      # only for machines without the OVS kernel module
        sw_opts['datapath'] = 'user'
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink,
                  autoSetMacs=True, build=False)
    net.addController('c0', controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    s1 = net.addSwitch('s1', **sw_opts)
    link_opts = {'delay': '%sms' % delay_ms} if delay_ms else {}
    for i in range(1, 5):
        h = net.addHost('h%d' % i, ip='10.0.0.%d/24' % i)
        net.addLink(h, s1, **link_opts)
    # link between the switch and the Ubuntu PC (root namespace)
    root = Node('root', inNamespace=False)
    link = Link(root, s1)
    root.setIP(ROOT_IP + '/24', intf=link.intf1)
    net.build()
    return net, root


def sandbox_fixups(net):
    """Only for machines without the OVS kernel module (MN_DATAPATH=user): the userspace
    datapath needs checksum offload disabled on the host interfaces."""
    if os.environ.get('MN_DATAPATH') != 'user':
        return
    for h in net.hosts:
        for intf in h.intfNames():
            h.cmd('ethtool -K %s tx off rx off >/dev/null 2>&1' % intf)
    os.system('ethtool -K root-eth0 tx off rx off >/dev/null 2>&1')


def rest_reachable(h2, timeout=3):
    out = h2.cmd('curl -s -m %d -o /dev/null -w "%%{http_code}" %s' % (timeout, REST_URL))
    return out.strip().endswith('200')


def run():
    net, root = build_network()
    net.start()
    net.waitConnected(timeout=20)
    sandbox_fixups(net)
    h2 = net.get('h2')
    h2.cmd('ping -c1 -W1 %s' % ROOT_IP)       # let the switch learn the root port
    if rest_reachable(h2):
        info('*** h2 -> controller REST at %s: reachable\n' % ROOT_IP)
    else:
        info('*** h2 -> controller REST at %s: NOT reachable\n'
             '    (is "osken-manager controller.py" running? otherwise at mininet>: '
             'sh sudo ip addr add %s/24 dev root-eth0)\n' % (ROOT_IP, ROOT_IP))
    CLI(net)
    net.stop()
    cleanup_root_link()


if __name__ == '__main__':
    setLogLevel('info')
    if os.geteuid() != 0:
        sys.exit('Run with sudo:  sudo python3 topology.py')
    run()
