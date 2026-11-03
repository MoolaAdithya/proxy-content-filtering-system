#!/usr/bin/env python3
"""OS-Ken SDN controller (OpenFlow 1.3) for Project 28.

Run:  osken-manager controller.py

Features
  * L2 learning switch.
  * Static rule: TCP destination port 9002 is dropped at the switch.
  * REST API (default 0.0.0.0:8080) used by the proxy and by the operator:
        POST /policy/block         {"ip": "10.0.0.4", "duration": 300, "reason": "..."}
        POST /policy/unblock       {"ip": "10.0.0.4"}
        POST /policy/port_block    {"port": 9002}                 all sources
        POST /policy/port_block    {"port": 22, "ip": "10.0.0.4"} only that source (precise)
        POST /policy/port_unblock  {"port": 9002}   (add "ip" to remove a per-source rule)
        GET  /policy/status        blocked IPs / ports + recent SDN actions
        GET  /policy/stats         packets & bytes dropped by every DROP rule (OpenFlow flow stats)
  * Flow statistics are polled from the switch every STATS_INTERVAL seconds so the
    dashboard can show how much traffic each drop rule really stopped.
  * Every decision is logged to controller.log.

Environment variables
  SDN_REST_HOST (0.0.0.0)   SDN_REST_PORT (8080)
  SDN_PROTECTED_IPS (10.0.0.254)   addresses that can never be blocked
  CONTROLLER_LOG (controller.log next to this file)
"""
import ipaddress
import json
import os
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                       DEAD_DISPATCHER, set_ev_cls)
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet, ether_types
from os_ken.ofproto import ofproto_v1_3

REST_HOST = os.environ.get('SDN_REST_HOST', '0.0.0.0')
REST_PORT = int(os.environ.get('SDN_REST_PORT', '8080'))
PROTECTED = set(os.environ.get('SDN_PROTECTED_IPS', '10.0.0.254').split(','))
LOG_FILE = os.environ.get(
    'CONTROLLER_LOG',
    os.path.join(os.path.dirname(os.path.abspath(__file__)), 'controller.log'))

STATIC_PORT = 9002
STATS_INTERVAL = float(os.environ.get('SDN_STATS_INTERVAL', '2'))
PRIO_LEARN = 10
PRIO_PORT_DROP = 100
PRIO_SCOPED_PORT_DROP = 150
PRIO_IP_DROP = 200


class _RestServer(HTTPServer):
    """HTTP server whose requests run in green threads (os-ken uses eventlet)."""
    daemon_threads = True
    allow_reuse_address = True

    def process_request(self, request, client_address):
        hub.spawn(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


class ProxySDNController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProxySDNController, self).__init__(*args, **kwargs)
        self.mac_table = {}
        self.datapaths = {}
        self.blocked_ips = {}      # ip -> {"reason", "since", "expires"}
        self.blocked_ports = {STATIC_PORT}
        self.scoped_ports = set()  # (ip, port): drop only this source -> port
        self.history = deque(maxlen=100)
        self.live_stats = {}       # (dpid, key) -> (packets, bytes) of rules present now
        self.archived_stats = {}   # key -> (packets, bytes) of rules that expired / were removed
        self.forwarded = (0, 0)
        self.stats_time = 0
        hub.spawn(self._start_rest)
        hub.spawn(self._poll_stats)

    # ------------------------------------------------------------ logging
    def log(self, line):
        stamp = time.strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open(LOG_FILE, 'a') as f:
                f.write('%s %s\n' % (stamp, line))
        except OSError:
            pass
        self.logger.info(line)

    def remember(self, action, **info):
        info.update(action=action, ts=time.time())
        self.history.appendleft(info)

    # --------------------------------------------------------- flow helpers
    def _ip_match(self, dp, ip):
        return dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)

    def _port_match(self, dp, port):
        return dp.ofproto_parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                          tcp_dst=port)

    def _scoped_match(self, dp, ip, port):
        return dp.ofproto_parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                          ipv4_src=ip, tcp_dst=port)

    def _add_drop(self, dp, match, priority, hard_timeout=0):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=[],
            hard_timeout=hard_timeout))

    def _del_drop(self, dp, match, priority):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, command=ofp.OFPFC_DELETE_STRICT, priority=priority,
            match=match, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

    def _prune_expired(self):
        now = time.time()
        for ip in [i for i, b in self.blocked_ips.items()
                   if b['expires'] and b['expires'] <= now]:
            del self.blocked_ips[ip]
            self.log('SDN_BLOCK_EXPIRED ip=%s' % ip)
            self.remember('expired', ip=ip)

    # ----------------------------------------------------- switch handling
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_ready(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        self.datapaths[dp.id] = dp

        # table-miss: send to controller (learning switch)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0,
                                      match=parser.OFPMatch(),
                                      instructions=inst))
        # static + dynamic drop rules (re-installed if the switch reconnects)
        for port in sorted(self.blocked_ports):
            self._add_drop(dp, self._port_match(dp, port), PRIO_PORT_DROP)
        for ip, port in sorted(self.scoped_ports):
            self._add_drop(dp, self._scoped_match(dp, ip, port), PRIO_SCOPED_PORT_DROP)
        self._prune_expired()
        now = time.time()
        for ip, b in self.blocked_ips.items():
            remaining = int(b['expires'] - now) if b['expires'] else 0
            self._add_drop(dp, self._ip_match(dp, ip), PRIO_IP_DROP,
                           hard_timeout=max(remaining, 1) if b['expires'] else 0)
        self.log('SWITCH_CONNECTED dpid=%s static_drop_tcp_port=%d'
                 % (dp.id, STATIC_PORT))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        if ev.state == DEAD_DISPATCHER and dp is not None and dp.id is not None:
            self.datapaths.pop(dp.id, None)
            self.log('SWITCH_DISCONNECTED dpid=%s' % dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        in_port = msg.match['in_port']
        table = self.mac_table.setdefault(dp.id, {})
        table[eth.src] = in_port
        out_port = table.get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src,
                                    eth_dst=eth.dst)
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=PRIO_LEARN,
                                          match=match, instructions=inst))

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions,
                                        data=data))

    # ------------------------------------------------------------ policy ops
    def block_ip(self, ip, duration, reason):
        ip = str(ipaddress.ip_address(ip))
        if ip in PROTECTED:
            return False, 'refusing to block protected address %s' % ip
        if not self.datapaths:
            return False, 'no switch connected'
        duration = int(duration or 0)
        now = time.time()
        self.blocked_ips[ip] = {'reason': reason, 'since': now,
                                'expires': now + duration if duration else 0}
        for dp in self.datapaths.values():
            self._add_drop(dp, self._ip_match(dp, ip), PRIO_IP_DROP,
                           hard_timeout=duration)
        self.log('SDN_BLOCK_INSTALLED ip=%s duration=%ss reason="%s"'
                 % (ip, duration or 'permanent', reason))
        self.remember('block_ip', ip=ip, duration=duration, reason=reason)
        return True, 'blocked %s' % ip

    def unblock_ip(self, ip):
        ip = str(ipaddress.ip_address(ip))
        self.blocked_ips.pop(ip, None)
        for dp in self.datapaths.values():
            self._del_drop(dp, self._ip_match(dp, ip), PRIO_IP_DROP)
        self.log('SDN_UNBLOCK ip=%s' % ip)
        self.remember('unblock_ip', ip=ip)
        return True, 'unblocked %s' % ip

    def block_port(self, port, ip=None):
        port = int(port)
        if not 0 < port < 65536:
            return False, 'invalid port'
        if ip:
            ip = str(ipaddress.ip_address(ip))
            if ip in PROTECTED:
                return False, 'refusing to block protected address %s' % ip
            self.scoped_ports.add((ip, port))
            for dp in self.datapaths.values():
                self._add_drop(dp, self._scoped_match(dp, ip, port), PRIO_SCOPED_PORT_DROP)
            self.log('SDN_PORT_BLOCK tcp_port=%d src=%s' % (port, ip))
            self.remember('block_port', port=port, ip=ip)
            return True, 'blocked tcp port %d for %s' % (port, ip)
        self.blocked_ports.add(port)
        for dp in self.datapaths.values():
            self._add_drop(dp, self._port_match(dp, port), PRIO_PORT_DROP)
        self.log('SDN_PORT_BLOCK tcp_port=%d' % port)
        self.remember('block_port', port=port)
        return True, 'blocked tcp port %d' % port

    def unblock_port(self, port, ip=None):
        port = int(port)
        if ip:
            ip = str(ipaddress.ip_address(ip))
            self.scoped_ports.discard((ip, port))
            for dp in self.datapaths.values():
                self._del_drop(dp, self._scoped_match(dp, ip, port), PRIO_SCOPED_PORT_DROP)
            self.log('SDN_PORT_UNBLOCK tcp_port=%d src=%s' % (port, ip))
            self.remember('unblock_port', port=port, ip=ip)
            return True, 'unblocked tcp port %d for %s' % (port, ip)
        self.blocked_ports.discard(port)
        for dp in self.datapaths.values():
            self._del_drop(dp, self._port_match(dp, port), PRIO_PORT_DROP)
        self.log('SDN_PORT_UNBLOCK tcp_port=%d' % port)
        self.remember('unblock_port', port=port)
        return True, 'unblocked tcp port %d' % port

    def status(self):
        self._prune_expired()
        now = time.time()
        return {
            'switches': sorted(self.datapaths),
            'blocked_ips': {ip: {'reason': b['reason'],
                                 'seconds_left': int(b['expires'] - now)
                                 if b['expires'] else None}
                            for ip, b in self.blocked_ips.items()},
            'blocked_tcp_ports': sorted(self.blocked_ports),
            'scoped_port_blocks': [{'ip': ip, 'port': port}
                                   for ip, port in sorted(self.scoped_ports)],
            'protected_ips': sorted(PROTECTED),
            'history': list(self.history)[:30],
        }

    # ------------------------------------------------------ flow statistics
    def _poll_stats(self):
        while True:
            for dp in list(self.datapaths.values()):
                try:
                    dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
                except Exception as e:      # switch went away between polls
                    self.logger.debug('stats request failed: %s', e)
            hub.sleep(STATS_INTERVAL)

    @staticmethod
    def _stat_key(st):
        m = st.match
        if st.priority == PRIO_IP_DROP:
            return ('ip', m.get('ipv4_src'), None)
        if st.priority == PRIO_SCOPED_PORT_DROP:
            return ('ip_port', m.get('ipv4_src'), m.get('tcp_dst'))
        if st.priority == PRIO_PORT_DROP:
            return ('port', None, m.get('tcp_dst'))
        return None

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        dpid = ev.msg.datapath.id
        seen, fwd_p, fwd_b = {}, 0, 0
        for st in ev.msg.body:
            key = self._stat_key(st)
            if key is None:
                if st.priority == PRIO_LEARN:
                    fwd_p += st.packet_count
                    fwd_b += st.byte_count
                continue
            seen[(dpid, key)] = (st.packet_count, st.byte_count)
        # rules that disappeared (expired/unblocked): keep their final counters
        for k in [k for k in self.live_stats if k[0] == dpid and k not in seen]:
            p, b = self.live_stats.pop(k)
            ap, ab = self.archived_stats.get(k[1], (0, 0))
            self.archived_stats[k[1]] = (ap + p, ab + b)
        self.live_stats.update(seen)
        self.forwarded = (fwd_p, fwd_b)
        self.stats_time = time.time()

    def stats(self):
        total = dict(self.archived_stats)
        active = set()
        for (dpid, key), (p, b) in self.live_stats.items():
            tp, tb = total.get(key, (0, 0))
            total[key] = (tp + p, tb + b)
            active.add(key)
        rows = [{'kind': k[0], 'ip': k[1], 'port': k[2], 'packets': p, 'bytes': b,
                 'active': k in active} for k, (p, b) in total.items()]
        rows.sort(key=lambda r: -r['packets'])
        return {'drops': rows,
                'dropped_packets': sum(r['packets'] for r in rows),
                'dropped_bytes': sum(r['bytes'] for r in rows),
                'forwarded_packets': self.forwarded[0],
                'forwarded_bytes': self.forwarded[1],
                'updated': self.stats_time}

    # -------------------------------------------------------------- REST API
    def _start_rest(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, obj):
                body = (json.dumps(obj) + '\n').encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get('Content-Length', 0) or 0)
                raw = self.rfile.read(n).decode('utf-8', 'ignore') if n else ''
                return json.loads(raw) if raw.strip() else {}

            def do_GET(self):
                if self.path.rstrip('/') == '/policy/status':
                    self._send(200, app.status())
                elif self.path.rstrip('/') == '/policy/stats':
                    self._send(200, app.stats())
                else:
                    self._send(404, {'error': 'not found'})

            def do_POST(self):
                try:
                    data = self._body()
                    route = self.path.rstrip('/')
                    if route == '/policy/block':
                        ok, msg = app.block_ip(data['ip'], data.get('duration', 0),
                                               data.get('reason', 'rest request'))
                    elif route == '/policy/unblock':
                        ok, msg = app.unblock_ip(data['ip'])
                    elif route == '/policy/port_block':
                        ok, msg = app.block_port(data['port'], data.get('ip'))
                    elif route == '/policy/port_unblock':
                        ok, msg = app.unblock_port(data['port'], data.get('ip'))
                    else:
                        return self._send(404, {'error': 'not found'})
                    self._send(200 if ok else 409, {'ok': ok, 'message': msg})
                except (KeyError, ValueError, TypeError) as e:
                    self._send(400, {'ok': False, 'error': 'bad request: %s' % e})

            def log_message(self, fmt, *args):
                pass

        try:
            server = _RestServer((REST_HOST, REST_PORT), Handler)
        except OSError as e:
            self.log('REST_SERVER_FAILED %s:%d error=%s' % (REST_HOST, REST_PORT, e))
            return
        self.log('CONTROLLER_STARTED rest=%s:%d' % (REST_HOST, REST_PORT))
        server.serve_forever()
