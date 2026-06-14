"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib.packet import ether_types

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import topo


class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        self.topo_net    = topo.Fattree(4)
        self.datapaths   = {}   # dpid -> datapath
        self.sw_port_map = {}   # (src_dpid, dst_dpid) -> out_port
        self.sw_ports    = {}   # dpid -> set of ports connected to other switches
        self.host_port   = {}   # dpid -> {ip -> port}
        self.arp_table   = {}   # ip -> mac

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switches = get_switch(self, None)
        links    = get_link(self, None)

        self.sw_port_map = {}
        self.sw_ports    = {}

        for link in links:
            src = link.src.dpid
            dst = link.dst.dpid
            self.sw_port_map[(src, dst)] = link.src.port_no
            self.sw_ports.setdefault(src, set()).add(link.src.port_no)

        self.logger.info("Topology updated: %d switches, %d links",
                         len(switches), len(links))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _dijkstra(self, src_dpid):
        INF  = float('inf')
        dist = {dpid: INF for dpid in self.datapaths}
        prev = {}
        dist[src_dpid] = 0
        unvisited = set(self.datapaths.keys())

        while unvisited:
            u = min(unvisited, key=lambda n: dist[n])
            if dist[u] == INF:
                break
            unvisited.remove(u)
            for (s, d) in self.sw_port_map:
                if s != u or d not in unvisited:
                    continue
                alt = dist[u] + 1
                if alt < dist[d]:
                    dist[d] = alt
                    prev[d] = u

        return dist, prev

    def _next_hop_port(self, src_dpid, dst_dpid):
        if src_dpid == dst_dpid:
            return None
        _, prev = self._dijkstra(src_dpid)
        node = dst_dpid
        while prev.get(node) != src_dpid:
            node = prev.get(node)
            if node is None:
                return None
        return self.sw_port_map.get((src_dpid, node))

    def _install_flows_for_host(self, host_ip, edge_dpid, edge_port):
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            if dpid == edge_dpid:
                out_port = edge_port
            else:
                out_port = self._next_hop_port(dpid, edge_dpid)
                if out_port is None:
                    continue
            match   = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                      ipv4_dst=host_ip)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions)

    def _is_host_port(self, dpid, port):
        return port not in self.sw_ports.get(dpid, set())

    def _handle_arp(self, datapath, in_port, pkt):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_mac = self.arp_table.get(arp_pkt.dst_ip)
            if target_mac:
                self._send_arp_reply(datapath, in_port,
                                     arp_pkt.src_mac, target_mac,
                                     arp_pkt.dst_ip, arp_pkt.src_ip)
            else:
                self._flood(datapath, pkt, in_port)

    def _send_arp_reply(self, datapath, port, dst_mac, src_mac, src_ip, dst_ip):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        e = ethernet.ethernet(dst=dst_mac, src=src_mac,
                              ethertype=ether_types.ETH_TYPE_ARP)
        a = arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=src_mac, src_ip=src_ip,
                    dst_mac=dst_mac, dst_ip=dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=p.data)
        datapath.send_msg(out)

    def _flood(self, datapath, pkt, in_port):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=pkt.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        dpid     = datapath.id
        in_port  = msg.match['in_port']
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        # ---- ARP -------------------------------------------------------
        if eth_pkt.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                src_ip = arp_pkt.src_ip
                if self._is_host_port(dpid, in_port):
                    if dpid not in self.host_port:
                        self.host_port[dpid] = {}
                    if src_ip not in self.host_port[dpid]:
                        self.host_port[dpid][src_ip] = in_port
                        self.arp_table[src_ip] = arp_pkt.src_mac
                        self.logger.info("Learned host %s on dpid=%s port=%s",
                                         src_ip, dpid, in_port)
                        self._install_flows_for_host(src_ip, dpid, in_port)
            self._handle_arp(datapath, in_port, pkt)
            return

        # ---- IPv4 -------------------------------------------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        if self._is_host_port(dpid, in_port):
            if dpid not in self.host_port:
                self.host_port[dpid] = {}
            if src_ip not in self.host_port[dpid]:
                self.host_port[dpid][src_ip] = in_port
                self.arp_table[src_ip] = eth_pkt.src
                self._install_flows_for_host(src_ip, dpid, in_port)

        dst_dpid = None
        dst_port = None
        for d, ip_port in self.host_port.items():
            if dst_ip in ip_port:
                dst_dpid = d
                dst_port = ip_port[dst_ip]
                break

        if dst_dpid is None:
            self._flood(datapath, pkt, in_port)
            return

        if dpid == dst_dpid:
            out_port = dst_port
        else:
            out_port = self._next_hop_port(dpid, dst_dpid)
            if out_port is None:
                return

        actions = [parser.OFPActionOutput(out_port)]
        match   = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                  ipv4_dst=dst_ip)
        self.add_flow(datapath, 10, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER
                       else ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)