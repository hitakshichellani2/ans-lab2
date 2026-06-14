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


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)

        self.k        = 4
        self.topo_net = topo.Fattree(self.k)

        self.datapaths   = {}
        self.sw_port_map = {}
        self.sw_ports    = {}
        self.host_port   = {}
        self.arp_table   = {}
        self._flows_installed = False

        self.dpid_to_ip = {}
        self.ip_to_dpid = {}
        for idx, sw_node in enumerate(self.topo_net.switches):
            dpid = idx   # 0-based: s0->0, s1->1, ...
            self.dpid_to_ip[dpid] = sw_node.id
            self.ip_to_dpid[sw_node.id] = dpid

    # ------------------------------------------------------------------ #
    # Topology discovery                                                   #
    # ------------------------------------------------------------------ #
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
        self._flows_installed = False

    # ------------------------------------------------------------------ #
    # Switch handshake                                                     #
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    # Flow installer                                                    #
    # ------------------------------------------------------------------ #
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
                       ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _is_host_port(self, dpid, port):
        return port not in self.sw_ports.get(dpid, set())

    def _switch_role(self, ip):
        
        a, b, c, d = (int(x) for x in ip.split('.'))
        k    = self.k
        half = k // 2
        if b == k:
            return ('core', c - 1, d - 1)
        elif c >= half:
            return ('aggregation', b, c - half)
        else:
            return ('edge', b, c)

    # ------------------------------------------------------------------ #
    # Install two-level routing                                          #
    # ------------------------------------------------------------------ #
    def _install_ft_routing(self):
        if self._flows_installed:
            return
        if not self.sw_port_map:
            return

        k    = self.k
        half = k // 2
        ft   = self.topo_net

        for dpid, datapath in self.datapaths.items():
            sw_ip = self.dpid_to_ip.get(dpid)
            if sw_ip is None:
                continue
            role   = self._switch_role(sw_ip)
            parser = datapath.ofproto_parser

            # ---------------------------------------------------------- #
            # CORE switches                                               #
            # ---------------------------------------------------------- #
            if role[0] == 'core':
                row, col = role[1], role[2]
                for pod in range(k):
                    asw      = ft.aggr_switches[pod][col]
                    asw_dpid = self.ip_to_dpid.get(asw.id)
                    if asw_dpid is None:
                        continue
                    port = self.sw_port_map.get((dpid, asw_dpid))
                    if port is None:
                        continue
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=(f"10.{pod}.0.0", "255.255.0.0"))
                    self.add_flow(datapath, 10, match,
                                  [parser.OFPActionOutput(port)])

            # ---------------------------------------------------------- #
            # AGGREGATION switches                                        #
            # ---------------------------------------------------------- #
            elif role[0] == 'aggregation':
                pod    = role[1]
                sw_idx = role[2]   

                for esw_idx, esw in enumerate(ft.edge_switches[pod]):
                    esw_dpid = self.ip_to_dpid.get(esw.id)
                    if esw_dpid is None:
                        continue
                    port = self.sw_port_map.get((dpid, esw_dpid))
                    if port is None:
                        continue
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=(f"10.{pod}.{esw_idx}.0", "255.255.255.0"))
                    self.add_flow(datapath, 20, match,
                                  [parser.OFPActionOutput(port)])

                for i in range(half):
                    host_byte = i + 2          
                    csw      = ft.core[i][sw_idx]
                    csw_dpid = self.ip_to_dpid.get(csw.id)
                    if csw_dpid is None:
                        continue
                    port = self.sw_port_map.get((dpid, csw_dpid))
                    if port is None:
                        continue
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=(f"0.0.0.{host_byte}", "0.0.0.255"))
                    self.add_flow(datapath, 10, match,
                                  [parser.OFPActionOutput(port)])

            # ---------------------------------------------------------- #
            # EDGE switches                                               #
            # ---------------------------------------------------------- #
            elif role[0] == 'edge':
                pod = role[1]

                for i, asw in enumerate(ft.aggr_switches[pod]):
                    host_byte = i + 2          
                    asw_dpid  = self.ip_to_dpid.get(asw.id)
                    if asw_dpid is None:
                        continue
                    port = self.sw_port_map.get((dpid, asw_dpid))
                    if port is None:
                        continue
                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=(f"0.0.0.{host_byte}", "0.0.0.255"))
                    self.add_flow(datapath, 10, match,
                                  [parser.OFPActionOutput(port)])

        self._flows_installed = True
        self.logger.info("Two-level FT routing installed.")

    # ------------------------------------------------------------------ #
    # /32 host entry on edge switch                                       #
    # ------------------------------------------------------------------ #
    def _install_host_entry(self, datapath, host_ip, port):
        parser  = datapath.ofproto_parser
        match   = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                  ipv4_dst=host_ip)
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(datapath, 30, match, actions)

    # ------------------------------------------------------------------ #
    # ARP proxy                                                            #
    # ------------------------------------------------------------------ #
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

    # ------------------------------------------------------------------ #
    # Packet-in handler                                                    #
    # ------------------------------------------------------------------ #
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

        # Install two-level routing on first packet if not yet done
        if not self._flows_installed:
            self._install_ft_routing()

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
                        self._install_host_entry(datapath, src_ip, in_port)
            self._handle_arp(datapath, in_port, pkt)
            return

        # ---- IPv4 -------------------------------------------------------
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Learn source host and install /32 return entry
        if self._is_host_port(dpid, in_port):
            if dpid not in self.host_port:
                self.host_port[dpid] = {}
            if src_ip not in self.host_port[dpid]:
                self.host_port[dpid][src_ip] = in_port
                self.arp_table[src_ip] = eth_pkt.src
                self._install_host_entry(datapath, src_ip, in_port)
        
        k    = self.k
        half = k // 2
        ft   = self.topo_net

        dst_parts     = list(map(int, dst_ip.split('.')))
        dst_pod       = dst_parts[1]
        dst_edge_idx  = dst_parts[2]
        dst_host_byte = dst_parts[3]

        sw_ip = self.dpid_to_ip.get(dpid, '')
        if not sw_ip:
            self._flood(datapath, pkt, in_port)
            return

        role     = self._switch_role(sw_ip)
        out_port = None

        if role[0] == 'edge':
            pod      = role[1]
            sw_idx   = role[2]
            if pod == dst_pod and sw_idx == dst_edge_idx:
                out_port = self.host_port.get(dpid, {}).get(dst_ip)
            else:
                aggr_idx = (dst_host_byte - 2) % half
                asw      = ft.aggr_switches[pod][aggr_idx]
                asw_dpid = self.ip_to_dpid.get(asw.id)
                out_port = self.sw_port_map.get((dpid, asw_dpid))

        elif role[0] == 'aggregation':
            pod    = role[1]
            sw_idx = role[2]
            if pod == dst_pod:
                esw      = ft.edge_switches[dst_pod][dst_edge_idx]
                esw_dpid = self.ip_to_dpid.get(esw.id)
                out_port = self.sw_port_map.get((dpid, esw_dpid))
            else:
                row      = (dst_host_byte - 2) % half
                csw      = ft.core[row][sw_idx]
                csw_dpid = self.ip_to_dpid.get(csw.id)
                out_port = self.sw_port_map.get((dpid, csw_dpid))

        elif role[0] == 'core':
            col      = role[2]
            asw      = ft.aggr_switches[dst_pod][col]
            asw_dpid = self.ip_to_dpid.get(asw.id)
            out_port = self.sw_port_map.get((dpid, asw_dpid))

        if out_port is None:
            self._flood(datapath, pkt, in_port)
            return

        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id if msg.buffer_id != ofproto.OFP_NO_BUFFER
                       else ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)