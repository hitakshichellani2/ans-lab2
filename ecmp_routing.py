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

# ryu-manager --ofp-tcp-listen-port 6653 ecmp_routing.py --observe-links

"""
ECMP (Equal-Cost Multi-Path) Routing for Fat-Tree Networks

Uses OpenFlow 1.3 SELECT group tables to hash on the 5-tuple
(src_ip, dst_ip, src_port, dst_port, protocol) and distribute
traffic across equal-cost next hops for per-flow load balancing.

Key difference from two-level routing:
- Two-level uses static suffix-based mapping (deterministic)
- ECMP uses 5-tuple hashing (per-flow, better distribution)
"""

from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet

from ryu.topology import event
from ryu.topology.api import get_switch, get_link

import topo


class ECMPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ECMPRouter, self).__init__(*args, **kwargs)

        # Initialize the topology with ports=4
        self.topo_net = topo.Fattree(4)
        self.topo_net.k = 4

        self.host_ports  = defaultdict(set)   # dpid -> {port numbers}
        self.edge_hosts  = defaultdict(set)   # dpid -> {IP strings}
        self.datapaths   = {}    # dpid  -> datapath object
        self.node_by_dpid = {}   # dpid -> topo.Node
        self.portmap      = {}   # (dpid, nbr_dpid) -> out_port
        self.group_id_counter = {}  # dpid -> next group_id

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        switches = get_switch(self, None)
        links = get_link(self, None)

        # Build dpid -> Node map
        self.node_by_dpid = {}
        for n in self.topo_net.switches:
            self.node_by_dpid[int(n.id[1:])] = n

        # Port adjacency
        self.portmap = {}
        for lnk in links:
            self.portmap[(lnk.src.dpid, lnk.dst.dpid)] = lnk.src.port_no
            self.portmap[(lnk.dst.dpid, lnk.src.dpid)] = lnk.dst.port_no

        # Program every switch
        for sw in switches:
            self._install_rules(sw.dp)

        self.logger.info("ECMP rules pushed (%d switches)", len(switches))

    def _safe_port(self, this_node, dst_node, dp):
        try:
            return self.portmap[(dp.id, int(dst_node.id[1:]))]
        except KeyError:
            for e in this_node.edges:
                nbr = e.rnode if e.lnode == this_node else e.lnode
                if nbr == dst_node:
                    return this_node.edges.index(e) + 1
            raise

    def _next_group_id(self, dpid):
        """Get next available group ID for a given switch."""
        if dpid not in self.group_id_counter:
            self.group_id_counter[dpid] = 1
        gid = self.group_id_counter[dpid]
        self.group_id_counter[dpid] += 1
        return gid

    def _install_ecmp_group(self, dp, group_id, out_ports):
        """
        Install a SELECT group with equal-weight buckets for each output port.
        OVS will hash on the packet header (5-tuple for TCP/UDP) to select a bucket.
        """
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        buckets = []
        for port in out_ports:
            actions = [parser.OFPActionOutput(port)]
            # Equal weight (50) for all buckets → equal distribution
            bucket = parser.OFPBucket(
                weight=50,
                watch_port=ofp.OFPP_ANY,
                watch_group=ofp.OFPG_ANY,
                actions=actions)
            buckets.append(bucket)

        # Create the SELECT group
        req = parser.OFPGroupMod(
            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id, buckets)
        dp.send_msg(req)
        self.logger.info("  ECMP group %d on s%d with ports %s",
                         group_id, dp.id, out_ports)

    def _install_rules(self, dp):
        """
        ECMP routing using OpenFlow 1.3 SELECT group tables.
        
        Same structure as two-level routing but instead of suffix-based
        static mapping, we use SELECT groups that hash on packet headers
        (5-tuple) to distribute flows across equal-cost paths.
        
        - Edge switches:
          1. /32 host-specific rules for directly connected hosts
          2. ECMP group for uplinks to aggregation switches
          
        - Aggregation switches:
          1. Prefix /24 rules for intra-pod traffic (downlink to edge)
          2. ECMP group for uplinks to core switches
          
        - Core switches:
          1. Prefix /16 rules for each pod
        """
        self.logger.info("Pushing ECMP rules on s%d", dp.id)
        parser, ofp = dp.ofproto_parser, dp.ofproto
        node = self.node_by_dpid.get(dp.id)
        k = self.topo_net.k

        if node.type == 'edge':
            # ─── EDGE SWITCH ───
            
            # 1) Host-specific /32 -> downlink port
            for e in node.edges:
                nbr = e.rnode if e.lnode == node else e.lnode
                if nbr.type != 'server':
                    continue
                host = nbr
                port = self._safe_port(node, host, dp)

                self.host_ports[dp.id].add(port)
                self.edge_hosts[dp.id].add(host.ip)

                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_dst=(host.ip, '255.255.255.255'))
                self.add_flow(dp, 20, match,
                              [parser.OFPActionOutput(port)])

            # 2) ECMP group across aggregation uplinks
            agg_uplinks = []
            for e in node.edges:
                nbr = e.rnode if e.lnode == node else e.lnode
                if nbr.type == 'agg':
                    port = self._safe_port(node, nbr, dp)
                    agg_uplinks.append(port)

            if len(agg_uplinks) > 1:
                # Multiple uplinks → ECMP group
                gid = self._next_group_id(dp.id)
                self._install_ecmp_group(dp, gid, agg_uplinks)
                # Default rule: send to ECMP group
                match = parser.OFPMatch(eth_type=0x0800)
                actions = [parser.OFPActionGroup(gid)]
                self.add_flow(dp, 1, match, actions)
            elif agg_uplinks:
                # Single uplink → direct output
                self.add_flow(dp, 1,
                              parser.OFPMatch(eth_type=0x0800),
                              [parser.OFPActionOutput(agg_uplinks[0])])

        elif node.type == 'agg':
            # ─── AGGREGATION SWITCH ───
            pod = node.pod

            # 1) Intra-pod prefix /24 -> downlink to correct edge switch
            for e in node.edges:
                nbr = e.rnode if e.lnode == node else e.lnode
                if nbr.type != 'edge':
                    continue
                subnet = f"10.{pod}.{nbr.index}.0"
                mask   = "255.255.255.0"
                port   = self._safe_port(node, nbr, dp)
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_dst=(subnet, mask))
                self.add_flow(dp, 20, match, [parser.OFPActionOutput(port)])

            # 2) ECMP group across core uplinks
            core_uplinks = []
            for e in node.edges:
                nbr = e.rnode if e.lnode == node else e.lnode
                if nbr.type == 'core':
                    port = self._safe_port(node, nbr, dp)
                    core_uplinks.append(port)

            if len(core_uplinks) > 1:
                gid = self._next_group_id(dp.id)
                self._install_ecmp_group(dp, gid, core_uplinks)
                match = parser.OFPMatch(eth_type=0x0800)
                actions = [parser.OFPActionGroup(gid)]
                self.add_flow(dp, 1, match, actions)
            elif core_uplinks:
                self.add_flow(dp, 1,
                              parser.OFPMatch(eth_type=0x0800),
                              [parser.OFPActionOutput(core_uplinks[0])])

        elif node.type == 'core':
            # ─── CORE SWITCH ───
            for pod in range(k):
                subnet = f"10.{pod}.0.0"
                mask   = "255.255.0.0"
                port = next((self._safe_port(node,
                               (e.rnode if e.lnode == node else e.lnode), dp)
                               for e in node.edges
                               if (e.rnode if e.lnode == node else e.lnode).type == 'agg'
                               and (e.rnode if e.lnode == node else e.lnode).pod == pod),
                              None)
                if port:
                    match = parser.OFPMatch(eth_type=0x0800,
                                            ipv4_dst=(subnet, mask))
                    self.add_flow(dp, 10, match,
                                  [parser.OFPActionOutput(port)])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.datapaths[dpid] = datapath

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)

        # 1) Proxy-ARP on edge switches
        if arp_pkt:
            node = self.node_by_dpid.get(dpid)

            if (node and node.type == 'edge' and
                    in_port in self.host_ports[dpid] and
                    arp_pkt.opcode == arp.ARP_REQUEST):

                dst_ip = arp_pkt.dst_ip
                if dst_ip not in self.edge_hosts[dpid]:

                    gw_ip  = f"10.{node.pod}.{node.index}.254"
                    gw_mac = "00:00:00:00:00:%02x" % (dpid & 0xff)

                    rep = packet.Packet()
                    rep.add_protocol(ethernet.ethernet(
                        dst=arp_pkt.src_mac, src=gw_mac, ethertype=0x0806))
                    rep.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=gw_mac, src_ip=gw_ip,
                        dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
                    rep.serialize()

                    self.logger.info("ECMP proxy-ARP s%d  %s → %s",
                                     dpid, arp_pkt.src_ip, dst_ip)

                    datapath.send_msg(
                        parser.OFPPacketOut(datapath=datapath,
                                            in_port=ofproto.OFPP_CONTROLLER,
                                            buffer_id=ofproto.OFP_NO_BUFFER,
                                            actions=[parser.OFPActionOutput(in_port)],
                                            data=rep.data))
                    return

        # 2) Ordinary ARP: flood once, then drop duplicates
        if arp_pkt:
            dst_ip = arp_pkt.dst_ip
            self.logger.info("ECMP ARP-flood dst=%s (switch s%d)", dst_ip, dpid)

            datapath.send_msg(
                parser.OFPPacketOut(datapath=datapath, in_port=in_port,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                                    data=msg.data))

            drop_match = parser.OFPMatch(eth_type=0x0806,
                                         arp_spa=arp_pkt.src_ip,
                                         arp_tpa=dst_ip)
            fm = parser.OFPFlowMod(datapath=datapath, priority=4,
                                   idle_timeout=5, match=drop_match,
                                   instructions=[])
            datapath.send_msg(fm)
            return

        # non-ARP: should be handled by flow rules
        return
