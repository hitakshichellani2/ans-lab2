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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import topo
class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.topo_net   = topo.Fattree(4)
        self.hosts      = {}   
        self.datapaths  = {}   
        self.adj        = {}   
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self._refresh_adj()
        self.logger.info("Topo updated: %d switches, %d links",
                         len(self.adj),
                         sum(len(v) for v in self.adj.values())//2)
    def _refresh_adj(self):
        self.adj = { sw.dp.id: {} for sw in get_switch(self, None) }
        for link in get_link(self, None):
            u, v = link.src.dpid, link.dst.dpid
            pu, pv = link.src.port_no, link.dst.port_no
            self.adj[u][v] = pu
            self.adj[v][u] = pv
    def _dijkstra_path(self, src, dst):
        self._refresh_adj()
        dist = { u: float('inf') for u in self.adj }
        prev = { u: None for u in self.adj }
        dist[src] = 0
        unseen = set(self.adj)
        while unseen:
            u = min(unseen, key=lambda x: dist[x])
            if u == dst or dist[u] == float('inf'):
                break
            unseen.remove(u)
            for v in self.adj[u]:
                if v not in unseen:
                    continue
                alt = dist[u] + 1
                if alt < dist[v]:
                    dist[v], prev[v] = alt, u
        if dist.get(dst, float('inf')) == float('inf'):
            self.logger.info("Dijkstra: no path %s to %s", src, dst)
            return None
        path = []
        u = dst
        while u is not None:
            path.append(u)
            u = prev[u]
        path = list(reversed(path))
        self.logger.info("Dijkstra: path %s to %s = %s", src, dst, path)
        return path
    def add_flow(self, datapath, priority, match, actions,
                buffer_id=None):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                buffer_id=(buffer_id
                                           if buffer_id is not None
                                           else ofp.OFP_NO_BUFFER))
        datapath.send_msg(mod)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match_any = parser.OFPMatch()
        actions_ctl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                            ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp,     0, match_any, actions_ctl)
        self.logger.info("Switch %s connected, table-miss rule installed", dp.id)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        self._refresh_adj()
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        self.logger.debug("PacketIn s%s port%s buf=%s",
                         dpid, in_port, msg.buffer_id)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt and eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.debug("Ignoring LLDP from s%s", dpid)
            return
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if src_ip not in self.hosts:
                self.hosts[src_ip] = (dpid, in_port)
                self.logger.info("Learned ARP host %s @ s%s:%s",
                                 src_ip, dpid, in_port)
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
                actions = [parser.OFPActionOutput(in_port)]
                self.add_flow(dp, 2, match, actions)
            if dst_ip in self.hosts:
                dst_dpid, dst_port = self.hosts[dst_ip]
                self.logger.info("ARP dst %s known at s%s:%s",
                                 dst_ip, dst_dpid, dst_port)
                path = self._dijkstra_path(dpid, dst_dpid)
                if path:
                    out_port = (dst_port if dpid == dst_dpid
                                else self.adj[dpid][path[1]])
                else:
                    self.logger.warning("No ARP path s%s to s%s, flooding",
                                        dpid, dst_dpid)
                    out_port = ofp.OFPP_FLOOD
            else:
                self.logger.info("ARP dst %s unknown, flooding", dst_ip)
                out_port = ofp.OFPP_FLOOD
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=[parser.OFPActionOutput(out_port)],
                data=msg.data))
            self.logger.info("Sent ARP PacketOut s%s to port%s", dpid, out_port)
            return
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            if src_ip not in self.hosts:
                self.hosts[src_ip] = (dpid, in_port)
                self.logger.info("Learned IPv4 host %s at s%s:%s",
                                 src_ip, dpid, in_port)
                match = parser.OFPMatch(eth_type=0x0800,
                                        ipv4_dst=src_ip)
                actions = [parser.OFPActionOutput(in_port)]
                self.add_flow(dp, 2, match, actions)
            if dst_ip not in self.hosts:
                self.logger.info("IPv4 dst %s unknown, flooding", dst_ip)
                dp.send_msg(parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                    data=msg.data))
                self.logger.info("Sent IPv4 flood on s%s", dpid)
                return
            dst_dpid, dst_port = self.hosts[dst_ip]
            self.logger.info("IPv4 dst %s known at s%s:%s",
                             dst_ip, dst_dpid, dst_port)
            path = self._dijkstra_path(dpid, dst_dpid)
            if path and len(path) > 1:
                for i, sw in enumerate(path):
                    dp_sw     = self.datapaths[sw]
                    p_sw, o_sw = dp_sw.ofproto_parser, dp_sw.ofproto
                    out_port  = (dst_port if i == len(path)-1
                                 else self.adj[sw][path[i+1]])
                    match  = p_sw.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
                    actions = [p_sw.OFPActionOutput(out_port)]
                    self.add_flow(dp_sw, 1, match, actions)
                    self.logger.info("Flow s%s  dst=%s to out%s prio=1",
                                     sw, dst_ip, out_port)
                out_port = (dst_port if dpid == dst_dpid
                            else self.adj[dpid][path[1]])
                self.logger.info("IPv4 outport on s%s to %s", dpid, out_port)
            else:
                self.logger.warning("Graph incomplete for IPv4 %s to %s, flooding",
                                     dpid, dst_dpid)
                out_port = ofp.OFPP_FLOOD
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=in_port,
                actions=[parser.OFPActionOutput(out_port)],
                data=msg.data))
            self.logger.info("Sent IPv4 PacketOut s%s to port%s",
                                dpid, out_port)
