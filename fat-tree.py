"""
 Copyright (c) 2025 Computer Networks Group @ UPB
 (see original for full license header)
"""
#!/usr/bin/env python3

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

import topo


class FattreeNet(Topo):
    def __init__(self, ft_topo):
        Topo.__init__(self)

        link_opts = dict(bw=15, delay='5ms')

        node_to_name = {}

        for idx, sw_node in enumerate(ft_topo.switches):
            # Use 1-based naming: s1, s2, ... to avoid dpid=0 which OVS
            # treats as "unset" and may reassign unpredictably.
            name = f"s{idx + 1}"
            self.addSwitch(name, cls=OVSKernelSwitch)
            node_to_name[sw_node] = name

        for srv_node in ft_topo.servers:
            ip_with_mask = srv_node.id + "/8"
            hname = "h" + srv_node.id.replace(".", "")
            self.addHost(hname, ip=ip_with_mask)
            node_to_name[srv_node] = hname

        added_edges = set()
        all_nodes = ft_topo.switches + ft_topo.servers
        for node in all_nodes:
            for edge in node.edges:
                key = tuple(sorted([id(edge.lnode), id(edge.rnode)]))
                if key in added_edges:
                    continue
                added_edges.add(key)
                left  = node_to_name[edge.lnode]
                right = node_to_name[edge.rnode]
                self.addLink(left, right, cls=TCLink, **link_opts)


def make_mininet_instance(graph_topo):
    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):
    lg.setLogLevel('info')
    net = make_mininet_instance(graph_topo)
    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)