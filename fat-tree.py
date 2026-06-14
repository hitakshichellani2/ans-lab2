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
    """
    Create a fat-tree network in Mininet from a topo.Fattree graph object.
    """

    def __init__(self, ft_topo):
        Topo.__init__(self)

        # Link parameters: 15 Mbps bandwidth, 5 ms latency
        link_opts = dict(bw=15, delay='5ms')

        # ------------------------------------------------------------------ #
        # 1. Add all switches                                                  #
        #    We map each topo.Node (switch) → a Mininet switch name.          #
        #    Names must be alphanumeric only (no '_', '.', '/').               #
        #    Strategy: "s<index>" where index is position in ft_topo.switches #
        # ------------------------------------------------------------------ #
        node_to_name = {}   # topo.Node → mininet name string

        for idx, sw_node in enumerate(ft_topo.switches):
            # name: s0, s1, s2, …
            name = f"s{idx}"
            # Store the fat-tree IP as a switch parameter for reference
            self.addSwitch(name, cls=OVSKernelSwitch)
            node_to_name[sw_node] = name

        # ------------------------------------------------------------------ #
        # 2. Add all servers (hosts)                                           #
        #    IP from fat-tree paper: 10.pod.edge_sw_idx.host_idx/8            #
        #    The Node.id field already holds the correct IP string.            #
        # ------------------------------------------------------------------ #
        for srv_node in ft_topo.servers:
            ip_with_mask = srv_node.id + "/8"
            # Host name: replace dots with nothing → e.g. "h10012"
            hname = "h" + srv_node.id.replace(".", "")
            self.addHost(hname, ip=ip_with_mask)
            node_to_name[srv_node] = hname

        # ------------------------------------------------------------------ #
        # 3. Add all edges (links)                                             #
        #    Walk every switch node; for each edge add the link once          #
        #    (guard with a visited set to avoid duplicates).                  #
        # ------------------------------------------------------------------ #
        added_edges = set()

        all_nodes = ft_topo.switches + ft_topo.servers
        for node in all_nodes:
            for edge in node.edges:
                # Canonical key: sorted pair of ids so we add each link once
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