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

from topo import Fattree


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)
        self.ft = ft_topo

        for sw in self.ft.switches:
            self.addSwitch(sw.id, protocols='OpenFlow10,OpenFlow13')

        for h in self.ft.servers:
            self.addHost(h.id, ip=h.ip + '/8')

        for e in self.ft.edges:
            self.addLink(e.lnode.id, e.rnode.id, cls=TCLink, bw=15, delay='5ms')


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    # mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()

def check_fat_tree_topology(ft, k):

        expected_hosts = (k ** 3) // 4
        expected_edge_sw = expected_agg_sw = k * (k // 2)
        expected_core_sw = (k // 2) ** 2
        expected_total_switches = expected_edge_sw + expected_agg_sw + expected_core_sw
        # Links: host-edge + edge-agg + agg-core
        expected_links = expected_hosts + k * (k // 2) ** 2 + k * (k // 2) ** 2

        actual_hosts = len(ft.servers)
        actual_switches = len(ft.switches)
        actual_links = len(ft.edges)

        # Count switches by type
        core_count = sum(1 for s in ft.switches if s.type == 'core')
        agg_count  = sum(1 for s in ft.switches if s.type == 'agg')
        edge_count = sum(1 for s in ft.switches if s.type == 'edge')

        print("\n--- Fat-Tree Sanity Checks (k={}) ---".format(k))
        print(f"  Hosts:    expected={expected_hosts}, actual={actual_hosts}")
        print(f"  Switches: expected={expected_total_switches}, actual={actual_switches}")
        print(f"    Core:   expected={expected_core_sw}, actual={core_count}")
        print(f"    Agg:    expected={expected_agg_sw}, actual={agg_count}")
        print(f"    Edge:   expected={expected_edge_sw}, actual={edge_count}")
        print(f"  Links:    expected={expected_links}, actual={actual_links}")

        assert actual_hosts == expected_hosts, "Host count mismatch"
        assert actual_switches == expected_total_switches, "Switch count mismatch"
        assert core_count == expected_core_sw, "Core switch count mismatch"
        assert agg_count == expected_agg_sw, "Aggregation switch count mismatch"
        assert edge_count == expected_edge_sw, "Edge switch count mismatch"
        assert actual_links == expected_links, f"Link count mismatch: expected {expected_links}, got {actual_links}"
        assert all(len(n.edges) == 1 for n in ft.servers), "Each host should connect to exactly one switch"

        # Degree checks
        for s in ft.switches:
            deg = len(s.edges)
            if s.type == 'core':
                assert deg == k, f"Core {s.id} degree {deg} != k={k}"
            elif s.type == 'agg':
                assert deg == k, f"Agg {s.id} degree {deg} != k={k}"
            elif s.type == 'edge':
                assert deg == k, f"Edge {s.id} degree {deg} != k={k}"

        print("  All sanity checks PASSED ✓")



if __name__ == '__main__':
    k = int(input('enter value of k: '))
    ft_topo = Fattree(k)
    check_fat_tree_topology(ft_topo, k)
    run(ft_topo)
    
    
    
    
    
    
