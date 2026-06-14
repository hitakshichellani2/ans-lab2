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
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 """


class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None

    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None


class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type

    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    def remove_edge(self, edge):
        self.edges.remove(edge)

    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False


class Fattree:
    """
    Fat-tree topology following Al-Fares et al., SIGCOMM 2008.

    For a k-port fat-tree:
      - k pods, each with k switches (k/2 edge + k/2 aggregation)
      - (k/2)^2 core switches
      - k^3/4 servers total

    IP addressing (10.pod.switch.host/24):
      - Servers:      10.pod.edge_sw_idx.host_idx  (host_idx 1..k/2)
      - Edge sw:      10.pod.sw_idx.1               (sw_idx 0..k/2-1)
      - Aggr  sw:     10.pod.sw_idx.1               (sw_idx k/2..k-1)
      - Core  sw:     10.k.(j+1).i                  (1-based coords)

    Node.id is the IP string. Node.type is one of:
      'server', 'edge', 'aggregation', 'core'
    """

    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)

    def generate(self, num_ports):
        k = num_ports
        half = k // 2

        # ------------------------------------------------------------------ #
        # 1. Create core switches  (k/2)^2 of them                           #
        #    IP: 10.k.(j+1).i   j in [0, k/2-1], i in [1, k/2]              #
        # ------------------------------------------------------------------ #
        core = []
        for j in range(half):
            row = []
            for i in range(1, half + 1):
                ip = f"10.{k}.{j + 1}.{i}"
                node = Node(ip, 'core')
                row.append(node)
                self.switches.append(node)
            core.append(row)

        # ------------------------------------------------------------------ #
        # 2. Create pods                                                       #
        # ------------------------------------------------------------------ #
        # Store edge switches per pod so we can attach servers afterward
        # edge_switches[pod][sw_idx]  (sw_idx 0..half-1)
        edge_switches = []
        aggr_switches = []

        for pod in range(k):
            pod_edge = []
            pod_aggr = []

            # -- edge switches (sw_idx 0 .. half-1) --
            for sw in range(half):
                ip = f"10.{pod}.{sw}.1"
                node = Node(ip, 'edge')
                pod_edge.append(node)
                self.switches.append(node)

            # -- aggregation switches (sw_idx half .. k-1) --
            for sw in range(half, k):
                ip = f"10.{pod}.{sw}.1"
                node = Node(ip, 'aggregation')
                pod_aggr.append(node)
                self.switches.append(node)

            edge_switches.append(pod_edge)
            aggr_switches.append(pod_aggr)

            # -- servers: each edge switch connects to k/2 servers --
            for sw_idx, esw in enumerate(pod_edge):
                for host in range(2, half + 2):          # host: 2 .. k/2+1
                    ip = f"10.{pod}.{sw_idx}.{host}"
                    srv = Node(ip, 'server')
                    self.servers.append(srv)
                    esw.add_edge(srv)

            # -- edge <-> aggregation links within pod --
            for esw in pod_edge:
                for asw in pod_aggr:
                    esw.add_edge(asw)

            # -- aggregation <-> core links --
            # aggr switch j (0-based within pod) connects to core switches
            # in column j, one per row  → core[row][j]
            for j, asw in enumerate(pod_aggr):
                for i in range(half):                    # row i
                    asw.add_edge(core[i][j])

        # Keep references for external use
        self.core = core
        self.edge_switches = edge_switches
        self.aggr_switches = aggr_switches
        self.k = k

    # ---------------------------------------------------------------------- #
    # Convenience helpers                                                      #
    # ---------------------------------------------------------------------- #
    def get_server_ips(self):
        return [s.id for s in self.servers]

    def sanity_check(self):
        """Print degree counts to verify topology correctness."""
        k = self.k
        half = k // 2
        print(f"k={k}  half={half}")
        print(f"  Core switches   : {half * half}  (expected {half**2})")
        print(f"  Aggr switches   : {k * half}  (expected {k * half})")
        print(f"  Edge switches   : {k * half}  (expected {k * half})")
        print(f"  Servers         : {len(self.servers)}  (expected {k**3 // 4})")

        # Check degrees
        for sw in self.core[0]:
            assert len(sw.edges) == k, f"Core sw degree wrong: {len(sw.edges)}"
        for pod in range(k):
            for esw in self.edge_switches[pod]:
                assert len(esw.edges) == k, \
                    f"Edge sw degree wrong: {len(esw.edges)}"
            for asw in self.aggr_switches[pod]:
                assert len(asw.edges) == k, \
                    f"Aggr sw degree wrong: {len(asw.edges)}"
        print("  All degree checks passed.")


if __name__ == '__main__':
    ft = Fattree(4)
    ft.sanity_check()