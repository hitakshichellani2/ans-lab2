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
  self.pod = None
  self.index = None
  self.ip = None
 def __repr__(self):
		return f"Node({self.id}, type={self.type}, pod={self.pod}, idx={self.index})"
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
	def __init__(self, num_ports):
		self.servers = []
  self.switches = []
  self.generate(num_ports)
 def generate(self, num_ports):
  k = num_ports
  self.edges = []
  def _link(n1, n2):
			e = n1.add_edge(n2)
   self.edges.append(e)
  self.switches, self.servers = [], []
  switch_id, host_id = 1, 1
  groups = rows = k // 2
  core = [[None] * groups for _ in range(rows)]
  for r in range(rows):
			for g in range(groups):
				n = Node(f's{switch_id}', 'core')
    switch_id += 1
    self.switches.append(n)
    core[r][g] = n
  for p in range(k):
			edges, aggs = [], []
   for e in range(k // 2):
				n = Node(f's{switch_id}', 'edge')
    n.pod, n.index = p, e
    switch_id += 1
    self.switches.append(n)
    edges.append(n)
   for a in range(k // 2):
				n = Node(f's{switch_id}', 'agg')
    n.pod, n.index = p, a
    switch_id += 1
    self.switches.append(n)
    aggs.append(n)
   for e in edges:
				for a in aggs:
					_link(e, a)
   for e in edges:
				for h in range(k // 2):
					host = Node(f'h{host_id}', 'server')
     host.ip = f"10.{p}.{e.index}.{h+1}"
     host_id += 1
     self.servers.append(host)
     _link(host, e)
   for a in aggs:
				row = a.index
    for g in range(groups):
					_link(a, core[row][g])
