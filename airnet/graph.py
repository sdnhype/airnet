# AirNet, a virtual network control language based on an Edge-Fabric model.
# Copyright (C) 2016-2017 Université Toulouse III - Paul Sabatier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from heapq import *

class Graph(object):
    """
    :param vertices: dict "s1": [(15, "s2"), (7, "s3"), ...]
    :param edges: set of nodes
    """
    def __init__(self, V, E):
        # vertex -> "edgeA":[(cost, "edgeB", edgeA's output_port)]
        self.vertices = dict(V.iteritems())
        # edge -> (edge_name, edge_type)
        self.edges = set(E)

    def get_adjacent(self, edge):
        nodes = set()
        for node in self.vertices.keys():
            if node == edge:
                for link in self.vertices[node]:
                    if link[1] in self.unvisitedNodes:
                        nodes.add(link[1])
        return nodes

    def get_link_cost(self, endA, endB):
        for node in self.vertices:
            if node == endA:
                for link in self.vertices[node]:
                    if link[1] == endB:
                        return link[0]

    def SPF_search(self):
        if self.candidates:
            current = heappop(self.candidates)
            self.unvisitedNodes.remove(current[1])
            current_adjacent = self.get_adjacent(current[1])
            if current_adjacent:
                for node in current_adjacent:
                    existe = False
                    nodeCost = current[0] + self.get_link_cost(current[1], node)
                    for candidate in self.candidates:
                        if candidate[1] == node:
                            if candidate[0] > nodeCost:
                                self.candidates.remove(candidate)
                            elif candidate[0] <= nodeCost:
                                existe = True
                    if not existe:
                        heappush(self.candidates, (nodeCost, node))
                        self.predecessor[node] = current[1]
            self.SPF_search()
        else:
            return

    def get_dst(self, node, port):
        """
        return the adjacent for "node" that is connected with "port"
        """
        for vertex in self.vertices[node]:
            if vertex[2] == port:
                return vertex[1]

    def SPF(self, start, end, excludes_nodes):
        self.predecessor = {}
        #####
        #self.unvisitedNodes = self.edges # deprecated
        # to be compatible with the modification introduced in infrastructure module
        # modification : add node's type in edges
        self.unvisitedNodes = set([node[0] for node in self.edges])
        for node in excludes_nodes:
            self.unvisitedNodes.remove(node)
        #####
        self.candidates = []
        heappush(self.candidates, (0, start))
        self.SPF_search()
        #####
        optimal_path = []
        self.get_optimal_path(start, end, optimal_path)
        optimal_path.reverse()
        return optimal_path

    def get_optimal_path(self, start, end, optimal_path):
        for node in self.predecessor:
            if node == end:
                optimal_path.append(node)
                if self.predecessor[node] == start:
                    optimal_path.append(start)
                else:
                    self.get_optimal_path(start,
                                          self.predecessor[node],
                                          optimal_path)
