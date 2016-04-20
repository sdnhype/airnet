from heapq import *
import pdb
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
            
"""            
def main():
    vertices = {
    "A": [ (1, "B", port), (27, "D", port), (5, "E", port), (2, "G", port) ], # le port est du cote entity 1 --> pour savoir d'ou sortir
    "B": [(1, "A"), (3, "E"), (1, "C")],
    "C": [(2, "F"), (2, "E"), (1, "B"), (3, "G")],
    "D": [(27, "A"), (1, "F"), (4, "G"), (7, "H")],
    "E": [(5, "A"), (3, "B"), (2, "C")],
    "F": [(2, "C"), (4, "G"), (1, "D"), (8, "H")],
    "G": [(2, "A"), (4, "D"), (3, "C"), (4, "F")],
    "H": [(8, "F"), (7, "D")] }
    
    edges = set(["A", "B", "C", "D" ,"E", "F", "G", "H"])
    
    g = Graph(vertices, edges)
    g.SPF("C", "E")
    
main()
"""       

