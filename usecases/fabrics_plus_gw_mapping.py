from proto.mapping import Mapping
from constants import *
"""
mininet_topo: topo_fabrics_plus_GW
h1---s1--s2---s3---s4---s5---s6---s7---s8---s9---h2
TODO
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s9")
        self.addEdgeMap(E_GW, "s5")
        self.addFabricMap(FAB1, "s2", "s3", "s4")
        self.addFabricMap(FAB2, "s6", "s7", "s8")
        self.addHostMap(C01,"170.146.9.11")
        self.addHostMap(WS, "170.146.15.11")

def main():
    return Mymapping()
