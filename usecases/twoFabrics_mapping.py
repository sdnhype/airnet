from proto.mapping import Mapping
from constants import *
"""
mininet_topo: topo_2_fabrics.py
TODO
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s1", "s2")
        self.addEdgeMap(E2, "s9")
        self.addEdgeMap(E3, "s10")
        self.addFabricMap(FAB1, "s3", "s4", "s5", "s6", "s7")
        self.addFabricMap(FAB2, "s3", "s7", "s8")
        self.addNetworkMap(NETA, "141.115.64.0/24")
        self.addHostMap(C01,"170.146.9.11")
        self.addHostMap(WS, "170.146.15.11")
        self.addHostMap(SSH_GW, "170.146.16.11")

def main():
    return Mymapping()
