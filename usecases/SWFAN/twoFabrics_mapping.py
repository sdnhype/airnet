from proto.mapping import Mapping
from constants import *
"""
TODO:
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s10")
        self.addEdgeMap(E3, "s11")
        self.addFabricMap(FAB1, "s2", "s3", "s4", "s5", "s6", "s9")
        self.addFabricMap(FAB2, "s2", "s7", "s8", "s9")
        self.addNetworkMap(INTERNET, "10.12.0.0/16")
        self.addNetworkMap(USERS,"10.11.0.0/16")
        self.addHostMap(WS, "10.13.0.13")
        self.addHostMap(SSH_GW, "10.14.0.14")

def main():
    return Mymapping()
