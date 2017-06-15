from proto.mapping import Mapping
from constants import *
"""
TODO:
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("E1", "s1")
        self.addEdgeMap("E2", "s10", "s11")
        self.addFabricMap("FAB", "s2", "s3", "s4", "s5", "s6" "s7", "s8", "s9")
        self.addNetworkMap("C1", "10.15.0.11")
        self.addNetworkMap("C2","10.15.0.12")
        self.addNetworkMap("C3","10.15.0.13")
        self.addNetworkMap("C4","10.15.0.14")
        self.addHostMap("WS1", "10.15.0.20")
        self.addHostMap("WS2", "10.15.0.21")

def main():
    return Mymapping()
