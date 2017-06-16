from proto.mapping import Mapping
"""
TODO:
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1")
        self.addEdgeMap("AC", "s10", "s11")
        self.addFabricMap("fabric", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9")
        self.addNetworkMap("Net.A", "10.11.0.0/16")
        self.addNetworkMap("Net.B", "10.12.0.0/16")
        self.addHostMap("WS1", "10.13.0.13")
        self.addHostMap("WS2", "10.14.0.14")

def main():
    return Mymapping()