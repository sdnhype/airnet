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
        self.addHostMap("client1", "10.11.0.11")
        self.addHostMap("client2", "10.12.0.12")
        self.addHostMap("server1", "10.13.0.13")
        self.addHostMap("server2", "10.14.0.14")

def main():
    return Mymapping()