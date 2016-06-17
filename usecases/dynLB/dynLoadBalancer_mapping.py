from proto.mapping import Mapping
"""
mininet topology: topo_8sw_6hosts.py


client1---|
          |---[s1]---|
client2---|          |          |--[s5]--[s6]--|                 |---WS1
                     |---[s3]---|              |---[s7]---[s8]---|
client3---|          |          |-----[s4]-----|                 |---WS2
          |---[s2]---|
client4---|

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1", "s2")
        self.addEdgeMap("LB", "s8")
        self.addFabricMap("fabric", "s3", "s4", "s5", "s6", "s7")
        self.addHostMap("client1", "192.168.0.11")
        self.addHostMap("client2", "192.168.0.12")
        self.addHostMap("client3", "192.168.0.13")
        self.addHostMap("client4", "192.168.0.14")
        self.addHostMap("WS1", "10.0.0.11")
        self.addHostMap("WS2", "10.0.0.12")

def main():
    return Mymapping()