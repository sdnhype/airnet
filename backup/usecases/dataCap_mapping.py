from proto.mapping import Mapping
"""

mininet topology: topo_7sw_3hosts.py

     h1(192.168.0.11)--|
                       |--[s1]----[s2]----[s3]----[s4]--|--h3(172.16.0.11)
     h2(192.168.0.12)--|

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1")
        self.addEdgeMap("AC", "s7")
        self.addFabricMap("fabric", "s2", "s3", "s4", "s5", "s6")
        self.addHostMap("client1", "192.168.0.11")
        self.addHostMap("client2", "192.168.0.12")
        self.addHostMap("server", "172.16.0.11")

def main():
    return Mymapping()