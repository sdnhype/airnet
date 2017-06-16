from proto.mapping import Mapping
"""
mininet topology: topo_10sw_5hosts.py

                                    |---[s8]---|---AS    
                                    |
users --|---[s1]---|           |---[s6]---[s7]----|           |---[s9]---WS
                   |---[s3] ---|                  |---[s5] ---| 
guests--|---[s2]---|           | -------[s4] -----|           |---[s10]---CC

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1", "s2")
        self.addEdgeMap("AC1", "s8")
        self.addEdgeMap("AC2", "s9", "s10")
        self.addFabricMap("fabric", "s3", "s4", "s5" ,"s6" ,"s7")
        self.addHostMap("WebServer", "192.168.0.11")
        self.addHostMap("ComputerCluster", "192.168.0.12")
        self.addHostMap("AuthServer", "10.0.0.11")
        self.addNetworkMap("users", "172.15.0.0/16")
        self.addNetworkMap("guests", "172.16.0.0/16")

def main():
    return Mymapping()
