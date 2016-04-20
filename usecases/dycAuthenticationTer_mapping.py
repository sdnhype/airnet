from proto.mapping import Mapping

"""
mininet topology: topo_9sw_4hosts.py


users --|---[s1]---|           |---[s6]---[s7]----|           |---[s9]---WebServer
                   |---[s3] ---|                  |---[s5] ---| 
guests--|---[s2]---|           | -------[s4] -----|           |---[s10]---ComputerCluster


---> NE MARCHE PAS sur topo_9sw_4hosts.py physical topo
     car AS mapped on same switches than IO.
     Du coup, regles en conflit : forward vers fabric (to AS)
                               vs forward vers controler (authenticate fct)

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1", "s2")
        self.addEdgeMap("AC", "s9", "s10")
        self.addEdgeMap("AS", "s1", "s2")
        self.addFabricMap("fabric", "s3", "s4", "s5" ,"s6" ,"s7")
        self.addHostMap("WebServer", "192.168.0.11")
        self.addHostMap("ComputerCluster", "192.168.0.12")
        self.addNetworkMap("users", "172.15.0.0/16")
        self.addNetworkMap("guests", "172.16.0.0/16")

def main():
    return Mymapping()