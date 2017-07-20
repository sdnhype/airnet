from mapping import Mapping

"""
* Virtual topo

                         dm1
                          |
    client1----[IO]---[ Fabric ]---[AC]---- server

* Mininet topo

@IP 192.168.0.0/16

                          VM1
                           | (eth2)
                           |
                           | (eth2)
     c1---[s1]----[s2]----[s3]------[s4]-------[s5]---[s6]---c2
   (.0.11)                                                  (.0.12)

VM1 not in mininet.
(wired through internal networks in virtual box)

* Mapping

Edge IO --> s1, Edge AC --> s6
Fabric --> s2, s3, s4, s5
dm1 --> VM1 with IPv4 address 10.1.1.11
        (and mininet eth2: 10.1.1.10 for example)

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1")
        self.addEdgeMap("AC", "s6")
        self.addFabricMap("fabric", "s2", "s3", "s4", "s5")
        self.addHostMap("client1", "192.168.0.11")
        self.addHostMap("server", "192.168.0.12")
        self.addDataMachineMap("dm1", "10.1.1.11")

def main():
    return Mymapping()
