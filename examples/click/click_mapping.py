from mapping import Mapping
"""

                       dm1  dm2
                        |    |
    client1----[IO]---[ fabric ]---[AC]---- server

Test mininet topo: topo_click.py

Mininet topo :
@IP 192.168.0.0/16
                         (.1.11)      (.2.11)
                          VM1         VM2
                           | (eth2)   | (eth2)
                           |          |
                           | (eth2)   | (eth3)
     c1---[s1]----[s2]----[s3]------[s4]-------[s5]---[s6]---c2
   (.0.11)                                                  (.0.12)

VM1 and VM2 not in mininet.
(wired through internal networks in virtual box)

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("IO", "s1")
        self.addEdgeMap("AC", "s6")
        self.addFabricMap("fabric", "s2", "s3", "s4", "s5")
        self.addHostMap("client1", "192.168.0.11")
        self.addHostMap("server", "192.168.0.12")
        self.addDataMachineMap("dm1", "192.168.1.11")
        self.addDataMachineMap("dm2", "192.168.2.11")

def main():
    return Mymapping()
