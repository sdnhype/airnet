from mapping import Mapping
from constants import *

"""

* Virtual topo:

                             DM1
                              |
Users_Net-----[IO]-------[ Fabric ]-------[AC]------ WebServer


* Mininet topo:

                 (192.168.1.11/16)
                         VM
                          | (eth2)
                          |
                          | (eth2)
users---[s1]------[s2]---[s3]---[s4]------[s5]---WS (192.168.0.11/16)

* Mapping:

IO  --> s1
AC  --> s5
Fabric --> [s2, s3, s4]
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(IO, "s1")
        self.addEdgeMap(AC, "s5")
        self.addFabricMap(FABRIC, "s2", "s3", "s4")
        self.addHostMap(WEB_SERVER, "192.168.0.11")
        self.addDataMachineMap("DM1", "192.168.1.11")
        self.addHostMap("H1", "172.16.0.11")
        self.addHostMap("H2", "172.16.0.12")
        #self.addNetworkMap(USERS_NET, "172.16.0.0/16")

def main():
    return Mymapping()
