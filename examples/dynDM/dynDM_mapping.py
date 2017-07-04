from mapping import Mapping
from constants import *

"""

* Virtual topo:

                             DM1
                              |
USERS_NET-----[IO]-------[ Fabric ]-------[AC]------ WEB_SERVER

* Mininet topo:

                           VM
                            | (eth2, 10.1.1.11/16)
                            |
                            | (eth2, 10.1.1.10/16)
u_black---[s1]------[s2]---[s3]---[s4]------[s5]---WS (192.168.0.11/16)
          /
u_white--/

* Mapping:

IO  --> s1
AC  --> s5
DM1 --> VM (10.1.1.11)
Fabric --> [s2, s3, s4]

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(IO, "s1")
        self.addEdgeMap(AC, "s5")
        self.addFabricMap(FABRIC, "s2", "s3", "s4")
        self.addHostMap(WEB_SERVER, "192.168.0.11")
        self.addDataMachineMap("DM1", "10.1.1.11")
        self.addNetworkMap(USERS_NET, "172.16.0.0/16")

def main():
    return Mymapping()
