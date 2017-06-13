from mapping import Mapping
from constants import *

"""

* Virtual topo:

-------------
- Admin Net ------[IO]--- |
-------------             |                       |-- WebServer
                          |----[ Fabric ]---[AC]--|
--------------            |                       |-- DataBase
- Guests Net -----[WAP]---|
--------------

* Mininet topo:

users --|---[s1]---|           |---[s5]---[s6]----|           |---[s8]---WebServer
                   |---[s3] ---|                  |---[s7] ---|
guests--|---[s2]---|           | -------[s4] -----|           |---[s9]---DataBase

* Mapping:

IO  --> s1
WAP --> s2
AC  --> [s8, s9]
Fabric --> [s3, s4, s5, s6, s7]

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(IO, "s1")
        self.addEdgeMap(WAP, "s2")
        self.addEdgeMap(AC, "s8", "s9")
        self.addFabricMap(FABRIC, "s3", "s4", "s5" ,"s6" ,"s7")
        self.addHostMap(WEB_SERVER, "192.168.0.11")
        self.addHostMap(DATA_BASE, "192.168.0.12")
        self.addNetworkMap(ADMIN_NET, "172.15.0.0/16")
        self.addNetworkMap(GUEST_NET, "172.16.0.0/16")

def main():
    return Mymapping()
