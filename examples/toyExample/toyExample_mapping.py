from mapping import Mapping
from constants import *

"""

********************
*** virtual topo ***
********************

    HOST_A----[E1]---[ Fabric ]---[E2]----HOST_C
               |
    HOST_B-----+

Policies (by network flows):

ALLOW ICMP between HOST_A and HOST_C
ALLOW ICMP between HOST_B and HOST_C
ALLOW HTTP between HOST_A and HOST_C
DENY others

************************
*** mininet topology ***
************************

host_A -- s1 -- s2 -- s3 -- s4 -- host_C
          |
host_B ---+

***************
*** mapping ***
***************

E1 --> s1
E2 --> s4
Fabric --> [s2, s3]

"""

class Mymapping(Mapping):

    def __init__(self):

        Mapping.__init__(self)

        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s4")

        self.addFabricMap(FAB, "s2", "s3")

        self.addHostMap(HA, "10.0.0.10")
        self.addHostMap(HB, "10.0.0.11")
        self.addHostMap(HC, "172.16.0.50")

def main():
    return Mymapping()
