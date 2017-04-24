from mapping import Mapping
from constants import *

"""

********************
*** virtual topo ***
********************

- HOST_A     ----[E1]---[ Fabric ]---[E2]----      HOSt_B -


Policies (by app flows):

ALLOW ICMP HOST_A to HOSt_B
ALLOW ICMP HOST_B to HOSt_A

************************
*** mininet topology ***
************************

    host_A -- s1 -- s2 -- s3 -- s4 -- host_B

"""

class Mymapping(Mapping):

    def __init__(self):

        Mapping.__init__(self)

        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s4")

        self.addFabricMap(FAB, "s2", "s3")

        self.addHostMap(HA, "10.0.0.11")
        self.addHostMap(HB, "172.16.0.50")

def main():
    return Mymapping()
