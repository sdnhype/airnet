from airnet.mapping import Mapping
from airnet.usecases.constants import *
"""

mininet_topo: topo_2_fabrics.py

INTERNET----|      /------FAB1------E2-----WS
            |----E1
USERS-------|      \------FAB2------E3-----SSH_GW


mapping:

                         +--------[s8] ---+   +---[s9]---WS
INET1 ---[s1]---|       /                 |  /
                |---[s3]---[s4]---[s5]---[s7]
USER1 ---[s2]---|       \                 |  \
                         +--------[s6] ---+   +---[s10]---SSH_GW

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s1", "s2")
        self.addEdgeMap(E2, "s9")
        self.addEdgeMap(E3, "s10")
        self.addFabricMap(FAB1, "s3", "s4", "s5", "s6", "s7")
        self.addFabricMap(FAB2, "s3", "s7", "s8")
        self.addNetworkMap(INTERNET, "5.0.0.0/8")
        self.addNetworkMap(USERS, "170.146.9.0/24")
        self.addHostMap(WS, "170.146.15.11")
        self.addHostMap(SSH_GW, "170.146.16.11")

def main():
    return Mymapping()
