from mapping import Mapping
from constants import *

"""

* Virtual topo:

    C01(host) ---- E1 ---- FAB1 ---- E_GW ---- FAB2 ---- E2 ---- WS(host)

* Mininet topo (edge_between_fabs_topo):

    h1 --- s1---s2---s3---s4---s5---s6---s7---s8---s9 --- h2

* Mapping

    E1 -> s1, E_GW -> s5, E2 -> s9
    FAB1 -> s2, s3, s4
    FAB2 -> s6, s7, s8

"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s9")
        self.addEdgeMap(E_GW, "s5")
        self.addFabricMap(FAB1, "s2", "s3", "s4")
        self.addFabricMap(FAB2, "s6", "s7", "s8")
        self.addHostMap(C01,"170.146.9.11")
        self.addHostMap(WS, "170.146.15.11")

def main():
    return Mymapping()
