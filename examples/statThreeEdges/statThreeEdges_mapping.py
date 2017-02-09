from mapping import Mapping
from names import *

"""
*** Virtual topo ***

    A --+                        +-- G
    B --+-- [E1]---[FAB]---[E3]--+-- H
    C --+            |           +-- I
                    [E2]
                     |
                  +--+--+
                  |  |  |
                  D  E  F


*** Mininet topo ***

    A --+                     (s1-s3 backup)
    B --+-- [s11]---[s1]......
    C --+             |      |            +-- G
                     [s2]---[s3]---[s33]--+-- H
                      |                   +-- I
                    [s22]
                      |
                   +--+--+
                   |  |  |
                   D  E  F

*** Mapping ***

    E1 -> s11
    E2 -> s22
    E3 -> s33
    FAB -> s1, s2, s3
"""

# =================
#     MAPPING
# =================
class MyMapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap(E1, "s11")
        self.addEdgeMap(E2, "s22")
        self.addEdgeMap(E3, "s33")
        self.addFabricMap(FAB, "s1", "s2", "s3")
        self.addHostMap(A, "10.0.0.1")
        self.addHostMap(B, "10.0.0.2")
        self.addHostMap(C, "10.0.0.3")
        self.addHostMap(D, "10.0.0.4")
        self.addHostMap(E, "10.0.0.5")
        self.addHostMap(F, "10.0.0.6")
        self.addHostMap(G, "10.0.0.7")
        self.addHostMap(H, "10.0.0.8")
        self.addHostMap(I, "10.0.0.9")

def main():
    return MyMapping()
