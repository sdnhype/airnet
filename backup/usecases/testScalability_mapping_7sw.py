from proto.mapping import Mapping
from constants import *

""" 

********************
*** virtual topo ***
********************

        +++ FABRIC +++
       /    /   \     \
      /    /     \     \
   [E1]  [E2]   [E3]   [E4]
     |     |      |      |
    HA     HB     HC     HD
     

Policies (by app flows):

- HA <--> WD  : allow HTTP & ICMP
- HB <--> WC  : allow ALL
- drop other

************************
*** mininet topology ***
************************
  
  TREE, depth=3, fanout=2
  (8 hosts, 7 switches)
  
"""

class Mymapping(Mapping):
    
    def __init__(self):
        
        Mapping.__init__(self)
        
        self.addEdgeMap(E1, "s3")
        self.addEdgeMap(E2, "s4")
        self.addEdgeMap(E3, "s6")
        self.addEdgeMap(E4, "s7")
        
        self.addFabricMap(FAB, "s1", "s2", "s5")
        
        self.addHostMap(HA, "192.168.0.11")
        self.addHostMap(HB, "192.168.0.12")
        self.addHostMap(HC, "192.168.0.13")
        self.addHostMap(HD, "192.168.0.14")
     
def main():
    return Mymapping()
