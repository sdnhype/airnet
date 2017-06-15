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
  
  TREE, depth=4, fanout=2
  (16 hosts, 15 switches)
  
"""

class Mymapping(Mapping):
    
    def __init__(self):
        
        Mapping.__init__(self)
        
        self.addEdgeMap(E1, "s5", "s6", "s8", "s9")
        self.addEdgeMap(E2, "s12", "s13", "s15", "s16")
        self.addEdgeMap(E3, "s20", "s21", "s23", "s24")
        self.addEdgeMap(E4, "s27", "s28", "s30", "s31")
        
        self.addFabricMap(FAB, "s1", "s2", "s3", "s4", "s7", "s10", "s11", "s14", "s17", "s18", "s19", "s22", "s25", "s26", "s29")
        
        self.addHostMap(HA, "192.168.0.11")
        self.addHostMap(HB, "192.168.0.12")
        self.addHostMap(HC, "192.168.0.13")
        self.addHostMap(HD, "192.168.0.14")
     
def main():
    return Mymapping()

