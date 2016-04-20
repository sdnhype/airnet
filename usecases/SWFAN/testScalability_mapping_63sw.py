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
        
        self.addEdgeMap(E1, "s6", "s7", "s9", "s10", "s13", "s14", "s16", "s17")
        self.addEdgeMap(E2, "s21", "s22", "s24", "s25", "s28", "s29", "s31", "s32")
        self.addEdgeMap(E3, "s37", "s38", "s40", "s41", "s44", "s45", "s47", "s48")
        self.addEdgeMap(E4, "s52", "s53", "s55", "s56", "s59", "s60", "s62", "s63")
        
        self.addFabricMap(FAB, "s1", "s2", "s3", "s4", "s5", "s8", "s11", "s12", "s15", "s18", "s19", "s20", "s23", "s26", "s27", "s30", "s33"
                          "s34", "s35", "s36", "s37", "s39", "s42", "s43", "s46", "s49", "s50", "s51", "s54", "s57", "s58", "s61")
        
        self.addHostMap(HA, "192.168.0.11")
        self.addHostMap(HB, "192.168.0.12")
        self.addHostMap(HC, "192.168.0.13")
        self.addHostMap(HD, "192.168.0.14")
     
def main():
    return Mymapping()


