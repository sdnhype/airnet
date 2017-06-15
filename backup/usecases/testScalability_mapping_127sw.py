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
        
        self.addEdgeMap(E1, "s7", "s8", "s10", "s11", "s14", "s15", "s17", "s18", "s22", "s23", "s25", "s26", "s29", "s30", "s32", "s33")
        self.addEdgeMap(E2, "s38", "s39", "s41", "s42", "s45", "s46", "s48", "s49", "s53", "s54", "s56", "s57", "s60", "s61", "s63", "s64")
        self.addEdgeMap(E3, "s70", "s71", "s73", "s74", "s77", "s78", "s80", "s81", "s85", "s86", "s88", "s89", "s92", "s93", "s95", "s96")
        self.addEdgeMap(E4, "s101", "s102", "s104", "s105", "s108", "s109", "s111", "s112", "s116", "s117", "s119", "s120", "s123", "s124", "s126", "s127")
        """
        self.addEdgeMap(E1, "s7")
        self.addEdgeMap(E2, "s38")
        self.addEdgeMap(E3, "s96")
        self.addEdgeMap(E4, "s127")
        switches1 = ["s"+str(item) for item in range(1,7)]
        switches2 = ["s"+str(item) for item in range(8,38)]
        switches3 = ["s"+str(item) for item in range(39,96)]
        switches4 = ["s"+str(item) for item in range(97,127)]
        switches1.extend(switches2)
        switches1.extend(switches3)
        switches1.extend(switches4)
        """
    
        switches = [1,2,3,4,5,6,9,12,13,16,19,20,21,24,27,28,31,34,35,36,37,40,43,44,47,50,51,52,
         55,58,59,62,65,66,67,68,69,72, 75,76,79,82,83,84,87,90,91,94,97,98,99,100,103,106,
         107,110,113,114,115,118, 121,122,125]
        switches = ["s"+str(item) for item in switches]
        
        self.addFabricMap(FAB, *switches)
        
        self.addHostMap(HA, "192.168.0.11")
        self.addHostMap(HB, "192.168.0.12")
        self.addHostMap(HC, "192.168.0.13")
        self.addHostMap(HD, "192.168.0.14")
     
def main():
    return Mymapping()

