from proto.mapping import Mapping
from constants import *

""" 

********************
*** virtual topo ***
********************

C01 ---|
C02 ---|---[E1]---[ Fabric ]---[E2]--- WS
C03 ---|

************************
*** mininet topology ***
************************
 
client1--|
client2--|---[s1]----[s2]----[s3]----[s4]---[s5]---WS
client3--|

"""

class Mymapping(Mapping):
    
    def __init__(self):
        
        Mapping.__init__(self)
        
        self.addEdgeMap(E1, "s1")
        self.addEdgeMap(E2, "s5")
        
        self.addFabricMap(FAB, "s2", "s3", "s4")
        
        self.addHostMap(C01, "10.0.0.10")
        self.addHostMap(C02, "10.0.0.20")
        self.addHostMap(C03, "10.0.0.30")
        self.addHostMap(WS, "192.168.10.16")

def main():
    return Mymapping()
