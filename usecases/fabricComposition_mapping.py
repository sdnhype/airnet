from proto.mapping import Mapping

"""
mininet topology: topo_10sw_6hosts.py (12 switches)

staff_net---|---[s1]---|
		       |
guests_net--|---[s2]-- |                                                      |--- WS1
		       |	  |----[s5]----[s6]----|          |---[s11]---|--- WS2
		       |---[s4]---|		       |---[s7]---|
		       |	  |--[s8]--[s9]--[s10]-|	  |---[s12]-------- DB
admins_net---|---[s3]--|
"""

class Mymapping(Mapping):
    def __init__(self):
        Mapping.__init__(self)
        self.addEdgeMap("users_IO", "s1", "s2")
        self.addEdgeMap("admins_IO", "s3")
        self.addEdgeMap("users_egress", "s11")
        self.addEdgeMap("admins_egress", "s12")
        self.addFabricMap("fabric", "s4", "s5", "s6", "s7", "s8", "s9", "s10")
        self.addNetworkMap("staff_net", "172.16.0.0/12")
        self.addNetworkMap("guests_net", "192.168.0.0/16")
        self.addNetworkMap("admins_net", "10.0.0.0/8")
        self.addHostMap("DB", "141.115.28.11")
        self.addHostMap("WS1", "141.115.28.12")
        self.addHostMap("WS2", "141.115.28.13")

def main():
    return Mymapping()
