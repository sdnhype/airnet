from language import *
from constants import *

"""
* Virtual topo

                         DM1
                          |
    client1----[IO]---[ Fabric ]---[AC]---- server

* Policies (transport)

ALL input flows from client1 to server pass through data machine dm1
ALL output flows from server to client1 go directly from edge AC to edge IO

"""

# Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",3)
    topologie.addEdge("IO",2)
    topologie.addEdge("AC",2)
    topologie.addDataMachine("dm1", 1)
    topologie.addHost("client1")
    topologie.addHost("server")
    topologie.addLink(("IO",1),("client1",0))
    topologie.addLink(("IO",2),("fabric",1))
    topologie.addLink(("AC",1),("server",0))
    topologie.addLink(("AC",2),("fabric",2))
    topologie.addLink(("fabric",3),("dm1",1))
    return topologie

# Policies
def IO_policy(VID):
    i1 = match(edge=VID, dst="server")  >> tag("in_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="client1") >> forward("client1")
    return i1 + i2

def AC_policy(VID):
    i1 = match(edge=VID, dst="server") >> forward("server")
    i2 = match(edge=VID, src="server") >> tag("out_flows") >> forward("fabric")
    return i1 + i2

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="in_flows") >> via("dm1", "fct") >> carry(dst="AC")
    t2 = catch(fabric=VID, src="AC", flow="out_flows") >> carry(dst="IO")
    return t1 + t2

# Main function
def main():
    in_network_functions = IO_policy("IO") + AC_policy("AC")
    transport_function = fabric_policy("fabric")
    topology = virtual_network()
    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
