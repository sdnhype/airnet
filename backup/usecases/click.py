#Import language primitives
from proto.language import *
import pdb

"""

                       dm1  dm2
                        |    |
    client1----[IO]---[ fabric ]---[AC]---- server

FAB policies:
(src=IO,   flow="in_web_flows")  >> via("dm1", "fct") >> via("dm2", "fct") >> carry(dst="AC")
(src="AC", flow="out_web_flows") >> carry(dst="IO")


Test mininet topo: topo_click.py

Mininet topo :
@IP 192.168.0.0/16
                        (.1.11)       (.2.11)
                          VM1         VM2
                            |          |
                            | (eth1)   | (eth2)
     c1---[s1]----[s2]----[s3]------[s4]-------[s5]---[s6]---c2
   (.0.11)                                                  (.0.12)

VM1 and VM2 not in mininet.
(wired through internal networks in virtual box)


"""

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",4)
    topologie.addEdge("IO",2)
    topologie.addEdge("AC",2)
    topologie.addDataMachine("dm1", 1)
    topologie.addDataMachine("dm2", 1)
    topologie.addHost("client1")
    topologie.addHost("server")
    topologie.addLink(("IO",1),("client1",0))
    topologie.addLink(("IO",2),("fabric",1))
    topologie.addLink(("AC",1),("server",0))
    topologie.addLink(("AC",2),("fabric",2))
    topologie.addLink(("fabric",3),("dm1",1))
    topologie.addLink(("fabric",4),("dm2",1))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, dst="server") >> tag("in_web_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="client1")  >> forward("client1")
    return i1 + i2 

def AC_policy(VID):
    i1 = match(edge=VID, dst="server") >> forward("server")
    i2 = match(edge=VID, src="server") >> tag("out_web_flows") >> forward("fabric") 
    return i1 + i2

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="in_web_flows") >> via("dm1", "fct") >> via("dm2", "fct") >> carry(dst="AC")
    t2 = catch(fabric=VID, src="AC", flow="out_web_flows") >> carry(dst="IO")
    return t1 + t2

#Main function
def main():
    in_network_functions = IO_policy("IO") + AC_policy("AC")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}

