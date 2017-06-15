#Import language primitives
from proto.language import *

"""
                        Auth Server
-------------                 |
- Net Users --|             [AC1]                         
------------- |               |              |-- WS
              |---[IO]---[ Fabric ]---[AC2]--|
--------------|                              |-- CC
- Net Guests -|
--------------

"""

@DynamicControlFct(data="packet", limit=1, split=["nw_src"])
def authenticate(packet, targetEdge):
    ip = packet.find('ipv4')
    auth_host_ip_src = ip.dstip.toStr()
    new_policy = (match(edge=targetEdge, nw_src=auth_host_ip_src, dst="WebServer") >> 
                  tag("auth_flows") >> forward("fabric"))
    return new_policy

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",3)
    topologie.addEdge("IO",3)
    topologie.addEdge("AC1",2)
    topologie.addEdge("AC2",3)
    topologie.addHost("WebServer")
    topologie.addHost("ComputerCluster")
    topologie.addHost("AuthServer")
    topologie.addNetwork("guests")
    topologie.addNetwork("users")
    topologie.addLink(("IO",1),("users",0))
    topologie.addLink(("IO",2),("guests",0))
    topologie.addLink(("IO",3),("fabric",1))
    topologie.addLink(("AC1",1),("AuthServer",0))
    topologie.addLink(("AC1",2),("fabric",2))
    topologie.addLink(("AC2",1),("WebServer",0))
    topologie.addLink(("AC2",2),("ComputerCluster",0))
    topologie.addLink(("AC2",3),("fabric",3))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, src="guests", dst="AuthServer") >> tag("non_auth_flows") >> forward("fabric")
    i2 = match(edge=VID, src="users", dst="WebServer") >> tag("auth_flows") >> forward("fabric")
    i3 = match(edge=VID, src="users", dst="ComputerCluster") >> tag("auth_flows") >> forward("fabric")
    i4 = match(edge=VID, dst="guests") >> forward("guests")
    i5 = match(edge=VID, dst="users") >> forward("users")
    return i1 + i2 + i3 + i4 + i5

def AC1_policy(VID):
    i1 = match(edge=VID, dst="AuthServer") >> forward("AuthServer")
    i2 = match(edge=VID, src="AuthServer") >> tag("AuthResponse") >>  (authenticate(targetEdge="IO") + forward("fabric")) 
    return i1 + i2

def AC2_policy(VID):
    i1 = match(edge=VID, src="guests", dst="WebServer") >> forward("WebServer")
    i2 = match(edge=VID, src="users", dst="WebServer") >> forward("WebServer")
    i3 = match(edge=VID, src="users", dst="ComputerCluster") >> forward("ComputerCluster")
    i4 = match(edge=VID, src="ComputerCluster") >> tag("CC_out_flows") >> forward("fabric")
    i5 = match(edge=VID, src="WebServer") >> tag("WS_out_flows") >> forward("fabric")
    return i1 + i2 + i3 + i4 + i5

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="non_auth_flows") >> carry(dst="AC1")
    t2 = catch(fabric=VID, src="IO", flow="auth_flows") >> carry(dst="AC2")
    t3 = catch(fabric=VID, src="AC1", flow="AuthResponse") >> carry(dst="IO")
    t4 = catch(fabric=VID, src="AC2", flow="CC_out_flows") >> carry(dst="IO")
    t5 = catch(fabric=VID, src="AC2", flow="WS_out_flows") >> carry(dst="IO")
    return t1 + t2 + t3 + t4 + t5

#Main function
def main():
    in_network_functions = IO_policy("IO") + AC1_policy("AC1") + AC2_policy("AC2")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}
