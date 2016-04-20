#Import language primitives
from proto.language import *
whitelist = {}
whitelist["172.16.0.12"] = "allow"

"""
------------- 
- Net Users --|                           
------------- |                             |-- WS
              |---[IO]---[ Fabric ]---[AC]--|
--------------|                             |-- CC
- Net Guests -|
--------------

"""

@DynamicControlFct(data="packet", limit=1, split=["nw_src"])
def authenticate(packet):
    ip = packet.find('ipv4')
    hostIP = ip.srcip.toStr()
    try:
        whitelist[ip.srcip.toStr()]
        new_policy = (match(edge="IO", nw_src=hostIP, dst="WebServer") >> 
                      tag("auth_flows") >> forward("fabric"))
    except IndexError:
        new_policy = (match(edge="IO", nw_src=hostIP, dst="WebServer") >> drop())
        
    return new_policy

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",2)
    topologie.addEdge("IO",3)
    topologie.addEdge("AC",3)
    topologie.addHost("WebServer")
    topologie.addHost("ComputerCluster")
    topologie.addNetwork("guests")
    topologie.addNetwork("users")
    topologie.addLink(("IO",1),("users",0))
    topologie.addLink(("IO",2),("guests",0))
    topologie.addLink(("IO",3),("fabric",1))
    topologie.addLink(("AC",1),("WS",0))
    topologie.addLink(("AC",2),("CC",0))
    topologie.addLink(("AC",3),("fabric",2))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, src="guests", dst="WebServer") >> authenticate()
    i2 = match(edge=VID, src="users", dst="WebServer") >> tag("auth_flows") >> forward("fabric")
    i3 = match(edge=VID, src="users", dst="ComputerCluster") >> tag("auth_flows") >> forward("fabric")
    i4 = match(edge=VID, dst="guests") >> forward("guests")
    i5 = match(edge=VID, dst="users") >> forward("users")
    return i1 + i2 + i3 + i4 + i5

def AC_policy(VID):
    i1 = match(edge=VID, src="guests", dst="WebServer") >> forward("WebServer")
    i2 = match(edge=VID, src="users", dst="WebServer") >> forward("WebServer")
    i3 = match(edge=VID, src="users", dst="ComputerCluster") >> forward("ComputerCluster")
    i4 = match(edge=VID, src="ComputerCluster") >> tag("CC_out_flows") >> forward("fabric")
    i5 = match(edge=VID, src="WebServer") >> tag("WS_out_flows") >> forward("fabric")
    return i1 + i2 + i3 + i4 + i5

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="auth_flows") >> carry(dst="AC")
    t2 = catch(fabric=VID, src="AC", flow="CC_out_flows") >> carry(dst="IO")
    t3 = catch(fabric=VID, src="AC", flow="WS_out_flows") >> carry(dst="IO")
    return t1 + t2 + t3 

#Main function
def main():
    in_network_functions = IO_policy("IO") + AC_policy("AC")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}
