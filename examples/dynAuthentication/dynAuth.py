#Import language primitives
from language import *
from usecases.constants import *
import ast
whitelist = {}
whitelist["172.16.0.12"] = "allow"

"""
------------- 
- Admin Net ------[IO]--- |                          
-------------             |                       |-- WebServer
                          |----[ Fabric ]---[AC]--|
--------------            |                       |-- DataBase
- Guests Net -----[WAP]---|
--------------

ADMIN_NET <--> WS and DB servers : OK
GUEST_NET <--> WS : only whitelist

"""

ADMIN_FLOWS = "ADMIN_FLOWS"
GUESTS_WS_FLOWS = "GUESTS_WS_FLOWS"

@DynamicControlFct(data="packet", limit=1, split=["nw_src"])
def authenticate(packet):
    """
    le paquet peut etre un paquet pox ou un dictionnaire
    """
    if isinstance(packet, dict):
        #ici il s'agit de {'dpid':..,'packet':{'ipv4':{......},'tcp':{....},...},'port':..}
        protos = packet.get('packet')
        protos = ast.literal_eval(str(protos))
        ip = protos.get('ipv4')
        hostIP = ip.get('src')
    else:
        ip = packet.find('ipv4')
        hostIP = ip.srcip.toStr()
    
    if whitelist.has_key(hostIP): 
        print(hostIP + " is whitelisted. --> fwd")
        new_policy = (match(edge=WAP, nw_src=hostIP, dst=WEB_SERVER, tp_dst=80) >> 
                      tag(GUESTS_WS_FLOWS) >> forward(FABRIC))
    else:
        print(hostIP + " is blacklisted. --> drop")
        new_policy = (match(edge=WAP, nw_src=hostIP, dst=WEB_SERVER) >> drop)
    return new_policy

#Virtual topology
def virtual_network():
    #VIRTUAL DEVICES
    topology = VTopology()
    topology.addFabric(FABRIC,3)
    topology.addEdge(IO,2)
    topology.addEdge(WAP,2)
    topology.addEdge(AC,3)
    topology.addHost(WEB_SERVER)
    topology.addHost(DATA_BASE)
    topology.addNetwork(GUEST_NET)
    topology.addNetwork(ADMIN_NET)
    #LINKS
    topology.addLink((IO,1),(ADMIN_NET,0))
    topology.addLink((IO,2),(FABRIC,1))
    topology.addLink((WAP,1),(GUEST_NET,0))
    topology.addLink((WAP,2),(FABRIC,2))
    topology.addLink((AC,1),(WEB_SERVER,0))
    topology.addLink((AC,2),(DATA_BASE,0))
    topology.addLink((AC,3),(FABRIC,3))
    return topology

#Policies
def InputOutput_policy():
    i1 = match(edge=IO, src=ADMIN_NET) >> tag(ADMIN_FLOWS) >> forward(FABRIC)
    i2 = match(edge=IO, dst=ADMIN_NET) >> forward(ADMIN_NET)
    i3 = match(edge=WAP, src=GUEST_NET, dst=WEB_SERVER) >> authenticate()
    i4 = match(edge=WAP, dst=GUEST_NET) >> forward(GUEST_NET)
    return i1 + i2 + i3 + i4

def Access_policy():
    i1 = match(edge=AC, dst=WEB_SERVER) >> forward(WEB_SERVER)
    i2 = match(edge=AC, dst=DATA_BASE) >> forward(DATA_BASE)
    i3 = match(edge=AC, dst=GUEST_NET) >> tag(GUESTS_WS_FLOWS) >> forward(FABRIC)
    i4 = match(edge=AC, dst=ADMIN_NET) >> tag(ADMIN_FLOWS) >> forward(FABRIC)
    return i1 + i2 + i3 + i4

def transport_policy():
    t1 = ((catch(fabric=FABRIC, src=IO, flow=ADMIN_FLOWS) + 
            catch(fabric=FABRIC, src=WAP, flow=GUESTS_WS_FLOWS))
                >> carry(dst=AC))
    t2 = catch(fabric=FABRIC, src=AC, flow=ADMIN_FLOWS) >> carry(dst=IO)
    t3 = catch(fabric=FABRIC, src=AC, flow=GUESTS_WS_FLOWS) >> carry(dst=WAP)
    return t1 + t2 + t3 

#Main function
def main():
    in_network_functions = InputOutput_policy() + Access_policy()
    transport_function = transport_policy()
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}
