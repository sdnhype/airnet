#Import language primitives
from language import *
from constants import *
import ast

whitelist = {}
whitelist["172.16.0.12"] = "allow"

"""
                             DM1
                              |
Users_Net-----[IO]-------[ Fabric ]-------[AC]------ WebServer

Policies:

USERS_NET <--> allow only whitelisted IP source addresses
               redirect other flows to DM (e.g. Deep Packet Inspector)
                  before allow/drop
"""

H1_FLOWS = "GRANTED_FLOWS"
H2_FLOWS = "CONTROLLED_FLOWS"

@DynamicControlFct(data="packet", limit=1, split=["nw_src"])
def control(packet):
    if isinstance(packet, dict):
        # packet: JSON {'dpid':..., 'packet':{'ipv4':{......},'tcp':{....},...},'port':...}
        protos = packet.get('packet')
        protos = ast.literal_eval(str(protos))
        ip = protos.get('ipv4')
        hostIP = ip.get('src')
    else:
        ip = packet.find('ipv4')
        hostIP = ip.srcip.toStr()

    if whitelist.has_key(hostIP):
        print(hostIP + " is whitelisted. --> no control")
        new_policy = (match(edge=IO, nw_src=hostIP, dst=WEB_SERVER) >>
                      tag(H1_FLOWS) >> forward(FABRIC))
    else:
        print(hostIP + " is blacklisted. --> control")
        new_policy = (match(edge=IO, nw_src=hostIP, dst=WEB_SERVER) >>
                      tag(H2_FLOWS) >> forward(FABRIC))
    return new_policy

# Virtual topology
def virtual_network():
    # Virtual components
    topology = VTopology()
    topology.addFabric(FABRIC,3)
    topology.addEdge(IO,3)
    topology.addEdge(AC,2)
    topology.addDataMachine("DM1", 1)
    topology.addHost(WEB_SERVER)
    #topology.addNetwork(USERS_NET)
    topology.addHost("H1")
    topology.addHost("H2")
    # Virtual links
    #topology.addLink((IO,1),(USERS_NET,0))
    topology.addLink((IO,1),("H1",0))
    topology.addLink((IO,2),("H2",0))
    topology.addLink((IO,3),(FABRIC,1))
    topology.addLink((AC,1),(WEB_SERVER,0))
    topology.addLink((AC,2),(FABRIC,2))
    topology.addLink((FABRIC,3),("DM1",1))
    return topology

# Policies
def access_policies():
    i1 = match(edge=IO, src="H1", dst=WEB_SERVER) >> control()
    i3 = match(edge=IO, src="H2", dst=WEB_SERVER) >> control()
    i2 = match(edge=AC, dst="H1") >> tag("AC_FLOWS") >> forward(FABRIC)
    i4 = match(edge=AC, dst="H2") >> tag("AC_FLOWS") >> forward(FABRIC)
    return i1 + i2 + i3 + i4

def distribution_policies():
    i1 = match(edge=IO, dst="H1")  >> forward("H1")
    i3 = match(edge=IO, dst="H2")  >> forward("H2")
    i2 = match(edge=AC, dst=WEB_SERVER) >> forward(WEB_SERVER)
    return i1 + i2 + i3

def transport_policies():
    t1 = (catch(fabric=FABRIC, src=IO,  flow=H1_FLOWS)
                >> carry(dst=AC) )
    t2 = (catch(fabric=FABRIC, src=IO,  flow=H2_FLOWS)
                >> via("DM1", "fct") >> carry(dst=AC) )
    t3 = catch(fabric=FABRIC, src=AC, flow="AC_FLOWS") >> carry(dst=IO)
    return t1 + t2 + t3

# Main function
def main():
    in_network_functions = access_policies() + distribution_policies()
    transport_function = transport_policies()
    topology = virtual_network()
    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
