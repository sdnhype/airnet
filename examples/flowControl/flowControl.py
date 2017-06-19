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

USERS_FLOWS = "USERS_FLOWS"

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
                      tag(USERS_FLOWS) >> forward(FABRIC))
    else:
        print(hostIP + " is blacklisted. --> control")
        """ new_policy = (match(edge=IO, nw_src=hostIP, dst=WEB_SERVER) >>
                      tag(USERS_FLOWS) >> forward(FABRIC)) + (catch (fabric=FABRIC,
                      src=IO, flow=USERS_FLOWS) >> carry(dst=AC) >> via("DM1", "fct"))
        """
        new_policy = (catch (fabric=FABRIC,
                      src=IO, flow=USERS_FLOWS) >> carry(dst=AC) >> via("DM1", "fct"))
    return new_policy

# Virtual topology
def virtual_network():
    # Virtual components
    topology = VTopology()
    topology.addFabric(FABRIC,3)
    topology.addEdge(IO,2)
    topology.addEdge(AC,2)
    topology.addHost(WEB_SERVER)
    topology.addNetwork(USERS_NET)
    # Virtual links
    topology.addLink((IO,1),(USERS_NET,0))
    topology.addLink((IO,2),(FABRIC,1))
    topology.addLink((AC,1),(WEB_SERVER,0))
    topology.addLink((AC,2),(FABRIC,2))
    topology.addLink(("DM1",1),(FABRIC,3))
    return topology

# Policies
def access_policies():
    i1 = match(edge=IO, src=USERS_NET, dst=WEB_SERVER) >> control()
    i2 = match(edge=AC, dst=USERS_NET) >> tag(USERS_FLOWS) >> forward(FABRIC)
    return i1 + i2

def distribution_policies():
    i1 = match(edge=IO,  dst=USERS_NET)  >> forward(USERS_NET)
    i2 = match(edge=AC,  dst=WEB_SERVER) >> forward(WEB_SERVER)
    return i1 + i2

def transport_policies():
    t1 = (catch(fabric=FABRIC, src=IO,  flow=USERS_FLOWS)
                >> carry(dst=AC) )
    t2 = catch(fabric=FABRIC, src=AC, flow=USERS_FLOWS) >> carry(dst=IO)
    return t1 + t2

# Main function
def main():
    in_network_functions = access_policies() + distribution_policies()
    transport_function = transport_policies()
    topology = virtual_network()
    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
