from language import *
from constants import *

"""
* Virtual topo

INTERNET ---|      /------FAB1------E2-----WS
            |----E1
USERS ------|      \------FAB2------E3-----SSH_GW

* Policies

HTTP from * to WS          OK (via FAB1)
ICMP from USERS to SSH_GW  OK (via FAB2)
"""

WEB_FLOWS = "Web_Flows"
ICMP_FLOWS = "ICMP_FLOWS"

# virtual topology
def virtual_network():
    topo = VTopology()
    topo.addFabric(FAB1, 2)
    topo.addFabric(FAB2, 2)
    topo.addEdge(E1, 4)
    topo.addEdge(E2, 2)
    topo.addEdge(E3, 2)
    topo.addNetwork(INTERNET)
    topo.addNetwork(USERS)
    topo.addHost(WS)
    topo.addHost(SSH_GW)
    topo.addLink((E1, 1),(INTERNET, 0))
    topo.addLink((E1, 2),(USERS, 0))
    topo.addLink((E1, 3),(FAB1, 1))
    topo.addLink((E1, 4),(FAB2, 1))
    topo.addLink((E2, 1),(WS, 0))
    topo.addLink((E2, 2),(FAB1, 2))
    topo.addLink((E3, 1),(SSH_GW, 0))
    topo.addLink((E3, 2),(FAB2, 2))
    return topo

def default_distribution_policy():
    e1 = match(edge=E1, dst=INTERNET) >> forward(INTERNET)
    e2 = match(edge=E1, dst=USERS) >> forward(USERS)
    e3 = match(edge=E2, dst=WS) >> forward(WS)
    e4 = match(edge=E3, dst=SSH_GW) >> forward(SSH_GW)
    return e1 + e2 + e3 + e4

def access_policies():

    e1 = match(edge=E1, dst=WS, nw_proto=TCP, tp_dst=HTTP) >> tag(WEB_FLOWS) >> forward(FAB1)
    e2 = match(edge=E1, src=USERS, nw_proto=ICMP, dst=SSH_GW) >> tag(ICMP_FLOWS) >> forward(FAB2)

    e3 = match(edge=E2, src=WS, nw_proto=TCP, tp_src=HTTP) >> tag(WEB_FLOWS) >> forward(FAB1)
    e4 = match(edge=E3, src=SSH_GW, nw_proto=ICMP, dst=USERS) >> tag(ICMP_FLOWS) >> forward(FAB2)

    return e1 + e2 + e3 + e4

def transport_policy():

    f1 = catch(fabric=FAB1, src=E1, flow=WEB_FLOWS) >> carry(dst=E2)
    f2 = catch(fabric=FAB1, src=E2, flow=WEB_FLOWS) >> carry(dst=E1)
    f3 = catch(fabric=FAB2, src=E1, flow=ICMP_FLOWS) >> carry(dst=E3)
    f4 = catch(fabric=FAB2, src=E3, flow=ICMP_FLOWS) >> carry(dst=E1)

    return f1 + f2 + f3 + f4


def main():
    topology = virtual_network()
    in_network_functions = default_distribution_policy() + access_policies()
    transport_function = transport_policy()
    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
