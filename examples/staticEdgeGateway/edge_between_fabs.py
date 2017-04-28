from language import *
from constants import *

"""

C01(host) ---- E1 ---- FAB1 ---- E_GW ---- FAB2 ---- E2 ---- WS(host)

C01 <---> WS : Fwd ALL FLOWS

"""

IN_FLOWS = "In_Web_Flows"
OUT_FLOWS = "Out_Web_Flows"

# virtual topology
def virtual_network():
    topo = VTopology()
    topo.addFabric(FAB1, 2)
    topo.addFabric(FAB2, 2)
    topo.addEdge(E1, 2)
    topo.addEdge(E2, 2)
    topo.addEdge(E_GW, 2)
    topo.addHost(C01)
    topo.addHost(WS)
    topo.addLink((E1, 1),(C01, 0))
    topo.addLink((E1, 2),(FAB1, 1))
    topo.addLink((E2, 1),(WS, 0))
    topo.addLink((E2, 2),(FAB2, 1))
    topo.addLink((E_GW, 1),(FAB1, 2))
    topo.addLink((E_GW, 2),(FAB2, 2))
    return topo

def default_distribution_policy():

    e1 = match(edge=E1, dst=C01) >> forward(C01)
    e2 = match(edge=E2, dst=WS) >> forward(WS)
    return e1 + e2

def access_policies():

    e1 = match(edge=E1, dst=WS) >> tag(IN_FLOWS) >> forward(FAB1)
    e2 = match(edge=E_GW, dst=WS) >> tag(IN_FLOWS) >> forward(FAB2)

    e3 = match(edge=E2, src=WS) >> tag(OUT_FLOWS) >> forward(FAB2)
    e4 = match(edge=E_GW, src=WS) >> tag(OUT_FLOWS) >> forward(FAB1)

    return e1 + e2 + e3 + e4

def transport_policy():

    f1 = catch(fabric=FAB1, src=E1, flow=IN_FLOWS) >> carry(dst=E_GW)
    f2 = catch(fabric=FAB2, src=E_GW, flow=IN_FLOWS) >> carry(dst=E2)
    f3 = catch(fabric=FAB2, src=E2, flow=OUT_FLOWS) >> carry(dst=E_GW)
    f4 = catch(fabric=FAB1, src=E_GW, flow=OUT_FLOWS) >> carry(dst=E1)

    return f1 + f2 + f3 + f4


def main():
    topology = virtual_network()
    in_network_functions = default_distribution_policy() + access_policies()
    transport_function = transport_policy()
    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
