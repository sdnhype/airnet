# Import language primitives
from language import *
# Import constants for all use cases
from constants import *

"""

    HOST_A----[E1]---[ Fabric ]---[E2]----HOST_C
               |
    HOST_B-----+

Policies (by network flows):

ALLOW ICMP between HOST_A and HOST_C
ALLOW ICMP between HOST_B and HOST_C
ALLOW HTTP between HOST_A and HOST_C
DENY others

"""

# Virtual topology
def virtual_network():

    topology = VTopology()
    topology.addFabric(FAB, 2)
    topology.addEdge(E1,2)
    topology.addEdge(E2,2)

    topology.addHost(HA)
    topology.addHost(HB)
    topology.addHost(HC)

    topology.addLink((E1,1),(HA,0))
    topology.addLink((E1,2),(HB,0))
    topology.addLink((E1,3),(FAB,1))
    topology.addLink((E2,1),(HC,0))
    topology.addLink((E2,2),(FAB,2))

    return topology

# ==========
# Policies
# ==========

# Egress edge policies (edges can forward to their connected hosts or networks)
def egress_policies():

    e1 = match(edge=E1, dst=HA) >> forward(HA)
    e2 = match(edge=E1, dst=HB) >> forward(HB)
    e3 = match(edge=E2, dst=HC) >> forward(HC)
    return e1 + e2 + e3

# Ingress edge policies (flows entering the fabric)
def ingress_policies():
    # ICMP
    e1 = match(edge=E1, dst=HC, nw_proto=ICMP) >> tag(ICMP_IN)  >> forward(FAB)
    e2 = match(edge=E2, dst=HA, nw_proto=ICMP) >> tag(ICMP_OUT) >> forward(FAB)
    e3 = match(edge=E2, dst=HB, nw_proto=ICMP) >> tag(ICMP_OUT) >> forward(FAB)
    # HTTP
    e4 = match(edge=E1, src=HA, dst=HC, nw_proto=TCP, tp_dst=HTTP) >> tag(HTTP_IN) >> forward(FAB)
    e5 = match(edge=E2, src=HC, dst=HA, nw_proto=TCP, tp_src=HTTP) >> tag(HTTP_OUT) >> forward(FAB)
    return e1 + e2 + e3 + e4 + e5

# Fabric policies
def transport_policies():

    f1 = catch(fabric=FAB, src=E1, flow=ICMP_IN)  >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow=ICMP_OUT) >> carry(dst=E1)
    f3 = catch(fabric=FAB, src=E1, flow=HTTP_IN)  >> carry(dst=E2)
    f4 = catch(fabric=FAB, src=E2, flow=HTTP_OUT) >> carry(dst=E1)
    return f1 + f2 + f3 + f4

# ===============
# Main function
# ===============
def main():

    topology = virtual_network()
    in_network_functions = egress_policies() + ingress_policies()
    transport_functions = transport_policies()

    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_functions}
