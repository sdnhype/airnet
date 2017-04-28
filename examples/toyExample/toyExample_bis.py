# Import language primitives
from language import *
# Import constants for all use cases
from constants import *

"""

- HOST_A     ----[E1]---[ Fabric ]---[E2]----      HOSt_B -

Policies (we test composition here):

DENY HTTP from HOST_A
ALLOW HOST_A to communicate with HOST_B

INTERSECTION here is HOST_A sending HTTP Request to HOST_B


"""

#Virtual topology
def virtual_network():

    topology = VTopology()
    topology.addFabric(FAB, 2)
    topology.addEdge(E1,2)
    topology.addEdge(E2,2)

    topology.addHost(HA)
    topology.addHost(HB)

    topology.addLink((E1,1),(HA,0))
    topology.addLink((E1,2),(FAB,1))
    topology.addLink((E2,1),(HB,0))
    topology.addLink((E2,2),(FAB,2))

    return topology


# ==========
# Policies
# ==========

# Edges can forward to their connected hosts or networks
def default_distribution_policy():

    e1 = match(edge=E1, dst=HA) >> forward(HA)
    e2 = match(edge=E2, dst=HB) >> forward(HB)
    return e1 + e2


def access_policies():

    e1 = match(edge=E1, dst=HB) >> tag("flow_in") >> forward(FAB)
    e2 = match(edge=E1, src=HA, tp_dst=80) >> drop
    e3 = match(edge=E2, dst=HA) >> tag("flow_out") >> forward(FAB)

    return e1 + e2 + e3

def transport_policy():

    f1 = catch(fabric=FAB, src=E1, flow="flow_in") >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow="flow_out") >> carry(dst=E1)

    return f1 + f2
# ===============
# Main function
# ===============
def main():

    topology = virtual_network()
    inf_base = default_distribution_policy()
    in_network_functions = default_distribution_policy() + access_policies()
    transport_function = transport_policy()

    return {"virtual_topology": topology,
            "edge_policies": in_network_functions,
            "fabric_policies": transport_function}
