# Import language primitives
from language import *
# Import constants for all use cases
from constants import *
import datetime

"""

- HOST_A     ----[E1]---[ Fabric ]---[E2]----      HOSt_B -

Policies (by app flows):

ALLOW ICMP HOST_A to HOSt_B
ALLOW ICMP HOST_B to HOSt_A


"""
@DynamicControlFct(data="stat", every=10.0, limit="none")
def saveStat( stat ):
    # Open log file
    logFile = open("log/statsLog.txt", 'a')
    time = datetime.datetime.now()
    logFile.write('[%s] nw_dst %s | packet count %s byte count %s\n' % (time, stat.nw_dst, stat.packet_count, stat.byte_count))
    logFile.close()
    # the following instructions are useless
    if stat.packet_count > 5:
        policy = (match(edge=E2, dst=HA, nw_proto=ICMP) >> tag("too_much_icmp_replies") >> forward(FAB))
        return policy

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
    e2 = match(edge=E2, dst=HB) >> (saveStat() + forward(HB))
    return e1 + e2


def access_policies():

    e1 = match(edge=E1, dst=HB, nw_proto=ICMP) >> tag("icmp_in") >> forward(FAB)
    e2 = match(edge=E2, dst=HA, nw_proto=ICMP) >> tag("icmp_out") >> forward(FAB)

    return e1 + e2

def transport_policy():

    f1 = catch(fabric=FAB, src=E1, flow="icmp_in") >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow="icmp_out") >> carry(dst=E1)

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
