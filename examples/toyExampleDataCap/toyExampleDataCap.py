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
data_threshold = 1000
hosts_data_amount = {}
hosts_permission = {}

@DynamicControlFct(data="stat", every=10, limit="none")
def dataCap(stat):
    """
        HOST_A can download at most 1000 bytes per 60 seconds
    """
    dataCap.time +=1
    print "Time == "+str(dataCap.time)+" minute(s)"
    try:
        if hosts_permission[stat.nw_dst] == "allow":
            hosts_data_amount[stat.nw_dst] = stat.byte_count - hosts_data_amount[stat.nw_dst]
            if hosts_data_amount[stat.nw_dst] > data_threshold:
                hosts_permission[stat.nw_dst] = "deny"
                print stat.nw_dst + " has exceeded its data quota"
                print stat.nw_dst + " communications are blocked for 60 seconds"
                return (match(edge="E1", nw_dst=stat.nw_dst) >> drop)
            else:
                hosts_data_amount[stat.nw_dst] = stat.byte_count
        else:
            print stat.nw_dst + " can again use the network"
            hosts_data_amount[stat.nw_dst] = stat.byte_count
            hosts_permission[stat.nw_dst] = "allow"
            return (match(edge="E1", nw_dst=stat.nw_dst) >> forward(HA))

    except KeyError:
        if stat.byte_count > data_threshold:
            hosts_permission[stat.nw_dst] = "deny"
            print stat.nw_dst + " has exceeded its data quota"
            print stat.nw_dst + " communications are blocked for 60 seconds"
            return (match(edge="E1", nw_dst=stat.nw_dst) >> drop)
        else:
            hosts_permission[stat.nw_dst] ="allow"
            hosts_data_amount[stat.nw_dst] = stat.byte_count

dataCap.time = 0

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

    e1 = match(edge=E1, dst=HA) >> (dataCap() + forward(HA))
    e2 = match(edge=E2, dst=HB) >> forward(HB)
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
