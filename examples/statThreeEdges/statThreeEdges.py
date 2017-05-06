from language import *
from names import *
import datetime

"""
* Virtual topo

    A --+                        +-- G
    B --+-- [E1]---[FAB]---[E3]--+-- H
    C --+            |           +-- I
                    [E2]
                     |
                  +--+--+
                  |  |  |
                  D  E  F

* Virtual Policies

    - Distributed packets to A, B, C on E1
    - Distributed packets to D, E, F on E2
    - Distributed packets to G, H, I on E3

TODO...

"""

# =================
# Virtual topology
# =================
def virtual_network():

    topo = VTopology()

    topo.addFabric(FAB, 3)
    topo.addEdge(E1, 4)
    topo.addEdge(E2, 4)
    topo.addEdge(E3, 4)

    topo.addHost(A)
    topo.addHost(B)
    topo.addHost(C)
    topo.addHost(D)
    topo.addHost(E)
    topo.addHost(F)
    topo.addHost(G)
    topo.addHost(H)
    topo.addHost(I)

    topo.addLink((E1, 1), (A, 0))
    topo.addLink((E1, 2), (B, 0))
    topo.addLink((E1, 3), (C, 0))
    topo.addLink((E1, 4), (FAB, 1))
    topo.addLink((E2, 1), (D, 0))
    topo.addLink((E2, 2), (E, 0))
    topo.addLink((E2, 3), (F, 0))
    topo.addLink((E2, 4), (FAB, 2))
    topo.addLink((E2, 1), (G, 0))
    topo.addLink((E2, 2), (H, 0))
    topo.addLink((E2, 3), (I, 0))
    topo.addLink((E2, 4), (FAB, 3))

    return topo

# ==========
# Policies
# ==========

# ============================================================================
# STATIC POLICIES
# ============================================================================

# Generic distribution policy
"""
def distribute(VID, destination):
    p = match(edge=VID, dst=destination) >> (saveStat() + forward(destination))
    return p
"""
# Generic MAC distribution policy
def distribute_mac(VID, destination):
    #p = match(edge=VID, dl_dst=(globals()["MAC_"+destination])) >> (forward(destination) + saveStat())
    p = match(edge=VID, dl_dst=(globals()["MAC_"+destination])) >> forward(destination)
    return p
"""
# Distribute traffic to the different members connected to the 3 edges
def distribute_edges():
    distribute_e1 = distribute(E1, A) + distribute(E1, B) + distribute(E1, C)
    distribute_e2 = distribute(E2, D) + distribute(E2, E) + distribute(E2, F)
    distribute_e3 = distribute(E3, G) + distribute(E3, H) + distribute(E3, I)
    return distribute_e1 + distribute_e2 + distribute_e3
"""
# Distribute traffic (BASED ON MAC @) to the different members connected to the 3 edges
def distribute_mac_edges():
    distribute_e1 = distribute_mac(E1, A) + distribute_mac(E1, B) + distribute_mac(E1, C)
    distribute_e2 = distribute_mac(E2, D) + distribute_mac(E2, E) + distribute_mac(E2, F)
    distribute_e3 = distribute_mac(E3, G) + distribute_mac(E3, H) + distribute_mac(E3, I)
    return distribute_e1 + distribute_e2 + distribute_e3


# Generic tagging policy
def set_tag(VID, destination, label):
    # p = match(edge=VID, dst=destination) >> tag(label) >> forward(FAB)
    p = match(edge=VID, dl_dst=(globals()["MAC_"+destination])) >> tag(label) >> forward(FAB)
    return p

# Tag traffic according to final destination
def tag_edges():

    tag_a = set_tag(E2, A, FOR_A) + set_tag(E3, A, FOR_A)
    tag_b = set_tag(E2, B, FOR_B) + set_tag(E3, B, FOR_B)
    tag_c = set_tag(E2, C, FOR_C) + set_tag(E3, C, FOR_C)

    tag_d = set_tag(E1, D, FOR_D) + set_tag(E3, D, FOR_D)
    tag_e = set_tag(E1, E, FOR_E) + set_tag(E3, E, FOR_E)
    tag_f = set_tag(E1, F, FOR_F) + set_tag(E3, F, FOR_F)

    tag_g = set_tag(E2, G, FOR_G) + set_tag(E1, G, FOR_G)
    tag_h = set_tag(E2, H, FOR_H) + set_tag(E1, H, FOR_H)
    tag_i = set_tag(E2, I, FOR_I) + set_tag(E1, I, FOR_I)

    return tag_a + tag_b + tag_c + tag_d + tag_e + tag_f + tag_g + tag_h + tag_i

# Generic transport policy
def transport(tag, from_edge, to_edge):
    t = catch(fabric=FAB, src=from_edge, flow=tag) >> carry(dst=to_edge)
    return t

# Transport policies wihtin the fabric
def fabric_policies():
    t1 = transport(FOR_A, E2, E1) + transport(FOR_A, E3, E1)
    t2 = transport(FOR_B, E2, E1) + transport(FOR_B, E3, E1)
    t3 = transport(FOR_C, E2, E1) + transport(FOR_C, E3, E1)
    t4 = transport(FOR_D, E1, E2) + transport(FOR_D, E3, E2)
    t5 = transport(FOR_E, E1, E2) + transport(FOR_E, E3, E2)
    t6 = transport(FOR_F, E1, E2) + transport(FOR_F, E3, E2)
    t7 = transport(FOR_G, E1, E3) + transport(FOR_G, E2, E3)
    t8 = transport(FOR_H, E1, E3) + transport(FOR_G, E2, E3)
    t9 = transport(FOR_I, E1, E3) + transport(FOR_G, E2, E3)
    return t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9


# ============================================================================
# DYNAMIC CONTROL POLICIES
# ============================================================================

@DynamicControlFct(data="stat", every=30.0)
def saveStat( stat ):
    # Open log file
    logFile = open("log/statsLog_ThreeEdges.txt", 'a')
    time = datetime.datetime.now()
    #logFile.write('[%s] dl_dst  %s | packet count %s | byte count %s\n' % (time, stat.dl_dst, stat.packet_count,stat.byte_count))
    logFile.write('[%s] dl_src %s dl_dst  %s | packet count %s | byte count %s\n' % (time, stat.dl_src,stat.dl_dst, stat.packet_count,stat.byte_count))
    logFile.close()
    return identity


# Generic statistics policy
def edgeStatForX(oneEdge, oneDestination):
    p = []
    for x in "ABCDEFGHI":
        if x == oneDestination.upper():
            continue
        p.append(match(edge=oneEdge, dl_dst=(globals()["MAC_"+oneDestination]), dl_src=(globals()["MAC_"+x])) >> saveStat())

    p1,p2,p3,p4,p5,p6,p7,p8 = p

    return p1 + p2 + p3 + p4 + p5 + p6 + p7 + p8

def statPolicy():
    #s1 = edgeStatForX(E1, A)
    s1 = edgeStatForX(E1, A) + edgeStatForX(E1, B) + edgeStatForX(E1, C)
    s2 = edgeStatForX(E2, D) + edgeStatForX(E2, E) + edgeStatForX(E2, F)
    s3 = edgeStatForX(E3, G) + edgeStatForX(E3, H) + edgeStatForX(E3, I)
    return s1 + s2 + s3


# ============================================================================
# Main function
# ============================================================================
def main():

    topology = virtual_network()
    #all_edges = distribute_edges() + tag_edges()
    all_edges = distribute_mac_edges() + tag_edges() + statPolicy()
    all_fabric = fabric_policies()

    return {"virtual_topology": topology,
            "edge_policies": all_edges,
            "fabric_policies": all_fabric}
