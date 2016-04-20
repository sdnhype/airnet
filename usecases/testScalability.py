# Import language primitives
from proto.language import *
# Import constants for all use cases
from constants import *

"""
        +++ FABRIC +++
       /    /   \     \
      /    /     \     \
   [E1]  [E2]   [E3]   [E4]
     |     |      |      |
    HA     HB     HC     HD
     

Policies (by app flows):

- HA <--> WD  : allow ICMP
- HB <--> WC  : allow ALL
- drop other

"""

#Virtual topology
def virtual_network():

    topology = VTopology()
    
    topology.addFabric(FAB, 4)
    topology.addEdge(E1,2)
    topology.addEdge(E2,2)
    topology.addEdge(E3,2)
    topology.addEdge(E4,2)
    
    topology.addHost(HA)
    topology.addHost(HB)
    topology.addHost(HC)
    topology.addHost(HD)
    
    topology.addLink((E1,1),(HA,0))
    topology.addLink((E1,2),(FAB,1))
    
    topology.addLink((E2,1),(HB,0))
    topology.addLink((E2,2),(FAB,2))

    topology.addLink((E3,1),(HC,0))
    topology.addLink((E3,2),(FAB,3))

    topology.addLink((E4,1),(HD,0))
    topology.addLink((E4,2),(FAB,4))
    
    return topology


# ==========
# Policies
# ==========

# Edges can forward to their connected hosts or networks
# --------------------------------------------------------
def default_distribution_policy():

    e1 = match(edge=E1, dst=HA) >> forward(HA)
    e2 = match(edge=E2, dst=HB) >> forward(HB)
    e3 = match(edge=E3, dst=HC) >> forward(HC)
    e4 = match(edge=E4, dst=HD) >> forward(HD)
    return e1 + e2 + e3 + e4


# Allow ALL HB <--> HC
# ---------------------
def hb_hc_policy():
    # Tags
    HB_HC_TAG_IN = "hb_hc_all_IN"
    HB_HC_TAG_OUT = "hb_hc_all_OUT"    
    # Edges
    e1 = match(edge=E2, src=HB,  dst=HC) >> tag(HB_HC_TAG_IN) >> forward(FAB)
    e2 = match(edge=E3, src=HC,  dst=HB) >> tag(HB_HC_TAG_OUT) >> forward(FAB)
    # Fabric
    f1 = catch(fabric=FAB, src=E2, flow=HB_HC_TAG_IN) >> carry(dst=E3)
    f2 = catch(fabric=FAB, src=E3, flow=HB_HC_TAG_OUT) >> carry(dst=E2)
    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)
	

# Allow ICMP HA <--> HD
# ---------------------
def ha_hd_policy():
	# Tags
    HA_HD_ICMP_IN = "ha_hd_icmp_in"
    HA_HD_ICMP_OUT = "ha_hd_icmp_out"

	# Edges
    e1 = match(edge=E1, src=HA, dst=HD, nw_proto=ICMP) >> tag(HA_HD_ICMP_IN) >> forward(FAB)
    e2 = match(edge=E4, src=HD, dst=HA, nw_proto=ICMP) >> tag(HA_HD_ICMP_OUT) >> forward(FAB)	
	 
	# Fabric
    f1 = catch(fabric=FAB, src=E1, flow=HA_HD_ICMP_IN) >> carry(dst=E4)
    f2 = catch(fabric=FAB, src=E4, flow=HA_HD_ICMP_OUT) >> carry(dst=E1)
	
	# return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)

# ===============
# Main function
# ===============
def main():

    topology = virtual_network()
    inf_base = default_distribution_policy()
    inf_01, tf_01 = hb_hc_policy()
    inf_02, tf_02 = ha_hd_policy()

    in_net_fct_global = inf_base + inf_01 + inf_02
    transport_fct_global = tf_01 + tf_02
    
    return {"virtual_topology": topology, 
            "edge_policies": in_net_fct_global, 
            "fabric_policies": transport_fct_global}
