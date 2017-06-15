# Import language primitives
from proto.language import *
# Import constants for all use cases
from constants import *

"""
  C01 ---|
  C02 ---|---[E1]---[ Fabric ]---[E2]--- WS
  C03 ---|

Policies:

- C01 <--> WS : allow ALL, no net function
- C02 <--> WS : allow ALL, data function on E1 (just for C02->WS)
- C03 <--> WS : allow ALL, dyn ctrl function on E1

"""

#Virtual topology
def virtual_network():

    topology = VTopology()
    topology.addFabric(FAB, 2)
    topology.addEdge(E1,4)
    topology.addEdge(E2,2)
    
    topology.addHost(WS)
    topology.addHost(C01)
    topology.addHost(C02)
    topology.addHost(C03)
    
    topology.addLink((E1,1),(C01,0))
    topology.addLink((E1,2),(C02,0))
    topology.addLink((E1,3),(C03,0))
    topology.addLink((E1,4),(FAB,1))
    
    topology.addLink((E2,1),(FAB,2))
    topology.addLink((E2,2),(WS,0))
    
    return topology


# ==========
# Policies
# ==========


# Network functions
# ------------------

packets_number = 0
@DataFct(limit=None)
def myDataFct(packet):

    global packets_number
    packets_number += 1
    print "--- Hit myDataFct {} ---".format(packets_number)
    return packet

@DynamicControlFct(data="packet", limit=1, split=["nw_src"])
def fakeAuthenticate(packet):
    ip = packet.find('ipv4')
    hostIP = ip.srcip.toStr()
    print "--- Fake authenticate of {} ---".format(hostIP)
    new_policy = ( match(edge=E1, nw_src=hostIP, dst=WS) >> tag("auth_flows") >> forward(FAB) )
        
    return new_policy


# Policies for each test client
# -----------------------------

# Edges can forward to their connected hosts or networks
def default_distribution_policy():
    
    e1 = match(edge=E1, dst=C01) >> forward(C01)
    e2 = match(edge=E1, dst=C02) >> forward(C02)
    e3 = match(edge=E1, dst=C03) >> forward(C03)
    e4 = match(edge=E2, dst=WS) >> forward(WS)

    return e1 + e2 + e3 + e4

# C01 policy
# C01 <--> WS : allow ALL, no net function
def c01_policy():

    # Tags
    C01_FLOW = "c01_flows"

    # Edges 
    e1 = match(edge=E1, src=C01, dst=WS) >> tag(C01_FLOW) >> forward(FAB)
    e2 = match(edge=E2, src=WS, dst=C01) >> tag(C01_FLOW) >> forward(FAB)
   
    # Fabric
    f1 = catch(fabric=FAB, src=E1, flow=C01_FLOW) >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow=C01_FLOW) >> carry(dst=E1)
    
    # Return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)


# C02 policy
# C02 <--> WS : allow ALL, data function on E1 (just for C02->WS)
def c02_policy():

    # Tags
    C02_FLOW = "c02_flows"

    # Edges 
    e1 = match(edge=E1, src=C02, dst=WS) >> tag(C02_FLOW) >> myDataFct() >> forward(FAB)
    e2 = match(edge=E2, src=WS, dst=C02) >> tag(C02_FLOW) >> forward(FAB)
   
    # Fabric
    f1 = catch(fabric=FAB, src=E1, flow=C02_FLOW) >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow=C02_FLOW) >> carry(dst=E1)
    
    # Return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)

# C03 policy
# C03 <--> WS : allow ALL, dyn ctrl function on E1
def c03_policy():

    # Tags
    C03_FLOW = "c03_flows"

    # Edges 
    e1 = match(edge=E1, src=C03, dst=WS) >> fakeAuthenticate()
    e2 = match(edge=E2, src=WS, dst=C03) >> tag(C03_FLOW) >> forward(FAB)
   
    # Fabric 
    f1 = catch(fabric=FAB, src=E1, flow="auth_flows") >> carry(dst=E2)
    f2 = catch(fabric=FAB, src=E2, flow=C03_FLOW) >> carry(dst=E1)
    
    # Return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)



# ===============
# Main function
# ===============
def main():

    topology = virtual_network()
    inf_base = default_distribution_policy()
    inf_01, tf_01 = c01_policy()
    inf_02, tf_02 = c02_policy()
    inf_03, tf_03 = c03_policy()

    in_net_fct_global = inf_base + inf_01 + inf_02 + inf_03
    transport_fct_global = tf_01 + tf_02 + tf_03
    
    return {"virtual_topology": topology, 
            "edge_policies": in_net_fct_global, 
            "fabric_policies": transport_fct_global}
