from proto.language import *
from constants import *

"""
TODO:
"""

WEB_FLOWS = "Web_Flows"
ICMP_FLOWS = "ICMP_FLOWS"

# virtual topology
def virtual_network():
    topo = VTopology()
    topo.addFabric("FAB", 2)
    topo.addEdge("E1", 5)
    topo.addEdge("E2", 3)
    topo.addHost("C1")
    topo.addHost("C2")
    topo.addHost("C3")
    topo.addHost("C4")
    topo.addHost("WS1")
    topo.addHost("WS2")
    topo.addLink(("E1", 1),("C1", 0))
    topo.addLink(("E1", 2),("C2", 0))
    topo.addLink(("E1", 3),("C3", 0))
    topo.addLink(("E1", 4),("C3", 0))
    topo.addLink(("E1", 5),("FAB", 1))
    topo.addLink(("E2", 1),("FAB", 2))
    topo.addLink(("E2", 2),("WS1", 0))
    topo.addLink(("E2", 3),("WS2", 0))
    return topo

def default_distribution_policy():
    e1 = match(edge="E1", dst="C1") >> forward("C1")
    e2 = match(edge="E2", dst="WS1") >> forward("WS1")
    #e3 = match(edge="E1", dst="C2") >> forward("C2")
    #e4 = match(edge="E2", dst="WS2") >> forward("WS2")
    #e5 = match(edge="E1", dst="C3") >> forward("C3")
    #e6 = match(edge="E1", dst="C4") >> forward("C4")
    return e1+e2#+e3#+e4#+e5#+e6

def access_policies():
    
    e1 = match(edge="E1", src="C1", dst="WS1") >> tag("C1_WS1_IN") >> forward("FAB")
    e2 = match(edge="E2", src="WS1", dst="C1") >> tag("C1_WS1_OUT") >> forward("FAB")
    #e3 = match(edge="E1", src="C2", dst="WS1") >> tag("C2_WS1_IN") >> forward("FAB")
    #e4 = match(edge="E2", src="WS1", dst="C2") >> tag("C2_WS1_OUT") >> forward("FAB")
    
    #e5 = match(edge="E1", src="C1", dst="WS2") >> tag("C1_WS2_IN") >> forward("FAB")
    #e6 = match(edge="E2", src="WS2", dst="C1") >> tag("C1_WS2_OUT") >> forward("FAB")
    #e7 = match(edge="E1", src="C2", dst="WS2") >> tag("C2_WS2_IN") >> forward("FAB")
    #e8 = match(edge="E2", src="WS2", dst="C2") >> tag("C2_WS2_OUT") >> forward("FAB")
    
    #e9 = match(edge="E1", src="C3", dst="WS1") >> tag("C3_WS1_IN") >> forward("FAB")
    #e10 = match(edge="E2", src="WS1", dst="C3") >> tag("C3_WS1_OUT") >> forward("FAB")
    #e11 = match(edge="E1", src="C3", dst="WS2") >> tag("C3_WS2_IN") >> forward("FAB")
    #e12 = match(edge="E2", src="WS2", dst="C3") >> tag("C3_WS2_OUT") >> forward("FAB")
    
    #e13 = match(edge="E1", src="C4", dst="WS1") >> tag("C4_WS1_IN") >> forward("FAB")
    #e14 = match(edge="E2", src="WS1", dst="C4") >> tag("C4_WS1_OUT") >> forward("FAB")
    #e15 = match(edge="E1", src="C4", dst="WS2") >> tag("C4_WS2_IN") >> forward("FAB")
    #e16 = match(edge="E2", src="WS2", dst="C4") >> tag("C4_WS2_OUT") >> forward("FAB")
    
    return e1+e2#+e3+e4#+e5+e6+e7+e8#+e9+e10+e11+e12#+e13+e14+e15+e16

def transport_policy():
    
    f1 = catch(fabric="FAB", src="E1", flow="C1_WS1_IN") >> carry(dst="E2")
    f2 = catch(fabric="FAB", src="E2", flow="C1_WS1_OUT") >> carry(dst="E1")
    #f3 = catch(fabric="FAB", src="E1", flow="C2_WS1_IN") >> carry(dst="E2")
    #f4 = catch(fabric="FAB", src="E2", flow="C2_WS1_OUT") >> carry(dst="E1")
    
    #f5 = catch(fabric="FAB", src="E1", flow="C1_WS2_IN") >> carry(dst="E2")
    #f6 = catch(fabric="FAB", src="E2", flow="C1_WS2_OUT") >> carry(dst="E1")
    #f7 = catch(fabric="FAB", src="E1", flow="C2_WS2_IN") >> carry(dst="E2")
    #f8 = catch(fabric="FAB", src="E2", flow="C2_WS2_OUT") >> carry(dst="E1")
    
    #f9 = catch(fabric="FAB", src="E1", flow="C3_WS1_IN") >> carry(dst="E2")
    #f10 = catch(fabric="FAB", src="E2", flow="C3_WS1_OUT") >> carry(dst="E1")
    #f11 = catch(fabric="FAB", src="E1", flow="C3_WS2_IN") >> carry(dst="E2")
    #f12 = catch(fabric="FAB", src="E2", flow="C3_WS2_OUT") >> carry(dst="E1")
    
    #f13 = catch(fabric="FAB", src="E1", flow="C4_WS1_IN") >> carry(dst="E2")
    #f14 = catch(fabric="FAB", src="E2", flow="C4_WS1_OUT") >> carry(dst="E1")
    #f15 = catch(fabric="FAB", src="E1", flow="C4_WS2_IN") >> carry(dst="E2")
    #f16 = catch(fabric="FAB", src="E2", flow="C4_WS2_OUT") >> carry(dst="E1")
    
    return f1+f2#+f3+f4#+f5+f6+f7+f8#+f9+f10+f11+f12#+f13+f14+f15+f16


def main():
    topology = virtual_network()
    in_network_functions = default_distribution_policy() + access_policies()
    transport_function = transport_policy() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}  

