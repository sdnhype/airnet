from proto.language import *
from constants import *

"""
NETA------E1-----FAB1------E2-----WS
          
C01-------E3-----FAB2------E4-----SSH_GW

mapping: twoFabrics_mapping_ter (topo_2_fabrics_ter.py)
"""

WEB_FLOWS = "Web_Flows"
ICMP_FLOWS = "ICMP_FLOWS"


@DataFct(split=['nw_src'], limit=None)
def monitor(packet):
    ip = packet.find('ipv4')
    print "packet ip_src: " + ip.srcip.toStr()  + " | packet ip_dst: " + ip.dstip.toStr()
    return packet


# virtual topology
def virtual_network():
    topo = VTopology()
    
    #Network1
    topo.addEdge(E1, 2)
    topo.addEdge(E2, 2)
    topo.addFabric(FAB1, 2)
    topo.addNetwork(NETA)
    topo.addHost(WS)
    topo.addLink((E1, 1),(NETA, 0))
    topo.addLink((E1, 2),(FAB1, 1))
    topo.addLink((E2, 1),(WS, 0))
    topo.addLink((E2, 2),(FAB1, 2))
    
    #Network2
    topo.addEdge(E3, 2)
    topo.addEdge(E4, 2)
    topo.addFabric(FAB2, 2)
    topo.addHost(C01)
    topo.addHost(SSH_GW)
    topo.addLink((E3, 1),(C01, 0))
    topo.addLink((E3, 2),(FAB2, 1))
    topo.addLink((E4, 1),(SSH_GW, 0))
    topo.addLink((E4, 2),(FAB2, 2))
    
    return topo

def network1_policy():
    e1 = match(edge=E1, dst=NETA) >> forward(NETA)
    e2 = match(edge=E2, dst=WS) >> forward(WS)
    e3 = match(edge=E1, src=NETA, dst=WS, nw_proto=TCP, tp_dst=HTTP) >> tag(WEB_FLOWS) >> forward(FAB1)
    e4 = match(edge=E2, src=WS, dst=NETA, nw_proto=TCP, tp_src=HTTP) >> tag(WEB_FLOWS) >> forward(FAB1)
    
    f1 = catch(fabric=FAB1, src=E1, flow=WEB_FLOWS) >> carry(dst=E2)
    f2 = catch(fabric=FAB1, src=E2, flow=WEB_FLOWS) >> carry(dst=E1)
    
    return (e1+e2+e3+e4, f1+f2)

def network2_policy():
    
    e1 = match(edge=E3, dst=C01) >> forward(C01)
    e2 = match(edge=E4, dst=SSH_GW) >> forward(SSH_GW)
    e3 = match(edge=E3, src=C01, dst=SSH_GW, nw_proto=ICMP) >> tag(ICMP_FLOWS) >> forward(FAB2)
    e4 = match(edge=E4, src=SSH_GW, dst=C01, nw_proto=ICMP) >> tag(ICMP_FLOWS) >> forward(FAB2)
    
    f1 = catch(fabric=FAB2, src=E3, flow=ICMP_FLOWS) >>carry(dst=E4)
    f2 = catch(fabric=FAB2, src=E4, flow=ICMP_FLOWS) >> carry(dst=E3)
    
    return (e1+e2+e3+e4, f1+f2)

def main():
    topology = virtual_network()
    net1_acs, net1_tp = network1_policy()
    net2_acs, net2_tp = network2_policy() 
    return {"virtual_topology": topology, 
            "edge_policies": (net1_acs + net2_acs), 
            "fabric_policies": (net1_tp + net2_tp)}  

