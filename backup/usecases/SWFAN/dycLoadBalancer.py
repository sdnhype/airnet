from pox.core import core
from proto.language import *
from airnet_lib import host_dlAddr
import pdb
public_nw_addr = "10.0.0.50"
public_dl_addr = "00:26:55:42:9a:62"

"""
TODO:                            
"""
#Network function declaration
@DynamicControlFct(data="packet", split=["nw_src"], limit=1)
def Dynamic_LB(packet):
    WS1_dl_addr = host_dlAddr("WS1")
    WS2_dl_addr = host_dlAddr("WS2")
    ip = packet.find('ipv4')
    host_ip_src = ip.srcip.toStr()
    tocken = int(ip.srcip.toStr()[-2:]) % 2
    if tocken == 1:
        print "flows coming from " + host_ip_src + " are redirected towards WS1 \n" 
        new_policy = (match(edge="IO", nw_src=host_ip_src, nw_dst=public_nw_addr) >> 
                      modify(nw_dst="10.13.0.13") >> modify(dl_dst = WS1_dl_addr) >> tag("in_web_flows") >> forward("fabric"))
    else:
        print "flows coming from " + host_ip_src + " are redirected towards WS2 \n"
        new_policy = (match(edge="IO", nw_src=host_ip_src, nw_dst=public_nw_addr) >> 
                      modify(nw_dst="10.14.0.14") >> modify(dl_dst = WS2_dl_addr) >> tag("in_web_flows") >> forward("fabric"))
    return new_policy

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",2)
    topologie.addEdge("IO",3)
    topologie.addEdge("AC",3)
    topologie.addNetwork("Net.A")
    topologie.addNetwork("Net.B")
    topologie.addHost("WS1")
    topologie.addHost("WS2") 
    topologie.addLink(("IO",1),("Net.A",0))
    topologie.addLink(("IO",2),("Net.B",0))
    topologie.addLink(("IO",5),("fabric",1))
    topologie.addLink(("AC",1),("WS1",0))
    topologie.addLink(("AC",2),("WS2",0))
    topologie.addLink(("AC",3),("fabric",2))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, nw_dst=public_nw_addr) >> Dynamic_LB()
    i2 = match(edge=VID, dst="Net.A")  >> forward("Net.A")
    i3 = match(edge=VID, dst="Net.B")  >> forward("Net.B")
    return i1 + i2 + i3

def LB_policy(VID):
    i1 = match(edge=VID, dst="WS1") >> forward("WS1")
    i2 = match(edge=VID, dst="WS2") >> forward("WS2") 
    i3 = match(edge=VID, src="WS1") >> modify(nw_src=public_nw_addr) >> modify(dl_src=public_dl_addr) >>tag("out_web_flows") >> forward("fabric")
    i4 = match(edge=VID, src="WS2") >> modify(nw_src=public_nw_addr) >>  modify(dl_src=public_dl_addr) >>tag("out_web_flows") >> forward("fabric") 
    return i1 + i2 + i3 + i4

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="in_web_flows") >> carry(dst="AC")
    t2 = catch(fabric=VID, src="AC", flow="out_web_flows") >> carry(dst="IO")
    return t1 + t2

#Main function
def main():
    in_network_functions = IO_policy("IO") + LB_policy("AC")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}