from pox.core import core
from proto.language import *
from airnet_lib import host_dlAddr
import pdb
public_nw_addr = "10.0.0.50"
public_dl_addr = "00:26:55:42:9a:62"

"""
     client1--|
     client1--|                               |--- WS1
              |-----[IO]---[ fabric ]---[LB]--|
     client1--|                               |--- WS2
     client2--|                              
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
        new_policy = (match(edge="LB", nw_src=host_ip_src, nw_dst=public_nw_addr) >> 
                      modify(nw_dst="10.0.0.11") >> modify(dl_dst = WS1_dl_addr) >> forward("WS1"))
    else:
        print "flows coming from " + host_ip_src + " are redirected towards WS2 \n"
        new_policy = (match(edge="LB", nw_src=host_ip_src, nw_dst=public_nw_addr) >> 
                      modify(nw_dst="10.0.0.12") >> modify(dl_dst = WS2_dl_addr) >> forward("WS2"))
    return new_policy

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",2)
    topologie.addEdge("IO",5)
    topologie.addEdge("LB",3)
    topologie.addHost("client1")
    topologie.addHost("client2")
    topologie.addHost("client3")
    topologie.addHost("client4")
    topologie.addHost("WS1")
    topologie.addHost("WS2") 
    topologie.addLink(("IO",1),("client1",0))
    topologie.addLink(("IO",2),("client2",0))
    topologie.addLink(("IO",3),("client3",0))
    topologie.addLink(("IO",4),("client4",0))
    topologie.addLink(("IO",5),("fabric",1))
    topologie.addLink(("LB",1),("WS1",0))
    topologie.addLink(("LB",2),("WS2",0))
    topologie.addLink(("LB",3),("fabric",2))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, nw_dst=public_nw_addr) >> tag("in_web_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="client1")  >> forward("client1")
    i3 = match(edge=VID, dst="client2")  >> forward("client2")
    i4 = match(edge=VID, dst="client3")  >> forward("client3")
    i5 = match(edge=VID, dst="client4")  >> forward("client4")
    return i1 + i2 + i3 + i4 + i5

def LB_policy(VID):
    i1 = match(edge=VID, nw_src="192.168.0.0/16", nw_dst=public_nw_addr) >> Dynamic_LB() 
    i2 = match(edge=VID, src="WS1", nw_dst="192.168.0.0/16") >> modify(nw_src=public_nw_addr) >> modify(dl_src=public_dl_addr) >>tag("out_web_flows") >> forward("fabric")
    i3 = match(edge=VID, src="WS2", nw_dst="192.168.0.0/16") >> modify(nw_src=public_nw_addr) >>  modify(dl_src=public_dl_addr) >>tag("out_web_flows") >> forward("fabric") 
    return i1 + i2 + i3

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="in_web_flows") >> carry(dst="LB")
    t2 = catch(fabric=VID, src="LB", flow="out_web_flows") >> carry(dst="IO")
    return t1 + t2

#Main function
def main():
    in_network_functions = IO_policy("IO") + LB_policy("LB")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}