#Import language primitives
from proto.language import *
import pdb

"""
     client1--|                              
              |---[IO]---[ fabric ]---[AC]--|-- server
     client2--|                              

"""

#Network functions declaration
@DataFct(split=['nw_src'], limit=None)
def compress(packet):
    ip = packet.find('ipv4')
    try:
        compress.nb_packets[ip.srcip.toStr()] += 1
    except KeyError:
        compress.nb_packets[ip.srcip.toStr()] = 1
    print "--- compress function ---"
    print "packet ip_src: " + ip.srcip.toStr()  + " | packet ip_dst: " + ip.dstip.toStr()
    print "nb packets from " + ip.srcip.toStr() + " == " + str(compress.nb_packets[ip.srcip.toStr()])  
    print "ip header size == " + str(ip.iplen) + " bytes"
    print "compressing ..."
    ip.ttl = 20
    print "new ip header size " + str(ip.ttl) + " bytes \n" 
    return packet
compress.nb_packets = {}

@DataFct(split=None, limit=None)
def uncompress(packet):
    ip = packet.find('ipv4')
    try:
        uncompress.nb_packets[ip.srcip.toStr()] += 1
    except KeyError:
        uncompress.nb_packets[ip.srcip.toStr()] = 1
    print "--- uncompress function ---"
    print "packet ip_src: " + ip.srcip.toStr()  + " | packet ip_dst: " + ip.dstip.toStr()
    print "nb packets from " + ip.srcip.toStr() + " == " + str(uncompress.nb_packets[ip.srcip.toStr()])  
    print "ip header size == " + str(ip.ttl) + " bytes"
    print "uncompressing ..."
    ip.ttl = ip.iplen
    print "new ip header size size " + str(ip.ttl) + " bytes \n"
    return packet
uncompress.nb_packets = {}

#Virtual topology
def virtual_network():
    topologie = VTopology()
    topologie.addFabric("fabric",2)
    topologie.addEdge("IO",3)
    topologie.addEdge("AC",2)
    topologie.addHost("client1")
    topologie.addHost("client2")
    topologie.addHost("server")
    topologie.addLink(("IO",1),("client1",0))
    topologie.addLink(("IO",3),("client2",0))
    topologie.addLink(("IO",2),("fabric",1))
    topologie.addLink(("AC",1),("server",0))
    topologie.addLink(("AC",2),("fabric",2))
    return topologie

#Policies
def IO_policy(VID):
    i1 = match(edge=VID, dst="server") >> tag("in_web_flows") >> compress() >> forward("fabric")
    i2 = match(edge=VID, dst="client1")  >> forward("client1")
    i3 = match(edge=VID, dst="client2")  >> forward("client2")
    return i1 + i2 + i3

def AC_policy(VID):
    i1 = match(edge=VID, dst="server") >> uncompress() >> forward("server")
    i2 = match(edge=VID, src="server") >> tag("out_web_flows") >> forward("fabric") 
    return i1 + i2

def fabric_policy(VID):
    t1 = catch(fabric=VID, src="IO", flow="in_web_flows") >> carry(dst="AC")
    t2 = catch(fabric=VID, src="AC", flow="out_web_flows") >> carry(dst="IO")
    return t1 + t2

#Main function
def main():
    in_network_functions = IO_policy("IO") + AC_policy("AC")
    transport_function = fabric_policy("fabric")
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}