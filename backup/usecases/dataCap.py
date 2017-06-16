#Import language primitives
from proto.language import *
from airnet_lib import host_to_nwAddr
import pdb

"""
     client1--|                              
              |---[IO]---[ fabric ]---[AC]--|-- server
     client2--|                              

"""

data_threshold = 1000
hosts_data_amount = {}
hosts_permission = {}

#Network functions declaration
@DynamicControlFct(data="stat", every=60.0, limit=None)
def checkDataCap(stat, id):
    """
    every host can download at most 1000 bytes per 60 seconds 
    """
    checkDataCap.time[id] +=1
    print "time elapsed for "+ id + " == "+  str(checkDataCap.time[id]) + " minute(s)"
    try:
        if hosts_permission[stat.nw_dst] == "allow":
            hosts_data_amount[stat.nw_dst] = stat.byte_count - hosts_data_amount[stat.nw_dst] 
            if hosts_data_amount[stat.nw_dst] > data_threshold:
                hosts_permission[stat.nw_dst] = "deny"
                print stat.nw_dst + " has exceeded its data quota"
                print stat.nw_dst + " communications are blocked for 60 seconds"
                return (match(edge="IO", nw_dst=stat.nw_dst) >> drop)
            else:
                hosts_data_amount[stat.nw_dst] = stat.byte_count
        else:
            print stat.nw_dst + " can again use the network"
            hosts_data_amount[stat.nw_dst] = stat.byte_count
            hosts_permission[stat.nw_dst] = "allow"
            return (match(edge="IO", nw_dst=stat.nw_dst) >> forward(host_to_nwAddr(stat.nw_dst)))
    except KeyError:
        if stat.byte_count > data_threshold:
            hosts_permission[stat.nw_dst] = "deny"
            print stat.nw_dst + " has exceeded its data quota"
            print stat.nw_dst + " communications are blocked for 60 seconds"
            return (match(edge="IO", nw_dst=stat.nw_dst) >> drop)
        else:
            hosts_permission[stat.nw_dst] ="allow"
            hosts_data_amount[stat.nw_dst] = stat.byte_count
checkDataCap.time = {"fct1":0, "fct2":0} 


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
    i1 = match(edge=VID, dst="server") >> tag("in_web_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="client1")  >> (checkDataCap(id="fct1") + forward("client1"))
    i3 = match(edge=VID, dst="client2")  >> (checkDataCap(id="fct2") + forward("client2"))
    return i1 + i2 + i3

def AC_policy(VID):
    i1 = match(edge=VID, dst="server") >> forward("server")
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