#  
#  VIRTUAL NETWORK
#
#  Convention: {network}, [Host], (Edge), +Fabric+
#
#                                 (MB)
#                                  |
#       {Internet} -- (INOUT) -- +Fab+ -- (MyServers) -- [Web_Server]
#                                                     -- [Priv_Server]
#



from proto.language import *


# virtual topology
def virtual_network():
    # need to add hosts into virtual topology definition
    topologie = VTopology()

    topologie.addNetwork("internet")
    topologie.addHost("web_server")
    topologie.addHost("priv_server")
    
    topologie.addEdge("inout",2)
    topologie.addEdge("mb",2)
    topologie.addEdge("myservers",3)
    
    topologie.addFabric("fabric",3)
    
    topologie.addLink(("fabric",1),("inout",1))
    topologie.addLink(("fabric",2),("mb",1))
    topologie.addLink(("fabric",3),("myservers",1))
    topologie.addLink(("internet",0),("inout",2))
    topologie.addLink(("myservers",2),("web_server",0))
    topologie.addLink(("myservers",3),("priv_server",0))
    
    return topologie


def inout_policy(VIdentifier):
    e1 = match(edge=VIdentifier, nw_dst="web_server", tp_dst=80) >> tag("web_flows_in") >> forward("fabric")
    e2 = match(edge=VIdentifier, nw_dst="priv_server", tp_dst=22) >> tag("ssh_flows_in") >> forward("fabric")
    e3 = match(edge=VIdentifier, nw_dst="internet") >> forward("internet")
    return e1 + e2 + e3

def mb_policy(VIdentifier):
    e1 = match(edge=VIdentifier, flow="web_flows_in") >> nfv("web_app_fw") >> tag("web_flows_in_processed") >> forward("fabric")
    e2 = match(edge=VIdentifier, flow="web_flows_out") >> nfv("web_app_fw") >> tag("web_flows_out_processed") >> forward("fabric")
    return e1 + e2

def myservers_policy(VIdentifier):
    e1 = match(edge=VIdentifier, nw_dst="web_server") >> forward("web_server")
    e2 = match(edge=VIdentifier, nw_src="web_server", tp_src=80) >> tag("web_flows_out") >> forward("fabric")
    # note pour e2, j'étais tenté de mettre >> fw("mb") directement ! idem e4, aie...
    e3 = match(edge=VIdentifier, nw_dst="priv_server") >> forward("priv_server")
    e4 = match(edge=VIdentifier, nw_src="priv_server", tp_src=22) >> tag("ssh_flows_out") >> forward("fabric")
    return e1 + e2 + e3 + e4

def fabric_policy():
    f1 = catch(fabric="fabric", flow="web_flows_in") >> carry("mb")
    f2 = catch(fabric="fabric", flow="web_flows_in_processed") >> carry("myservers")
    f3 = catch(fabric="fabric", flow="web_flows_out") >> carry("mb")
    f4 = catch(fabric="fabric", flow="web_flows_out_processed") >> carry("inout")
    f5 = catch(fabric="fabric", flow="ssh_flows_in") >> carry("myservers")
    f6 = catch(fabric="fabric", flow="ssh_flows_out") >> carry("inout")
    return f1 + f2 + f3 + f4 + f5 + f6

def main():
    in_network_functions = inout_policy("inout") + mb_policy("mb") + myservers_policy("myservers") 
    transport_function = fabric_policy()
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}  

