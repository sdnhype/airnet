from language import *

"""

* Virtual topo:

----------
staff_net-|---|
----------    |
              |---[users_IO]----|
----------    |                 |                                
guests_net-|--|                 |                                   |--- WS1
----------                      |              |---[users_egress]---|
                                |---[fabric]---|                    |--- WS2
-----------                     |              |
admins_net-|-----[admins_IO]----|              |---[admins_egress]--- DB
-----------

* Policies

    admins_net <--> DB   FWD ALL FLOWS
    staff_net  <--> WS1  FWD ALL FLOWS
    guests_net <--> WS2  FWD ALL FLOWS


"""


# virtual topology
def virtual_network():
    topo = VTopology()
    topo.addFabric("fabric", 4)
    topo.addEdge("users_IO", 3)
    topo.addEdge("admins_IO", 2)
    topo.addEdge("admins_egress", 2)
    topo.addEdge("users_egress", 3)
    topo.addHost("WS1")
    topo.addHost("WS2")
    topo.addHost("DB")
    topo.addNetwork("staff_net")
    topo.addNetwork("guests_net")
    topo.addNetwork("admins_net")
    topo.addLink(("users_IO", 1),("staff_net", 0))
    topo.addLink(("users_IO", 2),("guests_net", 0))
    topo.addLink(("users_IO", 3),("fabric", 1))
    topo.addLink(("admins_IO", 1),("admins_net", 0))
    topo.addLink(("admins_IO", 2),("fabric", 2))
    topo.addLink(("users_egress", 1),("WS1", 0))
    topo.addLink(("users_egress", 2),("WS2", 0))
    topo.addLink(("users_egress", 3),("fabric", 3))
    topo.addLink(("admins_egress", 1),("DB", 0))
    topo.addLink(("admins_egress", 2),("fabric", 4))
    return topo

def users_IO_policy(VID):
    i1 = match(edge=VID, src="staff_net", dst="WS1") >> tag("staff_in_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="staff_net")  >> forward("staff_net")
    i3 = match(edge=VID, src="guests_net", dst="WS2") >> tag("guests_in_flows") >> forward("fabric")
    i4 = match(edge=VID, dst="guests_net")  >> forward("guests_net")
    return i1 + i2 + i3 + i4

def admins_IO_policy(VID):
    i1 = match(edge=VID, src="admins_net", dst="DB") >> tag("admins_in_flows") >> forward("fabric")
    i2 = match(edge=VID, dst="admins_net") >> forward("admins_net")
    return i1 + i2 

def users_egress_policy(VID):
    i1 = match(edge=VID, dst="WS1") >> forward("WS1")
    i2 = match(edge=VID, dst="WS2") >> forward("WS2")
    i3 = match(edge=VID, dst="staff_net") >> tag("staff_out_flows") >> forward("fabric")
    i4 = match(edge=VID, dst="guests_net") >> tag("guests_out_flows") >> forward("fabric")
    return i1 + i2 + i3 + i4 

def admins_egress_policy(VID):
    i1 = match(edge=VID, dst="DB") >> forward("DB")
    i2 = match(edge=VID, dst="admins_net") >> tag("admins_out_flows") >> forward("fabric")
    return i1 + i2 

def fabric_policy():
    
    # ( catch() + catch() ) >> carry

    t1 = (catch(fabric="fabric", src="users_IO", flow="staff_in_flows") + 
            catch(fabric="fabric", src="users_IO", flow="guests_in_flows")) >> carry(dst="users_egress")
            
    t2 = (catch(fabric="fabric", src="users_egress", flow="staff_out_flows") + 
            catch(fabric="fabric", src="users_egress", flow="guests_out_flows")) >> carry(dst="users_IO")
            
    t3 = catch(fabric="fabric", src="admins_IO", flow="admins_in_flows") >> carry(dst="admins_egress")
    
    t4 = catch(fabric="fabric", src="admins_egress", flow="admins_out_flows") >> carry(dst="admins_IO")
    
    return t1 + t2 + t3 + t4

def main():
    in_network_functions = (users_IO_policy("users_IO") + admins_IO_policy("admins_IO") + 
                            users_egress_policy("users_egress") + admins_egress_policy("admins_egress"))
    transport_function = fabric_policy()
    topology = virtual_network() 
    return {"virtual_topology": topology, 
            "edge_policies": in_network_functions, 
            "fabric_policies": transport_function}  

