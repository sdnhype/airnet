# Import language primitives
from language import *
# Import constants for all use cases
from constants import *

#Virtual topology
def virtual_network():

    topology = VTopology()
    topology.addFabric(FAB, 4)
    topology.addEdge(EI,2)
    topology.addEdge(EW,3)
    topology.addEdge(ED,3)
    topology.addEdge(EC,2)

    topology.addHost(WS)
    topology.addHost(SSH_GW)
    topology.addNetwork(INTERNET)
    topology.addNetwork(WIFI_PUB)
    topology.addNetwork(WIFI_PRIV)
    topology.addNetwork(CORP_NET)

    topology.addLink((EI,1),(INTERNET,0))
    topology.addLink((EI,2),(FAB,1))
    topology.addLink((EW,1),(FAB,2))
    topology.addLink((EW,2),(WIFI_PUB,0))
    topology.addLink((EW,3),(WIFI_PRIV,0))
    topology.addLink((ED,1),(FAB,3))
    topology.addLink((ED,2),(WS,0))
    topology.addLink((ED,3),(SSH_GW,0))
    topology.addLink((EC,1),(FAB,4))
    topology.addLink((EC,2),(CORP_NET))

    return topology

# ==========
# Policies
# ==========

# Edges can forward to their connected hosts or networks
def default_distribution_policy():

    e1 = match(edge=EI, dst=INTERNET) >> forward(INTERNET)
    e2 = match(edge=EW, dst=WIFI_PUB) >> forward(WIFI_PUB)
    e3 = match(edge=EW, dst=WIFI_PRIV) >> forward(WIFI_PRIV)
    e4 = match(edge=ED, dst=WS) >> forward(WS)
    e5 = match(edge=ED, dst=SSH_GW) >> forward(SSH_GW)
    e6 = match(edge=EC, dst=CORP_NET) >> forward(CORP_NET)
    return e1 + e2 + e3 + e4 + e5 + e6


# WEB FLOWS POLICY
# [ Internet, WiFi Pub and Priv ] <--> WS  : allow HTTP
def web_flows_policy():

    # Tags
    WS_IN = "ws_flows_in"
    WS_OUT_WIFI = "ws_flows_out_wifi"
    WS_OUT_INET = "ws_flows_out_internet"

    # Edges -- web flows to the WebServer
    e1 = match(edge=EI, src=INTERNET,  dst=WS, nw_proto=TCP, tp_dst=HTTP) >> tag(WS_IN) >> forward(FAB)
    e2 = match(edge=EW, src=WIFI_PUB,  dst=WS, nw_proto=TCP, tp_dst=HTTP) >> tag(WS_IN) >> forward(FAB)
    e3 = match(edge=EW, src=WIFI_PRIV, dst=WS, nw_proto=TCP, tp_dst=HTTP) >> tag(WS_IN) >> forward(FAB)

    # Edges -- web flows from the WebServer
    e4 = match(edge=ED, src=WS, dst=INTERNET, nw_proto=TCP, tp_src=HTTP) >> tag(WS_OUT_INET) >> forward(FAB)
    # below, a unique tag for the 2 wifi networks since they are connected to the same edge
    e5 = match(edge=ED, src=WS, dst=WIFI_PUB,  nw_proto=TCP, tp_src=HTTP) >> tag(WS_OUT_WIFI) >> forward(FAB)
    e6 = match(edge=ED, src=WS, dst=WIFI_PRIV, nw_proto=TCP, tp_src=HTTP) >> tag(WS_OUT_WIFI) >> forward(FAB)

    # Fabric -- transport function
    f1 = catch(fabric=FAB, src=EI, flow=WS_IN) >> carry(dst=ED)
    f2 = catch(fabric=FAB, src=EW, flow=WS_IN) >> carry(dst=ED)
    f3 = catch(fabric=FAB, src=ED, flow=WS_OUT_INET) >> carry(dst=EI)
    f4 = catch(fabric=FAB, src=ED, flow=WS_OUT_WIFI) >> carry(dst=EW)

    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2+e3+e4+e5+e6, f1+f2+f3+f4)


# ICMP FLOWS POLICY
# [ Internet, WiFi Pub and Priv ] <-->  WS : allow ICMP
def icmp_flows_policy():

    # Tags
    ICMP_IN = "icmp_in"
    ICMP_OUT_INET = "icmp_out_inet"
    ICMP_OUT_WIFI = "icmp_out_wifi"

    # Edges
    e1 = match(edge=EI, src=INTERNET, dst=WS, nw_proto=ICMP) >> tag(ICMP_IN) >> forward(FAB)
    e2 = match(edge=EW, src=WIFI_PUB, dst=WS, nw_proto=ICMP) >> tag(ICMP_IN) >> forward(FAB)
    e3 = match(edge=EW, src=WIFI_PRIV, dst=WS, nw_proto=ICMP) >> tag(ICMP_IN) >> forward(FAB)

    e4 = match(edge=ED, src=WS, dst=INTERNET, nw_proto=ICMP) >> tag(ICMP_OUT_INET) >> forward(FAB)
    e5 = match(edge=ED, src=WS, dst=WIFI_PUB, nw_proto=ICMP) >> tag(ICMP_OUT_WIFI) >> forward(FAB)

    # Fabric
    f1 = ( catch(fabric=FAB, src=EI, flow=ICMP_IN) + catch(fabric=FAB, src=EW, flow=ICMP_IN) ) >> carry(dst=ED)
    f2 = catch(fabric=FAB, src=ED, flow=ICMP_OUT_INET) >> carry(dst=EI)
    f3 = catch(fabric=FAB, src=ED, flow=ICMP_OUT_WIFI) >> carry(dst=EW)

    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2+e3+e4+e5, f1+f2+f3)


# SSH FLOWS POLICY
# [ Internet, WiFi Pub and Priv ] <--> SSH_GW  : allow SSH
# [ SSH_GW ]                      <--> Corporate Net : allow ALL
def ssh_flows_policy():

    # Tags
    SSH_IN = "ssh_in"
    SSH_OUT_INET = "ssh_out_inet"
    SSH_OUT_WIFI = "ssh_out_wifi"
    AUTH_IN = "authenticated_flows_in"
    AUTH_OUT = "authenticated_flows_out"

    # Edges -- ssh flows to the air lock (SSH_GW)
    e1 = match(edge=EI, src=INTERNET,  dst=SSH_GW, nw_proto=TCP, tp_dst=SSH) >> tag(SSH_IN) >> forward(FAB)
    e2 = match(edge=EW, src=WIFI_PUB,  dst=SSH_GW, nw_proto=TCP, tp_dst=SSH) >> tag(SSH_IN) >> forward(FAB)
    e3 = match(edge=EW, src=WIFI_PRIV, dst=SSH_GW, nw_proto=TCP, tp_dst=SSH) >> tag(SSH_IN) >> forward(FAB)

    # Edges -- ssh flows from the air lock
    e4 = match(edge=ED, src=SSH_GW, dst=INTERNET,  nw_proto=TCP, tp_src=SSH) >> tag(SSH_OUT_INET) >> forward(FAB)
    e5 = match(edge=ED, src=SSH_GW, dst=WIFI_PUB,  nw_proto=TCP, tp_src=SSH) >> tag(SSH_OUT_WIFI) >> forward(FAB)
    e6 = match(edge=ED, src=SSH_GW, dst=WIFI_PRIV, nw_proto=TCP, tp_src=SSH) >> tag(SSH_OUT_WIFI) >> forward(FAB)

    # Edges -- all flows from ssh gw to corportate net
    e7 = match(edge=ED, src=SSH_GW, dst=CORP_NET) >> tag(AUTH_IN) >> forward(FAB)
    e8 = match(edge=EC, src=CORP_NET, dst=SSH_GW) >> tag(AUTH_OUT) >> forward(FAB)

    # Fabric -- transport function
    f1 = catch(fabric=FAB, src=EI, flow=SSH_IN) >> carry(dst=ED)
    f2 = catch(fabric=FAB, src=EW, flow=SSH_IN) >> carry(dst=ED)
    f3 = catch(fabric=FAB, src=ED, flow=SSH_OUT_INET) >> carry(dst=EI)
    f4 = catch(fabric=FAB, src=ED, flow=SSH_OUT_WIFI) >> carry(dst=EW)
    f5 = catch(fabric=FAB, src=ED, flow=AUTH_IN) >> carry(dst=EC)
    f6 = catch(fabric=FAB, src=EC, flow=AUTH_OUT) >> carry(dst=ED)

    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2+e3+e4+e5+e6+e7+e8, f1+f2+f3+f4+f5+f6)


# WIFI - INTERNET POLICY
# [ Wifi Pub and Priv ]  <--> Internet : allow ALL
def wifi_internet_policy():

    # Tags
    WIFI_IN = "wifi_in"
    WIFI_OUT = "wifi_out"

    # Edges
    e1 = match(edge=EI, src=INTERNET, dst=WIFI_PUB) >> tag(WIFI_IN) >> forward(FAB)
    e2 = match(edge=EI, src=INTERNET, dst=WIFI_PRIV) >> tag(WIFI_IN) >> forward(FAB)
    e3 = match(edge=EW, src=WIFI_PUB, dst=INTERNET) >> tag(WIFI_OUT) >> forward(FAB)
    e4 = match(edge=EW, src=WIFI_PRIV, dst=INTERNET) >> tag(WIFI_OUT) >> forward(FAB)

    # Fabric
    f1 = catch(fabric=FAB, src=EI, flow=WIFI_IN) >> carry(dst=EW)
    f2 = catch(fabric=FAB, src=EW, flow=WIFI_OUT) >> carry(dst=EI)

    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2+e3+e4, f1+f2)

# WIFI - CORPORATE POLICY
# [ WiFi Priv ] <--> Corporate Net : allow TCP 8080
def wifi_corporate_net_policy():

    # Tags
    AUTH_IN = "8080_in"
    AUTH_OUT = "8080_out"

    # Edges
    e1 = match(edge=EW, src=WIFI_PRIV, dst=CORP_NET, nw_proto=TCP, tp_dst=8080) >> tag(AUTH_IN) >> forward(FAB)
    e2 = match(edge=EC, src=CORP_NET, dst=WIFI_PRIV, nw_proto=TCP, tp_src=8080) >> tag(AUTH_OUT) >> forward(FAB)

    # Fabric
    f1 = catch(fabric=FAB, src=EW, flow=AUTH_IN) >> carry(dst=EC)
    f2 = catch(fabric=FAB, src=EC, flow=AUTH_OUT) >> carry(dst=EW)

    # return a tuple of 2 elements: in_network policies and transport policies
    return (e1+e2, f1+f2)

# ===============
# Main function
# ===============
def main():

    topology = virtual_network()
    inf_base = default_distribution_policy()
    inf_01, tf_01 = web_flows_policy()
    inf_02, tf_02 = icmp_flows_policy()
    inf_03, tf_03 = ssh_flows_policy()
    inf_04, tf_04 = wifi_internet_policy()
    inf_05, tf_05 = wifi_corporate_net_policy()

    in_net_fct_global = inf_base + inf_01 + inf_02 + inf_03 + inf_04 + inf_05
    transport_fct_global = tf_01 + tf_02 + tf_03 + tf_04 + tf_05

    return {"virtual_topology": topology,
            "edge_policies": in_net_fct_global,
            "fabric_policies": transport_fct_global}
