from mapping import Mapping
from constants import *

class Mymapping(Mapping):

    def __init__(self):

        Mapping.__init__(self)

        self.addEdgeMap(EI, "s1")
        self.addEdgeMap(ED, "s9")
        self.addEdgeMap(EW, "s8")
        self.addEdgeMap(EC, "s7")

        self.addFabricMap(FAB, "s2", "s3", "s4" ,"s5" ,"s6")

        self.addHostMap(WS, "192.168.10.16")
        self.addHostMap(SSH_GW, "192.168.10.17")

        self.addNetworkMap(INTERNET, "10.0.0.0/8")
        self.addNetworkMap(WIFI_PUB, "192.168.20.0/24")
        self.addNetworkMap(WIFI_PRIV, "192.168.30.0/24")
        self.addNetworkMap(CORP_NET, "172.16.0.0/16")

def main():
    return Mymapping()
