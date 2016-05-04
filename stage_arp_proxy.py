# ARP Proxy
from collections import namedtuple


class ARP_Proxy(object):
    """    
    """
    def __init__(self,infra):
        self.active = False
        self.infra = infra
        
    def resolve_ARP_request(self, packet):
        """
        packet est un named tuple
        """
        def build_arp_reply(packet):
            requested_mac_address = self.infra.arp(packet.ip_src)
            if requested_mac_address is None:
                requested_mac_address = "00:26:55:42:9a:62"
            #on construit le packet out
            
            
        