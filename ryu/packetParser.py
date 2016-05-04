from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
import ast

"""
classe qui permet de reconstituer un paquet et de l'envoyer sur un switch
"""
class PacketParser(object):

    def __init__(self):
        super(PacketParser, self).__init__()   
    
    """
    construit la partie arp pour un packet
    il recoit un dictionnaire contenant les infos du packet
    """
    def build_arp(self,data_arp):
        mac_src = data_arp.get('src_mac')
        mac_dst = data_arp.get('dst_mac')
        ip_src = data_arp.get('src_ip')
        ip_dst = data_arp.get('dst_ip')
        opcode = data_arp.get('opcode')
        ar = arp.arp_ip(opcode,mac_src,ip_src,mac_dst,ip_dst)
        return ar 
        
    """
    construit la partie ethernet pour un packet
    il recoit un dictionnaire contenant les infos du packet
    """
    def build_ethernet(self,data_ethernet):
        mac_src = data_ethernet.get('src')
        mac_dst = data_ethernet.get('dst')
        type = data_ethernet.get('ethertype')
        ether = ethernet.ethernet(ethertype=type,dst=mac_dst,src=mac_src)
        return ether
        
    """
    construit un packet
    il recoit une liste des differents protocoles constituant le packet
    """
    def build_packet(self,protos):
        pkt = packet.Packet()
        for proto in protos:
            index = proto.find(':') 
            protocole = proto[:index] #pour recupere le nom du protocole
            data_protocole = ast.literal_eval(proto[index+2:]) #pour avoir le dictionnaire du protocole  
            if protocole == "ethernet" :
                pkt.add_protocol(self.build_ethernet(data_protocole))
            elif protocole == "arp" :
                pkt.add_protocol(self.build_arp(data_protocole))
        return pkt 

    """
    recoit les donnees brutes construit le packet et l'envoie
    dp: datapath
    data: dictionnaire contenant les infos du packet
    """
    def send_packet(self,dp,data):
        port = data.get('port')
        protos = data.get('packet')
        packet = self.build_packet(protos)
        packet.serialize()
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        data = packet.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        dp.send_msg(out)
        