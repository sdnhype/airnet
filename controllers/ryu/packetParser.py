"""
Utility class to build a packet (ARP) or modify another packet and send it to a switch
(in an OF Packet-Out message)
"""
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp,ipv4,icmp,tcp,udp
import ast

class PacketParser(object):

    # def __init__(self):
    #     super(PacketParser, self).__init__()

    """
    recoit les donnees arp contenues dans un dictionnaire construit le packet et l'envoie
    dp: datapath du switch
    data: dictionnaire contenant les infos du packet sous cette forme
    {"port":..,"dpid":...,"packet":{"arp":{"src_mac":..,"dst_mac":..,"src_ip":..,"dst_ip":...,"opcode":..}}}
    """
    def send_arp(self,dp,data):

        port = int(data.get('port'))
        protos = data.get('packet')
        protos = ast.literal_eval(str(protos))
        protos = protos.get('arp')
        packet = self.build_packet_arp(protos)
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

    """
    envoie un packet out
    dp: datapath du switch par lequel doit passer le packet
    packet: un dictionnaire contenant les entetes du packet sous cette forme
    {"port":..,"output":..,"id_packet":..,"dpid":..,"packet": {"ipv4":{.....},"tcp":{....},"icmp":{...},
                                                                "udp":{.....},"eth_src":...,"eth_dst":...}}
    msg: donnees Openflow du packet
    """
    def send_packet(self,dp,packet,msg):

        in_port = msg.match['in_port']
        actions = self.build_actions(dp,packet)
        data = None
        if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        dp.send_msg(out)

    """
    construit une liste d'actions a appliquer au paquet
    dp: datapath du switch par lequel doit passer le packet
    packet: un dictionnaire contenant les entetes du packet sous cette forme
    {"port":..,"output":..,"id_packet":..,"dpid":..,"packet": {"ipv4":{.....},"tcp":{....},"icmp":{...},
                                                                "udp":{.....},"eth_src":...,"eth_dst":...}}
    """
    def build_actions(self,dp,packet):

        actions = []
        out_port = int(packet.get('output'))
        actions.append(dp.ofproto_parser.OFPActionOutput(out_port))
        protos = packet.get('packet')
        protos = ast.literal_eval(str(protos))
        if 'eth_src' in protos:
            actions.append(dp.ofproto_parser.OFPActionSetField(eth_src=protos.get('eth_src')))
        if 'eth_dst' in protos:
            actions.append(dp.ofproto_parser.OFPActionSetField(eth_dst=protos.get('eth_dst')))
        if 'ipv4' in protos:
            ip = protos.get('ipv4')
            actions.append(dp.ofproto_parser.OFPActionSetField(ipv4_src=ip.get('src')))
            actions.append(dp.ofproto_parser.OFPActionSetField(ipv4_dst=ip.get('dst')))
        if 'tcp' in protos:
            tp = protos.get('tcp')
            actions.append(dp.ofproto_parser.OFPActionSetField(tcp_src=tp.get('src_port')))
            actions.append(dp.ofproto_parser.OFPActionSeField(tcp_dst=tp.get('dst_port')))
        elif 'udp' in protos:
            tp = protos.get('udp')
            actions.append(dp.ofproto_parser.OFPActionSetField(udp_src=tp.get('src_port')))
            actions.append(dp.ofproto_parser.OFPActionSeField(udp_dst=tp.get('dst_port')))

        return actions


    """
    construit un packet arp de retour,
    data : dictionnaire contenant les entetes arp et ethernet sous cette forme
    {"src_mac":..,"dst_mac":..,"src_ip":..,"dst_ip":...,"opcode":..}
    """
    def build_packet_arp(self,data):

        pkt = packet.Packet()
        mac_src = data.get('src_mac')
        mac_dst = data.get('dst_mac')
        ip_src = data.get('src_ip')
        ip_dst = data.get('dst_ip')
        opcode = data.get('opcode')
        ar = arp.arp_ip(opcode,mac_src,ip_src,mac_dst,ip_dst)
        type = ether_types.ETH_TYPE_ARP
        ether = ethernet.ethernet(ethertype=type,dst=mac_dst,src=mac_src)
        pkt.add_protocol(ether)
        pkt.add_protocol(ar)
        return pkt

    """
    retourne un dictionnaire sous la forme
    {"arp":{"src_mac":..,"dst_mac":..,"src_ip":..,"dst_ip":...,"opcode":..}}
    packet: est un packet ryu recu avec Packet IN
    """
    def arp_to_dict(self,packet):

        d = {}
        ar = packet.get_protocol(arp.arp)
        d['opcode'] = ar.opcode
        d['src_mac'] = ar.src_mac
        d['src_ip'] = ar.src_ip
        d['dst_mac'] = ar.dst_mac
        d['dst_ip'] = ar.dst_ip
        retour = {}
        retour['arp'] = d
        return retour

    """
    retourne un dictionnaire de la forme
    {"ipv4":{.....},"tcp":{....},"icmp":{...},"udp":{.....},"eth_src":...,"eth_dst":...}
    pour chaque protocole present dans le paquet on recupere la source et la destination
    packet: est un packet ryu recu avec Packet IN
    """
    def packet_to_dict(self,packet):

        retour = {}
        ip = packet.get_protocol(ipv4.ipv4)
        if ip:
            d_ip = {}
            d_ip['src'] = ip.src
            d_ip['dst'] = ip.dst
            retour['ipv4'] = d_ip

        ic = packet.get_protocol(icmp.icmp)
        if ic:
            d_ic = {}
            retour['icmp'] = d_ic

        tc = packet.get_protocol(tcp.tcp)
        if tc:
            d_tc = {}
            d_tc['src_port'] = tc.src_port
            d_tc['dst_port'] = tc.dst_port
            retour['tcp'] = d_tc

        ud = packet.get_protocol(udp.udp)
        if ud:
            d_ud = {}
            d_ud['src_port'] = ud.src_port
            d_ud['dst_port'] = ud.dst_port
            retour['udp'] = d_ud

        eth = packet.get_protocol(ethernet.ethernet)
        retour['eth_src'] = eth.src
        retour['eth_dst'] = eth.dst
        return retour
