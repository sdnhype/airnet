# AirNet, a virtual network control language based on an Edge-Fabric model.
# Copyright (C) 2016-2017 Université Toulouse III - Paul Sabatier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp,ipv4,icmp,tcp,udp
import ast

class Parser(object):
    """
        This class is used by RYU to sends instructions
        to the physical infrastructure through the OF API
    """

    def send_arp(self,dp,data):
        """ receives a @param data dictionnary
            builds an ARP packet based on the dictionnary keys
            sends it to the appopriate switch (@param dpid)
        """
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

    def send_packet(self,dp,packet,msg):
        """ receives a @param packet packet
            builds an OF packet based on information in
            @param packet and @param msg
            sends it to the appopriate switch (@param dp)
        """

        in_port = msg.match['in_port']
        actions = self.build_actions(dp,packet)
        data = None
        if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        dp.send_msg(out)

    def build_actions(self,dp,packet):
        """ constructs a list of actions to
            apply on @param packet
        """
        actions = []
        out_port = int(packet.get('output'))
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
            actions.append(dp.ofproto_parser.OFPActionSetField(tcp_dst=tp.get('dst_port')))
        elif 'udp' in protos:
            tp = protos.get('udp')
            actions.append(dp.ofproto_parser.OFPActionSetField(udp_src=tp.get('src_port')))
            actions.append(dp.ofproto_parser.OFPActionSeField(udp_dst=tp.get('dst_port')))
        actions.append(dp.ofproto_parser.OFPActionOutput(out_port))
        return actions

    def build_packet_arp(self,data):
        """ builds an arp packet based on information
            in @param data """

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

    def arp_to_dict(self,packet):
        """ converts an ARP @param packet
            into a dictionnary """
        dict_part = {}
        arp_proto = packet.get_protocol(arp.arp)
        dict_part['opcode'] = arp_proto.opcode
        dict_part['src_mac'] = arp_proto.src_mac
        dict_part['src_ip'] = arp_proto.src_ip
        dict_part['dst_mac'] = arp_proto.dst_mac
        dict_part['dst_ip'] = arp_proto.dst_ip
        arp_dict = {}
        arp_dict['arp'] = dict_part
        return arp_dict

    def packet_to_dict(self,packet):
        """ converts an IP @param packet
            into a dictionnary """

        ip_dict = {}
        ip = packet.get_protocol(ipv4.ipv4)
        if ip:
            d_ip = {}
            d_ip['src'] = ip.src
            d_ip['dst'] = ip.dst
            ip_dict['ipv4'] = d_ip

        ic = packet.get_protocol(icmp.icmp)
        if ic:
            d_ic = {}
            ip_dict['icmp'] = d_ic

        tc = packet.get_protocol(tcp.tcp)
        if tc:
            d_tc = {}
            d_tc['src_port'] = tc.src_port
            d_tc['dst_port'] = tc.dst_port
            ip_dict['tcp'] = d_tc

        ud = packet.get_protocol(udp.udp)
        if ud:
            d_ud = {}
            d_ud['src_port'] = ud.src_port
            d_ud['dst_port'] = ud.dst_port
            ip_dict['udp'] = d_ud

        eth = packet.get_protocol(ethernet.ethernet)
        ip_dict['eth_src'] = eth.src
        ip_dict['eth_dst'] = eth.dst
        return ip_dict
