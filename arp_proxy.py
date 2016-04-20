from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr
from collections import namedtuple
import pdb


log = core.getLogger()

def countOfMessages(of_messages):
    #pdb.set_trace()
    cpt = 0
    for dpid, messages in of_messages.iteritems():
        cpt += len(messages)
    return cpt

class ARP_Proxy(object):
    
    _core_name = "arp_proxy"
    
    def __init__(self):
        self.active = False
    
    def start(self):
        print "arp proxy starting"
        self.active = True
        core.runtime.nexus.arpProxy = True
        switches = core.runtime.get_ARP_switches()
        ARP_messages = {}
        for switch in switches:
            dpid = int(switch[1:])
            ARP_messages[dpid] = []
            ARPmsg = of.ofp_flow_mod()
            ARPmsg.match.dl_type = 0x0806
            ARPmsg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            ARP_messages[dpid].append(ARPmsg)
        log.info("number of ARP rules: " + str(countOfMessages(ARP_messages)))
        core.runtime.nexus.send_of_messages(ARP_messages)
    
    def stop(self):
        self.active = False
        core.runtime.nexus.arpProxy = False
        
    def resolve_ARP_request(self, packet):
        """
        """
        def build_arp_reply(packet):
            requested_mac_address = core.infrastructure.arp(packet.payload.protodst.toStr())
            # useful in usecases like loadbalancer where the public ip adresse have no HWaddr 
            if requested_mac_address is None:
                # 00:26:55:42:9a:62 is the VHWaddr
                requested_mac_address = EthAddr("00:26:55:42:9a:62")
            arp_reply = arp()
            arp_reply.hwsrc = requested_mac_address
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = packet.payload.protodst
            arp_reply.protodst = packet.payload.protosrc
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = requested_mac_address
            ether.payload = arp_reply
            return ether
        
        arpReply = namedtuple('arpReply', ['switch', 'packet', 'output'])
        arpPacket = build_arp_reply(packet)
        switch, port = core.infrastructure.get_output_to_destination(packet.src)
        
        return arpReply(switch, arpPacket, port)

        
def launch():
    core.registerNew(ARP_Proxy)