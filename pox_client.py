from pox.core import core
from pox.lib.util import str_to_dpid
import pox.openflow.libopenflow_01 as of
from language import identity, forward, modify
from pox.lib.addresses import IPAddr
from pox.lib.addresses import EthAddr
from language import match
from pox.lib.packet.arp import arp
from collections import namedtuple
import copy
import time
import pdb

#TODO: infrastructure events need to be handled by the client, not by the runtime
#TODO: ARP messages
#TODO: priority increase not decrease, for reactive rules


log = core.getLogger()

class Stat(object):
    """
    """
    def __init__(self, byte_count, packet_count, **kwargs):
        self._byte_count = byte_count
        self._packet_count = packet_count
        self._issuing_match = match(**kwargs)
        try:
            self._nw_src = kwargs["nw_src"]
        except KeyError:
            self._nw_src = None
        try:
            self._nw_dst = kwargs["nw_dst"]
        except KeyError:
            self._nw_dst = None
        try:
            self._dl_src = kwargs["dl_src"]
        except KeyError:
            self._dl_src = None
        try:
            self._dl_dst = kwargs["dl_dst"]
        except KeyError:
            self._dl_dst = None
        try:
            self._tp_src = kwargs["tp_src"]
        except KeyError:
            self._tp_src = None
        try:
            self._tp_dst = kwargs["tp_dst"]
        except KeyError:
            self._tp_dst = None
        
    
    @property
    def byte_count(self):
        return self._byte_count
    
    @property
    def packet_count(self):
        return self._packet_count
    
    @property
    def nw_src(self):
        return self._nw_src
    
    @property
    def nw_dst(self):
        return self._nw_dst
    
    @property
    def dl_src(self):
        return self._dl_src
    
    @property
    def dl_dst(self):
        return self._dl_dst
    
    @property
    def tp_src(self):
        return self._tp_src
    
    @property
    def tp_dst(self):
        return self._tp_dst
    
    
class PoxClient(object):
    """
    """
    def __init__(self):
        """
        :param: classifiers
        """
        core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
        core.openflow.addListenerByName("FlowStatsReceived", _handle_flow_stats)
        self.switches_rules_cpt = {}
        self.arpProxy = False
    
    def build_match_field(self, src = None, dst = None,dl_src=None, dl_dst=None, 
                          nw_src = None, nw_dst = None, tp_src=None, tp_dst=None, nw_proto= None, in_port=None):
        """
        build Openflow match structure
        """
        my_match = of.ofp_match()
        if src:
            #TODO: add macAddr
            for ipAddr, host in core.runtime.mapping.hosts.iteritems():
                if host == src:
                    my_match.nw_src = IPAddr(ipAddr)
        if dst:
            for ipAddr, host in core.runtime.mapping.hosts.iteritems():
                if host == dst:
                    my_match.nw_dst = IPAddr(ipAddr)
        if dl_src:
            my_match.dl_src = EthAddr(dl_src)
        if dl_dst:
            my_match.dl_dst = EthAddr(dl_dst)
        if nw_src:
            my_match.nw_src = nw_src
            my_match.dl_type = 0x0800
        if nw_dst:
            my_match.nw_dst = nw_dst
            my_match.dl_type = 0x0800
        if tp_src:
            my_match.tp_src = tp_src
            my_match.dl_type = 0x0800
            my_match.nw_proto = 6
        if tp_dst:
            my_match.tp_dst = tp_dst
            my_match.dl_type = 0x0800
            my_match.nw_proto = 6
        if nw_proto:
            my_match.nw_proto = nw_proto
        if in_port:
            my_match.in_port = in_port   
        return my_match
        
    def install_ARP_rules(self, switches):
        ARP_messages = {}
        for switch in switches:
            dpid = int(switch[1:])
            ARP_messages[dpid] = []
            ARPmsg = of.ofp_flow_mod()
            ARPmsg.match.dl_type = 0x0806
            ARPmsg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            ARP_messages[dpid].append(ARPmsg)
        self.send_of_messages(ARP_messages)
                
    def install_rules_on_dp(self, classifiers):
        """
        """
        of_messages = {}
        for switch, rules in classifiers.iteritems():
            #str_to_dpid('10') == 16 !!!
            #dpid = str_to_dpid(switch[1:])
            dpid = int(switch[1:])
            of_messages[dpid] = []
            priority = len(rules)
            self.switches_rules_cpt[switch] = len(rules)
            for rule in rules:
                act_fwd = None
                act_mod = None
                ARPmsg = of.ofp_flow_mod()
                if rule.match != identity:
                    ARPmsg.match = self.build_match_field(**rule.match.map)
                    #if drop, we will have an empty list in msg actions
                    if not len(rule.actions) == 0:
                        for act in rule.actions:
                            if isinstance(act, modify):
                                if "nw_dst" in act.map:
                                    act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                                    ARPmsg.actions.append(act_mod)
                                    #ARPmsg.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"])))
                                if "nw_src" in act.map:
                                    act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                                    ARPmsg.actions.append(act_mod)
                                    #ARPmsg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"])))
                                if "dl_dst" in act.map:
                                    act_mod = of.ofp_action_dl_addr.set_dst(act.map["dl_dst"])
                                    ARPmsg.actions.append(act_mod)
                                if "dl_src" in act.map:
                                    act_mod = of.ofp_action_dl_addr.set_src(act.map["dl_src"])
                                    ARPmsg.actions.append(act_mod)
                            if isinstance(act, forward):
                                if act.output == "OFPP_CONTROLLER":
                                    act.output = of.OFPP_CONTROLLER
                                act_fwd = of.ofp_action_output(port=act.output)
                                #ARPmsg.actions.append(of.ofp_action_output(port=act.output))
                        if act_fwd: 
                            ARPmsg.actions.append(act_fwd)
                ARPmsg.priority =priority
                #ARP packets
                #ARPmsg.match.dl_type = 0x0806
                #self.of_messages[dpid].append(ARPmsg)
                #ICMP packets
                IPmsg = copy.deepcopy(ARPmsg)
                of_messages[dpid].append(IPmsg)
                # decrease priority for the next rule
                priority = priority - 1
                
        self.send_of_messages(of_messages)        
                
    def send_packet_out(self, switch, packet, output):
        dpid = int((switch[1:]))
        dpid = str_to_dpid(hex(dpid))
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.actions.append(of.ofp_action_output(port = output))
        msg.data = packet
        msg.buffer_id = None
        core.openflow.sendToDPID(dpid, msg)
        
    
    def send_stat_request(self, switches, target_match):
        _target_match = copy.deepcopy(target_match)
        _target_match.map.pop("edge")
        request = of.ofp_stats_request()
        request.type = of.OFPST_FLOW
        request.body = of.ofp_flow_stats_request()
        request.body.match = self.build_match_field(**_target_match.map)
        for switch in switches:
            dpid = int((switch[1:]))
            dpid = str_to_dpid(hex(dpid))
            if not core.openflow.sendToDPID(dpid, request):
                raise RuntimeError("stat request was not sent")
    
    def installNewRules(self, classifiers):
        of_messages = {}
        for switch, rules in classifiers.iteritems(): 
            dpid = int(switch[1:])
            of_messages[dpid] = []
            for rule in rules:
                priority = len(core.runtime.new_classifiers[switch]) - rule[1]
                act_fwd = None
                act_mod = None
                ofp_msg = of.ofp_flow_mod()
                ofp_msg.match = self.build_match_field(**rule[0].match.map)
                if not len(rule[0].actions) == 0:
                    for act in rule[0].actions:
                        if isinstance(act, modify):
                            if "nw_dst" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                                ofp_msg.actions.append(act_mod)
                            if "nw_src" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                                ofp_msg.actions.append(act_mod)
                            if "dl_dst" in act.map:
                                act_mod = of.ofp_action_dl_addr.set_dst(EthAddr(act.map["dl_dst"]))
                                ofp_msg.actions.append(act_mod)
                            if "dl_src" in act.map:
                                act_mod = of.ofp_action_dl_addr.set_src(EthAddr(act.map["dl_src"]))
                                ofp_msg.actions.append(act_mod)
                        if isinstance(act, forward):
                            if act.output == "OFPP_CONTROLLER":
                                act.output = of.OFPP_CONTROLLER
                            act_fwd = of.ofp_action_output(port=act.output)
                    if act_fwd: 
                        ofp_msg.actions.append(act_fwd)
                ofp_msg.priority = priority
                of_messages[dpid].append(ofp_msg)
            self.switches_rules_cpt[switch] += len(rules)
        self.send_of_messages(of_messages)
        
    def install_new_rules(self, classifiers):
        of_messages = {}
        for switch, rules in classifiers.iteritems():
            priority = self.switches_rules_cpt[switch] + len(rules) 
            dpid = int(switch[1:])
            of_messages[dpid] = []
            for rule in rules:
                act_fwd = None
                act_mod = None
                ofp_msg = of.ofp_flow_mod()
                ofp_msg.match = self.build_match_field(**rule.match.map)
                if not len(rule.actions) == 0:
                    for act in rule.actions:
                        if isinstance(act, modify):
                            if "nw_dst" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                                ofp_msg.actions.append(act_mod)
                            if "nw_src" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                                ofp_msg.actions.append(act_mod)
                            if "dl_dst" in act.map:
                                act_mod = of.ofp_action_dl_addr.set_dst(EthAddr(act.map["dl_dst"]))
                                ofp_msg.actions.append(act_mod)
                            if "dl_src" in act.map:
                                act_mod = of.ofp_action_dl_addr.set_src(EthAddr(act.map["dl_src"]))
                                ofp_msg.actions.append(act_mod)
                        if isinstance(act, forward):
                            if act.output == "OFPP_CONTROLLER":
                                act.output = of.OFPP_CONTROLLER
                            act_fwd = of.ofp_action_output(port=act.output)
                    if act_fwd: 
                        ofp_msg.actions.append(act_fwd)
                ofp_msg.priority = priority
                priority -= 1
                of_messages[dpid].append(ofp_msg)
            self.switches_rules_cpt[switch] += len(rules)
        self.send_of_messages(of_messages)
    
    def delete_rules(self, to_delete):
        of_messages = {}
        for switch, rules in to_delete.iteritems():
            cpt_deleted_rules = 0
            dpid = int(switch[1:])
            of_messages[dpid] = []
            for rule in rules:
                act_fwd = None
                act_mod = None
                ofp_msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
                ofp_msg.match = self.build_match_field(**rule[0].match.map)
                if not len(rule[0].actions) == 0:
                    for act in rule[0].actions:
                        if isinstance(act, modify):
                            if "nw_dst" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                            elif "nw_src" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                        if isinstance(act, forward):
                            if act.output == "OFPP_CONTROLLER":
                                act.output = of.OFPP_CONTROLLER
                            act_fwd = of.ofp_action_output(port=act.output)
                    if act_mod:
                        ofp_msg.actions.append(act_mod)
                    if act_fwd: 
                        ofp_msg.actions.append(act_fwd)
                ofp_msg.priority = self.switches_rules_cpt[switch] - rule[1]
                of_messages[dpid].append(ofp_msg)
                cpt_deleted_rules += 1
            self.switches_rules_cpt[switch] -= cpt_deleted_rules
        self.send_of_messages(of_messages)
    
    def modifyExistingRules(self, to_modify):
        
        def different_actions(act_list1, act_list2):
                # test if they have same number of 
            for act1 in act_list1:
                find = False
                for act2 in act_list2:
                    if act1 == act2:
                        find = True
                if not find:
                    return True
            if len(act_list1) != len(act_list2):
                return True
            return False
        
        def isSame(r1, r2):
            if (r1.match == r2.match and
                not different_actions(r1.actions, r2.actions)):
                return True
            return False
        
        def modify_priority(old_r, new_r, switch):
            """
            print "---"
            print "switch: " + str(switch)
            print "old_r: " + str(old_r[0].match)
            print "old priority: " + str(old_r[1])
            print "new_r: " + str(new_r[0].match)
            print "new priority: " + str(new_r[1])
            print "modifying rule priority"
            """
            to_delete = {switch:[]}
            to_delete[switch].append(old_r)
            self.delete_rules(to_delete)
            to_add = {switch:[]}
            to_add[switch].append(new_r)
            self.installNewRules(to_add)
        
        of_messages = {}
        for switch, rules in to_modify.iteritems():
            dpid = int(switch[1:])
            of_messages[dpid] = []
            for new_r, old_r in rules:
                if isSame(old_r[0], new_r[0]):
                    if self.switches_rules_cpt[switch]-old_r[1] != len(core.runtime.new_classifiers[switch])-new_r[1]:
                        modify_priority(old_r, new_r, switch)
                else:
                    act_fwd = None
                    act_mod = None
                    ofp_msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT)
                    ofp_msg.match = self.build_match_field(**new_r[0].match.map)
                    if not len(new_r[0].actions) == 0:
                        for act in new_r[0].actions:
                            if isinstance(act, modify):
                                if "nw_dst" in act.map:
                                    act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                                elif "nw_src" in act.map:
                                    act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                            if isinstance(act, forward):
                                if act.output == "OFPP_CONTROLLER":
                                    act.output = of.OFPP_CONTROLLER
                            act_fwd = of.ofp_action_output(port=act.output)
                        if act_mod:
                            ofp_msg.actions.append(act_mod)
                        if act_fwd: 
                            ofp_msg.actions.append(act_fwd)
                    ofp_msg.priority = self.switches_rules_cpt[switch] - new_r[1]
                    of_messages[dpid].append(ofp_msg)
            self.send_of_messages(of_messages)

        
    def modify_existing_rules(self, to_modify):
        """
        :param to_modify: 
        """
        of_messages = {}
        for switch, rules in to_modify.iteritems():
            dpid = int(switch[1:])
            of_messages[dpid] = []
            for rule in rules:
                act_fwd = None
                act_mod = None
                ofp_msg = of.ofp_flow_mod(command=of.OFPFC_MODIFY_STRICT)
                ofp_msg.match = self.build_match_field(**rule[0].match.map)
                if not len(rule[0].actions) == 0:
                    for act in rule[0].actions:
                        if isinstance(act, modify):
                            if "nw_dst" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_dst(IPAddr(act.map["nw_dst"]))
                            elif "nw_src" in act.map:
                                act_mod = of.ofp_action_nw_addr.set_src(IPAddr(act.map["nw_src"]))
                        if isinstance(act, forward):
                            if act.output == "OFPP_CONTROLLER":
                                act.output = of.OFPP_CONTROLLER
                            act_fwd = of.ofp_action_output(port=act.output)
                    if act_mod:
                        ofp_msg.actions.append(act_mod)
                    if act_fwd: 
                        ofp_msg.actions.append(act_fwd)
                ofp_msg.priority = self.switches_rules_cpt[switch] - rule[1]
                of_messages[dpid].append(ofp_msg)
        core.runtime.msgs = copy.deepcopy(of_messages)
        self.send_of_messages(of_messages)
                
    def send_of_messages(self, of_messages):
        for dpid, msg_list in of_messages.iteritems():
            for msg in msg_list:
                if not core.openflow.sendToDPID(dpid, msg):
                    raise RuntimeError("the OpenFlow message was not sent")
                
            
def match_from_packet(dpid, packet):
    """
    """
    my_match = match()
    ip = packet.find('ipv4')
    if ip:
        my_match.map["nw_src"] = ip.srcip.toStr()
        my_match.map["nw_dst"] = ip.dstip.toStr()
    tcp = packet.find('tcp')
    if tcp:
        my_match.map["tp_src"] = tcp.srcport
        my_match.map["tp_dst"] = tcp.dstport
        my_match.map["nw_proto"] = "TCP"
    udp = packet.find('udp')
    if udp:
        my_match.map["tp_src"] = udp.srcport
        my_match.map["tp_dst"] = udp.dstport
        my_match.map["nw_proto"] = 17
    icmp = packet.find('icmp')
    if icmp:
        my_match.map["nw_proto"] = 1
        
    #adding edge field in the match
    switch = 's' + str(dpid)
    edge = core.runtime.get_packetIn_edge(switch, copy.deepcopy(my_match))
    #LEGACY: edge = core.runtime.get_corresponding_virtual_edge(switch)
    if edge:        
        my_match.map['edge'] = edge
    else:
        # fabric's switches fired it
        return None
        #core.runtime.switch = switch
        #raise AssertionError('edge mapping error')
    
    return my_match


            
def _handle_PacketIn(event):
    packet = event.parsed
    if packet.type != packet.ARP_TYPE:
        log.info("PacketIn -- Time == " + str(int(round(time.time() * 1000))))
        core.runtime._event_time = int(round(time.time() * 1000))
        # packet_match is an instance of language.match class
        packet_match = match_from_packet(event.dpid, packet)
        if packet_match:
            core.runtime.handle_packet_in(event.dpid, packet_match, packet)
    else:
        if packet.payload.opcode == arp.REQUEST and core.runtime.nexus.arpProxy:
            reply = core.arp_proxy.resolve_ARP_request(packet)
            if reply:
                core.runtime.nexus.send_packet_out(reply.switch, reply.packet, reply.output)
                
def _handle_flow_stats(event):
    log.info("StatIn -- Time == " + str(int(round(time.time() * 1000))))
    core.runtime._event_time = int(round(time.time() * 1000))
    switch = "s" + str(event.dpid)
    edge = core.runtime.get_corresponding_virtual_edge(switch)
    for stat in event.stats:
        byte_count = stat.byte_count
        packet_count = stat.packet_count
        map = {}
        map["edge"] = edge
        if str(stat.match._nw_src) != "0.0.0.0": 
            map["nw_src"] = str(stat.match._nw_src)
        if str(stat.match._nw_dst) != "0.0.0.0":
            map["nw_dst"] = str(stat.match._nw_dst)
        if str(stat.match._dl_src) != "00:00:00:00:00:00":
            map["dl_src"] = str(stat.match._dl_src)
        if str(stat.match._dl_dst) != "00:00:00:00:00:00":
            map["dl_dst"] = str(stat.match._dl_dst)
        if stat.match._tp_src != 0:
            map["tp_src"] = stat.match._tp_src
        if stat.match._tp_dst != 0:
            map["tp_dst"] = stat.match._tp_dst
        response = Stat(byte_count, packet_count, **map)
        core.runtime.handle_flow_stats(response)
        
        