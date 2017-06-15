# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI


"""
    Receives queries from Airnet REST client
    Receives events from the physical infrastructure

    Sends Openflow instructions to the physical infrastructure
    Uses a REST client to :
        Sends events to the Airnet REST server
"""

import json
import ast
from pprint import pprint
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet,ethernet,ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from webob import Response
from log import Logger
from parser_packet import Parser
from restclient_airnet import RyuTopologyClient

logger = Logger("RYU_Server").Log()
logger_event = Logger("RYU_OF").Log()

# only Openflow 1.3 is supported here
supported_ofctl = {ofproto_v1_3.OFP_VERSION: ofctl_v1_3}

# data structures here allow to identify packets which
# have been sent to the controller
packets = {}
id_packet = 0

class FlowsController(ControllerBase):
    """ handle instructions that concern
        operations on flows
    """
    def __init__(self, req, link, data, **config):
        super(FlowsController, self).__init__(req, link, data, **config)
        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def modify_flow_entry(self, req, cmd, **_kwargs):
        """ modify an entry in the switch OF table """
        try:
            # Syntax verification
            flow = ast.literal_eval(req.body)
        except SyntaxError:
            logger.debug('Mod_Flow_Entry -- invalid syntax %s', req.body)
            return Response(status=400)

        # get the dpid field in the request
        dpid = flow.get('dpid')

        # check if the dpid field is correct
        if type(dpid) == str and not dpid.isdigit():
            logger.debug('invalid dpid %s', dpid)
            return Response(status=400)

        # get the switch that corresponds to the dpid value
        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        # application cmd is translated to ofp cmds
        if cmd == 'add':
            cmd = dp.ofproto.OFPFC_ADD
        elif cmd == 'modify':
            cmd = dp.ofproto.OFPFC_MODIFY
        elif cmd == 'modify_strict':
            cmd = dp.ofproto.OFPFC_MODIFY_STRICT
        elif cmd == 'delete':
            cmd = dp.ofproto.OFPFC_DELETE
        elif cmd == 'delete_strict':
            cmd = dp.ofproto.OFPFC_DELETE_STRICT
        else:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            _ofctl.mod_flow_entry(dp, flow, cmd)
        else:
            logger.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def delete_flow_entry(self, req, dpid, **_kwargs):
        """ delete an entry in the switch OF Table """

        if type(dpid) == str and not dpid.isdigit():
            logger.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        if ofproto_v1_0.OFP_VERSION == _ofp_version:
            flow = {}
        else:
            flow = {'table_id': dp.ofproto.OFPTT_ALL}

        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            _ofctl.mod_flow_entry(dp, flow, dp.ofproto.OFPFC_DELETE)

        else:
            logger.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

class PacketsController(ControllerBase):
    """ handles instructions that concern
        operations on packets """

    def __init__(self, req, link, data, **config):
        super(PacketsController, self).__init__(req, link, data, **config)
        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def push_packet(self, req, **_kwargs):
        """ push a packet to the physical infrastructure """

        sender = Parser()

        try:
            flow = ast.literal_eval(req.body)
        except SyntaxError:
            logger.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = flow.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            logger.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            # the switch was not found in the
            # physical infrastructure
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION


        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            # arp packets do not have id_packet field
            if 'id_packet' not in flow:
                # send an arp packet
                sender.send_arp(dp,flow)
            else:
                # it's definitely an IP packet
                # meaning that the packet was redirected before
                # to the hypervisor
                global packets
                id_pkt = int(flow.get('id_packet'))
                # get the msg stored in the packets dictionnary
                # before the packet was sent to the controller
                msg = packets.get(id_pkt)
                # send the packet
                sender.send_packet(dp,flow,msg)
                # Delete msg from the packet dict
                del packets[id_pkt]
        else:
            logger.debug('Unsupported OF protocol')
            return Response(status=501)

class StatsController(ControllerBase):
    """ handles instructions that concern
        operations on statistics """

    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)

        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def get_flow_stats(self, req, dpid, **_kwargs):
        """ get statistics on a flow in the
            switch @param {dpid} OF table """

        if req.body == '':
            flow = {}
        else:
            try:
                # Python syntax verification
                flow = ast.literal_eval(req.body)
            except SyntaxError:
                logger.debug('Invalid syntax %s', req.body)
                return Response(status=400)

        # Invalid type of switch # (dapath id)
        if type(dpid) == str and not dpid.isdigit():
            logger.debug('Invalid dpid %s', dpid)
            return Response(status=400)

        # datapath object obtained from the dpid field
        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        # get the ofp version used by the switch
        _ofp_version = dp.ofproto.OFP_VERSION

        # rest API tool that corresponds to the switch ofp version
        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            flows = _ofctl.get_flow_stats(dp, self.waiters, flow)
        else:
            logger.debug('Unsupported OF protocol')
            return Response(status=501)

        body = json.dumps(flows)

        # For debug
        print("sending statistics...")
        #logger.debug("Stat_Data {}".format(body))

        return Response(content_type='application/json', body=body)


class RestApi_main(app_manager.RyuApp):
    """
        This class listens for the Airnet Hypervisor queries on flows, packets and statistics
        The REST API used associates queries with URLs
            Receive an URLs triggers a method in the appropriate controller
            This method is in charge to send instructions to the physical infrastructure
        This class also suscribed to the physical infrastructure events
        Those events when they occur are transfered to the Hypervisor through a REST client
    """

    # Openflow 1.3 used here
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
        'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(RestApi_main, self).__init__(*args, **kwargs)

        # Connect to the Airnet Hypervisor REST Server
        # through a REST client
        self.client = RyuTopologyClient('localhost',9000)
        # list of managed switches
        self.dpset = kwargs['dpset']
        # wsgi application
        wsgi = kwargs['wsgi']
        self.waiters = {}

        self.data = {}
        self.data['dpset'] = self.dpset
        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper
        # register to the web controllers classes
        wsgi.registory['StatsController'] = self.data
        wsgi.registory['PacketsController'] = self.data
        wsgi.registory['FlowsController'] = self.data

        # one controller for each stats, packets and flows
        path1 = '/Stats'
        path2 = '/Packets'
        path3 = '/Flows'

        # when you receive this url
        uri = path1 + '/flow/{dpid}'
        # send the data to the stats controller method
        # in the action field
        mapper.connect('Stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        # when you receive this one
        uri = path3 + '/entry/{cmd}'
        # send the data to the flows controller method
        # in the action field
        mapper.connect('Flows', uri,
                       controller=FlowsController, action='modify_flow_entry',
                       conditions=dict(method=['POST']))
        # when you receive this one
        uri = path3 + '/entry/clear/{dpid}'
        # send the data to the flows controller method
        # in the action field
        mapper.connect('Flows', uri,
                       controller=FlowsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        # when you receive this one
        uri = path2 + '/push'
        # send the data to the packets controller method
        # in the action field
        mapper.connect('Packets', uri,
                       controller=PacketsController, action='push_packet',
                       conditions=dict(method=['POST']))


    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        logger_event.debug("\nSWITCH_ENTER : switch-{}".format(ev.switch.dp.id))

        # convert switch object informations to a dict
        msg = ev.switch.to_dict()

        logger_event.debug("{}".format("\n".join([str(porti) for porti in msg['ports']])))
        self.client.switchEnter(msg)

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        logger_event.debug("\nSWITCH_LEAVE : switch-{} ".format(ev.switch.dp.id))
        msg = ev.switch.to_dict()
        self.client.switchLeave(msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        logger_event.debug("\nADD_LINK : {}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkAdd(msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        logger_event.debug("\nDEL_LINK : {}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkDelete(msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        logger_event.debug("\nHOST_ADD : {}  ".format(str(ev.host.to_dict())))
        msg = ev.host.to_dict()
        self.client.hostAdd(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # get the msg
        msg = ev.msg
        # get the packet information
        pkt = packet.Packet(data=msg.data)
        # get the layer 2 header
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        parser = Parser()

        global id_packet
        global packets

        # get the switch which sent the packet
        datapath = msg.datapath
        # get the switch's id
        dpid = datapath.id
        # get the incoming port
        port = msg.match['in_port']
        # Initialize a dictionnary
        data = {}
        # Fulfill it with the switch information
        data['dpid'] = dpid
        data['port'] = port

        # if it's an arp packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            logger_event.debug("\nPACKET_IN : ARP packet from sw-{}".format(str(dpid)))
            # convert the arp packet into a dictionnary
            data['packet'] = parser.arp_to_dict(pkt)
        else:
            logger_event.debug("\nPACKET_IN : IP packet from sw-{}".format(str(dpid)))
            data['packet'] = parser.packet_to_dict(pkt)
            # Packet Numbering
            data['id_packet'] = id_packet
            # Packet Storage
            packets[id_packet] = msg
            id_packet = id_packet + 1

        # Packet contents are formatted in json
        data = json.dumps(data)
        # decomment if useful
        #logger.debug("\nData : {}".format(data))
        self.client.packetIn(data)

    @set_ev_cls([ofp_event.EventOFPStatsReply,
                 ofp_event.EventOFPDescStatsReply,
                 ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPAggregateStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPTableFeaturesStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPQueueStatsReply,
                 ofp_event.EventOFPQueueDescStatsReply,
                 ofp_event.EventOFPMeterStatsReply,
                 ofp_event.EventOFPMeterFeaturesStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPGroupStatsReply,
                 ofp_event.EventOFPGroupFeaturesStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply,
                 ofp_event.EventOFPPortDescStatsReply
                 ], MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return

        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        # OF 1.3
        flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    """ switches config at startup """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install a drop rule by default

        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,
                                             [])]
        req = parser.OFPFlowMod(
            datapath=datapath, match=match,command=ofproto.OFPFC_ADD,
            priority=0, instructions=inst)
        datapath.send_msg(req)

        # install a rule for arp flows
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        req = parser.OFPFlowMod(
            datapath=datapath, match=match, command=ofproto.OFPFC_ADD,
            priority=1,instructions=inst)
        datapath.send_msg(req)
