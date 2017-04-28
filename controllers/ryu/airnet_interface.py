"""
    Send events to AirNet via REST API (thanks to rest_client.py module)
    (switch enter, switch leave, link add, host add, etc.)
    and also RYU's REST API
    EDIT Telly Diallo: Adding  /stats/send  URI  (POST method)
    URI linked to send_packet() function to generate an OF Packet-Out message (by relying on the packet_parser utility class)
"""

# HTTP/JSON Response
from webob import Response
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3, ofproto_v1_4
from ryu.lib import ofctl_v1_0, ofctl_v1_2, ofctl_v1_3, ofctl_v1_4
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.topology import event, switches
from rest_client import RyuTopologyClient
from ryu.lib.packet import packet,ethernet,ether_types
from packetParser import PacketParser
from log import Logger
from pprint import pprint
import json, ast

#logger = logging.getLogger('ryu.app.ofctl_rest')
logger = Logger("airnet_interface").getLog()

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
    ofproto_v1_4.OFP_VERSION: ofctl_v1_4,
}

packets = {}
id_packet = 0

class StatsController(ControllerBase):
    """
        Methods in this class allows to manipulate OF switches tables
    """

    def __init__(self, req, link, data, **config):
        super(StatsController, self).__init__(req, link, data, **config)

        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def get_flow_stats(self, req, dpid, **_kwargs):
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
        print("Stat_Data {}".format(body))

        return Response(content_type='application/json', body=body)

class PacketsController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(PacketsController, self).__init__(req, link, data, **config)
        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def push_packet(self, req, **_kwargs):
        """
            Sends PacketOut
        """
        sender = PacketParser()

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
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            if 'id_packet' not in flow:
                sender.send_arp(dp,flow)
            else:
                global packets
                id_pkt = int(flow.get('id_packet'))

                msg = packets.get(id_pkt)
                sender.send_packet(dp,flow,msg)
                # Delete msg from the packet dict
                del packets[id_pkt]
        else:
            logger.debug('Unsupported OF protocol')
            return Response(status=501)

class FlowsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(FlowsController, self).__init__(req, link, data, **config)
        # get the set of switches managed by the controller
        self.dpset = data['dpset']
        self.waiters = data['waiters']

    def modify_flow_entry(self, req, cmd, **_kwargs):
        """
            Modify the OF switch Table
        """
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
        """
            Delete an entry in OF Table
        """
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

class RestStatsApi(app_manager.RyuApp):
    """
        This class receives statitics queries from the Airnet Hypervisor
        Since the REST API is used, queries are represented by URLs
        URLs are associated with methods in StatsController class which will
        collect information and provide responses
        Events from the OF switches are also collected here and transfered
        to the Airnet Hypervisor through the REST API
        (The RyuTopologyClient class is used here)
    """
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION]
    _CONTEXTS = {
        'dpset': dpset.DPSet,
        'wsgi': WSGIApplication,
    'switches': switches.Switches
    }

    def __init__(self, *args, **kwargs):
        super(RestStatsApi, self).__init__(*args, **kwargs)

        # Airnet REST Server
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
        # register to the StatsController class
        wsgi.registory['StatsController'] = self.data
        wsgi.registory['PacketsController'] = self.data
        wsgi.registory['FlowsController'] = self.data

        path1 = '/Stats'
        path2 = '/Packets'
        path3 = '/Flows'

        """
            Datas to redirect to StatsController
        """
        uri = path1 + '/flow/{dpid}'
        mapper.connect('Stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        """
            Datas to redirect to FlowsController
        """
        uri = path3 + '/entry/{cmd}'
        mapper.connect('Flows', uri,
                       controller=FlowsController, action='modify_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path3 + '/entry/clear/{dpid}'
        mapper.connect('Flows', uri,
                       controller=FlowsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        """
            Datas to redirect to PacketsController
        """
        uri = path2 + '/push'
        mapper.connect('Packets', uri,
                       controller=PacketsController, action='push_packet',
                       conditions=dict(method=['POST']))

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        logger.debug("*** Switch-{} Enter Event ".format(ev.switch.dp.id))

        # convert switch object informations to a dict
        msg = ev.switch.to_dict()

        logger.debug("\n\n{}".format("\n".join([str(porti) for porti in msg['ports']])))
        self.client.switchEnter(msg)

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        logger.debug("\n*** Switch-{} Leave Event ".format(ev.switch.dp.id))
        msg = ev.switch.to_dict()
        self.client.switchLeave(msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        logger.debug("\n*** Add Link Event\n{}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkAdd(msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        logger.debug("\n*** Delete Link Event\n{}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkDelete(msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        logger.debug("\n*** Host Add Event : {}  ".format(str(ev.host.mac)))
        msg = ev.host.to_dict()
        self.client.hostAdd(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # get the msg
        msg = ev.msg
        # get the packet information
        pkt = packet.Packet(data=msg.data)
        # get the layer 2 header
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        parser = PacketParser()

        global id_packet
        global packets

        # get the switch which sent the packet
        datapath = msg.datapath
        # get the switch's id
        dpid = datapath.id
        # get the incoming port
        port = msg.in_port
        # Initialize a dictionnary
        data = {}
        # Fulfill it with the switch information
        data['dpid'] = dpid
        data['port'] = port

        # if it's an arp packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            logger.debug("\nPACKET_IN : Received an ARP packet from sw-{}".format(str(dpid)))
            # convert the arp packet into a dictionnary
            data['packet'] = parser.arp_to_dict(pkt)
        else:
            logger.debug("\nPACKET_IN : Received an IP packet from sw-{}".format(str(dpid)))
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
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()

    """
    @set_ev_cls([ofp_event.EventOFPSwitchFeatures,
                 ofp_event.EventOFPQueueGetConfigReply], MAIN_DISPATCHER)
    def features_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        del self.waiters[dp.id][msg.xid]
        lock.set()
    """

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install a drop rule by default
        match_drop = parser.OFPMatch()
        req_drop = parser.OFPFlowMod(
            datapath=datapath, match=match_drop, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0,flags=0, actions=[])
        datapath.send_msg(req_drop)

        # install a rule for arp flows
        match_arp = parser.OFPMatch(dl_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        req_arp = parser.OFPFlowMod(
            datapath=datapath, match=match_arp, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=1,flags=0, actions=actions)
        datapath.send_msg(req_arp)
