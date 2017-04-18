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
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3, ofproto_v1_4
from ryu.lib import ofctl_v1_0, ofctl_v1_2, ofctl_v1_3, ofctl_v1_4
from ryu.app.wsgi import ControllerBase, WSGIApplication
from ryu.topology import event, switches
from rest_client import RyuTopologyClient
from ryu.lib.packet import packet,ethernet,ether_types
from packetParser import PacketParser
from log import Logger
from pprint import pprint
import logging, json, ast

#LOG = logging.getLogger('ryu.app.ofctl_rest')
logger = Logger("airnet_interface").getLog()

# supported ofctl versions in this restful app
supported_ofctl = {
    ofproto_v1_0.OFP_VERSION: ofctl_v1_0,
    ofproto_v1_2.OFP_VERSION: ofctl_v1_2,
    ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
    ofproto_v1_4.OFP_VERSION: ofctl_v1_4,
}

#rajoute pour stocker des packets
#dictionnaire qui contiendra les msg OpenFlow remontes comme PacketIn :{0:msg1,1:msg2,....}
packets = {}

#cle des packets dans le dictionnaire precedent
id_packet = 0

class StatsController(ControllerBase):
    """
        Class Description not to forget
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
        #trash_data = json.load(body)
        #pprint(trash_data)

        return Response(content_type='application/json', body=body)

    def mod_flow_entry(self, req, cmd, **_kwargs):
        """
            Function Description
        """
        try:
            # Syntax verification
            flow = ast.literal_eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        # get the dpid field in the request
        dpid = flow.get('dpid')

        # check if the dpid field is correct
        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
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
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def delete_flow_entry(self, req, dpid, **_kwargs):
        """

        """
        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
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
            LOG.debug('Unsupported OF protocol')
            return Response(status=501)

        return Response(status=200)

    def send_packet(self, req, **_kwargs):
        """
            Sends PacketOut
        """
        sender = PacketParser()

        try:
            flow = ast.literal_eval(req.body)
        except SyntaxError:
            LOG.debug('invalid syntax %s', req.body)
            return Response(status=400)

        dpid = flow.get('dpid')

        if type(dpid) == str and not dpid.isdigit():
            LOG.debug('invalid dpid %s', dpid)
            return Response(status=400)

        dp = self.dpset.get(int(dpid))

        if dp is None:
            return Response(status=404)

        _ofp_version = dp.ofproto.OFP_VERSION

        _ofctl = supported_ofctl.get(_ofp_version, None)

        if _ofctl is not None:
            if 'id_packet' not in flow:
                # le packet Arp ne sont pas numerotes
                """
                    What's the point ??
                """
                sender.send_arp(dp,flow)
        else:
            """
                The OF protocol is not supported here
            """
            global packets

            id_pkt = int(flow.get('id_packet'))

            """
                The OF protocol is already not supported here right ??
            """
            if id_pkt in flow:
                msg = packets.get(id_pkt)
                #on supprime le paquet du dictionnaires des packets
                del packets[id_pkt]
                sender.send_packet(dp,flow,msg)
            else:
                LOG.debug('Unsupported OF protocol')
                return Response(status=501)

class RestStatsApi(app_manager.RyuApp):

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

        # REST Server Parameters
        self.client = RyuTopologyClient('localhost',9000)

        self.dpset = kwargs['dpset']

        wsgi = kwargs['wsgi']

        self.waiters = {}
        self.data = {}

        self.data['dpset'] = self.dpset

        self.data['waiters'] = self.waiters

        mapper = wsgi.mapper

        wsgi.registory['StatsController'] = self.data
        path = '/stats'
        uri = path + '/flow/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='get_flow_stats',
                       conditions=dict(method=['GET', 'POST']))

        uri = path + '/flowentry/{cmd}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='mod_flow_entry',
                       conditions=dict(method=['POST']))

        uri = path + '/flowentry/clear/{dpid}'
        mapper.connect('stats', uri,
                       controller=StatsController, action='delete_flow_entry',
                       conditions=dict(method=['DELETE']))

        """
            a expliquer
        """
        # rajoute pour recevoir des demandes d'envoi de paquets depuis airnet
        uri = path + '/send'
        mapper.connect('stats', uri,
                       controller=StatsController, action='send_packet',
                       conditions=dict(method=['POST']))

    @set_ev_cls(event.EventSwitchEnter)
    def _event_switch_enter_handler(self, ev):
        logger.debug("*** Switch-{} Entering ".format(ev.switch.dp.id))

        # convert switch object informations to a dict
        msg = ev.switch.to_dict()

        logger.debug("\n{}".format("\n".join([str(porti) for porti in msg['ports']])))
        self.client.switchEnter(msg)

    @set_ev_cls(event.EventSwitchLeave)
    def _event_switch_leave_handler(self, ev):
        logger.debug("*** Switch-{} Leaving ".format(ev.switch.dp.id))
        msg = ev.switch.to_dict()
        self.client.switchLeave(msg)

    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        logger.debug("*** Adding Link \n{}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkAdd(msg)

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        logger.debug("*** Deleting Link \n{}".format(str(ev.link)))
        msg = ev.link.to_dict()
        self.client.linkDelete(msg)

    @set_ev_cls(event.EventHostAdd)
    def _event_host_add_handler(self, ev):
        logger.debug("*** Host {} Entering ".format(str(ev.host.mac)))
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

        # get the switch which send the packet
        datapath = msg.datapath
        # get the switch's id
        dpid = datapath.id
        #
        port = msg.in_port
        # Initialize a dictionnary
        data = {}
        # Fulfill it with the switch information
        data['dpid'] = dpid
        data['port'] = port

        # if it's an arp packet
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            logger.debug("PACKET_IN : Received an ARP packet from sw-{}".format(str(dpid)))
            # convert the arp packet into a dictionnary
            data['packet'] = parser.arp_to_dict(pkt)
        else:
            logger.debug("PACKET_IN : Received an IP packet from sw-{}".format(str(dpid)))
            data['packet'] = parser.packet_to_dict(pkt)
            # Packet Numbering
            data['id_packet'] = id_packet
            # Packet Storage
            packets[id_packet] = msg
            id_packet = id_packet + 1
        # Packet contents are formatted in json
        data = json.dumps(data)
        logger.debug("{}".format(data))
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
