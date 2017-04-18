# ryu application qui envoie les evenements a notre serveur
# elle s'abonne aux evenements concernes et utilise le client REST pour les envoyer

from ryu.base import app_manager
from ryu.topology import event, switches
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from rest_client import RyuTopologyClient
import json
import ast

class AppRyu(app_manager.RyuApp):
	_CONTEXTS = {
		   'switches': switches.Switches
	}

	def __init__(self,*args, **kwargs):
		super(AppRyu,self).__init__(*args,**kwargs)
		self.client = RyuTopologyClient('localhost',9000)

	@set_ev_cls(event.EventSwitchEnter)
	def _event_switch_enter_handler(self, ev):
    		msg = ev.switch.to_dict()
    		self.client.switchEnter(msg)

	@set_ev_cls(event.EventSwitchLeave)
	def _event_switch_leave_handler(self, ev):
		msg = ev.switch.to_dict()
		self.client.switchLeave(msg)

	@set_ev_cls(event.EventLinkAdd)
	def _event_link_add_handler(self, ev):
		msg = ev.link.to_dict()
		self.client.linkAdd(msg)

	@set_ev_cls(event.EventLinkDelete)
	def _event_link_delete_handler(self, ev):
		msg = ev.link.to_dict()
		self.client.linkDelete(msg)

	@set_ev_cls(event.EventHostAdd)
	def _event_host_add_handler(self, ev):
		msg = ev.host.to_dict()
		self.client.hostAdd(msg)

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)
		if eth.ethertype != ether_types.ETH_TYPE_ARP:
		# on ignore tout ce qui n'est pas ARP pour le moment
			return
		datapath = msg.datapath
		dpid = datapath.id
		port = msg.in_port
		data = pkt.__str__()
		data = data[:-1] #pour enlever la derniere parenthese fermante
		result = data.split("), ") # on recupere chaque protocole a part
		proto = []
		for res in result:
			res = res.replace("(",': {"') # on simule un dictionnaire pour chaque protocole
			res = res.replace("'",'"') # on remplace ' par "
			res = res.replace("=",'":') # on remplace = par ": pour la fin de la cle
			res = res.replace(",",',"') #on remplace , par ," pour le debut de chaque cle
			res = res + "}"
			proto.append(res)
		data = {}
		data["dpid"] = dpid
		data["port_in"] = port
		data["packet"] = proto
		data = json.dumps(data)
		self.client.packetIn(data)
