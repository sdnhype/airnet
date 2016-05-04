#Ryu client
import httplib
import json
from stage_language import identity, forward, modify,match
import ast

ARP_REQUEST = 1
ARP_REPLY = 2

class Client(object):
	"""Client de base qui permet d'envoyer des requetes et recevoir des resultats du controleur"""
	def __init__(self,host,port,prefix):
		super(Client, self).__init__()
		self.host = host
		self.port = port
		self.prefix = '/'+prefix+'/'

	def send_request(self,method,action,data=None):
		conn = httplib.HTTPConnection(self.host, self.port)
		url = self.prefix + action
		header = {}
		if data is not None:
			data = json.dumps(data)
			header['Content-Type'] = 'application/json'
		try:
			conn.request(method,url,data,header)
			res = conn.getresponse()
			if res.status in (httplib.OK,
						  httplib.CREATED,
						  httplib.ACCEPTED,
						  httplib.NO_CONTENT):
				return res
			else:
				raise Exception
		except Exception:
			raise Exception

	def send_and_read_request(self,method,action,data=None):
		try:
			res = self.send_request(method,action,data)
			return res.read()
		except Exception:
			return None
class ConfigFlow(Client):
 	"""Client pour configurer les Flows sur les switches"""
 	prefix_config = 'stats/flowentry'

 	def __init__(self,host,port):
 		super(ConfigFlow,self).__init__(host,port,ConfigFlow.prefix_config)
		 
 	""" teste """
 	def addFlow(self,data):
	 	try:
 			self.send_request('POST','add',data)
		except Exception:
			print 'Add flow : Exception'
 		 
 	def updateFlow(self,data):
	 	try:
 			self.send_request('POST','modify_strict',data)
		except Exception:
			print 'Update flow : Exception'

 	def deleteFlow(self,data):
 		try:
		 	self.send_request('POST','delete_strict',data)
		except Exception:
			print 'Delete flow : Exception'
		 
 	def deleteAllFlow(self,dpid):
 		action = 'clear/'+'%s' %(dpid)
		try:
 			self.send_request('DELETE',action)
		except Exception:
			print 'Clear flows : Exception'

class RecupStats(Client):
	"""Client pour recuperer les stats"""
	prefix_stat = 'stats'
	
	def __init__(self,host,port):
		super(RecupStats,self).__init__(host,port,RecupStats.prefix_stat)
		
	def getStatsFlow(self,dpid,data=None):
		action = 'flow/%s' % (dpid)
		return self.send_request('GET',action,data)
		
	def sendEx(self,data):
		action = 'send'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Send Packet : Exception'

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


class RyuClient(object):
	"""
	"""
	def __init__(self,runtime):
		self.switches_rules_cpt = {}
		self.runtime = runtime
		self.runtime_mode = False #indique si on deja installe les 1eres regles
	
	"""
	construit le dictionnaire de match
	"""	
	def build_match_field(self, src = None, dst = None,dl_src=None, dl_dst=None, 
                          nw_src = None, nw_dst = None, tp_src=None, tp_dst=None, nw_proto= None, in_port=None):
		match = {}
		if src:
			for ipAddr, host in self.runtime.mapping.hosts.iteritems():
				if host == src:
					match['nw_src'] = ipAddr
		if dst:
			for ipAddr, host in self.runtime.mapping.hosts.iteritems():
				if host == dst:
					match['nw_dst'] = ipAddr
		if dl_src:
			match['dl_src'] = dl_src
		if nw_src:
			match['nw_src'] = nw_src
        	match['dl_type'] = 0x0800
		if nw_dst:
			match['nw_dst'] = nw_dst
			match['dl_type'] = 0x0800
		if tp_src:
			match['tp_src'] = tp_src
		if tp_dst:
			match['tp_dst'] = tp_dst
		if nw_proto:
			match['nw_proto'] = nw_proto
		if in_port:
			match['in_port'] = in_port   
		return match
	
	"""
	construit la liste des actions,chaque action etant un dictionnaire	
	"""	
	def build_action_fields(self,actions):
		actions_mod = []
		for act in actions:
			if isinstance(act, modify):
				if "nw_dst" in act.map:
					actions_mod.append({'type':'SET_NW_DST','nw_dst':act.map["nw_dst"]})     
				if "nw_src" in act.map:
					actions_mod.append({'type':'SET_NW_SRC','nw_src':act.map["nw_src"]})
				if "dl_dst" in act.map:
					actions_mod.append({'type':'SET_DL_DST','dl_dst':act.map["dl_dst"]})
				if "dl_src" in act.map:
					actions_mod.append({'type':'SET_DL_SRC','dl_src':act.map["dl_src"]})
			if isinstance(act, forward):
				if act.output == "OFPP_CONTROLLER":
					act.output = 0xfffd #controller port
				actions_mod.append({'type':'OUTPUT','port':act.output})
		return actions_mod
	
	"""
	construit la liste des actions,chaque action etant un dictionnaire	
	"""
	def build_action_fields_bis(self,actions):
		actions_mod = []
		for act in actions:
			if isinstance(act, modify):
				if "nw_dst" in act.map:
					actions_mod.append({'type':'SET_NW_DST','nw_dst':act.map["nw_dst"]})
				elif "nw_src" in act.map:
					actions_mod.append({'type':'SET_NW_SRC','nw_src':act.map["nw_src"]})
			if isinstance(act, forward):
				if act.output == "OFPP_CONTROLLER":
					act.output = 0xfffd #controller port
				actions_mod.append({'type':'OUTPUT','port':act.output})
		return actions_mod
			
	"""
	installe les regles,utilise par le mode proactif
	classifiers : dictionnaire des regles a installer
	"""
	def install_rules_on_dp(self, classifiers):
		c = ConfigFlow('localhost',8080)
		for switch, rules in classifiers.iteritems():
			dpid = int(switch[1:])
			priority = len(rules)
			self.switches_rules_cpt[switch] = len(rules)
			for rule in rules:
				data = {} #dictionnaire qui sera envoye 
				data['dpid'] = dpid
				if rule.match != identity:
					data['match'] = self.build_match_field(**rule.match.map)
					if not len(rule.actions) == 0:
						data['actions'] = self.build_action_fields(rule.actions)
				data['priority'] = priority
				priority = priority-1
				c.addFlow(data)
		self.runtime_mode = True
	
	"""
	depreciee
	"""		
	def install_arp_bis(self,dpid,ip_src,ip_dst,mac_src,mac_dst,port):
		data = {'dpid':dpid,'port':port,'mac_src':mac_src,'mac_dst':mac_dst,'ip_src':ip_src,'ip_dst':ip_dst}
		c = RecupStats('localhost',8080)
		c.sendEx(data)
		
	"""
	installe des nouvelles regles,utilise par le mode reactif
	classifiers : dictionnaire des regles a installer
	"""
	def installNewRules(self, classifiers):
		c = ConfigFlow('localhost',8080)
		for switch,rules in classifiers.iteritems():
			dpid = int(switch[1:])
			for rule in rules:
				priority = len(self.runtime.new_classifiers[switch]) - rule[1]
				data = {} #dictionnaire qui sera envoye 
				data['dpid'] = dpid
				data['match'] = self.build_match_field(**rule[0].match.map)
				if not len(rule[0].actions) == 0:
					data['actions'] = self.build_action_fields(rule[0].actions)
				data['priority'] = priority
				c.addFlow(data)
			self.switches_rules_cpt[switch] += len(rules)	
	
	"""
	supprime des regles,utilise par le mode reactif
	to_delete: dictionnaire des regles a supprimer
	"""		
	def delete_rules(self, to_delete):
		c = ConfigFlow('localhost',8080)
		for switch, rules in to_delete.iteritems():
			cpt_deleted_rules = 0
			dpid = int(switch[1:])
			for rule in rules:
				data = {} #dictionnaire qui sera envoye 
				data['dpid'] = dpid
				data['match'] = self.build_match_field(**rule[0].match.map)
				if not len(rule[0].actions) == 0:
					data['actions'] = self.build_action_fields_bis(rule[0].actions)
				data['priority'] = self.switches_rules_cpt[switch] - rule[1]
				c.deleteFlow(data)
				cpt_deleted_rules += 1
			self.switches_rules_cpt[switch] -= cpt_deleted_rules
			 
	"""
	modifie des regles,utilise par le mode reactif
	to_modify est un dictionnaire contenant les regles a modifier 
	"""
	def modifyExistingRules(self, to_modify):
		c = ConfigFlow('localhost',8080)
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
			to_delete = {switch:[]}
			to_delete[switch].append(old_r)
			self.delete_rules(to_delete)
			to_add = {switch:[]}
			to_add[switch].append(new_r)
			self.installNewRules(to_add)
			
		for switch, rules in to_modify.iteritems():
			dpid = int(switch[1:])
			for new_r, old_r in rules:
				if isSame(old_r[0], new_r[0]):
					if self.switches_rules_cpt[switch]-old_r[1] != len(self.runtime.new_classifiers[switch])-new_r[1]:
						modify_priority(old_r, new_r, switch)
				else:
					data = {} #dictionnaire qui sera envoye 
					data['dpid'] = dpid
					data['match'] = self.build_match_field(**new_r[0].match.map)
					if not len(new_r[0].actions) == 0:
						data['actions'] = self.build_action_fields_bis(new_r[0].actions)
					data['priority'] = self.switches_rules_cpt[switch] - new_r[1]
					c.updateFlow(data)
	
	"""
	modifie des regles
	to_modify est un dictionnaire contenant les regles a modifier 
	"""
	def modify_existing_rules(self, to_modify):
		c = ConfigFlow('localhost',8080)
		for switch, rules in to_modify.iteritems():
			dpid = int(switch[1:])
			for rule in rules:
				data = {} #dictionnaire qui sera envoye
				data['dpid'] = dpid
				data['match'] = self.build_match_field(**rule[0].match.map)
				if not len(rule[0].actions) == 0:
					data['actions'] = self.build_action_fields_bis(rule[0].actions)
				data['priority'] = self.switches_rules_cpt[switch] - rule[1]
				#TODO runtime.msgs
				c.updateFlow(data)
				
	"""
	envoie des requetes pour recevoir les stats sur un flow
	switches est une liste de switch
	target_match est le matching correspondant au flow
	"""
	def send_stat_request(self, switches, target_match):
		"""
		"""
		s = RecupStats('localhost',8080)
		_target_match = copy.deepcopy(target_match)
		_target_match.map.pop("edge")
		request = {}
		request['match'] = self.build_match_field(**_target_match.map)
		for switch in switches:
			dpid = int((switch[1:]))
			request['dpid'] = dpid
			s.getStatsFlow(self,dpid,request)	
			#TODO comment transferer les donnees	
	
	"""
	gere les packet in
	pour le moment seul le ARP est traite
	le packet en parametre est au format json avec le dpid,le port et une liste de protocoles
	"""
	def handle_PacketIn(self,packet):
		dpid = int(packet.get('dpid'))
		port = int(packet.get('port_in'))
		protos = (packet.get('packet'))
		if str(protos[1]).startswith("arp"):
			data_arp = ast.literal_eval(str(protos[1])[5:])
			if data_arp.get('opcode') == ARP_REQUEST:
				self.install_arp(protos,dpid,port,data_arp)	
	
	"""
	fonction qui construit et envoie un packet ARP de reponse
	protos est la liste des protocoles
	dpid le switch, port est le numero de port
	data_arp est le dictionnaire contenant les infos ARP
	"""
	def install_arp(self,protos,dpid,port,data_arp):
		ip_src = data_arp.get('src_ip')
		ip_dst = data_arp.get('dst_ip')
		mac_src = data_arp.get('src_mac')
		requested_mac = self.runtime.infra.arp(ip_dst)
		if requested_mac is not None:
			#on reconstruit le paquet de retour
			data_arp["opcode"] = ARP_REPLY
			data_arp["src_ip"] = ip_dst
			data_arp["dst_ip"] = ip_src
			data_arp["src_mac"] = requested_mac
			data_arp["dst_mac"]	= mac_src
			data_arp = "arp: " + str(data_arp)
			data_arp = unicode (data_arp)
			protos[1] = data_arp
			data_ethernet = ast.literal_eval(str(protos[0])[10:])
			data_ethernet["dst"] = mac_src
			data_ethernet["src"] = requested_mac
			data_ethernet = "ethernet: " +str(data_ethernet)
			data_ethernet = unicode(data_ethernet)
			protos[0] = data_ethernet
			packet_out = {}
			packet_out['dpid'] = dpid
			packet_out['port'] = port
			packet_out['packet'] = protos
			c = RecupStats('localhost',8080)
			c.sendEx(packet_out)
			
		
						
		