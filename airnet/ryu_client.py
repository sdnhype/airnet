"""
Code executed by AirNet to interact with a remote RYU controller
(via REST API)
"""
from language import identity, forward, modify, match
import ast, pdb, httplib, json, copy

# **************** CODE AUDIT *******************
#TODO: REACTIVE Core Policies
#TODO: Remove build_action_fields_bis on #236
#TODO: Why stats Prefix on #57

ARP_REQUEST = 1
ARP_REPLY = 2

class Client(object):
	"""
		Sends requests and receives responses from the SDN controller
	"""
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
 	"""
		Push Flow to the physical switches through the REST API
	"""
 	prefix_config = 'stats/flowentry'

 	def __init__(self,host,port):
 		super(ConfigFlow,self).__init__(host,port,ConfigFlow.prefix_config)

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
	"""Client pour recuperer les stats et envoyer des packets"""
	prefix_stat = 'stats'

	def __init__(self,host,port):
		super(RecupStats,self).__init__(host,port,RecupStats.prefix_stat)

	def getStatsFlow(self,dpid,data=None):
		action = 'flow/%d' % (dpid)
		return self.send_request('GET',action,data)

	def sendPacket(self,data):
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
		self.runtime_mode = False # Proactive rules are not installed yet

	def build_match_field(self, src = None, dst = None,dl_src=None, dl_dst=None,
                          nw_src = None, nw_dst = None, tp_src=None, tp_dst=None, nw_proto= None, in_port=None):
		"""
			Construct OF MATCH fields in a dictionary
		"""
		match = {}

		if src:
			for ipAddr, host in self.runtime.mapping.hosts.iteritems():
				if host == src:
					match['nw_src'] = ipAddr
		if dst:
			for ipAddr, host in self.runtime.mapping.hosts.iteritems():
				if host == dst:
					match['nw_dst'] = ipAddr
		if dl_dst:
			match['dl_dst'] = dl_dst
		if dl_src:
			match['dl_src'] = dl_src
		if nw_src:
			match['nw_src'] = nw_src
        	match['dl_type'] = 0x0800 #ipv4
		if nw_dst:
			match['nw_dst'] = nw_dst
			match['dl_type'] = 0x0800 #ipv4
		if tp_src:
			match['tp_src'] = tp_src
		if tp_dst:
			match['tp_dst'] = tp_dst
		if nw_proto:
			match['nw_proto'] = nw_proto
		if in_port:
			match['in_port'] = in_port
		return match

	def build_action_fields(self,actions):
		"""
			Construct OF ACTIONS fields dictionary
		"""
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
		for act in actions:
			if isinstance(act, forward):
				if act.output == "OFPP_CONTROLLER":
					act.output = 0xfffd #controller port
				actions_mod.append({'type':'OUTPUT','port':act.output})
		return actions_mod

	"""
		For What ?
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

	def install_rules_on_dp(self, classifiers):
		"""
			Push Proactive Rules on the controller through the REST API
			Rules are taken from classifiers (dictionary --> sw1 : [r1,r2,r3...], sw2 :...)
		"""
		c = ConfigFlow('localhost',8080)

		for switch, rules in classifiers.iteritems():
			# get the switch id
			dpid = int(switch[1:])
			# set the highest priority
			priority = len(rules)
			# set the current switch number of rules
			self.switches_rules_cpt[switch] = len(rules)
			# for each rule
			for rule in rules:
				# initialize a dictionary
				data = {}
				# affect rules values to the dictionary
				data['dpid'] = dpid
				# the following is for every rule except the default one (identity -- identity -- drop)
				if rule.match != identity:
					data['match'] = self.build_match_field(**rule.match.map)
					# if there is at least one action
					if not len(rule.actions) == 0:
						data['actions'] = self.build_action_fields(rule.actions)
				# set a degressive priority
				data['priority'] = priority
				priority = priority-1
				# push the dictionary
				c.addFlow(data)
		# First rules are installed
		self.runtime_mode = True

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
	installe des nouvelles regles,utilise par le mode dynamique
	classifiers : dictionnaire des regles a installer
	"""
	def install_new_rules(self, classifiers):
		c = ConfigFlow('localhost',8080)
		for switch, rules in classifiers.iteritems():
			priority = self.switches_rules_cpt[switch] + len(rules)
			dpid = int(switch[1:])
			for rule in rules:
				data = {} #dictionnaire qui sera envoye
				data['dpid'] = dpid
				data['match'] = self.build_match_field(**rule.match.map)
				if not len(rule.actions) == 0:
					data['actions'] = self.build_action_fields(rule.actions)
				data['priority'] = priority
				priority -= 1
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
			s.getStatsFlow(dpid,request)
			#TODO comment transferer les donnees

	"""
	gere les packet in
	pour le moment seul le ARP est traite
	le packet en parametre est au format json avec le dpid,le port et les entetes des protocoles du packet
	{"port":..,"id_packet":..,"dpid":..,"packet": {"ipv4":{.....},"tcp":{....},"icmp":{...},
                                                   "udp":{.....},"dl_src":...,"dl_dst":...}}
	"""
	def handle_PacketIn(self,packet):
		dpid = int(packet.get('dpid'))
		port = int(packet.get('port'))
		protos = (packet.get('packet'))
		protos = ast.literal_eval(str(protos))
		if 'arp' in protos:
			data_arp = protos.get('arp')
			if data_arp.get('opcode') == ARP_REQUEST:
				self.install_arp(dpid,port,data_arp)
		else:
			print("Handling IP packetIn...")
			packet_match = self.match_from_packet(dpid,protos)
			self.runtime.handle_packet_in(dpid, packet_match, packet)

	"""
	fonction qui construit et envoie un packet ARP de reponse
	protos est la liste des protocoles
	dpid le switch, port est le numero de port
	data_arp est le dictionnaire contenant les infos ARP
	{"src_mac":..,"dst_mac":..,"src_ip":..,"dst_ip":...,"opcode":..}
	"""
	def install_arp(self,dpid,port,data_arp):
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
			packet = {}
			packet["arp"] = data_arp
			data_arp = unicode (data_arp)
			packet_out = {}
			packet_out['dpid'] = dpid
			packet_out['port'] = port
			packet_out['packet'] = packet
			c = RecupStats('localhost',8080)
			c.sendPacket(packet_out)
	"""
	permet d'envoyer un dictionnaire contenant le numero et les entetes d'un paquet
	au controleur ryu pour que celui-ci le delivre
	switch: nom du switch sur lequel envoyer le paquet
	output le numero de port du switch
	packet: dictionnaire contenant les infos du paquet
	{"port":..,"id_packet":..,"dpid":..,"packet": {"ipv4":{.....},"tcp":{....},"icmp":{...},
                                                   "udp":{.....},"dl_src":...,"dl_dst":...}}
	"""
	def send_packet_out(self, switch, packet, output):
		dpid = int((switch[1:]))
		packet['dpid'] = dpid
		packet['output'] = output
		c = RecupStats('localhost',8080)
		print("[DEBUG] ryu_client -- send_packet_out()")
		c.sendPacket(packet)

	"""
	cree un match a partir des entete d'un paquet
	dpid: numero du switch
	protos: dictionnaires contenant les entetes des protocoles du packet
	{"ipv4":{.....},"tcp":{....},"icmp":{...},"udp":{.....},"dl_src":...,"dl_dst":...}
	"""
	def match_from_packet(self,dpid, protos):
		my_match = match()
		if 'ipv4' in protos:
			ip = protos.get('ipv4')
			my_match.map["nw_src"] = ip.get('src')
			my_match.map["nw_dst"] = ip.get('dst')
		if 'tcp' in protos:
			tcp = protos.get('tcp')
			my_match.map["tp_src"] = tcp.get('src_port')
			my_match.map["tp_dst"] = tcp.get('dst_port')
			my_match.map["nw_proto"] = "TCP"
		if 'udp' in protos:
			udp = protos.get('udp')
			my_match.map["tp_src"] = udp.get('src_port')
			my_match.map["tp_dst"] = udp.get('dst_port')
			my_match.map["nw_proto"] = 17
		if 'icmp' in protos:
			my_match.map["nw_proto"] = 1
		#adding edge field in the match
		switch = 's' + str(dpid)
		edge = self.runtime.get_corresponding_virtual_edge(switch)
		if edge:
			my_match.map['edge'] = edge
		else:
			return None
		return my_match
