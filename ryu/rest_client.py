import httplib
import json

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
		conn.request(method,url,data,header)
		res = conn.getresponse()
		if res.status in (httplib.OK,
						  httplib.CREATED,
						  httplib.ACCEPTED,
						  httplib.NO_CONTENT):
			return res
		return None

	def send_and_read_request(self,method,action):
		res = self.send_request(method,action)
		return res.read()

class RyuTopologyClient(Client):
	"""Client qu'utilise l'app Ryu pour envoyer notifier les modifications de topologie"""
	prefix_ryu = 'Topo'

	def __init__(self,host,port):
		super(RyuTopologyClient,self).__init__(host,port,RyuTopologyClient.prefix_ryu)

	def switchEnter(self,data):
		action = 'Switch/enter'
		return self.send_request('POST',action,data)

	def switchLeave(self,data):
		action = 'Switch/leave'
		return self.send_request('POST',action,data)

	def linkAdd(self,data):
		action = 'Link/add'
		return self.send_request('POST',action,data)

	def linkDelete(self,data):
		action = 'Link/delete'
		return self.send_request('POST',action,data)

	def hostAdd(self,data):
		action = 'Host/add'
		return self.send_request('POST',action,data)

	def packetIn(self,data):
		action = 'Packet/in'
		return self.send_request('POST',action,data) 

