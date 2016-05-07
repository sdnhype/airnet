# client Rest
import httplib
import json

class Client(object):
	"""Client de base qui permet d'envoyer des requetes a un serveur REST
	   Elle utilise la bibliotheque httplib pour se connecter 
	   Et transfere des donnees sous le format JSON	
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

class RyuTopologyClient(Client):
	"""Client qu'utilise l'app Ryu pour notifier les modifications de topologie a notre serveur"""
	prefix_ryu = 'Topo'

	def __init__(self,host,port):
		super(RyuTopologyClient,self).__init__(host,port,RyuTopologyClient.prefix_ryu)

	def switchEnter(self,data):
		action = 'Switch/enter'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Switch enter : Exception'

	def switchLeave(self,data):
		action = 'Switch/leave'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Switch leave : Exception'

	def linkAdd(self,data):
		action = 'Link/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Link add : Exception'

	def linkDelete(self,data):
		action = 'Link/delete'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Link delete : Exception'

	def hostAdd(self,data):
		action = 'Host/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Host add : Exception'

	def packetIn(self,data):
		action = 'Packet/in'
		try:
			self.send_request('POST',action,data)
		except Exception:
			print 'Packet In : Exception'

class GenericClient(Client):
	""" client generique """
	def __init__(self,host,port,prefix):
		super(GenericClient,self).__init__(host,port,prefix)
		
	def doRequest(self,method,action,data=None):
		try:
			self.send_request(method,action,data)
		except Exception:
			print 'Generic method : Exception'
		
	def doRequestRead(self,method,action,data=None):
