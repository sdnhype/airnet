# client Rest
from log import Logger
import httplib, json, logging

handler_info = logging.StreamHandler()
handler_info.setLevel(logging.INFO)
logger = Logger("rest_client").getLog()
logger.addHandler(handler_info)

class Client(object):
	"""
	   Class which allows to send requests to a REST Server
	   Connection to the server is done through httplib library
	   Data are transmitted in JSON format
	"""
	def __init__(self,host,port,prefix):
		super(Client, self).__init__()
		self.host = host
		self.port = port
		self.prefix = '/'+prefix+'/'

	def send_request(self,method,action,data=None):
		# connection to the REST server
		conn = httplib.HTTPConnection(self.host, self.port)
		# Adding prefix (/Topo/)
		url = self.prefix + action
		header = {}
		# There is some information to send
		if data is not None:
			# Encode contents in json format
			data = json.dumps(data)
			#logger.debug("Json File : \n{}".format(json.dumps(data, sort_keys=True, ident=4, separators=(',',': '))))
			header['Content-Type'] = 'application/json'
		try:
			logger.debug("Send {} request via {} method".format(action,method))
			# send request to the REST Server and get the answer
			conn.request(method,url,data,header)
			res = conn.getresponse()
			#logger.debug("Got Response from REST server: {}".format(str(res)))
			# if everything is ok
			if res.status in (httplib.OK,
						  httplib.CREATED,
						  httplib.ACCEPTED,
						  httplib.NO_CONTENT):
				return res
			else:
				raise Exception("REST server response status isn't OK")
		except Exception:
			raise Exception("Error while sending request to the REST server")

	def send_and_read_request(self,method,action,data=None):
		try:
			res = self.send_request(method,action,data)
			return res.read()
		except Exception:
			return None

class RyuTopologyClient(Client):
	"""
		Client used by RYU to notify topology changes to REST Server
	"""
	prefix_ryu = 'Topo'

	def __init__(self,host,port):
		super(RyuTopologyClient,self).__init__(host,port,RyuTopologyClient.prefix_ryu)

	def switchEnter(self,data):
		action = 'Switch/enter'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Switch/enter request")

	def switchLeave(self,data):
		action = 'Switch/leave'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Switch/leave request")

	def linkAdd(self,data):
		action = 'Link/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Link/add request")

	def linkDelete(self,data):
		action = 'Link/delete'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Link/delete request")

	def hostAdd(self,data):
		action = 'Host/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Host/add request")

	def packetIn(self,data):
		action = 'Packet/in'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.info("Exception while sending Packet/in request")

class GenericClient(Client):
	"""

	"""
	def __init__(self,host,port,prefix):
		super(GenericClient,self).__init__(host,port,prefix)

	def doRequest(self,method,action,data=None):
		try:
			self.send_request(method,action,data)
		except Exception:
			print 'Generic method : Exception'

	def doRequestRead(self,method,action,data=None):
		return self.send_and_read_request(method,action,data)
