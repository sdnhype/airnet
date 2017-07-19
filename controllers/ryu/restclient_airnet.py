# coding: utf8

# AirNet, a virtual network control language based on an Edge-Fabric model.
# Copyright (C) 2016-2017 Université Toulouse III - Paul Sabatier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import httplib, json, logging
from log import Logger

logger = Logger("Ryu_Client").Log()

class GenericClient(object):
	"""
		RYU Rest GenericClient which send events to the Airnet REST Server
		-> Equipements events (switch enter, link delete, host add...)
		-> Packets events (Packet_in)
		-> Statistics events
		Sends events in json format through the httplib library to {0.0.0.0:9000}
	"""
	def __init__(self,host,port,prefix):
		super(GenericClient, self).__init__()
		self.host = host
		self.port = port
		self.prefix = '/'+prefix+'/'

	def send_request(self,method,action,data=None):
		""" sends requests through the httplib library """
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
			logger.debug("Send {} event via {} method to Airnet".format(action,method))
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

class RyuTopologyClient(GenericClient):
	""" use the GenericClient attributes to send
		events to Airnet """

	prefix_ryu = 'Topo'

	def __init__(self,host,port):
		super(RyuTopologyClient,self).__init__(host,port,RyuTopologyClient.prefix_ryu)

	def switchEnter(self,data):
		action = 'Switch/enter'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Switch/enter to Airnet")

	def switchLeave(self,data):
		action = 'Switch/leave'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Switch/leave to Airnet")

	def linkAdd(self,data):
		action = 'Link/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Link/add to Airnet")

	def linkDelete(self,data):
		action = 'Link/delete'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Link/delete to Airnet")

	def hostAdd(self,data):
		action = 'Host/add'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Host/add to Airnet")

	def packetIn(self,data):
		action = 'Packet/in'
		try:
			self.send_request('POST',action,data)
		except Exception:
			logger.debug("Exception occurs while sending Packet/in to Airnet")
