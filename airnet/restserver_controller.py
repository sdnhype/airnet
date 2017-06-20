# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI
"""
	Airnet REST Server to which the Controller REST Client sends information
		-> PacketIn
		-> Switch enter
		-> Switch leave
		-> Link add
		-> Host add
	Triggers updates in infrastructure and runtime modules depending of the information received
	Listens currently at {0.0.0.0:9000}
	-> based on the Flask micro web development framework (see flask.pocoo.org)
"""

#TODO: log here irrelevant or not ?
#TODO: ipAdrs thing in handle_host_add

import thread
import time
import sys
from pprint import pprint
from flask import Flask,json,request,Response

from infrastructure import Infrastructure
from restclient_controller import RyuClient
from runtime import Runtime

# WSGI Application
app = Flask(__name__)

"""formatter = logging.Formatter('%(asctime)s : %(name)s : [%(levelname)s] : %(message)s')
handler = logging.FileHandler("log/airnet.log",mode="a", encoding="utf-8")
handler.setFormatter(formatter)
app.logger.setLevel(logging.INFO)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)
"""
# initialize the global topology container
infra = Infrastructure()

control_module = sys.argv[1]
mapping_module = sys.argv[2]

# launch the runtime module
runtime = Runtime(control_module,mapping_module,infra)
# launch the REST client which communicates with RYU
client_ryu = RyuClient(runtime)
# link it to the runtime module
runtime.add_controller_client(client_ryu)

# received a switch enter event from the controller
@app.route('/Topo/Switch/enter',methods = ['POST'])
def handle_switch_enter():
	# get the content of json file received
	data = request.json
	# convert dpid in int
	dpid = int (data['dpid'],16)
	ports = data['ports']
	# add the new switch to the global topology view
	infra._handle_SwitchJoin(dpid,ports)
	return 'OK'

# received a switch leave event from the controller
@app.route('/Topo/Switch/leave',methods = ['POST'])
def handle_switch_leave():
	data = request.json
	dpid = int (data['dpid'],16)
	infra._handle_SwitchLeave(dpid)
	return 'OK'

# received a switch-to-switch link add event from the controller
@app.route('/Topo/Link/add',methods = ['POST'])
def handle_link_add():
	data = request.json
	src = data['src']
	dst = data['dst']
	dpid1 = int(src['dpid'],16)
	port1 = int(src['port_no'])
	dpid2 = int(dst['dpid'],16)
	port2 = int(dst['port_no'])
	infra._handle_LinkEvent(dpid1,port1,dpid2,port2,True)
	# Proactive (static) rules are installed
	if runtime.nexus.runtime_mode:
		# topology must change
		runtime.handle_topology_change()
	return 'OK'

# received a switch-to-switch link delete event from the controller
@app.route('/Topo/Link/delete',methods = ['POST'])
def handle_link_delete():
	data = request.json
	src = data['src']
	dst = data['dst']
	dpid1 = int (src['dpid'],16)
	port1 = int(src['port_no'])
	dpid2 = int (dst['dpid'],16)
	port2 = int(dst['port_no'])
	infra._handle_LinkEvent(dpid1,port1,dpid2,port2,False)
	if runtime.nexus.runtime_mode:
		runtime.handle_topology_change()
	return 'OK'

# received a host add event from the controller
@app.route('/Topo/Host/add',methods = ['POST'])
def handle_host_add():
	data = request.json
	ips = data['ipv4']
	ipadrs = {}
	for ip in ips:
		ipadrs[str(ip)] = 1

	mac = str(data['mac'])
	ports = data['port']
	dpid = int(ports['dpid'],16)
	port = int(ports['port_no'])
	# add the new host to the global topology view
	infra._handle_host_tracker_HostEvent(dpid, port, mac, ipadrs, True)
	# check if all hosts has been discovered
	if (runtime.all_hosts_discovered()) :
		print("All hosts discovered")
		# enforce proactive rules
		thread.start_new_thread(enforce_proactive_policies,())
	else :
		print("At least 1 more host to discover")
	return 'OK'

# received a packet in event from the controller
@app.route('/Topo/Packet/in',methods = ['POST'])
def handle_packet_in():
	if runtime.nexus.runtime_mode:
		packet = json.loads(request.json)
		runtime.nexus.handle_PacketIn(packet)
	return 'OK'

def enforce_proactive_policies():
	time.sleep(5)
	# show the global topology view with all equipments
	runtime.infra.view()
	# enforce proactive rules
	runtime.enforce_policies()

def main():
	app.run(host='0.0.0.0', port=9000)

if __name__ == '__main__':
	main()
