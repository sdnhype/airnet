"""
	This is the REST Server which receive events emanating from RYU
	(based on the Flask micro web development framework: flask.pocoo.org)
"""

from flask import Flask,json,request,Response
from infrastructure import Infrastructure
from runtime import Runtime
from pprint import pprint
from log import Logger
import thread,time,sys

# log events in a special file
#logger = Logger("Main","log/event.log").getLog()

# WSGI Application
app = Flask(__name__)

# initialize the infrastructure
infra = Infrastructure()

# f1 = $CTRL_MODULE et f2 = MAPPING_MODULE
f1 = sys.argv[1]
f2 = sys.argv[2]
# launch the runtime module (goto -> runtime.py)
runtime = Runtime(f1,f2,infra,"RYU")

# received a switch enter event from ryu
@app.route('/Topo/Switch/enter',methods = ['POST'])
def handle_switch_enter():
	# get the content of json file received
	data = request.json

	dpid = int (data['dpid'],16) # dpid est en hexadecimal
	ports = data['ports']

	infra._handle_SwitchJoin(dpid,ports)
	return 'OK'

# received a switch leave event from ryu
@app.route('/Topo/Switch/leave',methods = ['POST'])
def handle_switch_leave():
	data = request.json
	dpid = int (data['dpid'],16)
	infra._handle_SwitchLeave(dpid)
	return 'OK'

# received a switch-to-switch link add event from ryu
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
	# if the static rules are already installed topology has to change
	if runtime.nexus.runtime_mode:
		runtime.handle_topology_change()
	return 'OK'

# received a switch-to-switch link deletion event from ryu
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

# received a host add event from ryu
@app.route('/Topo/Host/add',methods = ['POST'])
def handle_host_add():
	data = request.json
	ips = data['ipv4']
	# that's weird !!
	ipadrs = {}
	for ip in ips:
		ipadrs[str(ip)] = 1 # ??

	mac = str(data['mac'])
	ports = data['port']
	dpid = int(ports['dpid'],16)
	port = int(ports['port_no'])

	infra._handle_host_tracker_HostEvent(dpid, port, mac, ipadrs, True)
	if len(runtime.mapping.hosts) == len (infra.hosts):
		# all hosts have been discovered, run enforce policies
		thread.start_new_thread(test,())
	return 'OK'

# received a packet in event from ryu
@app.route('/Topo/Packet/in',methods = ['POST'])
def handle_packet_in():
	if runtime.nexus.runtime_mode:
		print("Nexus Received a Packet : {}".format(str(request.json)))
		packet = json.loads(request.json)
		runtime.nexus.handle_PacketIn(packet)
	return 'OK'

def test():
	time.sleep(5)
	#time.sleep(2)
	runtime.infra.view()
	runtime.enforce_policies()

def main():
	app.run(host='0.0.0.0', port=9000)

if __name__ == '__main__':
	main()
