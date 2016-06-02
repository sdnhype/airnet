"""
TODO: renommer en launch_airnet_ryu.py
REST server to receive events emanating from RYU
(based on the Flask micro web development framework: flask.pocoo.org)
"""

from flask import Flask
from flask import json,request,Response
from stage_infrastructure import Infrastructure
import thread
import time
import sys
from stage_runtime import Runtime

app = Flask(__name__)
infra = Infrastructure()
f1 = sys.argv[1]
f2 = sys.argv[2]
runtime = Runtime(f1,f2,infra)

@app.route('/Topo/Switch/enter',methods = ['POST'])
def handle_switch_enter():
	data = request.json
	dpid = int (data['dpid'],16) # dpid est en hexadecimal
	ports = data['ports']
	infra._handle_SwitchJoin(dpid,ports)
	return 'OK'

@app.route('/Topo/Switch/leave',methods = ['POST'])
def handle_switch_leave():
	data = request.json
	dpid = int (data['dpid'],16)
	infra._handle_SwitchLeave(dpid)
	return 'OK'

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
	if runtime.nexus.runtime_mode:
		runtime.handle_topology_change()
	return 'OK'

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

@app.route('/Topo/Host/add',methods = ['POST'])
def handle_host_add():
	data = request.json
	ips = data['ipv4']
	#juste pour simuler un dict d'ip
	ipadrs = {}
	for ip in ips:
		ipadrs[str(ip)] = 1
	mac = str(data['mac'])
	ports = data['port']
	dpid = int(ports['dpid'],16)
	port = int(ports['port_no'])
	infra._handle_host_tracker_HostEvent(dpid, port, mac, ipadrs, True)
	if len(runtime.mapping.hosts) == len (infra.hosts):
		thread.start_new_thread(test,())
	return 'OK'

@app.route('/Topo/Packet/in',methods = ['POST'])
def handle_packet_in():
	if runtime.nexus.runtime_mode:
		packet = json.loads(request.json)
		runtime.nexus.handle_PacketIn(packet)
	return 'OK'

def test():
	time.sleep(10)
	#runtime.infra.view()
	runtime.enforce_policies()

def main():
	#thread.start_new_thread(test,())
	app.run(host='0.0.0.0', port=9000)
	
if __name__ == '__main__':
	main()
