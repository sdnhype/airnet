#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, Node, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import waitListening
from functools import partial
import pdb
import sys

"""
       host_A -- s1 -- s2 -- s3 -- s4 -- host_B
"""

def emptyNet(controller_ip, controller_port):


	# "Create an empty network and add nodes to it."
	switch = partial( OVSSwitch, protocols='OpenFlow13' )
	net = Mininet( controller=Controller ,switch=switch)

	info( '*** Adding controller\n' )
	net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

	info( '*** Adding hosts\n' )
	h_A = net.addHost( 'host_A', ip= '10.0.0.11/8', defaultRoute = 'via 10.0.0.11')
	h_B = net.addHost( 'host_B' , ip= '172.16.0.50/16', defaultRoute = "via 172.16.0.50")

	info( '*** Adding switch\n' )
	s1 = net.addSwitch( 's1' )
	s2 = net.addSwitch( 's2' )
	s3 = net.addSwitch( 's3' )
	s4 = net.addSwitch( 's4' )

	info( '*** Creating links\n' )
	net.addLink(s1, s2)
	net.addLink(s2, s3)
	net.addLink(s3, s4)
	net.addLink(s1, h_A)
	net.addLink(s4, h_B)

	info( '*** Starting network\n')
	net.start()

	print("*** Starting web service on host_B")
        h_B.cmd( 'python -m SimpleHTTPServer 80 &' )

	net.pingAll(timeout=1)

	info( '*** Running CLI\n' )
	CLI( net )

	info( '*** Stopping network' )
	net.stop()

if __name__ == '__main__':
	setLogLevel( 'info' )
	if len(sys.argv) != 3:
		print 'Usage: ', sys.argv[0], ' controller_ip controller_port'
		sys.exit()
	emptyNet(sys.argv[1], int(sys.argv[2]))
