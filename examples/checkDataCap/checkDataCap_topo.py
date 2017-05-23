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
h1(192.168.0.11)--|
       	 	  |-- s1 -- s2 -- s3 -- s4 -- s5 -- s6 -- s7 -- h3 (172.16.0.11)
h2(192.168.0.12)--|

"""

def emptyNet(controller_ip, controller_port):


	# "Create an empty network and add nodes to it."
    switch = partial( OVSSwitch, protocols='OpenFlow13')
	net = Mininet( controller=Controller, switch=switch )

	info( '*** Adding controller\n' )
	net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

	info( '*** Adding hosts\n' )
	h1 = net.addHost( 'h1', ip= '192.168.0.11/24', defaultRoute = 'via 192.168.0.11')
	h2 = net.addHost( 'h2' , ip= '192.168.0.12/24', defaultRoute = "via 192.168.0.12")
	h3 = net.addHost( 'h3' , ip= '172.16.0.11/24', defaultRoute = "via 172.16.0.11")

	info( '*** Adding switch\n' )
	s1 = net.addSwitch( 's1' )
	s2 = net.addSwitch( 's2' )
	s3 = net.addSwitch( 's3' )
	s4 = net.addSwitch( 's4' )
	s5 = net.addSwitch( 's5' )
	s6 = net.addSwitch( 's6' )
	s7 = net.addSwitch( 's7' )

	info( '*** Creating links\n' )
	net.addLink(s1, s2)
	net.addLink(s2, s3)
	net.addLink(s3, s4)
	net.addLink(s4, s5)
	net.addLink(s5, s6)
	net.addLink(s6, s7)
	net.addLink(s1, h1)
	net.addLink(s1, h2)
	net.addLink(s7, h3)

	info( '*** Starting network\n')
	net.start()

    net.ping([h1, h2], timeout=1)
    net.ping([h1, h3], timeout=1)

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
