#!/usr/bin/python
import pdb
import sys
"""

users---[s1]----|          |---[s5]---[s6]---|          |---[s8]---WS
	        |---[s3]---|                 |---[s7]---| 
guests---[s2]---|          |--------[s4] ----|          |---[s9]---CC

"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet(controller_ip, controller_port):

	"Create an empty network and add nodes to it."

	net = Mininet( controller=Controller )

	info( '*** Adding controller\n' )
	net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

	info( '*** Adding hosts\n' )
	h1 = net.addHost( 'NetA' , ip= '141.115.64.11/24', defaultRoute = 'via 141.115.64.11')
	h2 = net.addHost( 'C01' , ip= '170.146.9.11/24', defaultRoute = "via 170.146.9.11")
	h3 = net.addHost( 'WS', ip='170.146.15.11/24', defaultRoute='via 170.146.15.11')
	h4 = net.addHost( 'SSH_GW' , ip= '170.146.16.11/24', defaultRoute = "via 170.146.16.11")
	
	
	info( '*** Adding switch\n' )
	s1 = net.addSwitch( 's1' )
	s2 = net.addSwitch( 's2' )
	s3 = net.addSwitch( 's3' )
	s4 = net.addSwitch( 's4' )
	s5 = net.addSwitch( 's5' )
	s6 = net.addSwitch( 's6' )
	s7 = net.addSwitch( 's7' )
	s8 = net.addSwitch( 's8' )
	s9 = net.addSwitch( 's9')
	s10 = net.addSwitch( 's10')	

	info( '*** Creating links\n' )
	net.addLink( s1, s3)
	net.addLink( s2, s3)
	net.addLink( s3, s4)
	net.addLink( s3, s6)
	net.addLink( s4, s5)
	net.addLink( s5, s7)
	net.addLink( s6, s7)
	net.addLink( s3, s8)
	net.addLink( s8, s7)
	net.addLink( s7, s9)
	net.addLink( s7, s10)
	net.addLink(s1, h1)
	net.addLink(s2, h2)
	net.addLink(s9, h3)
	net.addLink(s10, h4)
	
	info( '*** Starting network\n')
	net.start()
	
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
