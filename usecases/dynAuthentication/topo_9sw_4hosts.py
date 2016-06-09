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
	h1 = net.addHost( 'users' , ip= '172.15.0.11/16', defaultRoute = 'via 172.15.0.11')
	h2 = net.addHost( 'guests' , ip= '172.16.0.12/16', defaultRoute = "via 172.16.0.12")
	h3 = net.addHost( 'WS', ip='192.168.0.11/16', defaultRoute='via 192.168.0.11')
	h4 = net.addHost( 'CC' , ip= '192.168.0.12/16', defaultRoute = "via 192.168.0.12")
	
	
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

	info( '*** Creating links\n' )
	net.addLink( s1, s3)
	net.addLink( s2, s3)
	net.addLink( s3, s4)
	net.addLink( s3, s5)
	net.addLink( s5, s6)
	net.addLink( s4, s7)
	net.addLink( s6, s7)
	net.addLink( s7, s8)
	net.addLink( s7, s9)
	net.addLink(s1, h1)
	net.addLink(s2, h2)
	net.addLink(s8, h3)
	net.addLink(s9, h4)
	
	info( '*** Starting network\n')
	net.start()

	print("*** Starting web service on ws")
	h3.cmd( 'python -m SimpleHTTPServer 80 &' )	

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

