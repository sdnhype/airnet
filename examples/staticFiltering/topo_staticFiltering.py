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
                                ws
                               /
   inet_h -- s1              s9 -- ssh_gw
               \            /
               s2 -- s3 -- s5 -- s7 -- priv_net_h
                 \        /
                  s4 -- s6 -- s8
                             /   \
                       wifipub_h   wifipriv_h

"""

def emptyNet(controller_ip, controller_port):


	# "Create an empty network and add nodes to it."
    switch = partial( OVSSwitch, protocols='OpenFlow13' )
	net = Mininet( controller=Controller ,switch=switch)

	info( '*** Adding controller\n' )
	net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

	info( '*** Adding hosts\n' )
	h_inet = net.addHost( 'inet_h', ip= '10.0.0.11/8', defaultRoute = 'via 10.0.0.11')
	h_ws = net.addHost( 'ws' , ip= '192.168.10.16/24', defaultRoute = 'via 192.168.10.16')
	h_ssh = net.addHost( 'ssh_gw', ip= '192.168.10.17/24', defaultRoute = 'via 192.168.10.17')
	h_privnet = net.addHost( 'priv_net_h' , ip= '172.16.0.50/16', defaultRoute = "via 172.16.0.50")
	h_wifipub = net.addHost( 'wifipub_h' , ip= '192.168.20.2/24', defaultRoute = "via 192.168.20.2")
	h_wifipriv = net.addHost( 'wifipriv_h' , ip= '192.168.30.3/24', defaultRoute = "via 192.168.30.3")

	info( '*** Adding switch\n' )
	s1 = net.addSwitch( 's1' )
	s2 = net.addSwitch( 's2' )
	s3 = net.addSwitch( 's3' )
	s4 = net.addSwitch( 's4' )
	s5 = net.addSwitch( 's5' )
	s6 = net.addSwitch( 's6' )
	s7 = net.addSwitch( 's7' )
	s8 = net.addSwitch( 's8' )
	s9 = net.addSwitch( 's9' )

	info( '*** Creating links\n' )
	net.addLink(s1, s2)
	net.addLink(s2, s3)
	net.addLink(s2, s4)
	net.addLink(s4, s6)
	net.addLink(s3, s5)
	net.addLink(s6, s5)
	net.addLink(s5, s7)
	net.addLink(s6, s8)
	net.addLink(s5, s9)
	net.addLink(s1, h_inet)
	net.addLink(s8, h_wifipub)
	net.addLink(s8, h_wifipriv)
	net.addLink(s7, h_privnet)
	net.addLink(s9, h_ws)
	net.addLink(s9, h_ssh)

	info( '*** Starting network\n')
	net.start()

	print "*** Starting ssh service on ssh_gw"
	h_ssh.cmd( '/usr/sbin/sshd -D -o UseDNS=no -u0 &' )
	print "*** Starting web service on ws"
        h_ws.cmd( 'python -m SimpleHTTPServer 80 &' )

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
