#!/usr/bin/python
import sys

"""
                 (192.168.1.11/16)
                         VM
                          | (eth2)
                          |
                          | (eth2)
users---[s1]------[s2]---[s3]---[s4]------[s5]---WS (192.168.0.11/16)

"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

def defaultNet(controller_ip, controller_port):

    # "Create an empty network and add nodes to it."
    switch = partial( OVSSwitch, protocols='OpenFlow13' )
    net = Mininet( controller=Controller , switch=switch )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'users_1', ip = '172.16.0.12/16',  defaultRoute = "via 172.16.0.12")
    h2 = net.addHost( 'users_2', ip = '172.16.0.13/16',  defaultRoute = "via 172.16.0.13")
    h3 = net.addHost( 'WS',     ip = '192.168.0.11/16', defaultRoute = "via 192.168.0.11")


    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )
    s4 = net.addSwitch( 's4' )
    s5 = net.addSwitch( 's5' )

    info( '*** Creating links\n' )
    net.addLink( s1, s2)
    net.addLink( s2, s3)
    net.addLink( s3, s4)
    net.addLink( s4, s5)
    net.addLink( s1, h1)
    net.addLink( s1, h2)
    net.addLink( s5, h3)

        from mininet.link import Intf
	switch3 = net.switches[2]
	_intf = Intf("eth2", node=switch3)

    info( '*** Starting network\n' )
    net.start()

    print("*** Starting web service on ws")
    h3.cmd( 'python -m SimpleHTTPServer 80 &' )

    net.ping([h1, h2], timeout=1)
    net.ping([h2, h3], timeout=1)

    info( '*** Running CLI\n' )
    CLI( net )

    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    if len(sys.argv) != 3:
        print 'Usage: ', sys.argv[0], ' controller_ip controller_port'
        sys.exit()
    defaultNet(sys.argv[1], int(sys.argv[2]))
