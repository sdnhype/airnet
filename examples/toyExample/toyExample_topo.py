#! /usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, Node, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.util import waitListening
from functools import partial
import pdb
import sys

"""

host_A -- s1 -- s2 -- s3 -- s4 -- host_C
          |
host_B ---+

"""

def defaultNet(controller_ip, controller_port):

    # "Create an empty network and add nodes to it."
    switch = partial( OVSSwitch, protocols='OpenFlow13' )
    net = Mininet( controller=Controller, switch=switch )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    hA = net.addHost( 'host_A', ip='10.0.0.10/8',    defaultRoute='via 10.0.0.10')
    hB = net.addHost( 'host_B', ip='10.0.0.11/8',    defaultRoute='via 10.0.0.11')
    hC = net.addHost( 'host_C', ip='172.16.0.50/16', defaultRoute='via 172.16.0.50')

    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )
    s4 = net.addSwitch( 's4' )

    info( '*** Creating links\n' )
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s1, hA)
    net.addLink(s1, hB)
    net.addLink(s4, hC)

    info( '*** Starting network\n' )
    net.start()

    info( '*** Starting web service on host C\n' )
    hC.cmd( 'python -m SimpleHTTPServer 80 &' )

    net.ping([hA, hC], timeout=1)
    net.ping([hB, hC], timeout=1)

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
