#!/usr/bin/python
import sys
from names import *

"""

*** Virtual topo ***

    A --+                        +-- G
    B --+-- [E1]---[FAB]---[E3]--+-- H
    C --+            |           +-- I
                    [E2]
                     |
                  +--+--+
                  |  |  |
                  D  E  F


*** Mininet topo ***

    A --+                     (s1-s3 backup)
    B --+-- [s11]---[s1]......
    C --+             |      |            +-- G
                     [s2]---[s3]---[s33]--+-- H
                      |                   +-- I
                    [s22]
                      |
                   +--+--+
                   |  |  |
                   D  E  F

*** Mapping ***

    E1 -> s11
    E2 -> s22
    E3 -> s33
    FAB -> s1, s2, s3

"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet(controller_ip, controller_port):

    # Create an empty network and add nodes to it.

    # autoStaticArp=True
    net = Mininet( controller=Controller, autoSetMacs=True )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    h1 = net.addHost( A , ip='10.0.0.1/16', defaultRoute = 'via 10.0.0.1')
    h2 = net.addHost( B , ip='10.0.0.2/16', defaultRoute = 'via 10.0.0.2')
    h3 = net.addHost( C , ip='10.0.0.3/16', defaultRoute = 'via 10.0.0.3')
    h4 = net.addHost( D , ip='10.0.0.4/16', defaultRoute = 'via 10.0.0.4')
    h5 = net.addHost( E , ip='10.0.0.5/16', defaultRoute = 'via 10.0.0.5')
    h6 = net.addHost( F , ip='10.0.0.6/16', defaultRoute = 'via 10.0.0.6')
    h7 = net.addHost( G , ip='10.0.0.7/16', defaultRoute = 'via 10.0.0.7')
    h8 = net.addHost( H , ip='10.0.0.8/16', defaultRoute = 'via 10.0.0.8')
    h9 = net.addHost( I , ip='10.0.0.9/16', defaultRoute = 'via 10.0.0.9')

    info( '*** Adding switch\n' )
    s1  = net.addSwitch( 's1' )
    s11 = net.addSwitch( 's11' )
    s2  = net.addSwitch( 's2' )
    s22 = net.addSwitch( 's22' )
    s3  = net.addSwitch( 's3' )
    s33 = net.addSwitch( 's33' )

    info( '*** Creating links\n' )
    net.addLink( h1, s11)
    net.addLink( h2, s11)
    net.addLink( h3, s11)
    net.addLink( h4, s22)
    net.addLink( h5, s22)
    net.addLink( h6, s22)
    net.addLink( h7, s33)
    net.addLink( h8, s33)
    net.addLink( h9, s33)

    net.addLink( s11, s1)
    net.addLink( s22, s2)
    net.addLink( s33, s3)
    net.addLink( s1, s2)
    net.addLink( s2, s3)
#    net.addLink( s1, s3) # backup

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
