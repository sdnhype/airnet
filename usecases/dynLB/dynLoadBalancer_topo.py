#!/usr/bin/python
import sys

"""
* Virtual topo

    client1--|
    client2--|                               |--- WS1
             |-----[IO]---[ fabric ]---[LB]--|
    client3--|                               |--- WS2
    client4--|

* Virtual Policies

    Dyn load balancer on LB edge (based on the source address)

* Mininet topology: topo_8sw_6hosts.py

client1---|
          |---[s1]---|
client2---|          |          |--[s5]--[s6]--|                 |---WS1
                     |---[s3]---|              |---[s7]---[s8]---|
client3---|          |          |-----[s4]-----|                 |---WS2
          |---[s2]---|
client4---|

* Mapping

    IO -> s1, s2
    FAB -> s3, s4, s5, s6, s7
    LB -> s8

"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def emptyNet(controller_ip, controller_port):

    "Create an empty network and add nodes to it."

    # autoStaticArp=True
    net = Mininet( controller=Controller, autoSetMacs=True )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    h1 = net.addHost( 'client1' , ip='192.168.0.11/16', defaultRoute = 'via 192.168.0.11')
    h2 = net.addHost( 'client2' , ip='192.168.0.12/16', defaultRoute = 'via 192.168.0.12')
    h3 = net.addHost( 'client3' , ip='192.168.0.13/16', defaultRoute = 'via 192.168.0.13')
    h4 = net.addHost( 'client4' , ip='192.168.0.14/16', defaultRoute = "via 192.168.0.14")
    h5 = net.addHost( 'WS1' , ip='10.0.0.11/16', defaultRoute = "via 10.0.0.11") 
    h6 = net.addHost( 'WS2' , ip='10.0.0.12/16', defaultRoute = "via 10.0.0.12")
    
    
    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )
    s4 = net.addSwitch( 's4' )
    s5 = net.addSwitch( 's5' )
    s6 = net.addSwitch( 's6' )
    s7 = net.addSwitch( 's7' )
    s8 = net.addSwitch( 's8' )

    info( '*** Creating links\n' )
    net.addLink( h1, s1)
    net.addLink( h2, s1)
    net.addLink( h3, s2)
    net.addLink( h4, s2)
    net.addLink( s1, s3)
    net.addLink( s2, s3)
    net.addLink( s3, s4)
    net.addLink( s3, s5)
    net.addLink( s5, s6)
    net.addLink( s4, s7)
    net.addLink( s6, s7)
    net.addLink( s7, s8)
    net.addLink( s8, h5)
    net.addLink( s8, h6)
    
    # [EL] what is this?
    net.public_WS = "10.0.0.21"

    info( '*** Starting network\n')
    net.start()

    # [EL] Insert static ARP entry because problem with proxy ARP in AirNet's Ryu version
    h1.cmd( 'ip neigh add 10.0.0.50 lladdr 00:26:55:42:9a:62 dev client1-eth0' )
    
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

