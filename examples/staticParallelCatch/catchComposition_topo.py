#!/usr/bin/python
import pdb
import sys

"""

* Virtual topo:

----------
staff_net-|---|
----------    |
              |---[users_IO]----|
----------    |                 |
guests_net-|--|                 |                                   |--- WS1
----------                      |              |---[users_egress]---|
                                |---[fabric]---|                    |--- WS2
-----------                     |              |
admins_net-|-----[admins_IO]----|              |---[admins_egress]--- DB
-----------

* Mininet topo (12 switches)

staff_net---|---[s1]---|
                       |
guests_net--|---[s2]-- |                                                      |--- WS1
                       |          |----[s5]----[s6]----|          |---[s11]---|--- WS2
                       |---[s4]---|                    |---[s7]---|
                       |          |--[s8]--[s9]--[s10]-|          |---[s12]-------- DB
admins_net---|---[s3]--|

* Mapping

    users_IO -> s1, s2
    admins_net -> s3
    users_egress -> s11
    admins_egress -> s12
    fab -> s4 to s10


"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

def defaultNet(controller_ip, controller_port):

    # Create an empty network and add nodes to it.
    switch = partial( OVSSwitch, protocols='OpenFlow13' )
    net = Mininet( controller=Controller, switch=switch )

    info( '*** Adding controller\n' )
    net.addController( 'c0', controller=RemoteController, ip=controller_ip, port=controller_port )

    info( '*** Adding hosts\n' )
    staff_net = net.addHost( 'staff_net' , ip= '172.16.0.11/12', defaultRoute = 'via 172.16.0.11')
    guests_net = net.addHost( 'guests_net' , ip= '192.168.0.11/16', defaultRoute = "via 192.168.0.11")
    admins_net = net.addHost( 'admins_net' , ip= '10.0.0.11/16', defaultRoute = "via 10.0.0.11")
    DB = net.addHost( 'DB', ip='141.115.28.11', defaultRoute='via 141.115.28.11')
    WS1 = net.addHost( 'WS1' , ip= '141.115.28.12', defaultRoute = "via 141.115.28.12")
    WS2 = net.addHost('WS2', ip='141.115.28.13', defaultRoute='via 141.115.28.13')


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
    s10 = net.addSwitch( 's10')
    s11 = net.addSwitch( 's11' )
    s12 = net.addSwitch( 's12' )

    info( '*** Creating links\n' )
    net.addLink( s1, s4)
    net.addLink( s2, s4)
    net.addLink( s3, s4)
    net.addLink( s4, s5)
    net.addLink( s5, s6)
    net.addLink( s6, s7)
    net.addLink( s4, s8)
    net.addLink( s8, s9)
    net.addLink( s9, s10)
    net.addLink( s10, s7)
    net.addLink( s7, s11)
    net.addLink( s7, s12)
    net.addLink(s11, WS1)
    net.addLink(s11, WS2)
    net.addLink(s12, DB)
    net.addLink(s1, staff_net)
    net.addLink(s2, guests_net)
    net.addLink(s3, admins_net)

    info( '*** Starting network\n')
    net.start()

    # pingAll takes too much time!
    # net.pingAll(timeout=1)
    net.ping([staff_net, guests_net], timeout=1)
    net.ping([admins_net, DB], timeout=1)
    net.ping([WS1, WS2], timeout=1)

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
