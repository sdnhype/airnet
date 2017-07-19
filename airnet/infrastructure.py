# coding: utf8

# AirNet, a virtual network control language based on an Edge-Fabric model.
# Copyright (C) 2016-2017 Université Toulouse III - Paul Sabatier
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# TODO: mac_addr associated with more than one ip_addr in Phy_Host
# TODO: assert avoids us to us critical log in _handle_SwitchJoin and Leave
# TODO: finalize rarp mechanism

import copy
from collections import namedtuple
from lib.ipaddr import IPv4Network

from graph import Graph
from log import Logger


logger = Logger("Airnet_INFRA").Log()

class Phy_Port(object):
    """ describes an switch physical port components """

    def __init__(self, id, name, number, addr):
        """
            @param id: switch port unique identifier in topology
            @param number: switch port number
            @param addr: switch port hardware address
            @param name: switch port name. e.g. -> s1-eth1
        """
        self.id = id
        self.number = number
        self.hwAddr = addr
        self.name = name

class Phy_Switch(object):
    """ describes a physical switch components """
    def __init__(self, dpid, ports):
        """
            @param dpid: switch unique datapath identifier in topology
            @param ports: switch's physical ports
            @format ports: {hwAddr: Phy_Port(id, name, number, hwAddr)}
        """
        self.dpid = dpid
        self.ports = ports

class Phy_Link(object):
    """ describes a physical link components """

    def __init__(self, entity1, entity2, bandwidth=1):
        """
        @param entity1: first link extremity
        @param entity2: second link extremity
        @format entity: {'type': 'switch_port/host_port', 'dpid': int/hwAddr, 'port': int}
        @param bandwidth: not used currently
        """
        self.entity1 = entity1
        self.entity2 = entity2
        self.bandwidth = bandwidth

    def __eq__(self, other):
        """ checks if the current link and another one are the same """
        if ( self.entity1 == other.entity1 and
             self.entity2 == other.entity2):
            return True
        return False

    def is_opposite(self, link):
        """ determines the bidirectionality """
        if ( self.entity1 == link.entity2 and
             self.entity2 == link.entity1):
            return True
        return False

class Phy_Host(object):
    """ describes a physical host components """

    def __init__(self, dpid, port, mac_addr, ip_addrs=None):
        """
        @param dpid: the switch's id to which the host is connected
        @param port: the switch's port to which the host is connected
        @param mac_addr: the host's mac address
        @param ip_addrs: ip addresses associated with the mac_addr
        """
        self.port = port
        self.dpid = dpid
        self.hwAddr = mac_addr
        self.ip_addrs = ip_addrs

class Infrastructure(object):
    """ contains the global topology components """

    def __init__(self):
        """ initializes global topology components
            - hosts    : dictionnary of physical hosts
            - switches : dictionnary of physical switches
            - links    : list of physical links between equipments
            - _hwAddrs : list of physical ports in topology
        """
        self.linkNum = 0          # int
        self.runtime_mode = False # not relevant here
        self.hosts = {}           # {EthAddr('f6:81:69:bf:be:85'): Phy_Host object}
        self.switches = {}        # {dpid: Phy_Switch object}
        self.links = []           # [Phy_Link objects]
        self._hwAddrs = []        # [Phy_Port objects]
        self._deleted_links = []  # [Phy_Link objects]

    def nb(self):
        """ counts of information given by switches
            e.g. dpid, hwAddr, name, port_no..."""
        return len(self.switches.keys())

    def link_exist(self, lnk):
        """ searches for a given link in infra """
        for link in self.links:
            if lnk == link:
                return True
        return False

    def _handle_SwitchJoin(self, dpid, ports):
        """ triggers an update in the global topology when
            received a switchJoin event from the controller
        """
        # we assume that a new switch can't be in the list of switches
        assert (dpid not in self.switches.keys()), "[Error] switch-{} already in the graph".format(dpid)
        switch_ports = {}
        # for each port described in the json file
        for port in ports:
            # create a list of Physical Ports
            switch_ports[int(port['port_no'])] = Phy_Port(int(port['dpid'],16), port['name'],
                                                  int(port['port_no']),  port['hw_addr'])
            # add that port to the mac_addr list
            self._hwAddrs.append(port['hw_addr'])

        # then create a physical switch object
        self.switches[dpid] = Phy_Switch(dpid, switch_ports)

        logger.debug("switch-{} created ".format(dpid))

    def _handle_SwitchLeave(self, dpid):
        """ triggers an update in the global topology when
            received a switchLeave event from the controller
        """
        # we assume that only a registered switch can leave
        assert (dpid in self.switches.keys()), "[Error] switch-{} not found in the graph".format(dpid)
        # for each port of the registered switch
        for port in self.switches[dpid].ports.values():
            # delete it address from the list of hardware addresses
            for hwAddr in self._hwAddrs:
                if hwAddr == port.hwAddr:
                    self._hwAddrs.remove(hwAddr)
        # then delete the switch
        del self.switches[dpid]

        logger.debug("switch-{} removed ".format(dpid))

    def _handle_LinkEvent(self, dpid1, port1, dpid2, port2, toAdd):
        """ triggers an update in the global topology when
            received a LinkEvent event from the controller
            @param toAdd: determines whether the link is to add or to delete
            @important : this function works only for switch links
        """
        # instantiate the two entities
        entity1 = {"type": "switch_port", "dpid": dpid1,
                   "port": port1}
        entity2 = {"type": "switch_port", "dpid": dpid2,
                   "port": port2}
        # create a physical link object
        link = Phy_Link(entity1, entity2)

        if toAdd:
            self.links.append(link)
        else:
            for lnk in self.links:
                if lnk == link:
                    self.links.remove(lnk)

    def _handle_host_tracker_HostEvent(self, dpid, port, macaddr, ipAddrs, join):
        """ triggers an update in the global topology when
            received a HostTracker event from the controller
            @param join: determines whether the host is to add or to remove
        """
        # create the two entities
        entity1 = {"type": "host_port", "dpid": macaddr, "port": 1}
        entity2 = {"type": "switch_port", "dpid": dpid, "port": port}

        # this is an Host add
        if join:
            assert(macaddr not in self._hwAddrs), "[Error] host {} already in the graph"
            # add a physical host to the hosts dictionnary
            self.hosts[macaddr] = Phy_Host(dpid, port, macaddr, ipAddrs)
            # create link between host and switch (and switch to host by the same way)
            self.links.append(Phy_Link(entity1, entity2))
            self.links.append(Phy_Link(entity2, entity1))
            logger.debug("host-{} created ".format(macaddr))
        # this is an Host delete
        else :
            assert(macaddr in self._hwAddrs), "[Error] host {} not found in the graph"
            # remove from _hwAddrs
            self._hwAddrs.remove(macaddr)
            # remove from hosts[macaddr]
            del self.hosts[macaddr]
            # remove from links
            del self.links[Phy_Link(entity1, entity2)]
            del self.links[Phy_Link(entity2, entity1)]
            logger.debug("Host {} removed ".format(macaddr))

    def get_graph(self):
        """ creates a graph object based on the global topology components
            - switches
            - hosts
            - links
        """

        # links
        edges = set()
        # summits
        vertices = {}

        # For each host
        for host in self.hosts.values():
            """
                At the end of the loop, we get :
                    edges = ("host",@macH1, @macH2...)
                    vertices = {"@macH1":'sX'}
            """
            edges.add(("{}".format(host.hwAddr), "host"))
            vertices["{}".format(host.hwAddr)] = []

            for link in self.links:
                if link.entity1["type"] == "host_port":
                    if link.entity1["dpid"] == host.hwAddr:
                        vertices["{}".format(host.hwAddr)].append((1, "s{}".format(link.entity2["dpid"]), 1))

        # For each switch
        for switch in self.switches.values():

            edges.add(("s{}".format(switch.dpid), "switch"))
            vertices["s{}".format(switch.dpid)] = []

            for link in self.links:
                if link.entity1["type"] == "switch_port":
                    if link.entity1["dpid"] == switch.dpid:
                        if link.entity2["type"] == "host_port":
                            vertices["s{}".format(switch.dpid)].append((1, "{}".format(link.entity2["dpid"]), link.entity1["port"]))
                        else:
                            vertices["s{}".format(switch.dpid)].append((1, "s{}".format(link.entity2["dpid"]), link.entity1["port"]))

        logger.debug("Global topology created")
        return Graph(vertices, edges)

    def view(self):
        print "\n----- Switches -----"
        for switch in self.switches.values():
            print "Switch-{}, Ports {}".format(switch.dpid, len(switch.ports.keys()))
            for port in switch.ports.values():
                print "    {}".format(port.hwAddr)
        print "\n----- Hosts -----"
        for host in self.hosts.values():
            print "MacAddr: {}, ipAddrs: {}".format(host.hwAddr,str(host.ip_addrs))

        print "\n----- Links -----"
        for link in self.links:
            print ("(dpid: {}, port: {}) /"
                   " (dpid: {}, port: {})".format(link.entity1["dpid"],
                                                  link.entity1["port"],
                                                  link.entity2["dpid"],
                                                  link.entity2["port"]))

    def arp(self, ipAddr):
        """ returns the hwAddr corresponding to the ipAddr in param """
        for key, host in self.hosts.iteritems():
            if (host.ip_addrs[0]) == ipAddr:
                return host.hwAddr
        return None

    def rarp(self, hwAddr):
        """ returns the ipAddr corresponding to the hwAddr in param """
        for key, host in self.hosts.iteritems():
            if host.hwAddr == hwAddr:
                return host.ip_addrs[0]

    def get_output_to_destination(self, hwAddr):
        output = namedtuple('output', ['switch', 'port'])
        graph = self.get_graph()
        for edge_key, adjacent_edges in graph.vertices.iteritems():
            for adjacent_edge in adjacent_edges:
                if (adjacent_edge[1] == hwAddr.toStr()):
                    return output(edge_key, adjacent_edge[2])
    """
        def resolve_ARP_request(self, packet):

            def build_arp_reply(packet):
                requested_mac_address = self.arp(packet.payload.protodst.toStr())
                arp_reply = arp()
                arp_reply.hwsrc = requested_mac_address
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = packet.payload.protodst
                arp_reply.protodst = packet.payload.protosrc
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = requested_mac_address
                ether.payload = arp_reply
                return ether

            def get_output_to_destination(hwAddr):
                output = namedtuple('output', ['switch', 'port'])
                graph = self.get_graph()
                for edge_key, adjacent_edges in graph.vertices.iteritems():
                    for adjacent_edge in adjacent_edges:
                        if (adjacent_edge[1] == hwAddr.toStr()):
                            return output(edge_key, adjacent_edge[2])

            arpReply = namedtuple('arpReply', ['switch', 'packet', 'output'])
            arpPacket = build_arp_reply(packet)
            switch, port = get_output_to_destination(packet.src)
            # for first pingall in topology
            if switch:
                return arpReply(switch, arpPacket, port)
    """
