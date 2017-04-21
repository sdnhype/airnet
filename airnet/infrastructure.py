from graph import Graph
from lib.ipaddr import IPv4Network
from collections import namedtuple
from log import Logger
import copy

# LOGGER CONSTRUCTION
logger = Logger("Airnet_Infrastructure").getLog()

class Phy_Port(object):
    """
        Physical port
    """
    def __init__(self, id, name, number, addr):
        """
        :param id: unique id in topo
        :param number: port number in switch (not unique in topo)
        :param addr: hardware address
        :param name: port name. e.g., s1-eth1
        """
        self.id = id
        self.number = number
        self.hwAddr = addr
        self.name = name

class Phy_Switch(object):
    """
        physical switch
    """
    def __init__(self, dpid, ports):
        """
        :param dpid: unique data path id

        :param ports: switch's ports
        :type dict: {hwAddr: Phy_Port(id, name, number, hwAddr)}
        """
        self.dpid = dpid
        self.ports = ports

        #TODO: forwarding table ? Purpose: nothing at the moment.

class Phy_Link(object):
    """
    physical link
    """
    def __init__(self, entity1, entity2, bandwidth=1):
        """
        :param entity1: first link extremity
        :param entity2: second link extremity
        :type dict: {'type': 'switch_port/host_port', 'dpid': int/hwAddr, 'port': int}

        :param bandwidth: at present not used
        """
        self.entity1 = entity1
        self.entity2 = entity2
        self.bandwidth = bandwidth

    def __eq__(self, other):
        if ( self.entity1 == other.entity1 and
             self.entity2 == other.entity2):
            return True
        return False

    def is_opposite(self, link):
        if ( self.entity1 == link.entity2 and
             self.entity2 == link.entity1):
            return True
        return False

class Phy_Host(object):
    """
    physical host
    """
    def __init__(self, dpid, port, mac_addr, ip_addrs=None):
        """
        :param dpid: the switch to which the host is connected
        :param port: the switch's port to which the host is connected
        :param mac_addr: host's mac address
        :param ip_addrs: ip addresses associated with the mac_addr
        """
        self.port = port
        self.dpid = dpid
        self.hwAddr = mac_addr
        self.ip_addrs = ip_addrs # BUG: ref and defaut value !!!


class Infrastructure(object):
    """
        Logical Containers are used here to describe the physical infrastructure
        components
    """
    def __init__(self):
        """
            Initialize physical topology components in logical containers

        :hosts: dict of hosts in physical topology
        :switches: dict of switches in physical topology
        :links: list of links connecting equipments
        :_hwAddrs: ports in topology
        """
        self.linkNum = 0          # int
        self.runtime_mode = False # prends pas ca en compte
        self.hosts = {}           # {EthAddr('f6:81:69:bf:be:85'): Phy_Host object}
        self.switches = {}        # {1: Phy_Switch object}
        self.links = []           # [Phy_Link objects]
        self._hwAddrs = []        # POX bug ! when a link is down
        self._deleted_links = []  # [Phy_Link objects]

    def nb(self):
        return len(self.switches.keys())

    def link_exist(self, lnk):
        for link in self.links:
            if lnk == link:
                return True
        return False

    def _handle_SwitchJoin(self, dpid, ports):
        # we assume that a new switch can't be in the list of switches
        assert (dpid not in self.switches.keys()), "Switch-{} has already joined".format(dpid)
        switch_ports = {}
        # for each port described in the json file
        for port in ports:
            # we create a list of Physical Ports
            switch_ports[int(port['port_no'])] = Phy_Port(int(port['dpid'],16), port['name'],
                                                  int(port['port_no']),  port['hw_addr'])
            # we add that port to the MAC @ list
            self._hwAddrs.append(port['hw_addr'])
        # we create the physical switch object then
        self.switches[dpid] = Phy_Switch(dpid, switch_ports)
        logger.debug("Switch-{} has joined ".format(dpid))

    def _handle_SwitchLeave(self, dpid):
        # we assume that only a registered switch can leave
        assert (dpid in self.switches.keys()), "Switch-{} has not joined yet".format(dpid)
        # for each port of the registered switch
        for port in self.switches[dpid].ports.values():
            # delete it address from the list of hardware addresses
            for hwAddr in self._hwAddrs:
                if hwAddr == port.hwAddr:
                    self._hwAddrs.remove(hwAddr)
        # then delete the switch
        del self.switches[dpid]
        logger.debug("Switch-{} has left ".format(dpid))

    # toAdd parameter is a boolean which determines if the link is to add or to remove
    def _handle_LinkEvent(self, dpid1, port1, dpid2, port2, toAdd):

        entity1 = {"type": "switch_port", "dpid": dpid1,
                   "port": port1}
        entity2 = {"type": "switch_port", "dpid": dpid2,
                   "port": port2}

        link = Phy_Link(entity1, entity2)

        if toAdd:
            self.links.append(link)
        else:
            for lnk in self.links:
                if lnk == link:
                    self.links.remove(lnk)

    def _handle_host_tracker_HostEvent(self, dpid, port, macaddr, ipAddrs, join):
        entity1 = {"type": "host_port", "dpid": macaddr, "port": 1}
        entity2 = {"type": "switch_port", "dpid": dpid, "port": port}

        if join:
            assert(macaddr not in self._hwAddrs), "Host with address {} has already joined"
            # add a physical to the hosts dictionnary
            self.hosts[macaddr] = Phy_Host(dpid, port, macaddr, ipAddrs)
            # create link between host and switch (and switch to host by the same way)
            self.links.append(Phy_Link(entity1, entity2))
            self.links.append(Phy_Link(entity2, entity1))
            logger.debug("Host-{} has joined ".format(macaddr))
        else : # remove the host here
            assert(macaddr in self._hwAddrs), "Host with address {} has not joined yet"
            # remove from _hwAddrs
            self._hwAddrs.remove(macaddr)
            # remove from hosts[macaddr]
            del self.hosts[macaddr]
            # remove from links
            del self.links[Phy_Link(entity1, entity2)]
            del self.links[Phy_Link(entity2, entity1)]
            logger.debug("Host-{} has left ".format(macaddr))

    def get_graph(self):
        """
        TODO: must be compatible with graph class and the algorithm
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

        logger.debug("Graph Components Actualized")
        return Graph(vertices, edges)

    def view(self):
        print "\n----- Switches -----"
        for switch in self.switches.values():
            print "Switch-{}, Ports {}".format(switch.dpid, len(switch.ports.keys()))
            for port in switch.ports.values():
                print "    {}".format(port.hwAddr)
        print "\n----- Hosts -----"
        for host in self.hosts.values():
            print "MacAddr: {}, ipAddrs: {}".format(host.hwAddr,host.ip_addrs.keys())

        print "\n----- Links -----"
        for link in self.links:
            print ("(dpid: {}, port: {}) /"
                   " (dpid: {}, port: {})".format(link.entity1["dpid"],
                                                  link.entity1["port"],
                                                  link.entity2["dpid"],
                                                  link.entity2["port"]))

    def arp(self, ipAddr):
        # work only for one ipAddr by host
        for key, host in self.hosts.iteritems():
            if (host.ip_addrs.keys()[0]) == ipAddr:
                return host.hwAddr
        return None

    def rarp(self, hwAddr):
        """ Return ip address TYPE??? TODO """
        # work only for one ipAddr by host
        for key, host in self.hosts.iteritems():
            if host.hwAddr == hwAddr:
                return host.ip_addrs.keys()[0]

    def get_output_to_destination(self, hwAddr):
        output = namedtuple('output', ['switch', 'port'])
        graph = self.get_graph()
        for edge_key, adjacent_edges in graph.vertices.iteritems():
            for adjacent_edge in adjacent_edges:
                if (adjacent_edge[1] == hwAddr.toStr()):
                    return output(edge_key, adjacent_edge[2])

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
