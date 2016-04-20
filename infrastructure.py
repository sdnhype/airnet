from pox.topology import topology
from pox.core import core
from graph import Graph
from ipaddr import IPv4Network
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet
from collections import namedtuple
import copy
import time
import pdb
#from IPython.utils.path import link

log = core.getLogger()

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
    physical infrastructure
    """
    _core_name = "infrastructure"

    def __init__(self):
        
        core.listen_to_dependencies(self, ['topology'], short_attrs=True)
        """
        :prop hosts: hosts present in physical topology
        :prop switches: switches present in physical topology 
        :type: dict:
        
        :prop links: links connecting hosts to switches and
                                                 switches to switches
        :type list:
        
        :prop _hwAddrs: ports in topology. POX HostEvent bug !!
                        switch, edge, join --> get switch hwAddr not host!
        """
        self.linkNum = 0
        self.runtime_mode = False
        self.hosts = {}
        self.switches = {}
        self.links = []
        self._hwAddrs = []  # POX bug ! when a link is down
        self._deleted_links = []
    
    def link_exist(self, lnk):
        for link in self.links:
            if lnk == link:
                return True
        return False 
    
    def _handle_topology_SwitchJoin(self, event):
        # TODO: use local variables in order to have smaller code line
        self.switch_event = event
        assert event.switch.dpid not in self.switches.keys()
        switch_ports = {}
        # TODO: named tuples
        for port in event.switch.ports.values():
            switch_ports[port.number] = Phy_Port(port.id, port.name,
                                                  port.number,  port.hwAddr)
            self._hwAddrs.append(port.hwAddr)
        self.switches[event.switch.dpid] = Phy_Switch(event.switch.dpid,
                                                       switch_ports)
                    
    def _handle_topology_SwitchLeave(self, event):
        assert event.switch.dpid in self.switches.keys()
        for port in self.switches[even.switch.dpid]._ports.values():
            for hwAddr in self._hwAddrs:
                if hwAddr == port._hwAddr:
                    self._hwAddrs.remove(hwAddr)
        del self.switches[even.switch.dpid]
    
    def opposite_link_exist(self, link):
        for lnk in self.links:
            if lnk.is_opposite(link):
                return True
        return False

    
    def _handle_openflow_discovery_LinkEvent(self, event):
        """
        LinkEvents are raised by POX only for switch to switch links
        """
        
        if event.link.dpid1 == 5 and event.link.dpid2 == 5:
            pdb.set_trace()
        
        entity1 = {"type": "switch_port", "dpid": event.link.dpid1, 
                   "port": event.link.port1}
        entity2 = {"type": "switch_port", "dpid": event.link.dpid2, 
                   "port": event.link.port2}
        link = Phy_Link(entity1, entity2)
        
        tmp_entity1 = {"type": "switch_port", "dpid": event.link.dpid2, 
                   "port": event.link.port2}
        tmp_entity2 = {"type": "switch_port", "dpid": event.link.dpid1, 
                   "port": event.link.port1}
        tmp_link = Phy_Link(tmp_entity1, tmp_entity2)
        
        if event.added:
            if not self.link_exist(link):
                self.linkNum += 2
                self.links.append(link)
                self.links.append(tmp_link)
                if self.opposite_link_exist(link) and self.runtime_mode:
                    core.runtime._event_time = int(round(time.time() * 1000))
                    log.info("Link up -- Time: " + str(int(round(time.time() * 1000)))) 
                    print event.link
                    print "enforcing new rules to adapt to topology changes"
                    core.runtime.handle_topology_change()
            else:
                print "link is already UP"
                #raise RuntimeError(str(event.link) + " : link is already UP") 
        else:
            if self.link_exist(link):
                for lnk in self.links:
                    if lnk == link:
                        self.links.remove(lnk)
                if (not self.opposite_link_exist(link)) and self.runtime_mode:
                    core.runtime._event_time = int(round(time.time() * 1000))
                    log.info("Link down -- Time: " + str(int(round(time.time() * 1000))))
                    print event.link
                    print "enforcing new rules to adapt to topology changes"
                    core.runtime.handle_topology_change()
            else:
                raise RuntimeError(str(event.link) + " : link is already DOWN")


    def _handle_host_tracker_HostEvent(self, event):
        # TODO: use local variable to have smaller line
        # POX bug ! ensure that the macaddr does not belong to a switch
        if not event.entry.macaddr in self._hwAddrs:
            print event.entry.macaddr 
            if event.join:
                self.hosts[event.entry.macaddr] = Phy_Host(event.entry.dpid,
                                                           event.entry.port,
                                                        event.entry.macaddr,
                                                         event.entry.ipAddrs)
                entity1 = {"type": "host_port", 
                           "dpid": event.entry.macaddr, "port": 1}
                entity2 = {"type": "switch_port", 
                           "dpid": event.entry.dpid, "port": event.entry.port}
                self.links.append(Phy_Link(entity1, entity2)) 
                self.links.append(Phy_Link(entity2, entity1))
            else:
                print event.link
                """
                for link in self.links:
                    if link.entity1["type"] == "host_port":
                        # to avoid __cmp__ error between int and hwAddr
                        if link.entity1["dpid"] == event.entry.macaddr: 
                            self.links.remove(link)
                for link in self.links:
                    if link.entity2["type"] == "host_port":
                        if link.entity2["dpid"] == event.entry.macaddr:
                            self.links.remove(link)                        
                if event.leave:
                    assert event.entry.macaddr in self.hosts.keys()
                    del self.hosts[event.entry.macaddr]
                elif event.move:
                    assert event.entry.macaddr in self.hosts.keys()
                    entity1 = {"type": "host_port", 
                               "dpid": event.entry.macaddr, "port": 1}
                    entity2 = {"type": "switch_port", "dpid": event.entry.dpid,
                                "port": event.entry.port}
                    self.links.append(Phy_Link(entity1, entity2)) 
                    self.links.append(Phy_Link(entity2, entity1))
                 """
    def discover(self):
        """
        switches
        """
        #TODO: can we refresh POX information ???
        self.switches.clear()
        del self._hwAddrs[:]
        for switch in core.topology.getEntitiesOfType(t=topology.Switch):
            dpid = switch.dpid
            switch_ports = {}
            # TODO: named tuples
            for port in switch.ports.values():
                switch_ports[port.number] = Phy_Port(port.id, port.name, 
                                                port.number,  port.hwAddr)
                self._hwAddrs.append(port.hwAddr)
            self.switches[dpid] = Phy_Switch(dpid, switch_ports)

        """
        links
        """
        del self.links[:]
        # TODO: named tuples        
        for link in core.openflow_discovery.adjacency:
            # TODO: link bandwidth 
            entity1 = {"type": "switch_port", 
                       "dpid": link.dpid1, "port": link.port1}
            entity2 = {"type": "switch_port", 
                       "dpid": link.dpid2, "port": link.port2}
            self.links.append(Phy_Link(entity1, entity2))
                
        """
        hosts
        """
        self.hosts.clear()    
        # core.topology.getEntitiesOfType(t=topology.Host) is empty ! why ?
        for host in core.host_tracker.entryByMAC.values():
            self.hosts[host.macaddr] = Phy_Host(host.dpid, host.port,
                                             host.macaddr, host.ipAddrs)
            entity1 = {"type": "host_port", "dpid": host.macaddr, "port": 1}
            entity2 = {"type": "switch_port", 
                       "dpid": host.dpid, "port": host.port}
            self.links.append(Phy_Link(entity1, entity2)) 
            self.links.append(Phy_Link(entity2, entity1))
        
        # TODO: descriptor 
    def  get_graph(self):
        """
        TODO: must be compatible with graph class and the algorithm
        """
        edges =set()
        vertices = {}
        for host in self.hosts.values():
            edges.add(("{}".format(host.hwAddr), "host"))
            vertices["{}".format(host.hwAddr)] = []
            for link in self.links:
                if link.entity1["type"] == "host_port":
                    if link.entity1["dpid"] == host.hwAddr:
                        vertices["{}".format(host.hwAddr)].append((1, "s{}".format(link.entity2["dpid"]), 1))
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
        return Graph(vertices, edges)
    
    def arp(self, ipAddr):
        """
        work only for one ipAddr by host
        """
        for key, host in self.hosts.iteritems():
            if (host.ip_addrs.keys()[0]).toStr() == ipAddr:
                return host.hwAddr
        return None
            
    def rarp(self, hwAddr):
        """
        work only for one ipAddr by host
        """
        for key, host in self.hosts.iteritems():
            if host.hwAddr.toStr() == hwAddr:
                return host.ip_addrs.keys()[0]
    
    def get_output_to_destination(self, hwAddr):
        output = namedtuple('output', ['switch', 'port'])
        graph = self.get_graph()
        for edge_key, adjacent_edges in graph.vertices.iteritems():
            for adjacent_edge in adjacent_edges:
                if (adjacent_edge[1] == hwAddr.toStr()):
                    return output(edge_key, adjacent_edge[2])
        
            
    def resolve_ARP_request(self, packet):
        """
        """
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
     
        
    def view(self):
        print "\n----- Switches -----"
        for switch in self.switches.values():
            print "switch dpid {}, ports {}".format(switch.dpid, 
                                                len(switch.ports.keys()))
            for port in switch.ports.values():
                print "    {}".format(port.hwAddr)
        print "----- Hosts -----"
        for host in self.hosts.values():
            print "host macAddr: {}, ipAddrs: {}".format(host.hwAddr, 
                                                         host.ip_addrs.keys())
        print "----- Links -----"
        for link in self.links:
            print ("(dpid: {}, port: {}) /"
                   " (dpid: {}, port: {})".format(link.entity1["dpid"], 
                                                  link.entity1["port"], 
                                                  link.entity2["dpid"], 
                                                  link.entity2["port"]))

def launch():
    core.registerNew(Infrastructure)
