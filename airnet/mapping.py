# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

#TODO: remove host_ipAddr as key in addHostMap
#TODO: mapping fabric with simple switches
#TODO: choose one instruction in addDataMachineMap

class Mapping(object):
    """ Mapping module base class
        Virtual elements (edge, fabric...) are associated with
        physical topology elements names (s1, h1...)
    """
    def __init__(self):
        """ Set of virtual elements """
        self.edges = {}
        self.hosts = {}
        self.fabrics = {}
        self.data_machines = {}

    def addEdgeMap(self, edge, *phy_switches):
        """ map an edge with one or several switches """
        self.edges[edge] = set(phy_switches)

    def addHostMap(self, business_identifier, host_ipAddr):
        """ map an host with a name and an ipAddr """
        self.hosts[host_ipAddr] = business_identifier

    def addNetworkMap(self, business_identifier, network_ipAddr):
        """ map an network with a name and an network ipAddr """
        self.hosts[network_ipAddr] = business_identifier

    def addFabricMap(self, fabric, *switches):
        """ map a fabric with one or several switches """
        self.fabrics[fabric] = set(switches)

    def addDataMachineMap(self, business_identifier, dm_ipAddr):
        """ map an data machine with a name and an ipAddr """
        self.hosts[dm_ipAddr] = business_identifier
        self.data_machines[dm_ipAddr] = business_identifier

    def resolve_host(self, host_name):
        """ returns the ipAddr of a given name host """
        for ipAddr, host in self.hosts.iteritems():
            if host == host_name:
                return ipAddr
