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
