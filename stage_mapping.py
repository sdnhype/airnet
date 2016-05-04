

#TODO: for mapping, arguments need to a list of node, not several nodes
# e.g : ("edge1", ["s1", "s2"]) not ("edge1", "s1", "s2") 

class Mapping(object):
    """
    base class for mapping module
    """
    def __init__(self):
        self.edges = {}
        self.hosts = {}
        self.fabrics = {}
        self.data_machines = {}
    
    def addEdgeMap(self, edge, *phy_switches):
        """
        add a mapping for an edge
        :param edge: edge to be mapped
        :param phy_switches: list of switches 
        """
        self.edges[edge] = set(phy_switches)
            
    def addHostMap(self, business_identifier, host_ipAddr):
        """
        TODO:
        """
        self.hosts[host_ipAddr] = business_identifier
        #TODO: put business_identifier as a key, not host_ipAddr
    
    def addNetworkMap(self, business_identifier, network_ipAddr):
        """
        TODO:
        """
        self.hosts[network_ipAddr] = business_identifier
    
    def addFabricMap(self, fabric, *switches):
        """
        add a mapping for a fabric
        :param fabric: fabric to map
        :param switches: list of switches that are included in fabric
        """ 
        self.fabrics[fabric] = set(switches)
        
    def addDataMachineMap(self, business_identifier, dm_ipAddr):
        """
        """
        #TODO: keep one of them!!
        self.hosts[dm_ipAddr] = business_identifier
        self.data_machines[dm_ipAddr] = business_identifier   
        
    def resolve_host(self, host_name):
        for ipAddr, host in self.hosts.iteritems():
            if host == host_name:
                return ipAddr
         
