from pox.core import core
from importlib import import_module
import copy
from language import identity
from language import forward, drop, CompositionPolicy, match, DataFctPolicy, NetworkFunction, Policy, DynamicPolicy
from classifier import Rule
from collections import namedtuple
from pox_client import PoxClient
from ipaddr import IPv4Network
from collections import namedtuple
from tools import match_from_packet, countOfMessages 
from threading import Timer
import time
#import logging
import pdb
from scipy.weave.catalog import intermediate_dir
#from Image import NONE

#TODO: in_port field  
#TODO: routing inside edge's switch and between edges
#TODO: more than one fabric, at present we have a partial support
#TODO: ICMP packets

########## Code audit ########"
#TODO: define formel rules and audit the code.
#TODO: generateur
#TODO: named tuples
#TODO: setters and getters
#TODO: private _functions and _var 
#TODO: simplify algo : functions inside complex functions

log = core.getLogger()

class PeriodicTimer(object):
    """
    PeriodicTimer for stat requests
    """
    def __init__(self, interval, maxticks, callback, *args, **kwargs):
        self._interval = interval
        self._callback = callback
        self._args = args
        self._kwargs = kwargs 
        if maxticks:
            self._nticks = 0
            self._maxticks = maxticks
        else:
            self._maxticks = None
    
    def _run(self):
        if self._maxticks:
            self._nticks += 1
            if self._nticks < self._maxticks: 
                self._timer = Timer(self._interval, self._run)
                self._timer.start()
        else:
            self._timer = Timer(self._interval, self._run)
            self._timer.start()
        self._callback(*self._args, **self._kwargs)
        
    def start(self):
        self._timer = Timer(self._interval, self._run)
        self._timer.start()
        
    def stop(self):
        self._timer.cancel()
        
            
class Bucket(object):
    """
    """
    def __init__(self, filter, type, split, limit, every):
        self.match = filter
        self.limit = limit
        self.split = split
        self.data = []
        if split is not None:
            self.nb_packets = {}
            self.locked = {}
        else:
            self.nb_packets = 0
            self.locked = False
        self.type = type
        if type == "stat":
            self.timer = PeriodicTimer(every, limit, core.runtime.send_stat_request, filter)
            self.timer.start()
    
    def update_bucket_state(self):
        pass
        #self.locked = True
    
    def update_stats(self, stat):
        """
        """
        self.data = stat
        core.runtime.apply_stat_network_function(self.match, stat)
    
    def get_micro_flow(self, packet):
        packet_match = match_from_packet(packet)
        try:
            return match(**{field:packet_match.map[field] for field in self.split})
        except KeyError:
            print "split can not be applied on this packet"
        
    def add_packet(self, dpid, packet_match, packet):        
        if self.limit is None:
            self.data.append(packet)
            core.runtime.apply_network_function(dpid, self.match, packet_match, packet)
        else:
            if self.split is not None:
                micro_flow = self.get_micro_flow(packet)
                try:
                    self.locked[micro_flow]
                except KeyError:
                    self.locked[micro_flow] = False
                if not self.locked[micro_flow]:
                    try:
                        self.nb_packets[micro_flow] += 1
                    except KeyError:
                        self.nb_packets[micro_flow] = 1
                    self.data.append(packet)
                    if self.nb_packets[micro_flow] == self.limit:
                        self.locked[micro_flow] = True
                        micro_flow_match = copy.deepcopy(self.match)
                        micro_flow_match.map.update(micro_flow.map)
                        core.runtime.micro_flow_limit_reached(micro_flow_match)
                    core.runtime.apply_network_function(dpid, self.match, packet_match, packet)
                else:
                    print " micro-flow locked"
                    # TODO: add something to handle this lasts packets --> packets concurrency
            else:
                if not self.locked:
                    self.nb_packets += 1
                    self.data.append(packet)
                    if self.nb_packets == self.limit:
                        self.locked = True
                        core.runtime.flow_limit_reached(self.match)
                    core.runtime.apply_network_function(dpid, self.match, packet_match, packet)
                else:
                    print "flow locked"
                    # TODO: packets concurrency
                    

class Runtime():
    """
    The proactive and reactive cores
    """
    _core_name = "runtime"
    
    def __init__(self, control_program, mapping_program):
        #TODO: put all global variables here.
        #mapping information
        log.info("starting compilation -- Time == " + str(int(round(time.time() * 1000))))
        _compilation_duration = int(round(time.time() * 1000))
        main_module = import_module(control_program)
        main_module = main_module.main()
        mapping_module = import_module(mapping_program)
        mapping_module = mapping_module.main()
        self.mapping = mapping_module
        # the graph corresponding to the physical infrastructure
        self.phy_topology = core.infrastructure.get_graph()

        #virtual topology
        self.virtual_topology = main_module["virtual_topology"]
        
        #edge and fabric control policies
        self.user_edge_policies = main_module["edge_policies"]
        self.edge_policies = main_module["edge_policies"]
        
        #Network functions
        self.nwFct_rules = []
        self.buckets = []
        self.NwFctItem = namedtuple('NwFctItem', ['match', 'tag', 'function', 'actions'])
        
        # first resolve filters headers, in order to pop "src" and "dst"
        self.resolve_match_headers(self.edge_policies)
        # then compile
        self.edge_policies = self.edge_policies.compile()
        self.fabric_policies = main_module["fabric_policies"]
        self.fabric_policies = self.fabric_policies.compile()
        
        #communication point with physical switches        
        self.nexus = PoxClient()
        
        self.main_module = main_module
        self._event_time = 0
        log.info("compilation finished -- Time == " + str(int(round(time.time() * 1000))))
        _compilation_duration = int(round(time.time() * 1000)) - _compilation_duration 
        log.info("compilation DURATION == " + str(_compilation_duration))

    def resolve_match_headers(self, policy):
        """
        #TODO:
        """
        if isinstance(policy, CompositionPolicy):
            for pol in policy.policies:
                self.resolve_match_headers(pol)
        elif isinstance(policy, match):
            if "src" in policy.map:
                policy.map["nw_src"] = self.mapping.resolve_host(policy.map["src"])
                policy.map.pop("src")
            if "dst" in policy.map:
                policy.map["nw_dst"] = self.mapping.resolve_host(policy.map["dst"])
                policy.map.pop("dst") 
    
    def get_host_nwAddr(self, id):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_name == id:
                return host_ipAddr
                        
    def get_host_dlAddr(self, id):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_name == id:
                return core.infrastructure.arp(host_ipAddr)
            
    def nwAddr_to_host(self, nwAddr):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_ipAddr == nwAddr:
                return host_name

    def dlAddr_to_host(self, nwAdd):
        #TODO
        pass

            
    def resolve_graph_hosts(self, graph):
        """
        this function change hwAddrs in graph with symbolic names (e.g., h1)
        :param graph: graph class returned by infrastructure module 
        """
        new_hosts = {}
        for edge in graph.edges:
            if edge[1] == "host":
                edge_ipAddr = core.infrastructure.rarp(edge[0])
                for host_ipAddr, host_name in self.mapping.hosts.iteritems():
                    # for hosts and networks
                    if (edge_ipAddr.toStr() == host_ipAddr or 
                        IPv4Network(edge_ipAddr.toStr()) in IPv4Network(host_ipAddr)):
                        # vertices update
                        """
                        create a copy of graph.vertices because i need to update it
                        but at the same time i'm iterating over him 
                        we do not a deepcopy to be able to update edge_list_adjacent 
                        """
                        vertices = copy.copy(graph.vertices)
                        for edge_key, edge_list_adjacent in vertices.iteritems():
                            for idx, adjacent_node in enumerate(edge_list_adjacent):
                                if adjacent_node[1] == edge[0]:
                                    # (link_weight, adjacent_node, output_port to adjacent)
                                    edge_list_adjacent[idx] = (adjacent_node[0], host_name, adjacent_node[2])
                            if edge_key == edge[0]:
                                graph.vertices[host_name] = graph.vertices.pop(edge_key)
                        # edges update
                        new_hosts[edge] = (host_name, "host")
                        #graph.edges.remove(edge)
                        #graph.edges.add((host_name, "host"))
        for old_edge, new_edge in new_hosts.iteritems():
            graph.edges.remove(old_edge)
            graph.edges.add(new_edge)
        return graph
    
    def get_edge_physical_corresponding(self, edge, port=None):
        """
        return a list of tuples (phy_switch, port) that correspond to the virtual edge
        :param edge: virtual edge name
        :param port: port mapping if it was specified
        """
        #**********
        # Used only for ingress rules
        #**********
        phy_switches = []
        end_host = None
        if port is not None:
            #**********
            # strong assumption : we have a one to one port mapping
            #**********
            for link in self.virtual_topology._links:
                if link.unitA[0] == edge and link.unitA[1] == port:
                    end_host = link.unitB[0]
                elif link.unitB[0] == edge and link.unitA[1] == port:
                    end_host = link.unitA[0]
            #end host are connected by a unique link witch a unique swicth
            for phy_switch in self.topology_graph.vertices[end_host]:
                phy_switches.append(phy_switch) 
        else:
            for edge_key, edge_mapping in self.mapping.edges.iteritems():
                if edge_key == edge: 
                        phy_switches = edge_mapping
        return phy_switches
    
    def get_packetIn_edge(self, phy_switch, my_match):
        edges = []
        if "nw_proto" in my_match.map.keys():
            my_match.map.pop("nw_proto") 
        for edge, mapping in self.mapping.edges.iteritems():
            if phy_switch in mapping:
                edges.append(edge)
        for edge in edges:
            my_match.map["edge"] = edge
            for rule in self.edge_policies.rules:                
                if ((my_match == rule.match) or (rule.match.covers(my_match))) and (rule.match != identity):                    
                    return rule.match.map["edge"]
    
    def get_corresponding_virtual_edge(self, physical_switch):
        """
        return the swicth's corresponding virtual edge
        :param physical_switch: physical switch name
        """
        for edge, mapping in self.mapping.edges.iteritems():
                if physical_switch in mapping:
                    return edge
        return None
    
    def get_match_switches_list(self, rule_match):
        #**********
        # Used only for ingress rules
        #**********
        """
        return a list of tuples (phy_switch, port) that correspond to the match policy
        :param match: rule's match (filter)
        """
        for header in rule_match.map:
            if header == "port":
                return self.get_edge_physical_corresponding(rule_match.map["edge"], rule_match.map["port"])   
            else:
                return self.get_edge_physical_corresponding(rule_match.map["edge"])
    
    def get_phy_switch_output_port(self, switch, dst_output):
        """
        return physical switch's output_port that allows to go to dst_output
        :param switch: phy_switch (start point)
        :param dst_output: fabric or host (end point). forward's output parameter 
        """
        #TODO: dst_output is an edge
        # test if the destination is a fabric (i.e., ingress edge)
        if dst_output in self.mapping.fabrics:
            for fab_key, fab_mapping in self.mapping.fabrics.iteritems():
                if fab_key == dst_output:
                    destination_switches_set = fab_mapping
                    
            for adjacent_node in self.topology_graph.vertices[switch]:
                if adjacent_node[1] in destination_switches_set:
                    #**********
                    #return the first node found, all costs are 1 (i.e., take the first path)
                    #TODO: link cost or load balancing
                    #********** 
                    return adjacent_node[2]
        # If the dst_output is a host
        elif dst_output in self.mapping.hosts.values(): 
            for adjacent_node in self.topology_graph.vertices[switch]:
                if adjacent_node[1] == dst_output:
                    return adjacent_node[2]
        # if the destination is the controller
        elif dst_output == "controller":
            return "OFPP_CONTROLLER"
        else: 
            raise AssertionError("no corresponding physical output port ")
                         
    def to_physical_switch_rule(self, rule, switch):
        """
        change forward logical destination with a phy_port (like in Openflow messages)
        pop the edge field from the rule since it's no more needed
        IMPORTANT: to be used only on edges that will send trafic to fabric, or hosts
        :param rule: rule to be transformed
        :param switch: switch on witch the rule will be installed
        """
        # we perform a deep copy to not change rule's value when pop 'edge' from phy_rule
        physical_rule = copy.deepcopy(rule)
        drop_rule = False
        for policy in physical_rule.actions:
            if isinstance(policy, forward):
                policy.output = self.get_phy_switch_output_port(switch, policy.output)
            if policy == drop:
                drop_rule = True
        if drop_rule:
            # set() == drop
            physical_rule.actions = set()
        physical_rule.match.map.pop("edge")
        return physical_rule
    
    def get_fabric_output_edges(self, fabric):
        """
        return the set of edges that 'fabric' will send to them flows
        :param fabric: fabric that will carry flows to edges
        """
        fabric_rules = [rule for rule in self.fabric_policies.rules if rule.flow.fabric == fabric]
        output_edges = [rule.action.destination for rule in fabric_rules]
        return output_edges
    
    def get_fabric_output_phy_switches(self, fabric):
        """
        return physical_switches (corresponding to fabric's output edges) that will receive flows from the fabric
        these physical switches are NOT INSIDE the fabric
        :param fabric: fabric that will carry flows to these physical switches
        """
        output_edges = self.get_fabric_output_edges(fabric)
        output_switches = set()
        for edge in output_edges:
            for switch in self.get_edge_physical_corresponding(edge):
                output_switches.add(switch)
        return output_switches
    
    def get_dycRule_forward(self, rule):
    if len(rule.actions) != 0:
        for act in rule.actions:
            if isinstance(act, forward):
                return act
        if isinstance(rule.function, DynamicPolicy):
            return self.get_nwFct_forward(rule.function)
    else:
        return None
    
    def get_nwFct_forward(self, fct):
        if not isinstance(fct, DynamicPolicy):
            for act in fct.sequential_actions:
                if isinstance(act, forward):
                    return act
                elif isinstance(act, DataFctPolicy):
                    self.get_nwFct_forward(act)
            for function in fct.parallel_functions:
                self.get_nwFct_forward(function)
    
    def get_fabric_input_rules(self, fabric, flow_src, classifiers):
        """
        return a list of all flows that enter the fabric.
        the list is formed from tuples, each tuple is formed in this way: 
        (phy_rule, fab_phy_switch that will receive flow, fab_phy_switch input_port)
        these physical switches are INSIDE the fabric
        :param fabric: virtual fabric
        """
               
        def sends_flows(switch, rule, target): 
            
            def _nwFct_rule_sends_flows(switch, rule, target):
                for act in rule.actions:
                    if isinstance(act, forward):
                        output = self.get_phy_switch_output_port(switch, act.output)
                        return output == target[2]
                rule_forward = self.get_nwFct_forward(rule.function)
                if rule_forward is not None:
                    rule_output = self.get_phy_switch_output_port(switch, rule_forward.output)
                    return rule_output == target[2] 
                           
            def _ctrl_sends_flows(swicth, match, target):
                edge = self.get_corresponding_virtual_edge(switch)
                rule_match = copy.deepcopy(match)
                rule_match.map["edge"] = edge
                for nwFct_rule in self.nwFct_rules:
                    if (nwFct_rule.match.map == rule_match.map): #and not isinstance(nwFct_rule.function, DynamicPolicy): 
                        if _nwFct_rule_sends_flows(switch, nwFct_rule, target):
                            return True
                return False
                
            #function start here
            for action in rule.actions:
                if isinstance(action, forward):
                        if action.output == target[2]:
                            return True
                        elif action.output == 'OFPP_CONTROLLER' or action.output == 65533:
                            if _ctrl_sends_flows(switch, rule.match, target):
                                return True
            return False
                        
        #function start here.            
        input_rules = []
        fabric_phy_switches = self.mapping.fabrics[fabric]
        fabric_input_edge = flow_src
        edge_switches = self.get_edge_physical_corresponding(fabric_input_edge)
        for edge_switch in edge_switches:  
            for vertex in self.topology_graph.vertices[edge_switch]:
                # vertex[0] == cost, vertex[1] == adjacent switch 
                # vertex[2] == switch's port to take in order to reach the adjacent
                if vertex[1] in fabric_phy_switches:
                    for rule in classifiers[edge_switch]:
                        #TODO: for s8 sends_flows is false for the rule {'nw_src': '10.0.0.11'} !
                        if sends_flows(edge_switch, rule, vertex):
                            for link in self.topology_graph.vertices[vertex[1]]:
                                #i use link to get in_port for the fab_switch
                                if link[1] == edge_switch:
                                    # assert that the rule doesn't exist.
                                    # because we install the same rules in ingress-edge's switches.
                                    # here we assume that a specific flow will always come from a unique switch. 
                                    exist = False
                                    for input_rule in input_rules:
                                        if (input_rule[0].match.map == rule.match.map and
                                            input_rule[1] == vertex[1]):
                                            exist = True
                                    if not exist:
                                        #list of (phy_rule, fab_input_switch, fab_input_switch_in_port)  
                                        input_rules.append((rule, vertex[1], link[2]))
        return input_rules
    
    def is_drop_rule(self, rule):
        """
        """
        if rule.match != identity:
            if len(rule.actions) == 0:
                return True
        return False
    
    def is_ingress_rule(self, rule):
        """
        allow to figure out if this rule send flows inside virtual network (ingress host-network interface)
        :param rule: concerned rule
        """
        for action in rule.actions:
            if isinstance(action, forward):
                if action.output in self.mapping.fabrics.keys():
                    return True
        return False
    
    def is_egress_rule(self, rule):
        """
        allow to figure out if this rule send flows outside virtual network (i.e., to hosts or ntwks)
        :param rule: concerned rule
        """
        for action in rule.actions:
            if isinstance(action, forward):
                if action.output in self.mapping.hosts.values():
                    return True
        return False
    def is_DataFct_rule(self, rule):
        """
        """
        for act in rule.actions:
            if isinstance(act, DataFctPolicy):
                return True
        return False
    
    def is_DynamicFct_rule(self, rule):
        for act in rule.actions:
            if isinstance(act, DynamicPolicy):
                return True
        return False
    
    def get_corresponding_match_switch_list(self, fabric, flow_src, label, classifiers):
        """
        search in 'fabric' input rules and return rules that correspond to 'label'
        the result is a list that contain tuples formed in this way: (match, switch)
        :param fabric:
        :param label:
        """
        from language import modify 
        
        def apply_modify_action(my_match, my_modify):
            for header, value in my_modify.map.iteritems():
                if header in my_match.map:
                    my_match.map[header] = value
            return my_match
        
        switch_match_list = []
        fabric_input_rules = self.get_fabric_input_rules(fabric, flow_src, classifiers)
        #TODO:
        # after a ping, self.get_fabric_input_rules returns a ampty list
        for rule in fabric_input_rules:
            #rule == (phy_rule, fab_input_switch, fab_input_switch_in_port)
            if rule[0].label.label == label:
                _match = copy.deepcopy(rule[0].match)
                _switch = rule[1]
                for act in rule[0].actions:
                    if isinstance(act, modify):
                        _match = apply_modify_action(_match, act)
                switch_match_list.append((_match, _switch))
        return switch_match_list   
    
    def add_fabric_flow_routing_entry(self, fabric, rule, input_switch, output_switch, via_list):
        """
        fill fabric routing table with a tuple containing :
        (the rule, the input_phy_switch, output_phy_switch)
        :param fabric: the concerned fabric
        :param rule: rule to be installed, with the intersection match
        :param input_switch: the fab_ input switch
        :param output_switch: the output_switch (do not belong to the fabric)
        """
        self.fabrics_flows_routing_table[fabric].append((rule, input_switch, output_switch, via_list))
        
    def get_output_port_path(self, path):
        """
        return a path on which each node have also the output_port that allows 
        to go from him directly to the next node in the path
        :param path: original path containing only node with no output_port
        """
        output_port_path = []
        for idx,node in enumerate(path):
            adjacents_nodes = self.topology_graph.vertices[node]
            for adjacent in adjacents_nodes:
                #TODO: we can have a better test
                if len(path)-1 == idx:
                        break
                if adjacent[1] == path[idx+1]:
                    output_port_path.append((node, adjacent[2]))
                    
        return output_port_path
                    
    def enforce_fabric_physical_rules(self, fabric, classifiers):
        """
        install rules on the physical paths inside the fabric
        :param fabric: fabric to process
        """
        excludes_nodes = set()
        for fab in self.mapping.fabrics:
            if fab != fabric:
                excludes_nodes.update(self.mapping.fabrics[fab])
        excludes_nodes = excludes_nodes - self.mapping.fabrics[fabric]        
        for rule in self.fabrics_flows_routing_table[fabric]:
            #rule[0] == intersec_match, rule[1] == input_switch, rule[2] == output_switch, rule[3]==via_list
            if rule[3] is None:
                #test if there is via actions
                path = self.topology_graph.SPF(rule[1], rule[2], excludes_nodes)
                output_port_path = self.get_output_port_path(path)
                #item: (switch, in_port, out_port)
                for item in output_port_path:
                    action = forward(item[1])
                    filter = rule[0]
                    #print "rule for switch " + str(item[0]) + " : " + str(filter) + str(action)
                    classifiers[item[0]].append(Rule(filter, identity, set([action])))
            else:
                self.enforce_data_machine_path(rule, classifiers, fabric, excludes_nodes) 
    
    def enforce_data_machine_path(self, rule, classifiers, fabric, excludes_nodes):
        """
        """
        def get_predecessors(switch, fabric):
            fabric_switches = self.mapping.fabrics[fabric]
            predecessors = list()
            for vertex in self.topology_graph.vertices[switch]:
                if not (vertex[1] in fabric_switches):
                    predecessors.append(vertex)
            return predecessors
        
        def get_corresponding_switches(dm_list):
            switches = list()
            for dm in dm_list:
                for vertex in self.topology_graph.vertices[dm]:
                    switches.append(vertex[1])
            return switches
        
        def get_in_port(target_switch, sending_switch):
            """
            return in_port from which target_switch recieve flows from sending_switch
            """
            for vertex in self.topology_graph.vertices[target_switch]:
                if vertex[1] == sending_switch:
                    return vertex[2]
        
        def get_data_machine_switch(data_machine):
            """
            return a tuple that contain the switch and the port to witch dm is connected
            nq:parm: data machine name
            :return: (switch, port)
            """
            adjacents = set()
            #can't use graph get_adjacent method, because it is integrated to SPF algo, fix it
            for link in self.topology_graph.vertices[data_machine]:
                adjacents.add(link[1])
            dm_switch = adjacents.pop()
            for vertex in self.topology_graph.vertices[dm_switch]:
                if vertex[1] == data_machine:
                    return (dm_switch, vertex[2])
                
        start = rule[1]
        last = None
        for dm in rule[3]:
            intermediate = get_data_machine_switch(dm)
            path = self.topology_graph.SPF(start, intermediate[0], excludes_nodes)
            output_port_path = self.get_output_port_path(path)
            dm_switches = get_corresponding_switches(rule[3])
            for item in output_port_path:
                if not item[0] in dm_switches:
                    action = forward(item[1])
                    filter = copy.deepcopy(rule[0])
                    classifiers[item[0]].append(Rule(filter, identity, set([action])))
                    last = item[0]
                else:
                    #to dm
                    action = forward(intermediate[1])
                    filter = copy.deepcopy(rule[0])
                    if last is None:
                        predecessors = get_predecessors(item[0], fabric)
                        for pred in predecessors:
                            filter.map["in_port"] = get_in_port(item[0], pred[1])
                            classifiers[item[0]].append(Rule(filter, identity, set([action])))
                    else:
                        filter.map["in_port"] = get_in_port(item[0], last)
                        classifiers[item[0]].append(Rule(filter, identity, set([action]))) 
                    #from dm
                    action = forward(item[1])
                    filter = copy.deepcopy(rule[0])
                    filter.map["in_port"] = intermediate[1]
                    classifiers[item[0]].append(Rule(filter, identity, set([action])))
                    last = item[0]
            start = intermediate[0]
        
        #pdb.set_trace()
            
        action = forward(intermediate[1])
        filter = copy.deepcopy(rule[0])
        filter.map["in_port"] = get_in_port(intermediate[0], last)
        classifiers[intermediate[0]].append(Rule(filter, identity, set([action])))
        
        
        path = self.topology_graph.SPF(intermediate[0], rule[2], excludes_nodes)
        output_port_path = self.get_output_port_path(path)
        for item in output_port_path:
            if not item[0] in dm_switches:
                action = forward(item[1])
                filter = copy.deepcopy(rule[0])
                classifiers[item[0]].append(Rule(filter, identity, set([action])))
            else:
                action = forward(item[1])
                filter = copy.deepcopy(rule[0])
                filter.map["in_port"] = intermediate[1]
                classifiers[item[0]].append(Rule(filter, identity, set([action])))
    
    def get_switch_phy_egress_rules(self, egress_switch, classifiers, fabric):
        """
        return switch's egress rule list
        """
        
        def get_nwFct_host_dst(switch, rule_match):
            edge = self.get_corresponding_virtual_edge(switch)
            rule_match = copy.deepcopy(rule_match)
            rule_match.map["edge"] = edge
            for nwFct_rule in self.nwFct_rules:
                if nwFct_rule.match.map == rule_match.map: 
                    if not isinstance(nwFct_rule.function, DynamicPolicy):
                        for act in nwFct_rule.actions:
                            if isinstance(act, forward):
                                return act.output
                    else:
                        #TODO: Find another solution 
                        return "DYNAMICPOLICY"
                    return self.get_nwFct_forward(nwFct_rule.function).output
                
        egress_rules = []
        hosts = [host.name for host in self.virtual_topology._hosts]
        #******
        #FOR edge_GW (edge between two fabrics)
        fabrics_switches = set()
        for fab in self.mapping.fabrics:
            if fab != fabric:
                fabrics_switches.update(self.mapping.fabrics[fab])
        #******
        for rule in classifiers[egress_switch]:
            destination =None
            for act in rule.actions:
                if isinstance(act, forward):
                    if act.output != 'OFPP_CONTROLLER':
                        destination = self.topology_graph.get_dst(egress_switch, act.output)
                    else:
                        destination = get_nwFct_host_dst(egress_switch, rule.match) 
                    if (destination in hosts) or (destination in fabrics_switches):
                        egress_rules.append(rule)
                    elif destination == "DYNAMICPOLICY" or act.output == 65533:
                        egress_rules.append(rule)
        return egress_rules
    
    #TODO: to remove               
    def optimize_switches_classifiers(self, classifiers):
        """
        """
        opt_c = {}
        for switch, classifier in classifiers.iteritems():
            opt_c[switch] = []
            # for priority : smallest value is the highest priority 
            for priority, rule in list(enumerate(classifier)):
                if not reduce(lambda acc, new_item: acc or 
                              (new_item[1].match.covers(rule.match) and new_item[0] < priority), 
                              list(enumerate(classifier)), False):
                    opt_c[switch].append(rule)
        classifiers = opt_c
    
    
    def enforce_drop_rule(self, rule, classifiers):
        match_switches_list = self.get_match_switches_list(rule.match)  
        for switch in match_switches_list:
            #Install on all corresponding switches, because we can have rules like match TCP==80
            physical_switch_rule = self.to_physical_switch_rule(rule, switch) 
            classifiers[switch].append(physical_switch_rule)
    
    def enforce_ingress_policies(self, rule, classifiers):
        """
        fill the physical_switches classifiers with a new ingress rule
        :param rule: the ingress rule that need to be mapped onto physical switches
        """
        match_switches_list = self.get_match_switches_list(rule.match)  
        for switch in match_switches_list:
            #Install on all corresponding switches, because we can have rules like match TCP==80
            physical_switch_rule = self.to_physical_switch_rule(rule, switch) 
            classifiers[switch].append(physical_switch_rule)
   
    def enforce_egress_policies(self, rule, classifiers):
        """
        fill the physical_switches classifiers with a new egress rule
        :param rule: the egress rule that need to be mapped onto physical switches
        """
        
        def get_nwFct_host_dst(rule_match):
            for nwFct_rule in self.nwFct_rules:
                if nwFct_rule.match.map == rule_match.map:
                    for act in nwFct_rule.actions:
                        if isinstance(act, forward):
                            return act.output
                    return self.get_nwFct_forward(nwFct_rule.function).output
                            
        def get_destination_host(rule):           
            for action in rule.actions:
                if isinstance(action, forward):
                    if action.output != "controller":
                        return action.output
                    else:
                        return get_nwFct_host_dst(rule.match)
        
        egress_edge = rule.match.map["edge"]
        dst_host = get_destination_host(rule)
        egress_edge_switches = self.get_edge_physical_corresponding(egress_edge)
        host_adjacent_switches = [node[1] for node in self.topology_graph.vertices[dst_host] if node[1] in egress_edge_switches]
        # Strong assumption : host_adjacent_switches will contain a unique phy_switch
        for switch in host_adjacent_switches:
            physical_switch_rule = self.to_physical_switch_rule(rule, switch)
            classifiers[switch].append(physical_switch_rule)
    
    
    def enforce_fabric_policies(self, fabric, classifiers):
        """
        main function to enforce fabric rules
        :param fabric: fabric to process
        """
        """
        def via_data_machine(actions):
            
            #check if the flow need to passes through a data machine
            
            from language import via
            for act in actions:
                if isinstance(act, via):
                    return True
            return False
        """
        def get_edge_destination(actions):
            """
            return carry's destination 
            """            
            from language import carry
            for act in actions:
                if isinstance(act, carry):
                    return act.destination
            raise RuntimeError("fabric rule have no final destination")
        """
        def get_via_list(actions):
            
            #return via destinations
            
            from language import via
            via_list = []
            for act in actions:
                if isinstance(act, via):
                    # We assume that we have one DataFct per DataMachine
                    via_list.append(act.data_machine)
            return via_list
        """
        
        fabric_rules = [rule for rule in self.fabric_policies.rules if rule.flow.fabric == fabric]
        for fab_rule in fabric_rules:
            egress_edge_destination = get_edge_destination(fab_rule.actions)
            # egress switches are outside the fabric
            flow_egress_switches = self.get_edge_physical_corresponding(egress_edge_destination)
            # ingress switches are inside the fabric
            flow_ingress_match_switch_list = self.get_corresponding_match_switch_list(fab_rule.flow.fabric,
                                                                                      fab_rule.flow.src, 
                                                                                      fab_rule.flow.flow, classifiers)
            for egress_switch in flow_egress_switches:
                for egress_rule in self.get_switch_phy_egress_rules(egress_switch, classifiers, fabric):
                    for item in flow_ingress_match_switch_list:
                        # item[0] == rule, item[1] == switch
                        intersection_match = egress_rule.match.intersec(item[0])
                        if intersection_match !=  drop:
                            if len(fab_rule.via_list)>0:
                                via_list = [act.data_machine for act in fab_rule.via_list]
                                self.add_fabric_flow_routing_entry(fab_rule.flow.fabric,
                                                                   intersection_match,
                                                                   item[1],
                                                                   egress_switch,
                                                                   via_list)
                            else:
                                self.add_fabric_flow_routing_entry(fab_rule.flow.fabric,
                                                                   intersection_match,
                                                                   item[1],
                                                                   egress_switch, None)
        #TODO: a function to optimize fabric rules
        self.enforce_fabric_physical_rules(fabric, classifiers)
    
    def enforce_data_function(self, rule, classifiers):
        """
        """
        def is_ingress(actions, nwFct):
            """
            :parm actions:
            :parm nwFct:
            """
            def is_fct_ingress(function):
                for act in function.sequential_actions:
                    if isinstance(act, forward):
                        if act.output in self.mapping.fabrics.keys():
                            return True
                    elif isinstance(act, DataFctPolicy):
                        is_fct_ingress(act)
                for fct in function.parallel_functions:
                    is_fct_ingress(fct)
                return False
            
            for act in actions:
                if isinstance(act, forward):
                    if act.output in self.mapping.fabrics.keys():
                        return True
            return is_fct_ingress(nwFct)
        
        actions = [act for act in rule.actions if not isinstance(act, DataFctPolicy)]
        # We can find at most one DataFct per rule
        function = [act for act in rule.actions if isinstance(act, DataFctPolicy)][0]
        exist = False
        # Use buckets instead of nwFct_rules because nwFct_rules can be updated.
        for bucket in self.buckets:
            if bucket.match.map == rule.match.map:
                exist = True
        # if i need to re-compile policies, it will not create new buckets and nwFct_rules
        if not exist:        
            self.nwFct_rules.append(self.NwFctItem(rule.match, rule.label, function, actions))
            self.buckets.append(Bucket(filter=rule.match, type='packet', 
                                       limit=function.limit, 
                                       split=function.split,
                                       every=None))
        # add a rule that sends packets towards controller
        rule_actions = {forward("controller")}
        for act in actions:
            if not isinstance(act, forward):
                rule_actions.add(act)
        controller_rule = Rule(rule.match, rule.label, set(rule_actions))
        
        # test if the final rule is ingress or egress
        if is_ingress(actions, function):            
            self.enforce_ingress_policies(controller_rule, classifiers)
        else:
            self.enforce_egress_policies(controller_rule, classifiers)
            
            
    def enforce_Dynamic_function(self, rule, classifiers):
        """
        """        
        actions = [act for act in rule.actions if not isinstance(act, DynamicPolicy)]
        # We can find at most one DynamicFct per rule
        function = [act for act in rule.actions if isinstance(act, DynamicPolicy)][0]
        exist = False
        # Use buckets instead of nwFct_rules because nwFct_rules can be updated.
        for bucket in self.buckets:
            if bucket.match.map == rule.match.map:
                exist = True
        # if i need to re-compile policies, it will not create new buckets and nwFct_rules
        if not exist:        
            self.nwFct_rules.append(self.NwFctItem(rule.match, rule.label, function, actions))
            if function.type == "packet":
                self.buckets.append(Bucket(filter=rule.match, type=function.type, 
                                       limit=function.limit, 
                                       split=function.split,
                                       every=None))
            elif function.type == "stat":
                self.buckets.append(Bucket(filter=rule.match, type=function.type, 
                                       limit=function.limit, 
                                       split=function.split,
                                       every=function.every))
            else:
                raise RuntimeError(str(rule.match) + " : dynamic function data type error")
           
        if function.type == "packet":
            # add a rule that sends packets towards controller
            rule_actions = {forward("controller")}
            for act in actions:
                if not isinstance(act, forward):
                    rule_actions.add(act)
            controller_rule = Rule(rule.match, rule.label, set(rule_actions))
            
            edge = controller_rule.match.map["edge"]
            edge_switches = self.get_edge_physical_corresponding(edge)
            # Strong assumption : host_adjacent_switches will contain a unique phy_switch
            for switch in edge_switches:
                physical_switch_rule = self.to_physical_switch_rule(controller_rule, switch)
                classifiers[switch].append(physical_switch_rule)
            
        elif function.type == "stat":
            switch_rule = Rule(rule.match, rule.label, set(actions))
            if self.is_ingress_rule(switch_rule):
                self.enforce_ingress_policies(switch_rule, classifiers)
            elif self.is_egress_rule(switch_rule):
                self.enforce_egress_policies(switch_rule, classifiers)
            else:
                raise RuntimeError(str(switch_rule.match) + " : stat rule is none ingress or egress")
        else:
            raise RuntimeError("dynamic function type error")

    
    def policies_to_physical_rules(self, policies, classifiers):
        
        # enforce edges rules
        for rule in policies.rules:
            if self.is_DataFct_rule(rule):
                self.enforce_data_function(rule, classifiers)
            elif self.is_DynamicFct_rule(rule):
                self.enforce_Dynamic_function(rule, classifiers)
            elif self.is_ingress_rule(rule):
                self.enforce_ingress_policies(rule, classifiers)
            elif self.is_egress_rule(rule):
                self.enforce_egress_policies(rule, classifiers)
            elif self.is_drop_rule(rule):
                self.enforce_drop_rule(rule, classifiers)
                #else:
                #raise TypeError("the rule don't much any template")
                #TODO: find a solution for (identity, identity, drop) rule because it trigger an exception
                
        #Fabric policies don't change, because that they stay here    
        # enforce fabric rules
        self.fabrics_flows_routing_table = {}
        for fabric in self.mapping.fabrics:
            #for each fabric a list: {match, input_switch, output_switch}
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabric_policies(fabric, classifiers)
            # To keep priority order between rules
            #for fabric, routing_list in self.fabrics_flows_routing_table.iteritems():
                #routing_list.reverse()
        
        #TODO: add s special rule for LLDP packets      
        # add a drop all rule for unknown flows in all phy switches
        #for switch_key in classifiers:
            #classifiers[switch_key].append(Rule(identity, identity, set()))
        
        #optimize physical classifiers
        #self.optimize_switches_classifiers(classifiers)
    
    def get_ARP_switches(self):
        """
        returns switches that are connected to hosts or networks
        """
        switches = []
        for edge in self.mapping.edges:
            switches.extend(self.get_edge_physical_corresponding(edge))
        return switches
    
    """
    def start_ARP_proxy(self):
        self.nexus.arpProxy = True
        graph = core.infrastructure.get_graph()
        self.topology_graph = self.resolve_graph_hosts(graph)
        switches = []
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                switches.append(edge[0])
        self.nexus.install_ARP_rules(switches)
    """
    
    def opt_physical_classifires(self, classifiers):
        
        def remove_shadowed_rules(classifiers):
            opt_c = {}
            for switch, rules in classifiers.iteritems():
                opt_c[switch] = []
                for rule in rules:
                    if not reduce(lambda acc, new_r: acc or
                                  new_r.match.covers(rule.match),
                                  opt_c[switch],
                                  False):
                        opt_c[switch].append(rule)
            return opt_c
                        
        def remove_same_src_dst(classifiers):
            opt_c = {}
            for switch, rules in classifiers.iteritems():
                opt_c[switch] = []
                for rule in rules:
                    if "nw_src" in rule.match.map:
                        if "nw_dst" in rule.match.map:
                            if rule.match.map["nw_src"] != rule.match.map["nw_dst"]:
                                opt_c[switch].append(rule)
                        else:
                            opt_c[switch].append(rule)
                    else:
                        opt_c[switch].append(rule)
                    if "dl_src" in rule.match.map:
                        if "dl_dst" in rule.match.map:
                            if rule.match.map["dl_src"] != rule.match.map["dl_dst"]:
                                opt_c[switch].append(rule)
                        else:
                            opt_c[switch].append(rule)
                    else:
                        opt_c[switch].append(rule)
                    if "tp_src" in rule.match.map:
                        if "tp_dst" in rule.match.map:
                            if rule.match.map["tp_src"] != rule.match.map["tp_dst"]:
                                opt_c[switch].append(rule)
                        else:
                            opt_c[switch].append(rule)
                    else:
                        opt_c[switch].append(rule)
        opt_c = remove_shadowed_rules(classifiers)
        #opt_c = remove_same_src_dst(opt_c)
        return opt_c
                             
                
        
    
    def enforce_policies(self):
        """
        Main proactive function
        """
        log.info("start enforcing policies -- Time == " + str(int(round(time.time() * 1000))))
        _enforcing_duration = int(round(time.time() * 1000))
        graph = core.infrastructure.get_graph()
        self.topology_graph = self.resolve_graph_hosts(graph)
        self.physical_switches_classifiers = {}
        #edge means point, not virtual edge.
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                self.physical_switches_classifiers[edge[0]] = []
        
        self.policies_to_physical_rules(self.edge_policies, self.physical_switches_classifiers)
        # send openflow messages to POX
        
        self.physical_switches_classifiers = self.opt_physical_classifires(self.physical_switches_classifiers)
        
        log.info("number of rules initially installed == " + str(countOfMessages(self.physical_switches_classifiers)))
        self.nexus.install_rules_on_dp(self.physical_switches_classifiers)
        log.info("policies enforcing finished -- Time == " + str(int(round(time.time() * 1000))))
        _enforcing_duration = int(round(time.time() * 1000)) - _enforcing_duration
        log.info("enforcing proactive rules DURATION== " + str(_enforcing_duration))       
    
    
    def handle_topology_change(self):
        """
        """
        graph = core.infrastructure.get_graph()
        self.topology_graph = self.resolve_graph_hosts(graph)
        new_classifiers = self.create_classifiers()
        
        for edge in self.mapping.edges:
            for switch in self.get_edge_physical_corresponding(edge):
                new_classifiers[switch] = copy.deepcopy(self.physical_switches_classifiers[switch]) 
        
        self.fabrics_flows_routing_table = {}
        for fabric in self.mapping.fabrics:
            #for each fabric a list: {match, input_switch, output_switch}
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabric_policies(fabric, new_classifiers)
            # To keep priority order between rules
            #for fabric, routing_list in self.fabrics_flows_routing_table.iteritems():
                #routing_list.reverse()
                
        new_classifiers = self.opt_physical_classifires(new_classifiers)
        self.new_classifiers = copy.deepcopy(new_classifiers)
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        self.install_diff_lists(diff_lists)
        self.physical_switches_classifiers = copy.deepcopy(new_classifiers)
        
        
    def send_stat_request(self, target_match):
        """
        """
        edge_switches = self.get_edge_physical_corresponding(target_match.map["edge"])
        self.nexus.send_stat_request(edge_switches, target_match)
    
    def apply_stat_network_function(self, bucket_match, stat):
        """
        """
        dyc_rule = None
        for rule in self.nwFct_rules:
            if rule.match.map == bucket_match.map:
                dyc_rule = rule
        result = dyc_rule.function.apply(stat)
        if isinstance(result, Policy):
            self.add_new_policy(result)
            
    
    def apply_network_function(self, dpid, bucket_match, packet_match, packet):
        """
        """
        from language import modify
        def handle_using_new_policy(dpid, policy, packet_match, packet):
            policy = policy.compile()
            matching_rule = None
            for rule in policy.rules:
                if rule.match.covers(packet_match):
                    matching_rule = rule
                    break
            switch = 's' + str(dpid)
            if matching_rule.match == identity:
                # if the new policy do not apply on the packet                
                for edge_rule in self.edge_policies.rules:
                    if edge_rule.match.covers(packet_match):
                        for act in edge_rule.actions:    
                            if isinstance(act, modify):
                                act.apply(packet)
                        for act in edge_rule.actions:    
                            if isinstance(act, forward):
                                output = self.get_phy_switch_output_port(switch, act.output)
                                self.nexus.send_packet_out(switch, packet, output)
                        # if no forward ... drop the packet
            else:
                for act in matching_rule.actions:
                    if isinstance(act, modify):
                        act.apply(packet)
                fwd = self.get_dycRule_forward(matching_rule)
                if fwd:
                    output = self.get_phy_switch_output_port(switch, fwd.output)
                    self.nexus.send_packet_out(switch, packet, output)
                    
        dyc_rule = None
        for rule in self.nwFct_rules:
            if rule.match.map == bucket_match.map:
                dyc_rule = rule
                break
                
        for act in dyc_rule.actions:
            if isinstance(act, modify):
                act.apply(packet)
        result = dyc_rule.function.apply(packet)
        
        if isinstance(result, Policy):
            self.add_new_policy(result)
            handle_using_new_policy(dpid, result, packet_match, packet)
        else:
            fwd = self.get_dycRule_forward(dyc_rule)
            switch = 's' + str(dpid)
            output = self.get_phy_switch_output_port(switch, fwd.output)
            self.nexus.send_packet_out(switch, result, output)
    
    def create_classifiers(self):
        new_classifiers = {}
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                new_classifiers[edge[0]] = []
        return new_classifiers

    def clear_fabric_switches(self, fabric, classifiers):
        fabric_switches = self.mapping.fabrics[fabric]
        #TODO: add a special rule for LLDP packets
        """
        for switch in fabric_switches:
            classifiers[switch] = [Rule(identity, identity, set())]
        """
        for switch in fabric_switches:
            classifiers[switch] = []
        

    def add_new_policy(self, new_policy):
        """
        """ 
        #V2
        self.resolve_match_headers(new_policy)
        new_policy = new_policy.compile()
        #1 remove (identity, identity, set()) rule
        for idx in range(len(new_policy.rules)):
            if ((new_policy.rules[idx].match==identity) and 
                (new_policy.rules[idx].label==identity) and 
                (len(new_policy.rules[idx].actions)==0)):
                del new_policy.rules[idx]
        
        #2 get from new policy the new physical rules
        tmp_classifiers = self.create_classifiers()
        for rule in new_policy.rules:
            if self.is_ingress_rule(rule):
                self.enforce_ingress_policies(rule, tmp_classifiers)
            elif self.is_egress_rule(rule):
                self.enforce_egress_policies(rule, tmp_classifiers)
            elif self.is_drop_rule(rule):
                self.enforce_drop_rule(rule, tmp_classifiers) 
        
        #3 if new_r exist in old_classifiers, replace the old one with the new one
        # otherwise add the new_r into old classifiers
        new_classifiers = copy.deepcopy(self.physical_switches_classifiers) 
        for switch, new_rules in tmp_classifiers.iteritems():
            for new_r in new_rules:
                find = False
                for idx, old_r in enumerate(new_classifiers[switch]):
                    if new_r.match == old_r.match:
                        find = True
                        new_classifiers[switch][idx] = new_r
                if not find:
                    new_classifiers[switch].insert(0, new_r)
        
        # recalculate fabric rules  
        self.fabrics_flows_routing_table = {}
        for fabric in self.mapping.fabrics:
            self.clear_fabric_switches(fabric, new_classifiers)
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabric_policies(fabric, new_classifiers)
            #for fabric, routing_list in self.fabrics_flows_routing_table.iteritems():
                #routing_list.reverse()
        
        #pdb.set_trace()
        new_classifiers = self.opt_physical_classifires(new_classifiers)
        self.new_classifiers = copy.deepcopy(new_classifiers)
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        self.install_diff_lists(diff_lists)
        self.diff = copy.deepcopy(diff_lists)
        self.physical_switches_classifiers = copy.deepcopy(new_classifiers)
        
        #V1
        
        """
        #INFO: policy == list(match, tag, actions)
        pdb.set_trace()
        #1 resolve match headers in new policy, to remove src and dst fields
        self.resolve_match_headers(new_policy)

        #2 find in old policies a same policy as the new one        
        find = False
        for idx, seq_policy in enumerate(self.user_edge_policies.policies):
            if new_policy.policies[0] == seq_policy.policies[0] and find == False:
                self.user_edge_policies.policies[idx] = new_policy
            elif new_policy.policies[0] == seq_policy.policies[0] and find == True:
                raise RuntimeError("new policy matches more the one existing policy")
        #3 if not found, add it
        if not find:
            self.user_edge_policies = self.user_edge_policies + new_policy
        
        #4 compile new policies
        new_edge_policies = self.user_edge_policies.compile()
        
        #5 transform to physical policies and edit new classifiers
        new_physical_switches_classifiers = {}
        #edge means point, not virtual edge.
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                new_physical_switches_classifiers[edge[0]] = []
        self.policies_to_physical_rules(new_edge_policies, new_physical_switches_classifiers)
        
        #6 get and install diff_lists between old and new classifiers, 
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_physical_switches_classifiers)
        self.install_diff_lists(diff_lists)
        
        self.diff = copy.deepcopy(diff_lists) 
        
        #7 update old switches physical classifiers
        self.physical_switches_classifiers = copy.deepcopy(new_physical_switches_classifiers)
        """
        
        # V0
        
        """
        # enforce edges rules
        for rule in new_policy.rules:
            if self.is_DataFct_rule(rule):
                self.enforce_data_function(rule, new_classifiers)
            elif self.is_DynamicFct_rule(rule):
                self.enforce_Dynamic_function(rule, new_classifiers)
            elif self.is_ingress_rule(rule):
                self.enforce_ingress_policies(rule, new_classifiers)
            elif self.is_egress_rule(rule):
                self.enforce_egress_policies(rule, new_classifiers)
            elif self.is_drop_rule(rule):
                self.enforce_drop_rule(rule, new_classifiers)
            else:
                pass
                #raise TypeError("the rule don't much any template")
                #TODO: find a solution for (identity, identity, drop) rule because it trigger an exception
                
        for edge in self.mapping.edges:
            for switch in self.get_edge_physical_corresponding(edge):
                for rule in self.physical_switches_classifiers[switch]:
                    if rule.match != identity:
                        new_classifiers[switch].append(copy.deepcopy(rule))
        
        for switch_key in new_classifiers:
            new_classifiers[switch_key].append(Rule(identity, identity, set()))
        
        del self.fabrics_flows_routing_table
        self.fabrics_flows_routing_table = {}
        for fabric in self.mapping.fabrics:
            #for each fabric a list: {match, input_switch, output_switch}
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabric_policies(fabric, new_classifiers)
            
            # To keep priority order between rules
            for fabric, routing_list in self.fabrics_flows_routing_table.iteritems():
                routing_list.reverse()
         
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        # we must not update classifiers because diff_lists will put them in the next round in to_delete when 
        # we compare them to edge_policies
        #self.physical_switches_classifiers = copy.deepcopy(new_classifiers)
        
        self.install_diff_lists(diff_lists)
        """

    def remove_nwFct_action(self, rule):
        def get_actions(function, actions):
            for act in function.sequential_actions:
                if not isinstance(act, DataFctPolicy):
                    actions.add(act)
                else:
                    get_actions(act, actions)
            for fct in function.parallel_functions:
                get_actions(fct, actions)
        actions = set()
        for act in rule.actions:
            if isinstance(act, DataFctPolicy):
                get_actions(act, actions)
            elif not isinstance(act, DynamicPolicy):
                actions.add(act)
        if len(actions) == 0:
            actions.add(identity)
        rule.actions = actions
    
    
    def micro_flow_limit_reached(self, micro_flow):
        """
        this fct is called before apply_network_function
        """
        target_rule = None
        for rule in self.edge_policies.rules:
            if (rule.match != identity and rule.match.covers(micro_flow)):
                target_rule = copy.deepcopy(rule)

        classifiers = self.create_classifiers()
        target_rule.match = micro_flow
        if self.is_DynamicFct_rule(target_rule) or self.is_DataFct_rule(target_rule): 
            self.remove_nwFct_action(target_rule)
            new_rule = False
            if self.is_ingress_rule(target_rule):
                self.enforce_ingress_policies(target_rule, classifiers)
                new_rule = True
            elif self.is_egress_rule(target_rule):
                self.enforce_egress_policies(target_rule, classifiers)
                new_rule = True
            # case where dynamicFct is the only action (i.e., match >> dycFct)    
            if new_rule:
                self.nexus.install_new_rules(classifiers)
                for switch, new_rules in classifiers.iteritems():
                    for new_r in new_rules:
                        find = False
                        for idx, old_r in enumerate(self.physical_switches_classifiers[switch]):
                            if new_r.match == old_r.match:
                                find = True
                                self.physical_switches_classifiers[switch][idx] = new_r
                        if not find:
                            self.physical_switches_classifiers[switch].append(new_r)
        else:
            raise RuntimeError("runtime failed to find the nwFct_rule corresponding to " + str(micro_flow))  
        
    
    def get_diff_lists(self, old_classifiers, new_classifiers):
            """
            """ 
            def find_same_rules(target, rule_list):
                rules = []
                for priority in range(len(rule_list)-1, -1, -1):
                    #TODO: fig identity bug!
                    # identity is a singleton, but i have different id(identity)
                    if ((target.match == rule_list[priority].match) or 
                        (len(target.match.map) == 0 and len(rule_list[priority].match.map)==0)):
                        rules.append((rule_list[priority], priority))
                if len(rules) != 0:
                    return rules
                else:
                    return None
            
            def different_actions(act_list1, act_list2):
                # test if they have same number of 
                for act1 in act_list1:
                    find = False
                    for act2 in act_list2:
                        if act1 == act2:
                            find = True
                    if not find:
                        return True
                if len(act_list1) != len(act_list2):
                    return True
                return False
            
            def opt_to_modify(to_modify, to_stay):
                for idx in range(len(to_modify)):
                    rules = find_same_rules(to_modify[idx][0][0], to_stay)
                    if rules:
                        for rule in rules:
                            if not different_actions(to_modify[idx][0][0].actions, rule[0].actions):
                                del to_modify[idx] 
                to_modify = [item[0] for item in to_modify]
                return to_modify
            
            DiffListItem = namedtuple('DiffListItem', ['to_add', 'to_delete', 'to_modify', 'to_stay'])
            diff_lists = {}

            for switch, old_rules in old_classifiers.iteritems():
                to_add = list()
                to_delete = list()
                to_modify = list()
                to_stay = list()
                
                # rules are ordered by priority in the classifier
                for priority in range(len(old_rules)-1, -1, -1):
                    new_rules = find_same_rules(old_rules[priority], new_classifiers[switch])
                    if new_rules is None:
                        to_delete.append((old_rules[priority], priority))
                    else:
                        for new in new_rules:
                            if (not different_actions(old_rules[priority].actions, new[0].actions) and
                                len(old_rules)-priority == len(new_classifiers[switch])-new[1]):
                                to_stay.append(old_rules[priority])
                            else:
                                #if switch == "s6":
                                    #print "get_diff_lists"
                                    #print "old==" + str(old_rules[priority].match) + " / priority==" + str(priority) + ", cpt==" + str(len(old_rules))
                                    #print "new: " + str(new[0].match) + " / priority: " + str(new[1]) + ", cpt==" + str(len(new_classifiers[switch]))
                                to_modify.append((new, (old_rules[priority], priority)))
                            
                for priority in range(len(new_classifiers[switch])-1, -1, -1):
                    rules = find_same_rules(new_classifiers[switch][priority], old_rules)
                    if rules is None:
                        to_add.append((new_classifiers[switch][priority], priority))
                         
                #to_modify = opt_to_modify(to_modify, to_stay)
                
                diff_lists[switch] = DiffListItem(to_add, to_delete, to_modify, to_stay) 
                            
            return diff_lists
    
    
    def install_diff_lists(self, diff_lists):
        """
        """
        to_add = {}
        to_delete = {}
        to_modify = {}
        for switch, diff_list in diff_lists.iteritems():    
            to_add[switch] = diff_list.to_add
            to_delete[switch] = diff_list.to_delete
            to_modify[switch] = diff_list.to_modify
        log.info("number of modified rules == " + str(countOfMessages(to_modify)))    
        self.nexus.modifyExistingRules(to_modify)
        log.info("number of new installed rules == " + str(countOfMessages(to_add)))
        self.nexus.installNewRules(to_add)
        log.info("number of deleted rules == " + str(countOfMessages(to_delete)))
        self.nexus.delete_rules(to_delete)
        log.info("diffLists enforcing finished -- Time == " + str(int(round(time.time() * 1000))))
        _enforce_diffList_duration = int(round(time.time() * 1000)) - self._event_time
        log.info("enforcing diffLists DURATION == " + str(_enforce_diffList_duration))
    
    def flow_limit_reached(self, fct_predicate):
        # first: remove fct item from nwFct_rules list
        for idx in range(len(self.nwFct_rules)):
            if self.nwFct_rules[idx].match.map == fct_predicate.map:
                del self.nwFct_rules[idx]
                break
                
        # second: in edge policies, replace the fct action with identity
        nwFct_rule = None
        for rule in self.edge_policies.rules:
            if rule.match is not identity:
                if rule.match.map == fct_predicate.map:
                        self.remove_nwFct_action(rule)
                        nwFct_rule = rule
        
        tmp_classifiers = self.create_classifiers()
        new_rule = False
        if self.is_ingress_rule(nwFct_rule):
            self.enforce_ingress_policies(nwFct_rule, tmp_classifiers)
            new_rule = True
        elif self.is_egress_rule(nwFct_rule):
            self.enforce_egress_policies(nwFct_rule, tmp_classifiers)
            new_rule = True
            
        new_classifiers = copy.deepcopy(self.physical_switches_classifiers) 
        # case where dynamicFct is the only action (i.e., match >> dycFct)
        if new_rule:
            for switch, new_rules in tmp_classifiers.iteritems():
                for new_r in new_rules:
                    find = False
                    for idx, old_r in enumerate(new_classifiers[switch]):
                        if new_r.match == old_r.match:
                            find = True
                            new_classifiers[switch][idx] = new_r
                    if not find:
                        # Unlike for micro-flows, here we need to modify an existing rule and not to add new one
                        raise RuntimeError
        else:
            # a rule with a single action: dycFct
            egress_edge = nwFct_rule.match.map["edge"]
            nwFct_rule.match.map.pop("edge")
            egress_edge_switches = self.get_edge_physical_corresponding(egress_edge)
            for switch in egress_edge_switches:
                for idx, old_r in enumerate(new_classifiers[switch]):
                    if nwFct_rule.match == old_r.match:
                        del new_classifiers[switch][idx]
                    
                        
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        self.install_diff_lists(diff_lists)
        self.physical_switches_classifiers = copy.deepcopy(new_classifiers)
            
        
    def handle_packet_in(self, dpid, packet_match, packet):
        #pdb.set_trace()
        for bucket in self.buckets:
            if bucket.match.covers(packet_match):
                bucket.add_packet(dpid, packet_match, packet)
                
    def handle_flow_stats(self, stat):
        issuing_match = stat._issuing_match
        for bucket in self.buckets:
            if bucket.match == issuing_match:
                bucket.update_stats(stat)
        
    def stop_timers(self):
        """
        """
        for bucket in self.buckets:
            if bucket.type == "stat":
                bucket.timer.stop()
                 

def launch(control_program, mapping_program):
    core.registerNew(Runtime, control_program, mapping_program)
    