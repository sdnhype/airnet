# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

import copy
import time
import logging
from importlib import import_module
from collections import namedtuple
from lib.ipaddr import IPv4Network

from dynfunction import Bucket,PeriodicTimer
from log import Logger

from restclient_controller import RyuClient
from language import identity, match, forward, drop, modify, carry,\
                     NetworkFunction, Policy,\
                     CompositionPolicy, DataFctPolicy, DynamicPolicy
from classifier import Rule

#TODO! Stop Stats Thread when Switch Leaves


# initialize a debug-level logger
logger = Logger("Airnet_RUN").Log()
# initialize info-level and error-level handlers and add them to the logger
handler_info = Logger("Airnet_RUN","log/info.log").handler
handler_error = Logger("Airnet_RUN","log/error.log").handler
handler_info.setLevel(logging.INFO)
handler_error.setLevel(logging.ERROR)
logger.addHandler(handler_info)
logger.addHandler(handler_error)

class Runtime():
    """ AIRNET RUNTIME module
        initialize the Proactive (static)
        and Reactive (dynamic) cores of the hypervisor
    """

    def __init__(self, control_program, mapping_program, infra):

        logger.info("\n\n**************************************************\
        **************************************************\n\
                                               GETTING STARTED\n**************************************************\
        **************************************************\n")

        print("Compilation started --")
        logger.info("Compilation started --")
        _compilation_duration = int(round(time.time() * 1000))

        logger.debug("Control program -- {}".format(control_program))
        main_module = import_module(control_program)
        main_module = main_module.main()

        logger.debug("Mapping program -- {}".format(mapping_program))
        mapping_module = import_module(mapping_program)
        mapping_module = mapping_module.main()
        self.mapping = mapping_module

        # the graph corresponding to the physical infrastructure
        self.infra = infra
        self.phy_topology = infra.get_graph()
        logger.debug("Got global topology ")

        # virtual topology
        self.virtual_topology = main_module["virtual_topology"]
        logger.debug("Got virtual topology")

        # edge and fabric control policies
        self.edge_policies = main_module["edge_policies"]
        logger.debug("Got edge policies")

        # Network functions
        # nwFct_rules --> list of NwFctItem
        self.nwFct_rules = []
        self.buckets = []

        # namedtuple: Tuples with Named Fields
        self.NwFctItem = namedtuple('NwFctItem', ['match', 'tag', 'function', 'actions'])

        # replace symbolic names in src and dst by ipAddrs
        self.replace_by_ipAddrs(self.edge_policies)


        # then compile edge_policies --> return a Classifier object
        logger.debug("Compiling edge policies")
        self.edge_policies = self.edge_policies.compile()
        logger.info("Edge rules generated : {}\n************\n{}************".format(self.edge_policies.getNbRules(),self.edge_policies.getLogRules()))

        # compile also fabric_policies --> return a FabricClassifier object
        self.fabric_policies = main_module["fabric_policies"]
        logger.debug("Got edge policies")
        logger.debug("Compiling fabric policies")
        self.fabric_policies = self.fabric_policies.compile()
        logger.info("Fabric rules generated : {}\n************\n{}************".format(self.fabric_policies.getNbRules(),self.fabric_policies.getLogRules()))

        # here none controller is instantiated
        self.nexus = None

        self.main_module = main_module
        self._event_time = 0

        _compilation_duration = int(round(time.time() * 1000)) - _compilation_duration
        print("Compilation finished after " + str(_compilation_duration) + " ms")
        logger.info("Compilation finished after " + str(_compilation_duration) + " ms")

    def add_controller_client(self, client):
        """ links the runtime module whith the REST client
            which will communicate with the controller
            REST server
        """
        self.nexus = client
        logger.debug("Airnet REST client started successfully")

    def add_fabric_flow_routing_entry(self, fabric, rule, input_switch, output_switch, via_list):
        """ fills @param fabric routing table with a tuple containing :
        (@param rule, @param input_switch, @param output_switch, @param via_list)
        """
        self.fabrics_flows_routing_table[fabric].append((rule, input_switch, output_switch, via_list))

    def add_new_policy(self, new_policy):
        """ used by dynamic function to install
            a new policy
        """
        # replace symbolic names by ipAddrs
        self.replace_by_ipAddrs(new_policy)

        # generate the new_policy classifier
        new_policy = new_policy.compile()

        # remove (identity, identity, set()) rule
        # this rule is always generated after compilation
        for idx in range(len(new_policy.rules)):
            if ((new_policy.rules[idx].match==identity) and
                (new_policy.rules[idx].label==identity) and
                (len(new_policy.rules[idx].actions)==0)):
                del new_policy.rules[idx]

        # create temporary classifiers
        tmp_classifiers = self.create_classifiers()

        # enforce each rule
        for rule in new_policy.rules:
            if self.is_ingress_rule(rule):
                self.enforce_ingressPolicies(rule, tmp_classifiers)
            elif self.is_egress_rule(rule):
                self.enforce_egressPolicies(rule, tmp_classifiers)
            elif self.is_drop_rule(rule):
                self.enforce_dropRule(rule, tmp_classifiers)

        # if new rules in tmp_classifiers already exist in physical_switches_classifiers,
        # replace the old ones with the new ones
        # otherwise add the new ones into physical_switches_classifiers
        # backup physical_switches_classifiers
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
            # empty fabric switches classifiers
            self.clear_fabric_switches(fabric, new_classifiers)
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabricPolicies(fabric, new_classifiers)

        new_classifiers = self.opt_physical_classifires(new_classifiers)
        # used by Ryu client
        self.new_classifiers = copy.deepcopy(new_classifiers)
        # get and install differences between old and new classifiers
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        self.install_diff_lists(diff_lists)
        # copy the resulting classifiers in physical_switches_classifiers
        self.physical_switches_classifiers = copy.deepcopy(new_classifiers)

    def all_hosts_discovered (self) :
        """ Checks if all hosts declared in the mapping module
            have been registered in the infrastructure module
        """
        # for each host in the mapping module
        for host_ip in self.mapping.hosts.keys():
            check = False
            # get each physical host in the infra module
            for phy_host in self.infra.hosts.values():
                # look for a match between the mapping host ip_addr
                # and the physical host ip_addr
                if host_ip in phy_host.ip_addrs :
                    check = True
                    break
                # check if the infra host is a part of a network
                # declared in mapping
                if IPv4Network(phy_host.ip_addrs[0]) in IPv4Network(host_ip) :
                    # add it to the mapping hosts
                    self.mapping.addHostMap(str(phy_host.hwAddr), phy_host.ip_addrs[0])
                    check = True
            # at least one host in mapping wasn't found in infra
            if not check :
                return False
        return True

    def apply_netFunction_fromPacket(self, dpid, bucket_match, packet_match, packet):
        """ apply the function declared in
            the @DynamicControl(data=packet...) decorator
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
            find = False

            # if the new policy does not apply on the packet
            if matching_rule.match == identity:
                for edge_rule in self.edge_policies.rules:
                    if edge_rule.match.covers(packet_match):
                        for act in edge_rule.actions:
                            if isinstance(act, modify):
                                act.apply(packet)
                        for act in edge_rule.actions:
                            if isinstance(act, forward):
                                output = self.get_phy_switch_output_port(switch, act.output)
                                self.nexus.send_PacketOut(switch, packet, output)
                                find = True
                                break
                    if find:
                        break
            else:
                # the new policy apply on the packet
                for act in matching_rule.actions:
                    if isinstance(act, modify):
                        act.apply(packet)

                fwd = self.get_dycRule_forward(matching_rule)
                if fwd:
                    output = self.get_phy_switch_output_port(switch, fwd.output)
                    self.nexus.send_PacketOut(switch, packet, output)

        dyc_rule = None

        for rule in self.nwFct_rules:
            if rule.match.map == bucket_match.map:
                dyc_rule = rule

        for act in dyc_rule.actions:
            if isinstance(act, modify):
                act.apply(packet)

        # function is a field of the named tuple dyc_rule (NwFctItem)
        result = dyc_rule.function.apply(packet)

        # don't u forget the identity bug
        if isinstance(result, Policy):
            self.add_new_policy(result)
            handle_using_new_policy(dpid, result, packet_match, packet)
        else:
            logger.debug("runtime -- net function result: new packet")
            fwd = self.get_dycRule_forward(dyc_rule)
            switch = 's' + str(dpid)
            output = self.get_phy_switch_output_port(switch, fwd.output)
            self.nexus.send_PacketOut(switch, result, output)

    def apply_netFunction_fromStat(self, bucket_match, stat):
        """ apply the function declared in
            the @DynamicControl(data=stat...) decorator
        """
        dyc_rule = None

        for rule in self.nwFct_rules:
            # find the appropriate rule
            if rule.match.map == bucket_match.map:
                dyc_rule = rule

        # apply the function in the dynamic rule
        result = dyc_rule.function.apply(stat)

        # fixed bug for "return identity" intruction in netFunction
        if isinstance(result, Policy) and result != identity:
            self.add_new_policy(result)

    def clear_fabric_switches(self, fabric, classifiers):
        """ empty fabric switches classifiers """
        fabric_switches = self.mapping.fabrics[fabric]
        for switch in fabric_switches:
            classifiers[switch] = []

    def create_classifiers(self):
        """ initialzes a classifier for each switch """
        sw_classifiers = {}

        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                sw_classifiers[edge[0]] = []
        return sw_classifiers

    def convert_to_physical_rules(self, policies, classifiers):
        """ convert each policy in @param policies
            into a physical rule which will be stored
            in @param classifiers
        """

        # enforce edge rules first
        for rule in policies.rules:
            # not used for now
            """
            if self.is_dataFunction_rule(rule):
                logger.debug("\n-- Data Function Rule : {}".format(str(rule)))
                self.enforce_dataFunction(rule, classifiers)
            """
            if self.is_dynamicFunction_rule(rule):
                logger.debug("\n\nDynamic Function Rule : {}".format(str(rule)))
                self.enforce_dynamicFunction(rule, classifiers)
            elif self.is_ingress_rule(rule):
                logger.debug("\n\nIngress Rule : {}".format(str(rule)))
                self.enforce_ingressPolicies(rule, classifiers)
            elif self.is_egress_rule(rule):
                logger.debug("\n\nEgress Rule : {}".format(str(rule)))
                self.enforce_egressPolicies(rule, classifiers)
            elif self.is_drop_rule(rule):
                logger.debug("\n\nDrop Rule : {}".format(str(rule)))
                self.enforce_dropRule(rule, classifiers)

        # enforce fabric rules then
        self.fabrics_flows_routing_table = {}

        for fabric in self.mapping.fabrics:
            # for each fabric a list: {match, input_switch, output_switch}
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabricPolicies(fabric, classifiers)

    def countOfMessages(self,of_messages):
        """ count the number of Openflow msgs
            received from a switch """
        cpt = 0
        for dpid, messages in of_messages.iteritems():
            cpt += len(messages)
        return cpt

    def enforce_dataFunction(self, rule, classifiers):
        """ not used for now """
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
                                       every=None, runtime=self))
        # add a rule that sends packets towards controller
        rule_actions = {forward("controller")}
        for act in actions:
            if not isinstance(act, forward):
                rule_actions.add(act)
        controller_rule = Rule(rule.match, rule.label, set(rule_actions))

        # test if the final rule is ingress or egress
        if is_ingress(actions, function):
            self.enforce_ingressPolicies(controller_rule, classifiers)
        else:
            self.enforce_egressPolicies(controller_rule, classifiers)

    def enforce_dataMachine_path(self, rule, classifiers, fabric, excludes_nodes):
        """
            not used for now
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
            return a tuple that contain the switch and the port to which dm is connected
            nq:parm: data machine name
            :return: (switch, port)
            """
            adjacents = set()
            # can't use graph get_adjacent method, because it is integrated to SPF algo, fix it
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

    def enforce_dropRule(self, rule, classifiers):
        """ fill @param classifiers with
            a new drop rule """

        match_switches_list = self.get_switchesList_onMatch(rule.match)
        for switch in match_switches_list:
            # Install on all corresponding switches
            physical_switch_rule = self.to_physical_switch_rule(rule, switch)
            classifiers[switch].append(physical_switch_rule)

    def enforce_dynamicFunction(self, rule, classifiers):
        """ converts a rule with a dynamic function action
            into a physical rule
            also creates a bucket associated to the rule
        """
        # get all non DynamicPolicy actions
        actions = [act for act in rule.actions if not isinstance(act, DynamicPolicy)]

        # get at least one DynamicPolicy actions
        function = [act for act in rule.actions if isinstance(act, DynamicPolicy)][0]
        exist = False

        # Use buckets instead of nwFct_rules because nwFct_rules can be updated.
        for bucket in self.buckets:
            if bucket.match.map == rule.match.map:
                exist = True
        # There is no bucket associated with this rule
        if not exist:
            # add it to the nwFct_rules list
            self.nwFct_rules.append(self.NwFctItem(rule.match, rule.label, function, actions))

            # create the correct type of bucket associated with this nwFct_rule
            if function.type == "packet":
                self.buckets.append(Bucket(_filter=rule.match, _type=function.type,
                                       limit=function.limit,
                                       split=function.split,
                                       every=None, runtime=self))
            elif function.type == "stat":
                self.buckets.append(Bucket(_filter=rule.match, _type=function.type,
                                       limit=function.limit,
                                       split=function.split,
                                       every=function.every, runtime=self))
            else:
                raise RuntimeError(str(rule.match) + " : dynamic function data type error")

        if function.type == "packet":
            # add a rule that sends this rule flow
            # packets to the controller
            rule_actions = {forward("controller")}
            # add all non-forward actions
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
                self.enforce_ingressPolicies(switch_rule, classifiers)
            elif self.is_egress_rule(switch_rule):
                self.enforce_egressPolicies(switch_rule, classifiers)
            else:
                raise RuntimeError(str(switch_rule.match) + " : stat rule is none ingress or egress")
        else:
            raise RuntimeError("dynamic function type error")

    def enforce_egressPolicies(self, rule, classifiers):
        """ fill @param classifiers with
            a new egress rule """

        def get_nwFct_host_dst(rule_match):
            """ returns a network function output """
            for nwFct_rule in self.nwFct_rules:
                if nwFct_rule.match.map == rule_match.map:
                    for act in nwFct_rule.actions:
                        if isinstance(act, forward):
                            return act.output
                    return self.get_netFunction_forward(nwFct_rule.function).output

        def get_destination_host(rule):
            """ returns a rule output """
            for action in rule.actions:
                if isinstance(action, forward):
                    if action.output != "controller":
                        return action.output
                    # here output is given by the network function
                    else:
                        return get_nwFct_host_dst(rule.match)

        def replace_fwd_destination (rule, new_destination) :
            """ replace in @param rule the forward action
                by @param new_destination """
            for action in rule.actions :
                if isinstance(action, forward):
                    action.output=new_destination

        # get the egress edge
        egress_edge = rule.match.map["edge"]
        # get the destination
        dst_host = get_destination_host(rule)

        # if dst_host is a network
        # we will need to send the traffic to the controller
        # so that it will determine the output port
        specific_rule = self.get_network_specific_rule(rule,dst_host)

        if specific_rule is not None:
            rule = specific_rule

        # get the physical switches that match to the egress edge
        egress_edge_switches = self.get_edge_physical_corresponding(egress_edge)
        host_adjacent_switches = [node[1] for node in self.topology_graph.vertices[dst_host] if node[1] in egress_edge_switches]

        logger.debug("Ouput switch(es) : {}".format(" ".join(host_adjacent_switches)))

        # Strong assumption : host_adjacent_switches will contain a unique phy_switch
        for switch in host_adjacent_switches:
            physical_switch_rule = self.to_physical_switch_rule(rule, switch)
            # install the rule in the switch classifier
            classifiers[switch].append(physical_switch_rule)

    def enforce_fabricPolicies(self, fabric, classifiers):
        """ constructs a routing table based on
            @param fabric rules """

        def get_edge_destination(actions):
            """ return carry's destination """
            for act in actions:
                if isinstance(act, carry):
                    return act.destination
            raise RuntimeError("No final destination found for this fabric rule")

        # Get all rules which concern the current fab
        fabric_rules = [rule for rule in self.fabric_policies.rules
                        if rule.flow.fabric == fabric]

        # for each current fab rule
        for fab_rule in fabric_rules:
            logger.debug("\n\nFabric Rule : {}".format(str(fab_rule)))
            # get the edge destination of the fab rule
            egress_edge_destination = get_edge_destination(fab_rule.actions)
            # get the physical switches which correspond to the edge destination
            flow_egress_switches = self.get_edge_physical_corresponding(egress_edge_destination)
            logger.debug("Egress switch(es) : {}".format(" ".join(flow_egress_switches)))

            # ingress switches are inside the fabric
            flow_ingress_match_switch_list = self.get_corresponding_match_switch_list(fab_rule.flow.fabric,
                                                                                      fab_rule.flow.src,
                                                                                      fab_rule.flow.flow, classifiers)

            # for each egress physical switches
            for egress_switch in flow_egress_switches:
                # for each egress rule of this egress physical switch
                for egress_rule in self.get_switch_phy_egress_rules(egress_switch, classifiers, fabric):
                    # for each couple [rule, src]
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
        # then enforce fabric rules
        self.enforce_fabric_physical_rules(fabric, classifiers)

    def enforce_fabric_physical_rules(self, fabric, classifiers):
        """ install rules on the physical paths inside
            the @param fabric routing table
        """
        def optimize_routing_table (fabric):
            """ Optimize fabric classifiers """

            # perform a copy of fabric routing table
            routing_table = copy.deepcopy(self.fabrics_flows_routing_table[fabric])
            out_table = []

            # entry[0] == intersec_match, entry[1] == input_switch, entry[2] == output_switch, entry[3]==via_list
            for entry in self.fabrics_flows_routing_table[fabric]:
                # each entry is compared to the other ones
                duplic = False
                for road in routing_table:
                    # if a another entry covers this current entry
                    if(road[0].covers(entry[0]) and not entry[0]==road[0]):
                        # verify that they have the same input and output switch
                        if(entry[1]==road[1] and entry[2]==road[2]):
                            # verify that they have the same via_list
                            if(entry[3]==road[3] and len(road[3]) > 0):
                                duplic = True
                                break
                # no other entry covers the current one
                if not duplic:
                    out_table.append(entry)


            self.fabrics_flows_routing_table[fabric] = copy.deepcopy(out_table)

        excludes_nodes = set()

        for fab in self.mapping.fabrics:
            if fab != fabric:
                # select all other fabrics switches
                excludes_nodes.update(self.mapping.fabrics[fab])
        # excludes switches that are not
        # in the current fabric
        excludes_nodes = excludes_nodes - self.mapping.fabrics[fabric]

        # optimize routing table before converting into physical rules
        optimize_routing_table(fabric)

        for rule in self.fabrics_flows_routing_table[fabric]:
            #rule[0] == intersec_match, rule[1] == input_switch, rule[2] == output_switch, rule[3]==via_list
            if rule[3] is None:
                # test if there is via actions
                path = self.topology_graph.SPF(rule[1], rule[2], excludes_nodes)
                output_port_path = self.get_output_port_path(path)
                #item: (switch, in_port, out_port)
                for item in output_port_path:
                    action = forward(item[1])
                    filtr = rule[0]
                    classifiers[item[0]].append(Rule(filtr, identity, set([action])))
            else:
                self.enforce_dataMachine_path(rule, classifiers, fabric, excludes_nodes)

    def enforce_ingressPolicies(self, rule, classifiers):
        """ fill @param classifiers with
            a new ingress rule """

        # get the list of switches that corresponds
        # to the rule match
        match_switches_list = self.get_switchesList_onMatch(rule.match)

        logger.debug("{} switch(es) found for this rule".format(len(match_switches_list)))
        for switch in match_switches_list:
            # Install on all corresponding switches
            physical_switch_rule = self.to_physical_switch_rule(rule, switch)
            classifiers[switch].append(physical_switch_rule)

    def enforce_policies(self):
        """ Enforce proactive core policies
            Done at the startup
        """
        logger.info("Proactive core policies enforcement started --")
        _enforcing_duration = int(round(time.time() * 1000))

        # get the global topology graph
        graph = self.infra.get_graph()
        logger.debug("Got global topology graph ")

        # replace hwAddrs in graph by symbolic names
        self.topology_graph = self.replace_hwAddrs_by_names(graph)

        # initialize classifiers
        self.physical_switches_classifiers = {}

        # edge means point or summit, not virtual edge.
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                self.physical_switches_classifiers[edge[0]] = []
        logger.debug("Initialized a per-switch classifier")

        # Convert policies to physical rules stored on classifiers
        logger.debug("Converting high-level policies to physical rules")
        self.convert_to_physical_rules(self.edge_policies, self.physical_switches_classifiers)
        logger.debug("Optimizing physical rules")
        self.physical_switches_classifiers = self.opt_physical_classifires(self.physical_switches_classifiers)

        # info printing
        logger.info("\n\n *** Physical rules to push on switches")
        for edge in self.topology_graph.edges :
            if edge[1] == "switch":
                logger.info("\n----- %s rules : (%d)\n%s" % (edge[0], len(self.physical_switches_classifiers[edge[0]]),"\n".join([str(j) for j in self.physical_switches_classifiers[edge[0]]])))

        self.nexus.push_ProactiveRules(self.physical_switches_classifiers)
        logger.info("\n# Proactive rules installed == " + str(self.countOfMessages(self.physical_switches_classifiers)))
        print("\n# Proactive rules installed == " + str(self.countOfMessages(self.physical_switches_classifiers)))

        _enforcing_duration = int(round(time.time() * 1000)) - _enforcing_duration
        print("Proactive core policies enforcement finished after " + str(_enforcing_duration) + " ms")
        logger.info("Proactive core policies enforcement finished after " + str(_enforcing_duration) + " ms")

    def flow_limit_reached(self, fct_predicate):
        """ install a new policy when the limit parameter
            in a network function is reached by a flow
        """
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
            self.enforce_ingressPolicies(nwFct_rule, tmp_classifiers)
            new_rule = True
        elif self.is_egress_rule(nwFct_rule):
            self.enforce_egressPolicies(nwFct_rule, tmp_classifiers)
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
                        # Unlike for micro-flows where we need to modify
                        # an existing rule and not to add new one
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

    def get_corresponding_match_switch_list(self, fabric, flow_src, label, classifiers):
        """ searches in @param fabric rules
            that correspond to @param label
            returns a list of tuples formed in this way: (match, switch)
        """

        def apply_modify_action(my_match, my_modify):
            for header, value in my_modify.map.iteritems():
                if header in my_match.map:
                    my_match.map[header] = value
            return my_match

        switch_match_list = []
        fabric_input_rules = self.get_fabric_input_rules(fabric, flow_src, classifiers)

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

    def get_corresponding_virtual_edge(self, physical_switch):
        """
        return the swicth's corresponding virtual edge
        :param physical_switch: physical switch name
        """
        for edge, mapping in self.mapping.edges.iteritems():
                if physical_switch in mapping:
                    return edge
        return None

    def get_diff_lists(self, old_classifiers, new_classifiers):
        """ Compares rules in @param old_classifiers and @param new_classifiers
            returns a list of DiffListItems
            diff_list = [DiffListItem[s1], DiffListItem[s2]...)
            with DiffListItem = a namedtuple
        """
        def find_same_rules(target, rule_list):
            rules = []
            # degressive priority
            for priority in range(len(rule_list)-1, -1, -1):
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

        diffListItem = namedtuple('DiffListItem', ['to_add', 'to_delete', 'to_modify', 'to_stay'])
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
                            to_modify.append((new, (old_rules[priority], priority)))

            for priority in range(len(new_classifiers[switch])-1, -1, -1):
                rules = find_same_rules(new_classifiers[switch][priority], old_rules)
                if rules is None:
                    to_add.append((new_classifiers[switch][priority], priority))

            diff_lists[switch] = diffListItem(to_add, to_delete, to_modify, to_stay)

        return diff_lists

    def get_dycRule_forward(self, rule):
        if len(rule.actions) != 0:
            for act in rule.actions:
                if isinstance(act, forward):
                    return act
            if isinstance(rule.function, DynamicPolicy):
                return self.get_netFunction_forward(rule.function)
        else:
            return None

    def get_edge_physical_corresponding(self, edge, port=None):
        """ returns a list of tuples (phy_switch, port)
            that corresponds to @param edge
        """

        phy_switches = []
        end_host = None
        if port is not None:
            # strong assumption : we have a one to one port mapping
            for link in self.virtual_topology._links:
                if link.unitA[0] == edge and link.unitA[1] == port:
                    end_host = link.unitB[0]
                elif link.unitB[0] == edge and link.unitA[1] == port:
                    end_host = link.unitA[0]
            # end host are connected by a unique link with a unique switch
            for phy_switch in self.topology_graph.vertices[end_host]:
                phy_switches.append(phy_switch)
        else:
            for edge_key, edge_mapping in self.mapping.edges.iteritems():
                if edge_key == edge:
                        phy_switches = edge_mapping
        return phy_switches

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
                rule_forward = self.get_netFunction_forward(rule.function)
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

    def get_fabric_output_edges(self, fabric):
        """
        return the set of edges that 'fabric' will send to them flows
        :param fabric: fabric that will carry flows to edges
        """
        fabric_rules = [rule for rule in self.fabric_policies.rules if rule.flow.fabric == fabric]
        output_edges = [rule.action.destination for rule in fabric_rules]
        return output_edges

    def get_network_specific_rule (self,rule,dst):
        """ add is forward action to the
            controller if @param dst is a network
        """
        def replace_fwd_destination (rule) :
            """ replace in @param rule the forward action
            """
            ctrller_fwd_action = False
            for action in rule.actions :
                if isinstance(action, forward) :
                    if action.output == "controller":
                        ctrller_fwd_action = True
                        break
            if not ctrller_fwd_action :
                rule_actions = {forward("controller")}
                for act in rule.actions:
                    if not isinstance(act, forward):
                        rule_actions.add(act)
                rule.actions=rule_actions
            return rule

        specific_rule = None
        # if the dst is a network
        # we may have to add controller rule
        for phy_host in self.infra.hosts.values() :
            # if one host in infra is in the network destination
            if rule.match.map.has_key("nw_dst") :
                if IPv4Network(phy_host.ip_addrs[0]) in IPv4Network(rule.match.map["nw_dst"]) \
                    and IPv4Network(phy_host.ip_addrs[0]) != IPv4Network(rule.match.map["nw_dst"]):
                    # replace the forward action
                    specific_rule = replace_fwd_destination(rule)

        return specific_rule

    def get_switch_phy_egress_rules(self, egress_switch, classifiers, fabric):
        """
            return switch's egress rules list
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
                    return self.get_netFunction_forward(nwFct_rule.function).output

        egress_rules = []
        hosts = [host.name for host in self.virtual_topology._hosts]

        #FOR edge_GW (edge between two fabrics)
        fabrics_switches = set()
        for fab in self.mapping.fabrics:
            if fab != fabric:
                fabrics_switches.update(self.mapping.fabrics[fab])

        for rule in classifiers[egress_switch]:
            destination=None
            for act in rule.actions:
                if isinstance(act, forward):
                    if act.output != 'OFPP_CONTROLLER':
                        destination = self.topology_graph.get_dst(egress_switch, act.output)
                    else:
                        destination = get_nwFct_host_dst(egress_switch, rule.match)
                    if (destination in hosts) or (destination in fabrics_switches):
                        egress_rules.append(rule)
                    elif destination == "DYNAMICPOLICY" or act.output == 'OFPP_CONTROLLER':
                        egress_rules.append(rule)
        return egress_rules

    def get_switchesList_onMatch(self, rule_match):
        """ returns a list of tuples (phy_switch, port)
            that corresponds to @param rule_match
        """
        for header in rule_match.map:
            if header == "port":
                return self.get_edge_physical_corresponding(rule_match.map["edge"], rule_match.map["port"])
            else:
                return self.get_edge_physical_corresponding(rule_match.map["edge"])

    def get_netFunction_forward(self, fct):
        """ returns a netFunction rule destination """
        if not isinstance(fct, DynamicPolicy):
            for act in fct.sequential_actions:
                if isinstance(act, forward):
                    return act
                elif isinstance(act, DataFctPolicy):
                    self.get_netFunction_forward(act)
            for function in fct.parallel_functions:
                self.get_netFunction_forward(function)

    def get_phy_switch_output_port(self, switch, dst_output):
        """ return @param switch output_port in global topology
            that allows to go to @param dst_output
        """
        #TODO: dst_output is an edge
        # dst_output is a fabric (ingress edge)

        if dst_output in self.mapping.fabrics:
            for fab_key, fab_mapping in self.mapping.fabrics.iteritems():
                if fab_key == dst_output:
                    destination_switches_set = fab_mapping
                    logger.debug("Destination : {}".format(str(dst_output)))

            for adjacent_node in self.topology_graph.vertices[switch]:
                if adjacent_node[1] in destination_switches_set:
                    #return the first node found, all costs are 1 (i.e., take the first path)
                    #TODO: link cost or load balancing
                    return adjacent_node[2]

        # dst_output is a host (egress edge)
        elif dst_output in self.mapping.hosts.values():
            logger.debug("Destination : {}".format(str(dst_output)))
            for adjacent_node in self.topology_graph.vertices[switch]:
                if adjacent_node[1] == dst_output:
                    return adjacent_node[2]

        # dst_output is the controller
        elif dst_output == "controller":
            logger.debug("Destination : Controller")
            return "OFPP_CONTROLLER"
        else:
            raise AssertionError("no corresponding physical output port ")

    def handle_flow_stats(self, stat):
        """
            Transfers statistics received to the appropriate bucket
            and applies the function which is in the @DynamicControlFct decorator
        """
        issuing_match = stat._issuing_match
        for bucket in self.buckets:
            # stats requests are called by the @Dynamic... decorator
            # each bucket is tied to one network function rule
            # from there the appropriate bucket has the same match fields
            # as the stat object
            if bucket.match == issuing_match:
                # transfer stats to the bucket
                bucket.update_stats(stat)
                # apply the netFunction content which is in the decorator
                self.apply_netFunction_fromStat(bucket.match, stat)

    def handle_packet_in(self, dpid, packet_match, packet):
        logger.debug("Handling a Packet/in")
        for bucket in self.buckets:
            if bucket.match.covers(packet_match):
                logger.debug("Found a bucket for this packet!")
                bucket.add_packet(dpid, packet_match, packet)

    def install_diff_lists(self, diff_lists):
        """ Install/Delete/Modify rules in diff_lists """
        to_add = {}
        to_delete = {}
        to_modify = {}

        for switch, diff_list in diff_lists.iteritems():
            to_add[switch] = diff_list.to_add
            to_delete[switch] = diff_list.to_delete
            to_modify[switch] = diff_list.to_modify

        _enforce_diffList_duration = int(round(time.time() * 1000))
        logger.info("\nDifferentiated rules list enforcement started --")

        self.nexus.push_ModifiedRules(to_modify)
        logger.info("Rules modified == " + str(self.countOfMessages(to_modify)))

        self.nexus.push_NewRules(to_add)
        logger.info("Rules installed == " + str(self.countOfMessages(to_add)))

        self.nexus.push_DeletedRules(to_delete)
        logger.info("Rules deleted == " + str(self.countOfMessages(to_delete)))

        _enforce_diffList_duration = int(round(time.time() * 1000)) - _enforce_diffList_duration
        logger.info("Differentiated rules list enforcement finished -- Duration == "+str(_enforce_diffList_duration)+" ms\n")

    def is_dataFunction_rule(self, rule):
        for act in rule.actions:
            if isinstance(act, DataFctPolicy):
                return True
        return False

    def is_drop_rule(self, rule):
        if rule.match != identity:
            if len(rule.actions) == 0:
                return True
        return False

    def is_dynamicFunction_rule(self, rule):
        for act in rule.actions:
            if isinstance(act, DynamicPolicy):
                return True
        return False

    def is_ingress_rule(self, rule):
        for action in rule.actions:
            if isinstance(action, forward):
                # if the output is in the fabric components
                if action.output in self.mapping.fabrics.keys():
                    return True
        return False

    def is_egress_rule(self, rule):
        for action in rule.actions:
            if isinstance(action, forward):
                # if the output is in the hosts components
                if action.output in self.mapping.hosts.values():
                    return True
        return False

    def micro_flow_limit_reached(self, micro_flow):
        """
            Function called when the limit parameter is ""
            for the micro_flow in argument
        """
        target_rule = None

        for rule in self.edge_policies.rules:
            if (rule.match != identity and rule.match.covers(micro_flow)):
                target_rule = copy.deepcopy(rule)

        classifiers = self.create_classifiers()
        target_rule.match = micro_flow

        if self.is_dynamicFunction_rule(target_rule) or self.is_dataFunction_rule(target_rule):
            # remove network function actions in target rule
            self.remove_nwFct_action(target_rule)

            new_rule = False
            if self.is_ingress_rule(target_rule):
                self.enforce_ingressPolicies(target_rule, classifiers)
                new_rule = True
            elif self.is_egress_rule(target_rule):
                self.enforce_egressPolicies(target_rule, classifiers)
                new_rule = True

            if new_rule:
                self.nexus.push_NewRules_onTop(classifiers)

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

    def opt_physical_classifires(self, classifiers):
        """ optimizes rules stored in @param classifiers
        """
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

        return opt_c

    def remove_nwFct_action(self, rule):
        """
            function called when the limit parameter in dynamic control functions is reached
            remove the dynamic function from the rule list of actions
        """
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

    def replace_by_ipAddrs(self, policy):
        if isinstance(policy, CompositionPolicy):
            for pol in policy.policies:
                self.replace_by_ipAddrs(pol)
        elif isinstance(policy, match):
            if "src" in policy.map:
                policy.map["nw_src"] = self.mapping.resolve_host(policy.map["src"])
                policy.map.pop("src")
            if "dst" in policy.map:
                policy.map["nw_dst"] = self.mapping.resolve_host(policy.map["dst"])
                policy.map.pop("dst")

    def replace_hwAddrs_by_names(self, graph):
        """
        this function replaces hwAddrs in graph with symbolic names (e.g., h1)
        :param graph: graph class returned by infrastructure module
        """
        new_hosts = {}
        # cross all graph summits
        for edge in graph.edges:
            # if the summit is an endPoint
            if edge[1] == "host":
                # get its ip address
                edge_ipAddr = self.infra.rarp(edge[0])
                # cross all endPoints in the mapping modules
                for host_ipAddr, host_name in self.mapping.hosts.iteritems():
                    # it's the same endPoint (host or network)
                    if (edge_ipAddr == host_ipAddr or IPv4Network(edge_ipAddr) in IPv4Network(host_ipAddr)):
                        # vertices update
                        """
                        create a copy of graph.vertices because i need to update it
                        but at the same time i'm iterating over him
                        we do not perform a deepcopy to be able to update edge_list_adjacent
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

    def send_stat_request(self, target_match):
        """ used by buckets (network functions rules containers)
            as callback methods to send stats requests
        """
        # get physical switches which will send stats
        edge_switches = self.get_edge_physical_corresponding(target_match.map["edge"])
        # send stat requests through the Airnet Client
        stat =  self.nexus.send_StatsRequest(edge_switches, target_match)
        # collect stats received from RYU
        self.handle_flow_stats(stat)

    def to_physical_switch_rule(self, rule, switch):
        """ replaces forward logical destination (e.g: H1)
            with a phy_port (like in OF)
            pops the edge field from the rule since it's no more needed
        """
        # perform a deep copy so that
        # @param rule value remains unchanged
        physical_rule = copy.deepcopy(rule)
        drop_rule = False

        for policy in physical_rule.actions:
            if isinstance(policy, forward):
                policy.output = self.get_phy_switch_output_port(switch, policy.output)
            if policy == drop:
                drop_rule = True
        if drop_rule:
            physical_rule.actions = set()

        physical_rule.match.map.pop("edge")
        logger.debug("\n   --> Physical rule stored : {}".format(str(physical_rule)))
        return physical_rule




    """
    def get_host_nwAddr(self, id):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_name == id:
                return host_ipAddr

    def get_host_dlAddr(self, id):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_name == id:
                return self.infra.arp(host_ipAddr)

    def nwAddr_to_host(self, nwAddr):
        for host_ipAddr, host_name in self.mapping.hosts.iteritems():
            if host_ipAddr == nwAddr:
                return host_name

    def dlAddr_to_host(self, nwAdd):
        #TODO
        pass


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

    def get_fabric_output_phy_switches(self, fabric):
        """ """
        return physical_switches (corresponding to fabric's output edges) that will receive flows from the fabric
        these physical switches are NOT INSIDE the fabric
        :param fabric: fabric that will carry flows to these physical switches
        """ """
        output_edges = self.get_fabric_output_edges(fabric)
        output_switches = set()
        for edge in output_edges:
            for switch in self.get_edge_physical_corresponding(edge):
                output_switches.add(switch)
        return output_switches
    """

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



#TODO


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
        self.topology_graph = self.replace_hwAddrs_by_names(graph)
        switches = []
        for edge in self.topology_graph.edges:
            # verify that the edge is a switch, not a host
            if edge[1] == "switch":
                switches.append(edge[0])
        self.nexus.install_ARP_rules(switches)
    """


    def handle_topology_change(self):
        """
            Modify the topology graph according to events received from RYU
        """
        graph = self.infra.get_graph()
        self.topology_graph = self.replace_hwAddrs_by_names(graph)
        new_classifiers = self.create_classifiers()

        for edge in self.mapping.edges:
            for switch in self.get_edge_physical_corresponding(edge):
                new_classifiers[switch] = copy.deepcopy(self.physical_switches_classifiers[switch])

        self.fabrics_flows_routing_table = {}

        for fabric in self.mapping.fabrics:
            #for each fabric a list: {match, input_switch, output_switch}
            self.fabrics_flows_routing_table[fabric] = []
            self.enforce_fabricPolicies(fabric, new_classifiers)
            # To keep priority order between rules
            #for fabric, routing_list in self.fabrics_flows_routing_table.iteritems():
                #routing_list.reverse()

        new_classifiers = self.opt_physical_classifires(new_classifiers)
        self.new_classifiers = copy.deepcopy(new_classifiers)
        diff_lists = self.get_diff_lists(self.physical_switches_classifiers, new_classifiers)
        self.install_diff_lists(diff_lists)
        self.physical_switches_classifiers = copy.deepcopy(new_classifiers)











    def stop_timers(self):
        """
        """
        for bucket in self.buckets:
            if bucket.type == "stat":
                bucket.timer.stop()
