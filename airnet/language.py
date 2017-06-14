# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

from lib.ipaddr import IPv4Network
from lib.addresses import IPAddr
from classifier import *

#TODO : comment dataFct in dynamic policies
#TODO : udp on modify.apply()
#TODO : should we keep across ?
#TODO : is dataFct still useful ?

##################################################
#           VIRTUAL TOPOLOGY ELEMENTS            #
##################################################

class Edge(object):
    """ represents an edge """
    def __init__(self, name, ports):
        self.name = name
        self.ports = ports

    def __eq__(self, other):
        return self.name == other.name

class Fabric(object):
    """ reprensents a  fabric class"""
    def __init__(self, name, ports):
        self.name = name
        self.ports = ports

    def __eq__(self, other):
        return self.name == other.name

class DataMachine(object):
    """ reprensents a dataMachine """
    def __init__(self, name, ports):
        self._name = name
        if ports > 0:
            self._ports = ports
        else:
            raise TypeError("ports value must be greater than zero")

    @property
    def name(self, value):
        return self._name

    @property
    def ports(self, value):
        return self._ports

class Host(object):
    """ reprensents a host object """
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

class VLink(object):
    """ represents a ling """
    def __init__(self, VirtualUnitA, VirtualUnitB):
        # unit is a tuple --> (device, port)
        self.unitA = VirtualUnitA
        self.unitB = VirtualUnitB

class Network(object):
    pass

class VTopology(object):
    """ represents a virtual topology """
    def __init__(self):
        self._edges = []
        self._fabrics = []
        self._links = []
        self._hosts = []
        self._networks = []
        self._data_machines = []

    def addEdge(self, name, ports):
        self._edges.append(Edge(name, ports))

    def addFabric(self, name, ports):
        self._fabrics.append(Fabric(name, ports))

    def addDataMachine(self, name, ports):
        self._data_machines.append(DataMachine(name, ports))

    def addHost(self, name):
        self._hosts.append(Host(name))

    def addNetwork(self, name):
        self._hosts.append(Host(name))

    def addLink(self, VirtualUnitA, VirtualUnitB):
        self._links.append(VLink(VirtualUnitA, VirtualUnitB))

    def getFabricAdjacentEdges(self, fabric):
        """ returns edges connected to fabric """
        def is_edge(name):
            for edge in self._edges:
                if edge.name == name:
                    return True
            return False

        edges = []
        for link in self._links:
            if link.unitA[0] == fabric:
                if is_edge(link.unitB[0]):
                    edges.append(link.unitB[0])
            if link.unitB[0] == fabric:
                if is_edge(link.unitA[0]):
                    edges.append(link.unitA[0].name)
        return edges

##################################################
#                  POLICIES                      #
##################################################

class Policy(object):
    """ Top level abstract class for
        all policies (edge and fabric) """
    def __init__(self):
        self._classifier = None

    def compile(self):
        """ compile a policy call the policy
            generateClassifier method """
        self._classifier = self.generateClassifier()
        return self._classifier

    def name(self):
        return self.__class__.__name__

*********** singleton policies **********************

def singleton(f):
    return f()

                ----------

@singleton
class identity(Policy):
    """ neutral policy which performed no changes
        equivalent to NULL in other languages
    """
    def __init__(self):
        self.map = {}

    def intersec(self, other):
        """ intersection between identity and another policy
            always returns the other policy """
        return other

    def covers(self, other):
        """ intersection always covers other policy """
        return True

    def __eq__(self, other):
        return ( id(self) == id(other)
            or ( isinstance(other, match) and len(other.map) == 0) )

    def __repr__(self):
        return "identity"

@singleton
class drop(Policy):
    """ drop is an absorbing policy
        it generates a rule with an empty set of actions
    """
    def generateClassifier(self):
        return Classifier([Rule(identity, identity, set())])

    def intersec(self, other):
        """ intersection between drop an another policy
            always returns drop """
        return self

    def __repr__(self):
        return "drop"

    def __str__(self):
        return "drop"

************* edge policies ***********************

class EdgePolicy(Policy):
    """ abstract superclass for edge policies
        and composition between those policies
    """
    def __add__(self, policy):
        if isinstance(policy, ParallelComposition):
            return ParallelComposition([self] + policy.policies)
        else:
            return ParallelComposition([self, policy])

    def __rshift__(self, policy):
        if isinstance(policy, SequentialComposition):
            return SequentialComposition([self] + policy.policies)
        else:
            return SequentialComposition([self, policy])

class match(EdgePolicy):
    """ match on specified fields """
    def __init__(self, **kwargs):
        """
            @param **kwargs : list of couples field:value
            - self.map stores match fields and values
        """
        self.map = dict(**kwargs)

    def generateClassifier(self):
        """ generates a rule for packets
            thats corresponds to the match
            and a default drop rule for packets
            that do not corresponds """
        r1 = Rule(self, identity, {identity})
        r2 = Rule(identity, identity, set())
        return Classifier([r1, r2])

    def intersec(self, policy):
        """ return a new match which is the result
            of the intersection between the current match
            and another policy
        """

        def _intersect_ip(ipfx, opfx):
            """ returns the most specific address
                between two IP addresses """
            most_specific = None

            if (IPv4Network(ipfx) in IPv4Network(opfx)):
                most_specific = ipfx
            elif (IPv4Network(opfx) in IPv4Network(ipfx)):
                most_specific = opfx
            return most_specific


        if policy == identity:
            return self
        elif policy == drop:
            return drop
        elif not isinstance(policy, match):
            raise TypeError

        self_keys = set(self.map.keys())
        other_keys = set(policy.map.keys())

        # intersection between fields
        shared = self_keys & other_keys # set intersection

        most_specific_src = None
        most_specific_dst = None

        for field in shared:
            if (field == 'nw_src'):
                # choose the most specific src address
                most_specific_src = _intersect_ip(self.map[field], policy.map[field])
                # none most specific src -> different flows
                if most_specific_src is None:
                    return drop

            elif (field == 'nw_dst'):
                most_specific_dst = _intersect_ip(self.map[field], policy.map[field])
                if most_specific_dst is None:
                    return drop

            elif (self.map[field] != policy.map[field]):
                # if fields are different, there is no intersection
                return drop

        if 'nw_src' in self_keys:
            if 'nw_dst' in other_keys:
                if self.map['nw_src'] == policy.map['nw_dst']:
                    return drop
        elif 'nw_dst' in self_keys:
            if 'nw_src' in other_keys:
                if self.map['nw_dst'] == policy.map['nw_src']:
                    return drop

        # if there is no shared field, then merge
        d = dict(self.map.items() + policy.map.items())

        if most_specific_src is not None:
            d.update({'nw_src' : most_specific_src})
        if most_specific_dst is not None:
            d.update({'nw_dst' : most_specific_dst})

        return match(**d)

    def covers(self, other):
        """ returns True if another policy is
            fully included in the current match """

        # match do not covers identity
        if other == identity and len(self.map.keys()) > 0:
            return False
        # here match is empty (identity)
        elif other == identity:
            return True
        # match covers drop
        elif other == drop:
            return True

        if set(self.map.keys()) - set(other.map.keys()) :
            # We get there -> resulting set is not empty
            # the resulting set has elements of the self fields
            # with all fields from other removed
            return False

        for (f, v) in self.map.items():
            if(f=='nw_src' or f=='nw_dst'):
                if(IPv4Network(v) != IPv4Network(other.map[f])):
                    if(not IPv4Network(other.map[f]) in IPv4Network(v)):
                        return False
            elif v != other.map[f]:
                return False
        return True

    def __hash__(self):
        """ allows to use match object as dictionary key
        """
        return hash(repr(self.map))

    def __eq__(self, other):
        return ((isinstance(other, match) and self.map == other.map)
                 or (len(self.map) == 0 and other == identity) )

    def __repr__(self):
        return "match " + str(self.map)

class forward(EdgePolicy):
    """ forward a flow to one port
        of the current edge """

    def __init__(self, output):
        """ @param output : port number """
        self.output = output

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, {self})])

    def __eq__(self, other):
        return (isinstance(other, forward)) and (self.output == other.output)

    def __repr__(self):
        return "forward to " + str(self.output)

    def __str__(self):
        return "forward ('{}'')".format(self.output)

class modify(EdgePolicy):
    """ modify fields values on a specific flow """

    def __init__(self, **kwargs):
        self.map = dict(**kwargs)

    def apply(self, packet):
        """ apply modification(s) on packet headers """

        protos = packet.get('packet')

        if "dl_src" in self.map:
            protos['eth_src'] = self.map["dl_src"]
        if "dl_dst" in self.map:
            protos['eth_dst'] = self.map["dl_dst"]
        if 'ipv4' in protos:
            ip = protos.get('ipv4')
            if "nw_src" in self.map:
                ip['src'] = self.map["nw_src"]
            if "nw_dst" in self.map:
                ip['dst'] = self.map["nw_dst"]
        if 'tcp' in protos:
            tcp = protos.get('tcp')
            if 'src_port' in self.map:
                tcp['src_port'] = self.map["tp_src"]
            if 'dst_port' in self.map:
                tcp['dst_port'] = self.map["tp_dst"]

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, {self})])

    def __eq__(self, other):
        return (isinstance(other, modify)) and (self.map == other.map)

    def __repr__(self):
        return "modify such as " + str(self.map)

class tag(EdgePolicy):
    """ assigns a label to a matched flow """

    def __init__(self, label):
        self.label = label

    def generateClassifier(self):
        return Classifier([Rule(identity, self, {identity})])

    def __eq__(self, other):
        return (isinstance(other, tag)) and (self.label == other.label)

    def __repr__(self):
        return "flow == " + self.label

class across(EdgePolicy):
    """
    transists a flow by a data machine, where a data function will be applied on him
    :param dataMachine: data machine on which dataFct is executed
    :param dataFct: function to apply on data flow
    """
    def __init__(self, dataMachine, dataFct):
        self.dataMachine = dataMachine
        self.dataFct = dataFct

    def generateClassifier(self):
        # different from others !
        return Classifier([Rule(identity, identity, {self})])

    def __eq__(self, other):
        return ((isinstance(other, across)) and
                (self.dataMachine == other.dataMachine) and
                (self.dataFct == other.dataFct))

    def __repr__(self):
        return ("across by: " + self.dataMachine + " | " + self.dataFct)


************ fabric policies **********************

class FabricPolicy(Policy):
    """
    abstract class for all fabric policies
    """
    def __add__(self, policy):
        if isinstance(policy, FabricParallelComposition):
            return FabricParallelComposition([self] + policy.policies)
        else:
            return FabricParallelComposition([self, policy])


    def __rshift__(self, policy):
        if isinstance(policy, FabricSequentialComposition):
            return FabricSequentialComposition([self] + policy.policies)
        else:
            return FabricSequentialComposition([self, policy])

class catch(FabricPolicy):
    """ match tagged flows in a fabric based
        on a label and the edge which inserted
        the label """

    def __init__(self, src, fabric, flow):
        self.flow = flow
        self.fabric = fabric
        self.src= src

    def generateClassifier(self):
        return FabricClassifier([FabricRule(self, {identity}, list())])

    def __repr__(self):
        return "fabric = '{}' ,src = '{}' flow = '{}'".format(self.fabric,self.src,self.flow)

class carry(FabricPolicy):
    """ carry a tagged flow to one port
        of the current fabric """

    def __init__(self, dst, **constraints):
        self.destination = dst
        if constraints is not None:
            self.constraints = dict(**constraints)
        else:
            self.constraints = None

    def __repr__(self):
        return "carry ({},{})".format(self.destination,str(self.constraints))

    def generateClassifier(self):
        return FabricClassifier([FabricRule(identity, {self}, list())])

class via(FabricPolicy):
    """ redirects a tagged flow towards a dataMachine
        dataMachine should then apply a data_function
        on the flow """

    def __init__(self, data_machine, data_fct):
        self._data_machine = data_machine
        self._data_fct = data_fct

    @property
    def data_machine(self):
        return self._data_machine

    @property
    def data_fct(self):
        return self._data_fct

    def generateClassifier(self):
        return FabricClassifier([FabricRule(identity, {identity}, [self])])

    def __eq__(self, other):
        return (isinstance(other, via) and
                self.data_machine == other.data_machine and
                self.data_fct == other.data_fct)

    def __repr__(self):
        return ("via dataMachine " + self.data_machine +
                 " and dataFct " + self.data_fct)


************ dynamic policies *********************

"""
def DataFct(**decorator_kwargs):
    def data_fct_decorator(fct ):
        def fct_warper(**fct_kwargs):
            return DataFctPolicy(fct, fct_kwargs, decorator_kwargs)
        return fct_warper
    return data_fct_decorator
"""
def DynamicControlFct(**decorator_kwargs):
    def dynamic_fct_decorator(fct):
        def fct_warper(**fct_kwargs):
            return DynamicPolicy(fct, fct_kwargs, decorator_kwargs)
        return fct_warper
    return dynamic_fct_decorator

                ----------

class NetworkFunction(EdgePolicy):
    """ base class for network functions """
    def __init__(self,  callback, callback_kwargs, decorator_kwargs):
        """
            @param callback         : function which will be executed
            @param callback_kwargs  : function arguments
            @param decorator_kwargs : decorator arguments
        """
        self.callback = callback
        self.callback_kwargs = callback_kwargs

        try:
            self._type = decorator_kwargs["data"]
        except KeyError:
            self._type = None
        try:
            self._limit = decorator_kwargs["limit"]
        except KeyError:
            self._limit = None
        try:
            self._split = decorator_kwargs["split"]
        except KeyError:
            self._split = None
        try:
            self._every = decorator_kwargs["every"]
        except KeyError:
            self._every = None

    @property
    def type(self):
        return self._type

    @property
    def limit(self):
        return self._limit

    @property
    def split(self):
        return self._split

    @property
    def every(self):
        return self._every

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, {self})])

class DataFctPolicy(NetworkFunction):

    def __init__(self,  callback, callback_kwargs, decorator_kwargs):
        super(DataFctPolicy, self).__init__(callback, callback_kwargs, decorator_kwargs)
        self.sequential_actions = set()
        self.parallel_functions = set()


    def add_seq_actions(self, actions):
        added = False
        for act in self.sequential_actions:
            if isinstance(act, DataFctPolicy):
                added = True
                act.add_seq_actions(actions)
        if not added:
            sequential_actions = {act for act in actions if act!=identity}
            self.sequential_actions.update(sequential_actions)

    def add_parallel_fct(self, fct):
        self.parallel_functions.add(fct)

    def apply(self, packet):
        pkt = self.callback(packet, **self.callback_kwargs)
        try:
            assert pkt is not None
        except AssertionError:
            raise Exception("Data Function returns no packet!")
        for act in self.sequential_actions:
            if isinstance(act, modify):
                act.apply(pkt)
        for fct in self.parallel_functions:
            fct.apply(pkt)
        return pkt

    def __eq__(self, other):
        return (isinstance(other, DataFctPolicy))

class DynamicPolicy(NetworkFunction):
    """ class for dynamic control policies
        on packets or statistics
    """

    def __eq__(self, other):
        return (isinstance(other, DynamicPolicy))

    def apply(self, packet):
        """ apply a dynamic control function """
        print("... Applying {}()... ".format(self.callback.__name__))
        return self.callback(packet, **self.callback_kwargs)

    def __repr__(self):
        return "{}()".format(self.callback.__name__)


##################################################
#                 COMPOSITION                    #
##################################################


class CompositionPolicy(EdgePolicy):
    """
    Abstract class for edge policies composition
    :param policies: the policies ( a list) to be combined
    """
    def __init__(self, policies):
        self.policies = list(policies)

class FabricCompositionPolicy(FabricPolicy):
    """
    Abstract class for fabric policies composition
    :param policies: the policies ( a list) to be combined
    """
    def __init__(self, policies):
        self.policies = list(policies)


################# Edge policies composition ##################

class ParallelComposition(CompositionPolicy):
    """
    Combinator for several edge policies in parallel.

    :param policies: the policies to be combined.
    """

    def __init__(self, policies):
        super(ParallelComposition, self).__init__(policies)

    def generateClassifier(self):
        # call compile method for each basic policy in self.policies
        # and return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # parallel composition of all classifiers
        return reduce(lambda acc, c: acc + c, classifiers)

class SequentialComposition(CompositionPolicy):
    """
    Combinator for several edge policies in sequence.

    :param policies: the policies to be combined.
    """

    def __init__(self, policies):
        CompositionPolicy.__init__(self, policies)

    def generateClassifier(self):
        # call compile() method for each CompositionPolicy and basic policy in self.policies
        # return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # sequential composition of all classifiers
        return reduce(lambda acc, c: acc >> c, classifiers)

################# Fabric policies composition ##################

class FabricParallelComposition(FabricCompositionPolicy):
    """
    Combinator for several fabric policies in parallel.

    :param policies: the policies to be combined.
    """

    def __init__(self, policies):
        super(FabricParallelComposition, self).__init__(policies)

    def generateClassifier(self):
        # call compile method for each basic policy in self.policies
        # and return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # parallel composition of all classifiers
        return reduce(lambda acc, c: acc + c, classifiers)

class FabricSequentialComposition(FabricCompositionPolicy):
    """
    Combinator for several fabric policies in sequence.

    :param policies: the policies to be combined.
    """
    def __init__(self, policies):
        FabricCompositionPolicy.__init__(self, policies)

    def generateClassifier(self):
        # call compile method for each basic policy in self.policies
        # and return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # parallel composition of all classifiers
        return reduce(lambda acc, c: acc >> c, classifiers)
