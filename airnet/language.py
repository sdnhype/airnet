from tools import *
from lib.ipaddr import IPv4Network
# TODO replace POX's IPAddr class by another one... ?
# from pox.lib.addresses import IPAddr
from lib.addresses import IPAddr
from classifier import Classifier, Rule, FabricRule, FabricClassifier
import pdb

#import traceback, sys
#traceback.print_exception(*sys.exc_info())

##################################################
#            virtual topology                    #
##################################################
class Edge(object):
    """ Edge class"""
    def __init__(self, name, ports):
        self.name = name
        self.ports = ports

    def __eq__(self, other):
        return self.name == other.name

class Fabric(object):
    """ Fabric class"""
    def __init__(self, name, ports):
        self.name = name
        self.ports = ports

    def __eq__(self, other):
        return self.name == other.name


class DataMachine(object):
    """ Data Machine class """

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
    """ Host class """
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

class VLink(object):
    """ virtual link class"""
    def __init__(self, VirtualUnitA, VirtualUnitB):
        # unit is a tuple --> (device, port)
        self.unitA = VirtualUnitA
        self.unitB = VirtualUnitB

#TODO:
"""
class Host(object):
    pass

class Network(object):
    pass
"""

class VTopology(object):
    """ virtual topology class"""
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

        def is_edge(id):
            for edge in self._edges:
                if edge.name == id:
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
#            control policies                    #
##################################################

class Policy(object):
    """
    Top-level abstract class for all policies (edge and fabric)
    """
    def __init__(self):
        self._classifier = None

    def compile(self):
        self._classifier = self.generateClassifier()
        return self._classifier

    def name(self):
        return self.__class__.__name__

################ Singleton policies ####################
@singleton
class identity(Policy):
    """
    The identity policy (or neutral policy), leave all packets unchanged
    """
    def __init__(self):
        self.map = {}

    def intersec(self, other):
        return other

    def covers(self, other):
        return True
    # pas de generate classifier car y a pas d'instruction identity

    def __eq__(self, other):
        return ( id(self) == id(other)
            or ( isinstance(other, match) and len(other.map) == 0) )

    def __repr__(self):
        return "identity"

@singleton
class drop(Policy):
    """
    the drop policy (or absorbing element), produce the empty set of packets
    """

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, set())])

    def intersec(self, other):
        return self

    def __repr__(self):
        return "drop"

################ Edge policies ####################



class EdgePolicy(Policy):
    """
    abstract class for all edge policies
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
    """
    the match policy, Match on all specified fields.

    :param **kwargs: field matches in keyword-argument format
    """
    def __init__(self, **kwargs):
        """
        self.map is a dictionary that stores match fields
        """
        self.map = dict(**kwargs)

    def generateClassifier(self):
        """
        Matched packets are kept, non-matched packets are dropped.
        """
        r1 = Rule(self, identity, {identity})
        r2 = Rule(identity, identity, set())
        return Classifier([r1, r2])


    def intersec(self, pol):
        """
        return a new math which is the result of the intersection between self and pol
        """
        def _intersect_ip(ipfx, opfx):
            """
            IP intersection, return the most specific IP address
            """
            most_specific = None
            if (IPv4Network(ipfx) in IPv4Network(opfx)):
                most_specific = ipfx
            elif (IPv4Network(opfx) in IPv4Network(ipfx)):
                most_specific = opfx
            return most_specific
        # fct logic start here
        if pol == identity:
            return self
        elif pol == drop:
            return drop
        elif not isinstance(pol,match):
            raise TypeError
        fs1 = set(self.map.keys())
        fs2 = set(pol.map.keys())
        shared = fs1 & fs2 # set intersection
        most_specific_src = None
        most_specific_dst = None
        for f in shared:
            if (f=='nw_src'):
                most_specific_src = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_src is None:
                    return drop # y a aucune intersection, c'est deux flux different
            elif (f=='nw_dst'):
                most_specific_dst = _intersect_ip(self.map[f], pol.map[f])
                if most_specific_dst is None:
                    return drop
            elif (self.map[f] != pol.map[f]):
                #if there is only one different field, then the intersection is an empty set
                return drop

        if 'nw_src' in fs1:
            if 'nw_dst' in fs2:
                if self.map['nw_src'] == pol.map['nw_dst']:
                    return drop
        elif 'nw_dst' in fs1:
            if 'nw_src' in fs2:
                if self.map['nw_dst'] == pol.map['nw_src']:
                    return drop

        # if there is no shared field, then merge
        d = dict(self.map.items() + pol.map.items())
        #d = self.map.update(pol.map) --> pyretic code, update method return nothing !

        if most_specific_src is not None:
            #d = d.update({'srcip' : most_specific_src}) --> pyretic code !
            d.update({'nw_src' : most_specific_src})
        if most_specific_dst is not None:
            #d = d.update({'dstip' : most_specific_dst})- -> pyretic code !
            d.update({'nw_dst' : most_specific_dst})

        return match(**d)

    def covers(self, other):
        """
        return true, if other is totally included in self
        """
        if other == identity and len(self.map.keys()) > 0:
            return False
        elif other == identity:
            return True
        elif other == drop:
            return True
        if set(self.map.keys()) - set(other.map.keys()):
            #if the set is empthy == false, if not == true
            # A - B: the resulting set has elements of the "A" set with all elements from the "B" set removed.
            return False

        for (f, v) in self.map.items():
            if(f=='nw_src' or f=='nw_dst'):
                if(IPv4Network(v) != IPv4Network(other.map[f])):
                    if(not IPv4Network(other.map[f]) in IPv4Network(v)):
                        return False
            elif v != other.map[f]:
                return False
        return True

    # to be able to use match object as dictionary key
    def __hash__(self):
        return hash(repr(self.map))

    def __eq__(self, other):
        return ( (isinstance(other, match) and self.map == other.map)
                 or (len(self.map) == 0 and other == identity) )

    def __repr__(self):
        return "match " + str(self.map)



class forward(EdgePolicy):
    """
    forward a flow at one of edge's port

    :param destination: virtual device which is directly connected to the edge (or edge's port number)
    """
    def __init__(self, output):
        self.output = output

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, {self})])

    def __eq__(self, other):
        return (isinstance(other, forward)) and (self.output == other.output)

    def __repr__(self):
        return "forward to " + str(self.output)



class modify(EdgePolicy):
    """
    Modify on all specified fields to specified values.

    :param **kwargs: field assignments in keyword-argument format
    """
    def __init__(self, **kwargs):
        self.map = dict(**kwargs)

    def apply(self, packet):
        """
        EDIT Telly: le paquet peut etre un paquet pox ou un dictionnaire
        """
        import ast
        if isinstance(packet, dict):
            #ici il s'agit de {'dpid':..,'packet':{'ipv4':{......},'tcp':{....},...},'port':..}
            protos = packet.get('packet')
            protos = ast.literal_eval(str(protos))
            if "dl_src" in self.map:
                protos['dl_src'] = self.map["dl_src"]
            if "dl_dst" in self.map:
                protos['dl_dst'] = self.map["dl_dst"]
            if 'ipv4' in protos:
                ip = dict()
                if "nw_src" in self.map:
                    ip['src'] = self.map["nw_src"]
                if "nw_dst" in self.map:
                    ip['dst'] = self.map["nw_dst"]
                protos['ipv4'] = ip
            if 'tcp' in protos:
                tcp = dict()
                if 'src_port' in self.map:
                    tcp['src_port'] = self.map["tp_src"]
                if 'dst_port' in self.map:
                    tcp['dst_port'] = self.map["tp_dst"]
                protos['tcp'] = tcp
            packet['packet'] = unicode(protos)
            """
            if 'ipv4' in protos:
                pdb.set_trace()
                ip = protos.get('ipv4')
                ip['src'] = self.map["nw_src"]
                ip['dst'] = self.map["nw_dst"]
                protos['ipv4'] = ip
            if 'tcp' in protos:
                tcp = protos.get('tcp')
                tcp['src_port'] = self.map["tp_src"]
                tcp['dst_port'] = self.map["tp_dst"]
                protos['tcp'] = tcp
            packet['packet'] = unicode(protos)
            """
        else:
        # End EDIT Telly
            if "dl_src" in self.map:
                packet.src = self.map["dl_src"]
            if "dl_dst" in self.map:
                packet.dst = self.map["dl_dst"]
            ip = packet.find('ipv4')
            if ip:
                if hasattr(ip, "srcip"):
                    if "nw_src" in self.map:
                        ip.srcip = IPAddr(self.map["nw_src"])
                if hasattr(ip, "dstip"):
                    if "nw_dst" in self.map:
                        ip.dstip = IPAddr(self.map["nw_dst"])
            tcp = packet.find('tcp')
            if tcp:
                if hasattr(tcp, "srcport"):
                    if "tp_src" in self.map:
                        tcp.srctp = self.map["tp_src"]
                if hasattr(tcp, "dstport"):
                    if "tp_dst" in self.map:
                        tcp.dsttp = self.map["tp_dst"]

    def generateClassifier(self):
        return Classifier([Rule(identity, identity, {self})])

    def __eq__(self, other):
        return (isinstance(other, modify)) and (self.map == other.map)

    def __repr__(self):
        return "modify such as " + str(self.map)



class tag(EdgePolicy):
    """
    the tag policy allows to assigns a label to a matched flow

    :param label: identifier to be attached to the matched flow
    """
    def __init__(self, label):
        self.label = label

    def generateClassifier(self):
        # different from others !
        return Classifier([Rule(identity, self, {identity})])

    def __eq__(self, other):
        return (isinstance(other, tag)) and (self.label == other.label)

    def __repr__(self):
        return "flowID==" + self.label



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


"""
TODO: Dynamic policies
"""
class NetworkFunction(EdgePolicy):
    """
    base class for network functions
    """
    def __init__(self,  callback, callback_kwargs, decorator_kwargs):
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

    def __eq__(self, other):
        return (isinstance(other, DynamicPolicy))

    def apply(self, packet):
        print("applying dyn control policy")
        print(type(self.callback))
        return self.callback(packet, **self.callback_kwargs)


def DataFct(**decorator_kwargs):
    def data_fct_decorator(fct ):
        def fct_warper(**fct_kwargs):
            return DataFctPolicy(fct, fct_kwargs, decorator_kwargs)
        return fct_warper
    return data_fct_decorator


def DynamicControlFct(**decorator_kwargs):
    def dynamic_fct_decorator(fct ):
        def fct_warper(**fct_kwargs):
            return DynamicPolicy(fct, fct_kwargs, decorator_kwargs)
        return fct_warper
    return dynamic_fct_decorator




################ Fabric policies ####################



class FabricPolicy(Policy):
    """
    abstract class for all edge policies
    not yet being used
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
    """
    the catch policy, match flows based on a label that has been inserted beforehand by an edge.

    :param **kwargs: field (fabric, flow) matches in keyword-argument format
    """

    def __init__(self, src, fabric, flow):
        self.flow = flow
        self.fabric = fabric
        self.src= src

    def generateClassifier(self):
        """
        Matched packets are kept, non-matched packets are dropped.
        """
        #r1 = FabricRule(self, identity)
        #r2 = FabricRule(identity, set())
        #return Classifier([r1, r2])
        return FabricClassifier([FabricRule(self, {identity}, list())])



class carry(FabricPolicy):
    """
    carry a flow at one of fabric's port

    :param destination: virtual device which is directly connected to the fabric (or fabric's port number)
    :param **constraints: bandwidth constraint (the only constraint that is covered for now)
    """

    def __init__(self, dst, **constraints):
        self.destination = dst
        if constraints is not None:
            self.constraints = dict(**constraints)
        else:
            self.constraints = None


    def generateClassifier(self):
        return FabricClassifier([FabricRule(identity, {self}, list())])


class via(FabricPolicy):
    """
    allows to redirect a flow towards a data machine

    :param dataMachine: target data machine
    :param dataFct: target data function
    """
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


################ Composition policies ################


class CompositionPolicy(EdgePolicy):
    """
    Abstract class for policy composition (edge and fabric)

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

    def __add__(self, policy):
        if isinstance(policy, ParallelComposition):
            return ParallelComposition(self.policies + policy.policies)
        else:
            return ParallelComposition(self.policies + [policy])

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

    def __rshift__(self, policy):
        if isinstance(policy, SequentialComposition):
            return SequentialComposition(self.policies + policy.policies)
        else:
            return SequentialComposition(self.policies + [policy])


    def generateClassifier(self):
        # call compile() method for each CompositionPolicy and basic policy in self.policies
        # return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # sequential composition of all classifiers
        return reduce(lambda acc, c: acc >> c, classifiers)

################# Fabric policies composition ##################

class FabricParallelComposition(CompositionPolicy):
    """
    Combinator for several fabric policies in parallel.

    :param policies: the policies to be combined.
    """

    def __init__(self, policies):
        super(FabricParallelComposition, self).__init__(policies)

    def __add__(self, policy):
        if isinstance(policy, FabricParallelComposition):
            return FabricParallelComposition(self.policies + policy.policies)
        else:
            return FabricParallelComposition(self.policies + [policy])

    def generateClassifier(self):
        # call compile method for each basic policy in self.policies
        # and return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # parallel composition of all classifiers
        return reduce(lambda acc, c: acc + c, classifiers)


class FabricSequentialComposition(CompositionPolicy):
    """
    Combinator for several fabric policies in sequence.

    :param policies: the policies to be combined.
    """
    def __init__(self, policies):
        CompositionPolicy.__init__(self, policies)

    def __rshift__(self, policy):
        if isinstance(policy, FabricSequentialComposition):
            return FabricSequentialComposition(self.policies + policy.policies)
        else:
            return FabricSequentialComposition(self.policies + [policy])

    def generateClassifier(self):
        # call compile method for each basic policy in self.policies
        # and return a list of classifiers
        classifiers = map(lambda p: p.compile(), self.policies)
        # parallel composition of all classifiers
        return reduce(lambda acc, c: acc >> c, classifiers)
