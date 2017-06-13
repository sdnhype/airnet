# AIRNET PROJECT
# Copyright (c) 2017 Messaoud AOUADJ, Emmanuel LAVINAL, Mayoro BADJI

#TODO: packet concurrency in add_packet

from threading import Timer
from language import identity,match
import copy, ast

class Bucket(object):
    """ Containers for data/stats received from the controller
        One bucket is instantiated for each dynamic network function
    """
    def __init__(self, _filter, _type, split, limit, every, runtime):
        """ initializes bucket components
            @param _filter : flow on which the network function applies
            @param _type   : whether it's a stat or packet network function
            @param _split  : whether the flow is discriminated or not (_type->packet)
            @param _limit  : # of flow packets which will be treated  (_type->packet)
            @param _every  : interval in which stats are recovered
            @param runtime : hypervisor runtime module
        """
        self.runtime = runtime
        self.match = _filter
        self.limit = limit
        self.split = split
        self.data = []
        # here we can have multiples micro-flows
        if split is not None:
            self.nb_packets = {}
            self.locked = {}
        else:
            self.nb_packets = 0
            self.locked = False

        self.type = _type

        if _type == "stat":
            # instantiates a thread which will send requests
            self.timer = PeriodicTimer(every, limit, self.runtime.send_stat_request, _filter)
            self.timer.start()

    def getMatch_fromPacket(self, packet):
        """
            generates a match object based on
            fields in the packet param
        """
        packet_match = match()
        # {'dpid':..,'packet':{'ipv4':{......},'tcp':{....},...},'port':..}
        protos = packet.get('packet')
        protos = ast.literal_eval(str(protos))
        if 'ipv4' in protos:
            ip = protos.get('ipv4')
            packet_match.map["nw_src"] = ip.get('src')
            packet_match.map["nw_dst"] = ip.get('dst')
        if 'tcp' in protos:
            tcp = protos.get('tcp')
            packet_match.map["tp_src"] = tcp.get('src_port')
            packet_match.map["tp_dst"] = tcp.get('dst_port')

        return packet_match

    def update_bucket_state(self):
        """ not relevant """
        pass

    def update_stats(self, stat):
        """ transfer stats data to the network function """
        self.data = stat

    def get_micro_flow(self, packet):
        """ get a match (corresponding to a micro_flow)
            based on packet param headers """
        packet_match = self.getMatch_fromPacket(packet)
        try:
            return match(**{field:packet_match.map[field] for field in self.split})
        except KeyError:
            print("[Error] Packet {} can't be splitted".format(str(packet)))

    def add_packet(self, dpid, packet_match, packet):
        """
            coordonates dynamic function execution after
            datas are collected
        """
        # all packets are pulled
        if self.limit is None:
            # store the packet
            self.data.append(packet)
            # apply the network function stored in the bucket
            self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
        else:
            # there are micro_flows here
            if self.split is not None:
                # get the micro_flow based on packet headers
                micro_flow = self.get_micro_flow(packet)
                # lock it
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
                    # check if the micro_flow reached the limit field
                    if self.nb_packets[micro_flow] == self.limit:
                        # lock the micro_flow
                        self.locked[micro_flow] = True
                        micro_flow_match = copy.deepcopy(self.match)
                        micro_flow_match.map.update(micro_flow.map)
                        self.runtime.micro_flow_limit_reached(micro_flow_match)
                    self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                else:
                    print "[Error] Micro-Flow Locked"
                    # TODO: add something to handle this lasts packets --> packets concurrency
            else:
                if not self.locked:
                    self.nb_packets += 1
                    self.data.append(packet)
                    if self.nb_packets == self.limit:
                        print("Flow Locked because Limit is reached")
                        self.locked = True
                        self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                        self.runtime.flow_limit_reached(self.match)
                    else :
                        self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                else:
                    print "[Error] Flow Locked"
                    # TODO: packets concurrency

class PeriodicTimer(object):
    """ Sends periodic stats requests
        through the callback function parameter """
    def __init__(self, interval, maxticks, callback, *args, **kwargs):
        """
            @param interval : in which threads are created
            @param maxticks :
            @param callback : dynamic function which is executed
        """
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
        """ function executed by threads """
        if self._maxticks:
            self._nticks += 1
            if self._nticks < self._maxticks:
                self._timer = Timer(self._interval, self._run)
                self._timer.start()
        else:
            self._timer = Timer(self._interval, self._run)
            self._timer.start()
        # sends the request
        self._callback(*self._args, **self._kwargs)

    def start(self):
        """ launches threads """
        self._timer = Timer(self._interval, self._run)
        self._timer.start()

    def stop(self):
        """ stops threads"""
        self._timer.cancel()

class Stat(object):
    """ represents statistics data structure collected
    """
    def __init__(self, byte_count, packet_count, **kwargs):
        """
            @param byte_count : # of bytes that hit a match
            @param packet_count : # of packets that hit a match
            @param **kwargs : other statistics features
        """
        self.byte_count = byte_count
        self.packet_count = packet_count
        self._issuing_match = match(**kwargs)

        try:
            self.nw_src = kwargs["nw_src"]
        except KeyError:
            self.nw_src = None
        try:
            self.nw_dst = kwargs["nw_dst"]
        except KeyError:
            self.nw_dst = None
        try:
            self.dl_src = kwargs["dl_src"]
        except KeyError:
            self.dl_src = None
        try:
            self.dl_dst = kwargs["dl_dst"]
        except KeyError:
            self.dl_dst = None
        try:
            self.tp_src = kwargs["tp_src"]
        except KeyError:
            self.tp_src = None
        try:
            self.tp_dst = kwargs["tp_dst"]
        except KeyError:
            self.tp_dst = None

	@property
	def byte_count(self):
		return self._byte_count

	@property
	def packet_count(self):
		return self._packet_count

	@property
	def nw_src(self):
		return self._nw_src

	@property
	def nw_dst(self):
		return self._nw_dst

	@property
	def dl_src(self):
		return self._dl_src

	@property
	def dl_dst(self):
		return self._dl_dst

	@property
	def tp_src(self):
		return self._tp_src

	@property
	def tp_dst(self):
		return self._tp_dst
