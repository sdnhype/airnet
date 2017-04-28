from threading import Timer
from tools import match_from_packet
from language import identity,match
import copy

#TODO: what's the point on #66
#TODO: merge tools.py on #84
#TODO: addPacket on #91

class Bucket(object):
    """
        Containers for data/stats received from the controller
        One bucket is instantiated for each network function
    """
    def __init__(self, _filter, _type, split, limit, every, runtime):
        self.runtime = runtime
        self.match = _filter
        self.limit = limit
        self.split = split
        self.data = []
        # here we can multiples micro-flows
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

    def update_bucket_state(self):
        """
            Don't know yet the point
        """
        pass
        #self.locked = True

    def update_stats(self, stat):
        """
            Transfer statistics data to the network function
        """
        self.data = stat
        #self.runtime.apply_netFunction_fromStat(self.match, stat)

    def get_micro_flow(self, packet):
        packet_match = match_from_packet(packet)
        try:
            return match(**{field:packet_match.map[field] for field in self.split})
        except KeyError:
            print "This packet can't be splitted"

    def add_packet(self, dpid, packet_match, packet):
        print("add packet")
        if self.limit is None:
            self.data.append(packet)
            self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
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
                        self.runtime.micro_flow_limit_reached(micro_flow_match)
                    self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                else:
                    print "micro-flow locked"
                    # TODO: add something to handle this lasts packets --> packets concurrency
            else:
                if not self.locked:
                    self.nb_packets += 1
                    self.data.append(packet)
                    if self.nb_packets == self.limit:
                        print("locked because of limit")
                        self.locked = True
                        self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                        self.runtime.flow_limit_reached(self.match)
                    else :
                        self.runtime.apply_netFunction_fromPacket(dpid, self.match, packet_match, packet)
                else:
                    print "flow locked"
                    # TODO: packets concurrency

class PeriodicTimer(object):
    """
        Sends periodic stats requests through the callback function parameter
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
        # sends the request
        self._callback(*self._args, **self._kwargs)

    def start(self):
        self._timer = Timer(self._interval, self._run)
        self._timer.start()

    def stop(self):
        self._timer.cancel()

class Stat_object(object):
    """
    Represents a stat object received from the RYU Controller
    """
    def __init__(self, byte_count, packet_count, **kwargs):
        self.byte_count = byte_count
        self.packet_count = packet_count
        # the matching fields
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
