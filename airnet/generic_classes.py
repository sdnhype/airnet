from language import identity,match


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
