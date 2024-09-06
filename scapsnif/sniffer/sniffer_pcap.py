from scapy.all import *
from scapsnif.sniffer import Sniffer

class PcapSniffer(Sniffer):
    def __init__(self):
        self.filename = None


    def load(self, filename):
        assert isinstance(filename, str)
        self.filename = filename
        packets = rdpcap(filename)
        return packets
