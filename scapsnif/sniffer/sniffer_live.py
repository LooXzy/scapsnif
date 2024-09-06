from scapy.all import *
from scapsnif.sniffer import Sniffer

class LiveSniffer(Sniffer):
    def __init__(self):
        pass


    def run(self, interface):
        assert isinstance(interface, str)
        pkt = sniff(iface=interface)
        return pkt
