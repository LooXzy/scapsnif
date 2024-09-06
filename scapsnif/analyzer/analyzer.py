from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.http import HTTPRequest

class Analyzer:
    def __init__(self, packets):
        assert isinstance(packets, PacketList)
        self.packets = packets


    def exfiltration_dns(self):
        query_filtered_packets = []
        for pkt in self.packets:
            if pkt.haslayer("DNSQR") and not pkt.haslayer("DNSRR"):
                query = pkt[DNSQR]
                query = query.qname
                query_filtered_packets.append(query)
        return query_filtered_packets


    def exfiltration_http(self):
        request_filtered_packets = []
        for pkt in self.packets:
            if pkt.haslayer("HTTPRequest"):
                request = pkt[HTTPRequest]
                request_filtered_packets.append(request)
        return request_filtered_packets