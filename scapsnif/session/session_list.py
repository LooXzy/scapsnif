from scapy.all import *
from scapy.all import TCP, IP
from collections import defaultdict
from scapsnif.session import Session


class SessionsList(Session):
    def __init__(self, packets):
        assert isinstance(packets, PacketList)
        self.packets = packets


    def display_session(self):
        # tab_session = []
        # for pkt in self.packets:
        #     ip_src = pkt[IP].src
        #     ip_dst = pkt[IP].dst
        #     tcp_sport = pkt[TCP].sport
        #     tcp_dport = pkt[TCP].dport
        #     session_key = (ip_src, tcp_sport, ip_dst, tcp_dport)
        #     tab_session.append(session_key)
        # # return tab_session (for debug)

        # Dict : Use defaultdict
        tab_sessions = defaultdict(list)

        for pkt in self.packets:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport

            session_key = (ip_src, tcp_sport), (ip_dst, tcp_dport)

            tab_sessions[session_key].append(pkt)

        tab_display_session = []
        for session in tab_sessions:
            tab_display_session.append(session)
        return tab_display_session


    def pickle_mode(self):
        # Dict : Use defaultdict
        sessions = defaultdict(list)

        for pkt in self.packets:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport

            # Session bidirectionnelle
            session_key = tuple(sorted([(ip_src, tcp_sport), (ip_dst, tcp_dport)]))

            sessions[session_key].append(pkt)

        return sessions
