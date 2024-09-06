import json
from collections import defaultdict
from scapsnif.session import Session


class SecureSession(Session):
    def __init__(self, packets):
        self.packets = packets

    def display_session(self):
        tab_sessions = defaultdict(list)

        for pkt in self.packets:
            ip_src = pkt.get('ip_src')
            ip_dst = pkt.get('ip_dst')
            tcp_sport = pkt.get('tcp_sport')
            tcp_dport = pkt.get('tcp_dport')

            session_key = (ip_src, tcp_sport), (ip_dst, tcp_dport)
            tab_sessions[session_key].append(pkt)

        tab_display_session = list(tab_sessions.keys())
        return tab_display_session

    def serialize_sessions(self):
        sessions = defaultdict(list)

        for pkt in self.packets:
            ip_src = pkt.get('ip_src')
            ip_dst = pkt.get('ip_dst')
            tcp_sport = pkt.get('tcp_sport')
            tcp_dport = pkt.get('tcp_dport')

            # Session bidirectionnelle
            session_key = tuple(sorted([(ip_src, tcp_sport), (ip_dst, tcp_dport)]))
            sessions[session_key].append(pkt)

        # Sérialisation en JSON
        return json.dumps(sessions)

    @staticmethod
    def deserialize_sessions(serialized_data: str):
        # Désérialisation de JSON
        return json.loads(serialized_data)
