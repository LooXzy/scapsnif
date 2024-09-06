from scapy.all import *
import datetime


class Filter:
    def __init__(self, packets):
        assert isinstance(packets, PacketList)
        self.packets = packets


    def by_protocol(self, protocol):
        assert isinstance(protocol, str)  # Type Layer
        filtered_packets = PacketList()  # Liste de packets (scapy)
        for pkt in self.packets:
            if pkt.haslayer(protocol):
                filtered_packets.append(pkt)
        return filtered_packets


    def by_source_ip(self, source_ip):
        assert isinstance(source_ip, str)
        filtered_packets = PacketList()
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt[IP].src == source_ip:
                filtered_packets.append(pkt)
        return filtered_packets

    def get_capture_times(self):
        start_time = min(pkt.time for pkt in self.packets)
        end_time = max(pkt.time for pkt in self.packets)

        # Convertion des timestamps en float avant de les convertir en datetime
        start_time = float(start_time)
        end_time = float(end_time)

        dur_start_time = datetime.datetime.fromtimestamp(start_time)
        dur_end_time = datetime.datetime.fromtimestamp(end_time)
        # Calc
        duration = dur_end_time - dur_start_time

        # Convertir la durée en heures, minutes et secondes
        hours, remainder = divmod(duration.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours}h {minutes}m {seconds}s"

        # Formattage de l'heure proprement pour le PDF
        format_start_time = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        format_end_time = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')

        return [format_start_time, format_end_time, duration_str]
