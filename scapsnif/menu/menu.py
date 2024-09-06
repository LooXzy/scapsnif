from scapsnif import LiveSniffer
from scapsnif import PcapSniffer
from scapsnif import Filter
from scapsnif import Saver
from scapsnif.session import SessionsList
from scapsnif.pdf import Graph

from datetime import datetime
import os
import psutil

class Menu():
    def __init__(self):
        self.display_sniffer()
        self.display_filter()
        self.display_saver()
        self.run()
        ##
        self.mode = None
        self.interface_sniffer = None
        self.read_file_input = None
        self.filter = None
        self.session = None
        self.saver = None
        self.save_file_output = None
        self.export = None

    def display_sniffer(self):
        while True:
            self.mode = input("[*] Quel mode souhaitez-vous utiliser ? \n[1] - Sniff Live\n[2] - Read Pcap\n> ")
            if self.mode == "1":  # Live Mode
                self.interface_sniffer = input("[*] Sur quel interface réseau souhaitez-vous démarrer la capture ?\n> ")
                if self.interface_sniffer in psutil.net_if_stats().keys():
                    break
                else:
                    print("[!] L'interface spécifiée n'existe pas !")
                    exit(1)

            elif self.mode == "2":  # Pcap Mode
                self.read_file_input = input("[*] Quel est le nom du fichier de la capture à lire ?\n> ")
                if os.path.isfile(self.read_file_input):
                    break
                else:
                    print("[!] Le fichier indiqué n'existe pas !")
                    exit(1)

            else:
                print("[!] Erreur lors de la sélection du mode !")
                exit(1)

    def display_filter(self):
        list_compatible_protocol = ["IP", "IPv6", "ARP", "ICMP", "ICMPv6", "TCP", "UDP", "DNS", "DHCP", "DHCP6", "HTTP", "HTTPS", "FTP", "SSH", "Telnet", "SMTP", "POP", "IMAP", "SNMP", "SMB", "NFS", "SIP", "RTP", "TLS", "SSL", "OSPF"]
        self.filter = input("[*] Sur quel protocole souhaitez-vous filtrer ?\n> ")
        # self.filter = self.filter.upper()
        if self.filter in list_compatible_protocol:
            self.session = input("[*] Souhaitez-vous utiliser le mode d'analyse des sessions (oui / non) ?\n> ")

            if self.session == "oui":
                self.export = input("[*] Souhaitez-vous un rapport PDF (oui / non) ?\n> ")

                if self.export == "oui":
                    pass
                elif self.export == "non":
                    pass
                else:
                    print("[!] Erreur lors de la sélection du mode !")
                    exit(1)

            elif self.session == "non":
                pass

            else:
                print("[!] Erreur lors de la sélection du mode !")
                exit(1)

        else:
            print("[!] Le protocole spécifié n'existe pas ou n'est pas compatible avec ce programme !")
            exit(1)


    def display_saver(self):
        while True:
            if self.session == "oui":
                break
            elif self.session == "non":
                self.saver = input("[*] Souhaitez-vous sauvegarder la capture ? (oui / non)\n> ")

                if self.saver == "oui":
                    self.save_file_output = input("[*] Quel nom souhaitez-vous donner au fichier ?\n> ")

                elif self.saver == "non":
                    print("[!] Les packets seront affichés dans la console à la fin de l'exécution du programme.\n")
                    break

                else:
                    exit(1)
            else:
                print("[!] Erreur lors de la sélection du mode session [DISPLAY_SAVER] !")
                exit(1)

    def run(self):
        if self.mode == "1":  # Live Mode
            print("[*] Une fois votre capture réalisée, arrêter le programme pour obtenir le résultat.\n")
            live_packets = LiveSniffer().run(interface=self.interface_sniffer)
            filtered_packets = Filter(live_packets).by_protocol(protocol=self.filter)
            if self.saver == "oui":
                Saver(filtered_packets, output_file=self.save_file_output).write_pcap()
            elif self.saver == "non":
                for pkt in filtered_packets:
                    print(pkt.summary())
            else:
                print("[!] Erreur lors de la sauvegarde ou de l'affichage !")
                exit(1)

        elif self.mode == "2":  # Pcap Mode
            print("[*] Lecture en cours, veuillez patienter...\n")
            # start_reader_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            read_packets = PcapSniffer().load(filename=self.read_file_input)
            filtered_packets = Filter(read_packets).by_protocol(protocol=self.filter)
            if self.session == "oui":
                captures_times = Filter(read_packets).get_capture_times()
                list_session = SessionsList(packets=filtered_packets).pickle_mode()
                Saver(list_session).write_pickle(input_file_name=self.read_file_input, list_session=list_session)
                # end_reader_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                if self.export == "oui":
                    # GRAPH
                    Graph().generate_top10_sessions_summaries(list_sessions=list_session)
                    Graph().generate_all_sessions_summaries(list_sessions=list_session, output_dir="./assets/output_sessions_graph", path_pdf="rapport_scapsnif.pdf", cover_logo_path="./assets/img/python.png", cover_name="Name", cover_surname="Surname", sum_pcap_file=self.read_file_input, sum_start_time=captures_times[0], sum_end_time=captures_times[1], sum_duration=captures_times[2])
                    print("[*] Programme terminé, le fichier 'rapport_scapsnif.pdf' est disponible !")
                elif self.export == "non":
                    SessionsList(packets=filtered_packets).display_session()
                    print("[*] Programme terminé !")
                else:
                    print("[!] Erreur lors du mode export !")
                    exit(1)

            elif self.session == "non":
                if self.saver == "oui":
                    Saver(filtered_packets).write_pcap(output_file=self.save_file_output)
                elif self.saver == "non":
                    for pkt in filtered_packets:
                        print(pkt.summary())
                else:
                    print("[!] Erreur lors de la sauvegarde ou de l'affichage !")
                    exit(1)
            else:
                print("[!] Erreur lors du mode session !")
                exit(1)

        else:
            print("[!] Erreur lors de l'exécution !")
            exit(1)