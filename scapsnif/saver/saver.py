from scapy.all import *
import os
import pickle


class Saver:
    def __init__(self, packets):
        # assert isinstance(packets, PacketList) -> Commenté pour prendre en charge write pickle qui n'est pas une PacketList
        self.packets = packets


    def write_pcap(self, output_file):
        assert isinstance(self.packets, PacketList)  # -> Ajouté voir commentaire plus haut
        assert isinstance(output_file, str)
        wrpcap(output_file, self.packets)
        print(f"[*] Le fichier {output_file} a été sauvegardé avec les packets filtrés !")

    def write_pickle(self, input_file_name, list_session):
        # Extraire le nom de base du fichier PCAP sans extension
        base_name = os.path.basename(input_file_name)
        name_without_ext = os.path.splitext(base_name)[0]
        # Création du nouveau dossier
        dir_path = os.path.join(os.path.dirname(input_file_name), name_without_ext)
        os.makedirs(dir_path, exist_ok=True)

        # Sérialiser chaque session dans un fichier .pickle
        for session, packets in list_session.items():
            ip_port_1, ip_port_2 = session
            ip1, port1 = ip_port_1
            ip2, port2 = ip_port_2

            # Création des fichiers .pickle
            pickle_filename = f"{ip1}-{ip2}_transport_{port1}-{port2}.pickle"
            pickle_filepath = os.path.join(dir_path, pickle_filename)

            # Save packets dans fichier pickle
            with open(pickle_filepath, 'wb') as f:
                pickle.dump(packets, f)

            # print(f"Session {ip1}:{port1} -> {ip2}:{port2} sérialisée dans {pickle_filepath}") -> DEBUG
