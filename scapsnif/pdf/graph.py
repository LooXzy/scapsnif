from scapsnif.pdf import Pdf
import plotly.graph_objs as go
from collections import defaultdict
from scapy.all import TCP, IP
import pandas as pd
import os


class Graph(Pdf):
    def __init__(self):
        pass

    def generate_top10_sessions_summaries(self, list_sessions):
        sessions = list_sessions
        adresse_sessions = defaultdict(int)

        # Compter le nombre de sessions distinctes par adresse IP
        for session_key in sessions.keys():
            ip_src = session_key[0][0]
            ip_dst = session_key[1][0]

            adresse_sessions[ip_src] += 1
            adresse_sessions[ip_dst] += 1

        # Trier les adresses par nombre de sessions décroissant et prendre les 10 premières
        top_addresses = sorted(adresse_sessions.items(), key=lambda x: x[1], reverse=True)[:10]

        # Séparer les adresses et les sessions pour le graphique
        adresses = [addr[0] for addr in top_addresses]
        sessions_count = [addr[1] for addr in top_addresses]

        # Graphique à barres avec Plotly
        fig = go.Figure(data=[go.Bar(x=adresses, y=sessions_count)])

        fig.update_layout(title="Top 10 des adresses réseau impliquées dans les sessions TCP",
                          xaxis_title="Adresses réseau",
                          yaxis_title="Nombre de sessions")

        fig.write_image("./assets/graph_top_10sessions.png")

    def generate_all_sessions_summaries(self, list_sessions, output_dir, path_pdf, cover_logo_path, cover_name, cover_surname, sum_pcap_file, sum_start_time, sum_end_time, sum_duration):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        sessions = list_sessions

        # Init PDF
        pdf = Pdf()

        # Page de couverture
        pdf.add_cover_page(logo_path=cover_logo_path, name=cover_name, surname=cover_surname)

        # Page de synthèse
        pdf.add_summary_page(pcap_file_name=sum_pcap_file, start_time=sum_start_time, end_time=sum_end_time, duration=sum_duration, num_sessions=len(sessions))

        for session_key, packets in sessions.items():
            ip1, port1 = session_key[0]
            ip2, port2 = session_key[1]

            timestamps_ip1_to_ip2 = []
            timestamps_ip2_to_ip1 = []
            sizes_ip1_to_ip2 = []
            sizes_ip2_to_ip1 = []

            for pkt in packets:
                timestamp = pkt.time
                size = len(pkt)
                if pkt[IP].src == ip1 and pkt[IP].dst == ip2:
                    timestamps_ip1_to_ip2.append(timestamp)
                    sizes_ip1_to_ip2.append(size)
                elif pkt[IP].src == ip2 and pkt[IP].dst == ip1:
                    timestamps_ip2_to_ip1.append(timestamp)
                    sizes_ip2_to_ip1.append(size)

            # Conversion des timestamps en datetime en s'assurant qu'ils sont numériques
            df_ip1_to_ip2 = pd.DataFrame({'timestamp': timestamps_ip1_to_ip2})
            df_ip1_to_ip2['timestamp'] = pd.to_numeric(df_ip1_to_ip2['timestamp'], errors='coerce')
            df_ip1_to_ip2 = df_ip1_to_ip2.dropna()  # Supprimer les valeurs non numériques
            df_ip1_to_ip2['timestamp'] = pd.to_datetime(df_ip1_to_ip2['timestamp'], unit='s')
            df_ip1_to_ip2['count'] = 1
            df_ip1_to_ip2 = df_ip1_to_ip2.set_index('timestamp').resample('1s').sum().fillna(0)

            fig1 = go.Figure(data=[go.Scatter(x=df_ip1_to_ip2.index, y=df_ip1_to_ip2['count'], mode='lines')])
            fig1.update_layout(
                title=f"Débit en paquets par seconde de {ip1}:{port1} vers {ip2}:{port2}",
                xaxis_title="Temps",
                yaxis_title="Paquets par seconde"
            )

            # Img du graph
            image_path_1 = os.path.join(output_dir, f"debit_{ip1}_{port1}_vers_{ip2}_{port2}.png")
            fig1.write_image(image_path_1)

            # Conversion des timestamps en datetime pour le second sens
            df_ip2_to_ip1 = pd.DataFrame({'timestamp': timestamps_ip2_to_ip1})
            df_ip2_to_ip1['timestamp'] = pd.to_numeric(df_ip2_to_ip1['timestamp'], errors='coerce')
            df_ip2_to_ip1 = df_ip2_to_ip1.dropna()  # Supprimer les valeurs non numériques
            df_ip2_to_ip1['timestamp'] = pd.to_datetime(df_ip2_to_ip1['timestamp'], unit='s')
            df_ip2_to_ip1['count'] = 1
            df_ip2_to_ip1 = df_ip2_to_ip1.set_index('timestamp').resample('1s').sum().fillna(0)

            fig2 = go.Figure(data=[go.Scatter(x=df_ip2_to_ip1.index, y=df_ip2_to_ip1['count'], mode='lines')])
            fig2.update_layout(
                title=f"Débit en paquets par seconde de {ip2}:{port2} vers {ip1}:{port1}",
                xaxis_title="Temps",
                yaxis_title="Paquets par seconde"
            )

            # Img du graph
            image_path_2 = os.path.join(output_dir, f"debit_{ip2}_{port2}_vers_{ip1}_{port1}.png")
            fig2.write_image(image_path_2)

            # Graphique montrant la répartition de la taille des paquets échangés entre IP1 et IP2
            fig3 = go.Figure()
            fig3.add_trace(go.Histogram(x=sizes_ip1_to_ip2, name=f"{ip1} vers {ip2}"))
            fig3.add_trace(go.Histogram(x=sizes_ip2_to_ip1, name=f"{ip2} vers {ip1}"))
            fig3.update_layout(
                barmode='overlay',
                title="Répartition de la taille des paquets échangés",
                xaxis_title="Taille des paquets (octets)",
                yaxis_title="Nombre de paquets"
            )
            fig3.update_traces(opacity=0.75)

            # Img du graph
            image_path_3 = os.path.join(output_dir, f"taille_paquets_{ip1}_{port1}_vers_{ip2}_{port2}.png")
            fig3.write_image(image_path_3)

            # Add les sessions au PDF principal
            pdf.add_session_summaries(ip1, port1, ip2, port2, image_path_1, image_path_2, image_path_3)

        # Save le PDF
        pdf.output(path_pdf)