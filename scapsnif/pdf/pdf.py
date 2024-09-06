from fpdf import FPDF
import datetime


class Pdf(FPDF):
    def __init__(self):
        super().__init__()  # Initialisation de FPDF

    def add_cover_page(self, logo_path, name, surname):
        self.add_page()

        # Logo
        self.image(logo_path, x=10, y=8, w=33)

        # Titre
        self.set_xy(0, 50)
        self.set_font('Arial', 'B', 24)
        self.cell(0, 10, f"Rapport ScapSnif", 0, 1, 'C')

        # Nom et prénom
        self.set_xy(0, 70)
        self.set_font('Arial', '', 12)
        self.cell(0, 10, f"Personnel : {name} {surname}", 0, 1, 'C')

        # Date et heure d'export
        self.set_xy(0, 80)
        self.set_font('Arial', '', 12)
        current_datetime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.cell(0, 10, f"Date et heure de l'export : {current_datetime}", 0, 1, 'C')

        return self

    def add_summary_page(self, pcap_file_name, start_time, end_time, duration, num_sessions):
        self.add_page()

        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Synthèse', 0, 1, 'C')
        self.ln(10)

        self.set_font('Arial', '', 12)
        self.cell(0, 10, f"Nom du fichier PCAP : {pcap_file_name}", 0, 1, 'L')
        self.ln(5)
        self.cell(0, 10, f"Heure de début d'enregistrement : {start_time}", 0, 1, 'L')
        self.ln(5)
        self.cell(0, 10, f"Heure de fin d'enregistrement : {end_time}", 0, 1, 'L')
        self.ln(5)
        self.cell(0, 10, f"Durée de l'enregistrement : {duration}", 0, 1, 'L')
        self.ln(5)
        self.cell(0, 10, f"Nombre de sessions : {num_sessions}", 0, 1, 'L')
        self.ln(5)
        self.image("./assets/graph_top_10sessions.png", x=10, y=100, w=190)

        return self

    def add_session_summaries(self, ip1, port1, ip2, port2, image_path_1, image_path_2, image_path_3):
        self.add_page()

        self.set_font("Arial", size=12)
        self.cell(200, 10, txt=f"Résumé de la session: {ip1}:{port1} vers {ip2}:{port2}", ln=True, align='C')

        self.set_font("Arial", size=10)
        self.cell(200, 10, txt=f"Adresses IP impliquées: {ip1} <-> {ip2}", ln=True)
        self.cell(200, 10, txt=f"Protocole de transport: TCP", ln=True)
        self.cell(200, 10, txt=f"Ports: {port1} <-> {port2}", ln=True)

        self.ln(10)
        self.image(image_path_1, x=10, y=80, w=90)  # Gauche
        self.image(image_path_2, x=110, y=80, w=90)  # Droite
        self.image(image_path_3, x=10, y=150, w=190)  # Bas

        return self
