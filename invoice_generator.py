#!/usr/bin/env python3
"""
Peoples Post - Outil de génération de factures à partir de CSV
Convertit les fichiers CSV d'expédition en factures PDF professionnelles.
"""

import csv
import os
import json
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
from collections import defaultdict
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import argparse


# Configuration de l'émetteur (Peoples Post)
EMETTEUR = {
    "nom": "PEOPLES POST",
    "adresse": "22 rue Emeriau",
    "code_postal": "75015",
    "ville": "Paris",
    "pays": "FR",
    "email": "victor.estines@peoplespost.fr",
    "siret": "98004432500010",
    "bic": "QNTOFRP1XXX",
    "iban": "FR7616958000018908124561391"
}

# Chemin vers le fichier de configuration des clients
CLIENTS_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "clients.json")

# Chemin vers le logo
LOGO_PATH = os.path.join(os.path.dirname(__file__), "logo.png")


def load_clients_config():
    """Charge la configuration des clients depuis le fichier JSON."""
    if os.path.exists(CLIENTS_CONFIG_FILE):
        with open(CLIENTS_CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def save_clients_config(clients):
    """Sauvegarde la configuration des clients."""
    with open(CLIENTS_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(clients, f, indent=2, ensure_ascii=False)


def get_client_info(shipper_name, clients_config):
    """Récupère les informations d'un client ou crée une entrée par défaut."""
    if shipper_name in clients_config:
        return clients_config[shipper_name]

    # Créer une entrée par défaut
    default_client = {
        "nom": shipper_name,
        "adresse": "Adresse à compléter",
        "code_postal": "00000",
        "ville": "Ville",
        "pays": "France",
        "email": "email@example.com",
        "siret": "00000000000000"
    }
    clients_config[shipper_name] = default_client
    save_clients_config(clients_config)
    return default_client


def parse_csv(csv_path):
    """Parse le fichier CSV et groupe les données par expéditeur (Shipper)."""
    data_by_shipper = defaultdict(list)

    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        # Détecte le délimiteur
        sample = f.read(2048)
        f.seek(0)

        if ';' in sample:
            delimiter = ';'
        else:
            delimiter = ','

        reader = csv.DictReader(f, delimiter=delimiter)

        # Nettoie les noms de colonnes (enlève les espaces)
        if reader.fieldnames:
            clean_fieldnames = [name.strip() for name in reader.fieldnames]
            reader.fieldnames = clean_fieldnames

        for row in reader:
            # Nettoie aussi les clés du row
            clean_row = {k.strip(): v for k, v in row.items()}
            shipper = clean_row.get('Shipper', '').strip()
            if shipper:
                data_by_shipper[shipper].append(clean_row)

    return data_by_shipper


def format_price(value):
    """Formate un prix en euros avec 2 décimales."""
    try:
        # Gère les virgules comme séparateur décimal
        if isinstance(value, str):
            value = value.replace(',', '.').strip()
        d = Decimal(str(value)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        return d
    except:
        return Decimal('0.00')


def format_currency(amount):
    """Formate un montant pour affichage (format européen)."""
    formatted = f"{amount:,.2f}".replace(',', ' ').replace('.', ',')
    return f"{formatted} €"


def generate_invoice_number(prefix="PP", year=None, sequence=None):
    """Génère un numéro de facture unique."""
    if year is None:
        year = datetime.now().year
    if sequence is None:
        sequence = datetime.now().strftime("%m%d%H%M")
    return f"{prefix}-{year}-{sequence:04d}" if isinstance(sequence, int) else f"{prefix}-{year}-{sequence}"


def build_description(row):
    """Construit la description d'une ligne de facture."""
    carrier = row.get('Carrier name or Supplement', '').strip()
    method = row.get('PP Shipping method', '').strip()
    weight = row.get('Weight range', '').strip()
    service = row.get('Shipper Service', '').strip()
    start_date = row.get('Invoice Staring date', '').strip()
    end_date = row.get('Invoice Ending date', '').strip()

    # Construction de la description principale
    if method and weight:
        # Ligne de service d'expédition
        main_line = f"{carrier} – {method} {weight}"
        if service:
            sub_line = f"{service} du {start_date} au {end_date}"
        else:
            sub_line = f"du {start_date} au {end_date}"
    else:
        # Supplément ou charge
        main_line = f"{carrier} –"
        sub_line = f"du {start_date} au {end_date}"

    return main_line, sub_line


class InvoicePDFGenerator:
    """Générateur de factures PDF."""

    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Configure les styles personnalisés."""
        self.styles.add(ParagraphStyle(
            name='InvoiceTitle',
            fontSize=24,
            fontName='Helvetica-Bold',
            textColor=colors.black,
            spaceAfter=10
        ))

        self.styles.add(ParagraphStyle(
            name='CompanyName',
            fontSize=14,
            fontName='Helvetica-Bold',
            textColor=colors.black,
            spaceAfter=5
        ))

        self.styles.add(ParagraphStyle(
            name='CompanyInfo',
            fontSize=10,
            fontName='Helvetica',
            textColor=colors.black,
            spaceAfter=2
        ))

        self.styles.add(ParagraphStyle(
            name='TableHeader',
            fontSize=9,
            fontName='Helvetica-Bold',
            textColor=colors.black
        ))

        self.styles.add(ParagraphStyle(
            name='TableCell',
            fontSize=9,
            fontName='Helvetica',
            textColor=colors.black
        ))

        self.styles.add(ParagraphStyle(
            name='TableSubCell',
            fontSize=8,
            fontName='Helvetica',
            textColor=colors.grey
        ))

        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            fontSize=12,
            fontName='Helvetica-Bold',
            textColor=colors.black,
            spaceBefore=20,
            spaceAfter=10
        ))

        self.styles.add(ParagraphStyle(
            name='Footer',
            fontSize=8,
            fontName='Helvetica',
            textColor=colors.black
        ))

    def generate_invoice(self, shipper_name, rows, client_info, invoice_number, emission_date=None):
        """Génère une facture PDF pour un expéditeur."""

        if emission_date is None:
            emission_date = datetime.now()

        echeance_date = emission_date + timedelta(days=30)

        filename = f"facture_{invoice_number.replace('-', '_')}_{shipper_name.replace(' ', '_')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=20*mm,
            leftMargin=20*mm,
            topMargin=20*mm,
            bottomMargin=20*mm
        )

        elements = []

        # En-tête avec logo et titre
        elements.extend(self._build_header(invoice_number, emission_date, echeance_date))

        # Informations émetteur et client
        elements.extend(self._build_parties_info(client_info))

        # Tableau des lignes de facture
        elements.extend(self._build_invoice_table(rows))

        # Détails de paiement et totaux
        total_ht, total_tva, total_ttc = self._calculate_totals(rows)
        elements.extend(self._build_payment_details(total_ht, total_tva, total_ttc, invoice_number))

        # Mentions légales
        elements.extend(self._build_legal_mentions())

        doc.build(elements)

        return filepath, total_ttc

    def _build_header(self, invoice_number, emission_date, echeance_date):
        """Construit l'en-tête de la facture."""
        elements = []

        # Tableau pour le logo et le titre
        header_data = []

        # Titre "Facture" à gauche
        title = Paragraph("<u>Facture</u>", self.styles['InvoiceTitle'])

        # Logo à droite
        if os.path.exists(LOGO_PATH):
            logo = Image(LOGO_PATH, width=50*mm, height=25*mm)
        else:
            logo = Paragraph("PEOPLES POST", self.styles['CompanyName'])

        header_data.append([title, logo])

        header_table = Table(header_data, colWidths=[100*mm, 70*mm])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))

        elements.append(header_table)
        elements.append(Spacer(1, 10*mm))

        # Informations de facture
        invoice_info = [
            ["Numéro de facture", invoice_number],
            ["Date d'émission", emission_date.strftime("%d/%m/%Y")],
            ["Date d'échéance", echeance_date.strftime("%d/%m/%Y")],
        ]

        for label, value in invoice_info:
            p = Paragraph(f"<b>{label}</b>     {value}", self.styles['CompanyInfo'])
            elements.append(p)

        elements.append(Spacer(1, 10*mm))

        return elements

    def _build_parties_info(self, client_info):
        """Construit les informations émetteur et client."""
        elements = []

        # Tableau à deux colonnes pour émetteur et client
        emetteur_content = [
            Paragraph(f"<b>{EMETTEUR['nom']}</b>", self.styles['CompanyName']),
            Paragraph(EMETTEUR['adresse'], self.styles['CompanyInfo']),
            Paragraph(f"{EMETTEUR['code_postal']}, {EMETTEUR['ville']}, {EMETTEUR['pays']}", self.styles['CompanyInfo']),
            Paragraph(EMETTEUR['email'], self.styles['CompanyInfo']),
            Paragraph(f"SIRET {EMETTEUR['siret']}", self.styles['CompanyInfo']),
        ]

        client_content = [
            Paragraph(f"<b>{client_info['nom']}</b>", self.styles['CompanyName']),
            Paragraph(client_info['adresse'], self.styles['CompanyInfo']),
            Paragraph(f"{client_info['code_postal']}, {client_info['ville']}, {client_info['pays']}", self.styles['CompanyInfo']),
            Paragraph(client_info['email'], self.styles['CompanyInfo']),
            Paragraph(f"SIRET {client_info['siret']}", self.styles['CompanyInfo']),
        ]

        # Créer les cellules
        left_cell = []
        for p in emetteur_content:
            left_cell.append(p)

        right_cell = []
        for p in client_content:
            right_cell.append(p)

        parties_table = Table(
            [[left_cell, right_cell]],
            colWidths=[85*mm, 85*mm]
        )
        parties_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))

        elements.append(parties_table)
        elements.append(Spacer(1, 15*mm))

        return elements

    def _build_invoice_table(self, rows):
        """Construit le tableau des lignes de facture."""
        elements = []

        # En-tête du tableau
        header = [
            Paragraph("<b>Description</b>", self.styles['TableHeader']),
            Paragraph("<b>Quantité</b>", self.styles['TableHeader']),
            Paragraph("<b>Prix unitaire</b>", self.styles['TableHeader']),
            Paragraph("<b>TVA (%)</b>", self.styles['TableHeader']),
            Paragraph("<b>Total HT</b>", self.styles['TableHeader']),
        ]

        table_data = [header]

        # Lignes de données
        for row in rows:
            main_line, sub_line = build_description(row)

            qty = int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
            price = format_price(row.get('Prix', '0'))
            tva = row.get('TVA en %', '20').replace(',', '.').strip() or '20'
            total_ht = price * qty

            # Description sur deux lignes
            desc = Paragraph(
                f"{main_line}<br/><font size='8' color='grey'>{sub_line}</font>",
                self.styles['TableCell']
            )

            table_data.append([
                desc,
                Paragraph(str(qty), self.styles['TableCell']),
                Paragraph(format_currency(price), self.styles['TableCell']),
                Paragraph(f"{tva} %", self.styles['TableCell']),
                Paragraph(format_currency(total_ht), self.styles['TableCell']),
            ])

        # Créer le tableau
        col_widths = [80*mm, 20*mm, 25*mm, 20*mm, 25*mm]

        invoice_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        invoice_table.setStyle(TableStyle([
            # En-tête
            ('BACKGROUND', (0, 0), (-1, 0), colors.Color(0.95, 0.95, 0.95)),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),

            # Corps
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 8),

            # Alignement
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (-1, 0), (-1, -1), 'RIGHT'),
            ('ALIGN', (-2, 0), (-2, -1), 'RIGHT'),

            # Bordures
            ('LINEBELOW', (0, 0), (-1, 0), 1, colors.Color(0.8, 0.8, 0.8)),
            ('LINEBELOW', (0, 1), (-1, -2), 0.5, colors.Color(0.9, 0.9, 0.9)),
            ('LINEBELOW', (0, -1), (-1, -1), 1, colors.Color(0.8, 0.8, 0.8)),

            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))

        elements.append(invoice_table)
        elements.append(Spacer(1, 10*mm))

        return elements

    def _calculate_totals(self, rows):
        """Calcule les totaux HT, TVA et TTC."""
        total_ht = Decimal('0.00')
        total_tva = Decimal('0.00')

        for row in rows:
            qty = int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
            price = format_price(row.get('Prix', '0'))
            tva_rate = Decimal(row.get('TVA en %', '20').replace(',', '.').strip() or '20')

            line_ht = price * qty
            line_tva = (line_ht * tva_rate / 100).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

            total_ht += line_ht
            total_tva += line_tva

        total_ttc = total_ht + total_tva

        return total_ht, total_tva, total_ttc

    def _build_payment_details(self, total_ht, total_tva, total_ttc, invoice_number):
        """Construit les détails de paiement et les totaux."""
        elements = []

        elements.append(Paragraph("<b>Détails du paiements</b>", self.styles['SectionTitle']))

        # Tableau à deux colonnes: infos bancaires à gauche, totaux à droite
        bank_info = [
            ["Nom du bénéficiaire", EMETTEUR['nom']],
            ["BIC", EMETTEUR['bic']],
            ["IBAN", EMETTEUR['iban']],
        ]

        totals_info = [
            ["Total HT", format_currency(total_ht)],
            ["TVA 20%", format_currency(total_tva)],
            ["Montant Total de la TVA", format_currency(total_tva)],
            ["", ""],
            ["<b>Total TTC</b>", f"<b>{format_currency(total_ttc)}</b>"],
        ]

        # Infos bancaires
        bank_content = []
        for label, value in bank_info:
            p = Paragraph(f"<b>{label}</b>     {value}", self.styles['CompanyInfo'])
            bank_content.append(p)

        # Totaux
        totals_data = []
        for label, value in totals_info:
            totals_data.append([
                Paragraph(label, self.styles['CompanyInfo']),
                Paragraph(value, self.styles['CompanyInfo'])
            ])

        totals_table = Table(totals_data, colWidths=[45*mm, 30*mm])
        totals_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('LINEABOVE', (0, -1), (-1, -1), 1, colors.black),
            ('TOPPADDING', (0, -1), (-1, -1), 5),
        ]))

        # Assemblage
        main_table = Table(
            [[bank_content, totals_table]],
            colWidths=[95*mm, 75*mm]
        )
        main_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ]))

        elements.append(main_table)
        elements.append(Spacer(1, 15*mm))

        # Ligne de signature
        signature = Paragraph(
            f"PEOPLES POST SAS <font color='white'>{'_' * 100}</font> {invoice_number}",
            self.styles['CompanyInfo']
        )
        elements.append(signature)
        elements.append(Spacer(1, 5*mm))

        return elements

    def _build_legal_mentions(self):
        """Construit les mentions légales obligatoires."""
        elements = []

        mentions = [
            "Type de transaction : Bien et service",
            "Pas d'escompte accordé pour paiement anticipé.",
            "En cas de non-paiement à la date d'échéance, des pénalités calculées à trois fois le taux d'intérêt légal seront appliquées.",
            "Tout retard de paiement entraînera une indemnité forfaitaire pour frais de recouvrement de 40€.",
        ]

        for mention in mentions:
            p = Paragraph(mention, self.styles['Footer'])
            elements.append(p)
            elements.append(Spacer(1, 2*mm))

        return elements


def main():
    parser = argparse.ArgumentParser(
        description="Générateur de factures PDF Peoples Post",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python invoice_generator.py input.csv
  python invoice_generator.py input.csv -o factures/
  python invoice_generator.py input.csv --prefix PP-2025
        """
    )

    parser.add_argument('csv_file', help="Chemin vers le fichier CSV d'entrée")
    parser.add_argument('-o', '--output', default='output', help="Dossier de sortie pour les PDF (défaut: output)")
    parser.add_argument('--prefix', default='PP', help="Préfixe pour les numéros de facture (défaut: PP)")
    parser.add_argument('--start-number', type=int, default=1, help="Numéro de départ pour les factures (défaut: 1)")

    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"Erreur: Le fichier {args.csv_file} n'existe pas.")
        return 1

    print(f"Lecture du fichier CSV: {args.csv_file}")
    data_by_shipper = parse_csv(args.csv_file)

    if not data_by_shipper:
        print("Aucune donnée trouvée dans le fichier CSV.")
        return 1

    print(f"Nombre d'expéditeurs trouvés: {len(data_by_shipper)}")

    # Charger la configuration des clients
    clients_config = load_clients_config()

    # Générer les factures
    generator = InvoicePDFGenerator(output_dir=args.output)
    year = datetime.now().year

    invoice_num = args.start_number
    generated_files = []

    for shipper_name, rows in data_by_shipper.items():
        print(f"\nTraitement de: {shipper_name} ({len(rows)} lignes)")

        client_info = get_client_info(shipper_name, clients_config)
        invoice_number = generate_invoice_number(args.prefix, year, invoice_num)

        filepath, total_ttc = generator.generate_invoice(
            shipper_name,
            rows,
            client_info,
            invoice_number
        )

        generated_files.append((filepath, shipper_name, total_ttc))
        print(f"  -> Facture générée: {filepath}")
        print(f"     Total TTC: {format_currency(total_ttc)}")

        invoice_num += 1

    print(f"\n{'='*60}")
    print(f"Génération terminée!")
    print(f"Nombre de factures générées: {len(generated_files)}")
    print(f"Dossier de sortie: {os.path.abspath(args.output)}")

    # Vérifier si des clients ont des informations manquantes
    save_clients_config(clients_config)
    print(f"\nConfiguration des clients sauvegardée dans: {CLIENTS_CONFIG_FILE}")
    print("IMPORTANT: Veuillez vérifier et compléter les informations des clients dans ce fichier.")

    return 0


if __name__ == "__main__":
    exit(main())
