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


def find_best_column_match(fieldnames, target_names, threshold=0.6):
    """
    Trouve la meilleure correspondance de colonne parmi les noms de champs.

    Args:
        fieldnames: Liste des noms de colonnes du CSV
        target_names: Liste des noms possibles à rechercher (par priorité)
        threshold: Seuil de similarité minimum (0-1)

    Returns:
        Le nom de la colonne trouvée ou None
    """
    if not fieldnames:
        return None

    # Normalise les noms de colonnes pour comparaison
    def normalize(s):
        return s.lower().strip().replace('_', '').replace('-', '').replace(' ', '')

    normalized_fields = {normalize(f): f for f in fieldnames}

    # 1. Recherche exacte (insensible à la casse)
    for target in target_names:
        norm_target = normalize(target)
        if norm_target in normalized_fields:
            return normalized_fields[norm_target]

    # 2. Recherche par inclusion (le nom cible est contenu dans le champ)
    for target in target_names:
        norm_target = normalize(target)
        for norm_field, original_field in normalized_fields.items():
            if norm_target in norm_field or norm_field in norm_target:
                return original_field

    # 3. Similarité de Levenshtein simplifiée
    def similarity(s1, s2):
        """Calcule un score de similarité simple entre deux chaînes."""
        s1, s2 = normalize(s1), normalize(s2)
        if not s1 or not s2:
            return 0

        # Score basé sur les caractères communs
        common = sum(1 for c in s1 if c in s2)
        return (2.0 * common) / (len(s1) + len(s2))

    best_match = None
    best_score = threshold

    for target in target_names:
        for field in fieldnames:
            score = similarity(target, field)
            if score > best_score:
                best_score = score
                best_match = field

    return best_match


# Mapping des colonnes attendues vers leurs variations possibles
COLUMN_MAPPINGS = {
    'shipper': ['Shipper', 'ShipperName', 'SipperName', 'Sipper', 'Client', 'Expéditeur',
                'Expediteur', 'CustomerName', 'Customer', 'Nom Client', 'NomClient',
                'Société', 'Societe', 'Company', 'Account', 'Compte'],
    'carrier': ['Carrier name or Supplement', 'Carrier', 'Transporteur', 'CarrierName'],
    'method': ['PP Shipping method', 'Shipping method', 'Method', 'Méthode', 'Service'],
    'weight': ['Weight range', 'Weight', 'Poids', 'Tranche'],
    'service': ['Shipper Service', 'Service', 'ShipperService'],
    'quantity': ['Quantité', 'Quantity', 'Qty', 'Qté', 'Nombre', 'Count'],
    'price': ['Prix', 'Price', 'Montant', 'Amount', 'PU', 'Prix Unitaire', 'Unit Price'],
    'start_date': ['Invoice Staring date', 'Invoice Starting date', 'Start Date', 'StartDate',
                   'Date Début', 'DateDebut', 'From', 'Du'],
    'end_date': ['Invoice Ending date', 'End Date', 'EndDate', 'Date Fin', 'DateFin', 'To', 'Au'],
    'tva': ['TVA en %', 'TVA', 'VAT', 'Tax', 'Taxe', 'TVA %'],
    'invoice_num': ['Invoice Num', 'InvoiceNum', 'Invoice Number', 'Numéro Facture', 'NumFacture']
}


def map_csv_columns(fieldnames):
    """
    Crée un mapping entre les colonnes standards et les colonnes réelles du CSV.

    Returns:
        Dict avec les noms standards comme clés et les noms réels comme valeurs
    """
    mapping = {}
    for standard_name, variations in COLUMN_MAPPINGS.items():
        found = find_best_column_match(fieldnames, variations)
        if found:
            mapping[standard_name] = found
    return mapping


def normalize_row(row, column_mapping):
    """
    Normalise une ligne CSV en utilisant le mapping de colonnes.
    Retourne un dictionnaire avec les noms standards + les noms originaux.
    """
    normalized = {}

    # Copie toutes les valeurs originales
    for key, value in row.items():
        if key:
            normalized[key.strip()] = value.strip() if value else ''

    # Ajoute les clés standards mappées vers les valeurs
    standard_to_original = {
        'shipper': 'Shipper',
        'carrier': 'Carrier name or Supplement',
        'method': 'PP Shipping method',
        'weight': 'Weight range',
        'service': 'Shipper Service',
        'quantity': 'Quantité',
        'price': 'Prix',
        'start_date': 'Invoice Staring date',
        'end_date': 'Invoice Ending date',
        'tva': 'TVA en %',
        'invoice_num': 'Invoice Num'
    }

    for standard, original_key in standard_to_original.items():
        if standard in column_mapping:
            csv_column = column_mapping[standard]
            value = row.get(csv_column, '').strip() if row.get(csv_column) else ''
            # Met la valeur sous le nom original attendu par le reste du code
            normalized[original_key] = value

    return normalized


def parse_csv(csv_path):
    """
    Parse le fichier CSV et groupe les données par expéditeur.

    Cette version est intelligente et adaptative:
    - Détecte automatiquement le délimiteur (; ou ,)
    - Trouve les colonnes par similarité (insensible à la casse, typos tolérées)
    - Supporte plusieurs variations de noms de colonnes
    """
    data_by_shipper = defaultdict(list)

    with open(csv_path, 'r', encoding='utf-8-sig') as f:
        # Détecte le délimiteur
        sample = f.read(4096)
        f.seek(0)

        # Compte les occurrences pour mieux détecter
        semicolons = sample.count(';')
        commas = sample.count(',')
        delimiter = ';' if semicolons > commas else ','

        reader = csv.DictReader(f, delimiter=delimiter)

        # Nettoie les noms de colonnes (enlève les espaces et BOM)
        if reader.fieldnames:
            clean_fieldnames = [name.strip().lstrip('\ufeff') for name in reader.fieldnames]
            reader.fieldnames = clean_fieldnames

        # Crée le mapping intelligent des colonnes
        column_mapping = map_csv_columns(reader.fieldnames or [])

        # Trouve la colonne shipper
        shipper_column = column_mapping.get('shipper')

        if not shipper_column:
            print(f"⚠️  Colonnes détectées: {reader.fieldnames}")
            print(f"⚠️  Aucune colonne 'Shipper' trouvée. Colonnes attendues: {COLUMN_MAPPINGS['shipper']}")
            return data_by_shipper

        print(f"✓ Colonne shipper détectée: '{shipper_column}'")
        print(f"✓ Mapping des colonnes: {column_mapping}")

        for row in reader:
            # Normalise la ligne avec le mapping
            normalized_row = normalize_row(row, column_mapping)

            shipper = normalized_row.get('Shipper', '').strip()
            if shipper:
                data_by_shipper[shipper].append(normalized_row)

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


def generate_invoice_number(prefix="PP-2026-", year=None, sequence=None):
    """Génère un numéro de facture.

    Format: {prefix}{sequence}
    Le préfixe peut déjà contenir l'année (ex: PP-2026-)
    Exemple: PP-2026-0001, PP-2026-0002, etc.
    """
    if sequence is None:
        sequence = 1

    # Formater le numéro de séquence sur 4 chiffres
    if isinstance(sequence, int):
        seq_str = f"{sequence:04d}"
    else:
        seq_str = str(sequence).zfill(4)

    # Le préfixe contient déjà l'année et le tiret final
    return f"{prefix}{seq_str}"


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

        # Extraire la date de fin de période depuis les données CSV
        period_end_str = rows[0].get('Invoice Ending date', '') if rows else ''

        # Parser la date de fin de période (format DD/MM/YYYY ou similaire)
        period_date = None
        if period_end_str:
            for fmt in ['%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y', '%d.%m.%Y']:
                try:
                    period_date = datetime.strptime(period_end_str.strip(), fmt)
                    break
                except ValueError:
                    continue

        # Date d'échéance: dernier jour du mois de la période facturée
        # Si pas de période, utiliser le mois d'émission
        ref_date = period_date if period_date else emission_date

        if ref_date.month == 12:
            next_month = ref_date.replace(year=ref_date.year + 1, month=1, day=1)
        else:
            next_month = ref_date.replace(month=ref_date.month + 1, day=1)
        echeance_date = next_month - timedelta(days=1)

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
        total_ht, total_tva, total_ttc, tva_by_rate = self._calculate_totals(rows)
        elements.extend(self._build_payment_details(total_ht, total_tva, total_ttc, invoice_number, tva_by_rate))

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

        # Logo à droite (préserver le ratio d'aspect automatiquement)
        if os.path.exists(LOGO_PATH):
            # Laisser reportlab calculer les dimensions en préservant le ratio
            # On spécifie seulement la hauteur désirée
            from PIL import Image as PILImage
            with PILImage.open(LOGO_PATH) as img:
                orig_width, orig_height = img.size
                # Hauteur cible de 30mm, largeur calculée automatiquement
                target_height = 30*mm
                target_width = target_height * (orig_width / orig_height)
            logo = Image(LOGO_PATH, width=target_width, height=target_height)
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
        """Calcule les totaux HT, TVA par taux et TTC."""
        total_ht = Decimal('0.00')
        tva_by_rate = {}  # {taux: montant_tva}

        for row in rows:
            qty = int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
            price = format_price(row.get('Prix', '0'))
            tva_rate_str = row.get('TVA en %', '20').replace(',', '.').strip() or '20'
            tva_rate = Decimal(tva_rate_str)

            line_ht = price * qty
            line_tva = (line_ht * tva_rate / 100).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

            total_ht += line_ht

            # Grouper TVA par taux
            if tva_rate not in tva_by_rate:
                tva_by_rate[tva_rate] = Decimal('0.00')
            tva_by_rate[tva_rate] += line_tva

        total_tva = sum(tva_by_rate.values(), Decimal('0.00'))
        total_ttc = total_ht + total_tva

        return total_ht, total_tva, total_ttc, tva_by_rate

    def _build_payment_details(self, total_ht, total_tva, total_ttc, invoice_number, tva_by_rate=None):
        """Construit les détails de paiement et les totaux."""
        elements = []

        elements.append(Paragraph("<b>Détails du paiements</b>", self.styles['SectionTitle']))

        # Tableau à deux colonnes: infos bancaires à gauche, totaux à droite
        bank_info = [
            ["Nom du bénéficiaire", EMETTEUR['nom']],
            ["BIC", EMETTEUR['bic']],
            ["IBAN", EMETTEUR['iban']],
        ]

        # Construire les lignes de TVA par taux
        totals_info = [
            ["Total HT", format_currency(total_ht)],
        ]

        # Ajouter chaque taux de TVA séparément (triés par taux décroissant)
        if tva_by_rate:
            for rate in sorted(tva_by_rate.keys(), reverse=True):
                amount = tva_by_rate[rate]
                if amount > 0:  # N'afficher que si montant > 0
                    # Formater le taux (enlever les décimales inutiles: 20.00 -> 20, 5.50 -> 5.5)
                    rate_str = str(rate).rstrip('0').rstrip('.') if '.' in str(rate) else str(rate)
                    totals_info.append([f"TVA {rate_str}%", format_currency(amount)])

        totals_info.extend([
            ["Montant Total de la TVA", format_currency(total_tva)],
            ["", ""],
            ["<b>Total TTC</b>", f"<b>{format_currency(total_ttc)}</b>"],
        ])

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
