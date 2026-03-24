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
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML as WeasyHTML
import argparse


# Configuration de l'émetteur (Peoples Post)
EMETTEUR = {
    "nom": os.environ.get("EMETTEUR_NOM", "PEOPLES POST"),
    "adresse": os.environ.get("EMETTEUR_ADRESSE", "22 rue Emeriau"),
    "code_postal": os.environ.get("EMETTEUR_CP", "75015"),
    "ville": os.environ.get("EMETTEUR_VILLE", "Paris"),
    "pays": os.environ.get("EMETTEUR_PAYS", "FR"),
    "email": os.environ.get("EMETTEUR_EMAIL", "victor.estines@peoplespost.fr"),
    "siret": os.environ.get("EMETTEUR_SIRET", "98004432500010"),
    "bic": os.environ.get("EMETTEUR_BIC", "QNTOFRP1XXX"),
    "iban": os.environ.get("EMETTEUR_IBAN", "FR7616958000018908124561391"),
}

# Chemins
CLIENTS_CONFIG_FILE = os.path.join(os.path.dirname(__file__), "clients.json")
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
FONTS_DIR = os.path.join(os.path.dirname(__file__), "static", "fonts")
FONT_URL = f"file://{os.path.join(FONTS_DIR, 'Montserrat-Regular.ttf')}"

# Singletons (évite de recréer à chaque instance)
_jinja_env = None
_font_data = None

def _get_jinja_env():
    """Retourne un Environment Jinja2 singleton (compilé une seule fois)"""
    global _jinja_env
    if _jinja_env is None:
        _jinja_env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    return _jinja_env

def _get_font_data():
    """Charge les fonts en mémoire une seule fois"""
    global _font_data
    if _font_data is None:
        font_path = os.path.join(FONTS_DIR, 'Montserrat-Regular.ttf')
        if os.path.exists(font_path):
            with open(font_path, 'rb') as f:
                _font_data = f.read()
    return _font_data


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
    'shipper': ['Shipper', 'Shipper Name', 'ShipperName', 'SipperName', 'Sipper', 'Client', 'Expéditeur',
                'Expediteur', 'CustomerName', 'Customer', 'Nom Client', 'NomClient',
                'Société', 'Societe', 'Company', 'Account', 'Compte'],
    'siret': ['SIRET', 'SIRET NUM', 'Siret', 'N° SIRET', 'Numero SIRET', 'NumeroSIRET', 'SIREN',
              'Siret Client', 'Client SIRET', 'SIRET Client'],
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
    used_fields = set()
    for standard_name, variations in COLUMN_MAPPINGS.items():
        available = [f for f in fieldnames if f not in used_fields]
        found = find_best_column_match(available, variations)
        if found:
            mapping[standard_name] = found
            used_fields.add(found)
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
        'siret': 'SIRET',
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
    """Générateur de factures PDF via HTML → WeasyPrint."""

    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._jinja_env = _get_jinja_env()
        # Pré-charger les fonts en mémoire
        _get_font_data()

    def generate_invoice(self, shipper_name, rows, client_info, invoice_number, emission_date=None):
        """Génère une facture PDF via HTML → WeasyPrint."""
        if emission_date is None:
            emission_date = datetime.now()

        # Date d'échéance : dernier jour du mois d'émission
        if emission_date.month == 12:
            next_month = emission_date.replace(year=emission_date.year + 1, month=1, day=1)
        else:
            next_month = emission_date.replace(month=emission_date.month + 1, day=1)
        echeance_date = next_month - timedelta(days=1)

        filename = f"facture_{invoice_number.replace('-', '_')}_{shipper_name.replace(' ', '_')}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        # Calcul des totaux
        total_ht, total_tva, total_ttc, tva_by_rate = self._calculate_totals(rows)

        # Préparation des lignes du tableau
        items = []
        for row in rows:
            main_line, sub_line = build_description(row)
            qty = int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
            price = format_price(row.get('Prix', '0'))
            tva = row.get('TVA en %', '20').replace(',', '.').strip() or '20'
            line_ht = price * qty
            items.append({
                'main_line': main_line,
                'sub_line': sub_line,
                'quantity': qty,
                'unit_price': format_currency(price),
                'tax_rate': tva,
                'total_ht': format_currency(line_ht),
            })

        # Détail TVA par taux
        tax_breakdown = []
        for rate in sorted(tva_by_rate.keys(), reverse=True):
            amount = tva_by_rate[rate]
            if amount > 0:
                rate_str = str(rate).rstrip('0').rstrip('.') if '.' in str(rate) else str(rate)
                tax_breakdown.append({'rate': rate_str, 'amount': format_currency(amount)})

        # Données du template
        context = {
            'document_title': 'Facture',
            'invoice_number': invoice_number,
            'invoice_date': emission_date.strftime('%d/%m/%Y'),
            'due_date': echeance_date.strftime('%d/%m/%Y'),
            'customer': {
                'name': client_info.get('nom', shipper_name),
                'address': client_info.get('adresse', ''),
                'postal_code': client_info.get('code_postal', ''),
                'city': client_info.get('ville', ''),
                'country': client_info.get('pays', 'France'),
                'email': client_info.get('email', ''),
                'siret': client_info.get('siret', ''),
            },
            'items': items,
            'subtotal': format_currency(total_ht),
            'tax_breakdown': tax_breakdown,
            'tax_total': format_currency(total_tva),
            'grand_total': format_currency(total_ttc),
            'notes': None,
            'font_url': FONT_URL,
            'font_bold_url': FONT_URL,
            'emetteur': EMETTEUR,
        }

        # Rendu HTML → PDF
        template = self._jinja_env.get_template('invoice_pdf.html')
        html_string = template.render(**context)
        WeasyHTML(string=html_string, base_url=os.path.dirname(__file__)).write_pdf(filepath)

        return filepath, total_ttc

    def _calculate_totals(self, rows):
        """Calcule les totaux HT, TVA par taux et TTC."""
        total_ht = Decimal('0.00')
        tva_by_rate = {}

        for row in rows:
            qty = int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
            price = format_price(row.get('Prix', '0'))
            tva_rate_str = row.get('TVA en %', '20').replace(',', '.').strip() or '20'
            tva_rate = Decimal(tva_rate_str)

            line_ht = price * qty
            line_tva = (line_ht * tva_rate / 100).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            total_ht += line_ht

            tva_by_rate.setdefault(tva_rate, Decimal('0.00'))
            tva_by_rate[tva_rate] += line_tva

        total_tva = sum(tva_by_rate.values(), Decimal('0.00'))
        total_ttc = total_ht + total_tva

        return total_ht, total_tva, total_ttc, tva_by_rate


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
