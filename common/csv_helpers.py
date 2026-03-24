"""
Helpers pour le parsing des CSV de détail.
"""

import csv
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def parse_details_csv(filepath):
    """Parse le CSV de détail et groupe les lignes par SIRET et par nom de shipper."""
    details_by_siret = defaultdict(list)
    details_by_name = defaultdict(list)

    shipper_variations = ['shipper', 'shipper name', 'shippername', 'client', 'expéditeur', 'expediteur']

    for encoding in ['utf-8-sig', 'utf-16', 'latin-1', 'cp1252']:
        try:
            details_by_siret = defaultdict(list)
            details_by_name = defaultdict(list)
            with open(filepath, 'r', encoding=encoding) as f:
                sample = f.read(4096)
                f.seek(0)
                delimiter = ';' if sample.count(';') > sample.count(',') else ','

                reader = csv.DictReader(f, delimiter=delimiter)
                if reader.fieldnames:
                    reader.fieldnames = [n.strip().lstrip('\ufeff') for n in reader.fieldnames]

                logger.debug(f"[parse_details_csv] Encoding={encoding}, delimiter='{delimiter}', nb_colonnes={len(reader.fieldnames) if reader.fieldnames else 0}")

                siret_col = None
                siret_variations_list = ['siret num', 'siret', 'numero siret', 'siret number', 'n° siret', 'num siret']
                for fieldname in (reader.fieldnames or []):
                    if fieldname.lower().strip() in siret_variations_list:
                        siret_col = fieldname
                        break

                shipper_col = None
                for fieldname in (reader.fieldnames or []):
                    if fieldname.lower().strip() in shipper_variations:
                        shipper_col = fieldname
                        break

                if not siret_col and not shipper_col:
                    logger.debug(f"[parse_details_csv] Ni SIRET ni Shipper trouvé avec encoding={encoding}")
                    continue

                logger.debug(f"[parse_details_csv] Colonne SIRET: '{siret_col}', Colonne Shipper: '{shipper_col}'")

                for row in reader:
                    row_dict = dict(row)
                    if siret_col:
                        raw_siret = row.get(siret_col, '') or ''
                        clean_siret_val = ''.join(c for c in str(raw_siret) if c.isdigit())
                        if clean_siret_val:
                            details_by_siret[clean_siret_val].append(row_dict)
                    if shipper_col:
                        raw_name = (row.get(shipper_col, '') or '').strip()
                        if raw_name:
                            details_by_name[raw_name].append(row_dict)

                logger.debug(f"[parse_details_csv] Résultat: {len(details_by_siret)} SIRETs, {len(details_by_name)} noms, {sum(len(v) for v in details_by_siret.values())} lignes")
            break
        except (UnicodeDecodeError, UnicodeError):
            logger.debug(f"[parse_details_csv] Encoding {encoding} échoué, essai suivant...")
            continue

    return details_by_siret, details_by_name


def save_detail_csv(rows, filepath):
    """Sauvegarde les lignes de détail dans un CSV UTF-8 BOM (compatible Excel)."""
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()
        writer.writerows(rows)
