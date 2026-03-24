"""
Helpers pour l'historique des factures : construction, mise à jour, nettoyage.
"""

import os
import json
import logging
from datetime import datetime
from pymongo import ReturnDocument

from common.config import INVOICE_HISTORY_FILE
from common.database import invoice_history_collection
from common.helpers import safe_filepath

logger = logging.getLogger(__name__)


def load_invoice_history(limit=100):
    """Charge l'historique des factures depuis MongoDB (limité par défaut)"""
    query = invoice_history_collection.find().sort('created_at', -1)
    if limit:
        query = query.limit(limit)
    history = list(query)
    if history:
        for h in history:
            h['_id'] = str(h['_id']) if '_id' in h else h.get('id')
        return history
    # Migration: charger depuis le fichier JSON si existe
    if os.path.exists(INVOICE_HISTORY_FILE):
        with open(INVOICE_HISTORY_FILE, 'r', encoding='utf-8') as f:
            history = json.load(f)
            if history:
                for h in history:
                    invoice_history_collection.insert_one(h)
            return history
    return []


def save_invoice_history(history):
    """Sauvegarde l'historique des factures dans MongoDB (remplace tout)"""
    invoice_history_collection.delete_many({})
    if history:
        invoice_history_collection.insert_many(history)


def _build_history_entry(invoice_data, batch_id):
    """Construit un document historique à partir des données de facture"""
    return {
        'id': f"{batch_id}_{invoice_data['invoice_number']}",
        'invoice_number': invoice_data['invoice_number'],
        'client_name': invoice_data.get('company_name', invoice_data.get('shipper', '')),
        'shipper': invoice_data.get('shipper', ''),
        'total_ht': invoice_data.get('total_ht', 0),
        'total_tva': invoice_data.get('total_tva', invoice_data.get('total_ttc', 0) - invoice_data.get('total_ht', 0)),
        'total_ttc': invoice_data.get('total_ttc', 0),
        'total_ht_formatted': invoice_data.get('total_ht_formatted', ''),
        'total_ttc_formatted': invoice_data.get('total_ttc_formatted', ''),
        'filename': invoice_data.get('filename', ''),
        'batch_id': batch_id,
        'period': invoice_data.get('period', ''),
        'client_email': invoice_data.get('client_email', ''),
        'email_sent': invoice_data.get('email_sent', False),
        'created_at': datetime.now().isoformat(),
        'payment_status': 'pending',
        'reminder_1_sent': False,
        'reminder_1_at': None,
        'reminder_2_sent': False,
        'reminder_2_at': None,
        'reminder_3_sent': False,
        'reminder_3_at': None,
        'reminder_4_sent': False,
        'reminder_4_at': None,
        'client_siret': invoice_data.get('client_siret', ''),
        'detail_filename': invoice_data.get('detail_filename', None),
        'has_detail': invoice_data.get('has_detail', False),
        'emission_date': invoice_data.get('emission_date', ''),
        'due_date': invoice_data.get('due_date', '')
    }


def add_to_invoice_history(invoice_data, batch_id):
    """Ajoute une facture à l'historique dans MongoDB"""
    history_entry = _build_history_entry(invoice_data, batch_id)
    invoice_history_collection.insert_one(history_entry)
    return history_entry


def update_invoice_in_history(invoice_id, updates):
    """Met à jour une facture dans l'historique MongoDB"""
    result = invoice_history_collection.find_one_and_update(
        {'id': invoice_id},
        {'$set': updates},
        return_document=ReturnDocument.AFTER
    )
    if result:
        result['_id'] = str(result['_id']) if '_id' in result else result.get('id')
        return result
    return None


def cleanup_invoice_files(invoices, output_folder):
    """Supprime les fichiers PDF/détail des factures et les dossiers batch vides"""
    batch_dirs_to_check = set()
    for inv in invoices:
        batch_id = inv.get('batch_id')
        if not batch_id:
            continue
        batch_folder = safe_filepath(output_folder, f"batch_{batch_id}")
        if not batch_folder or not os.path.isdir(batch_folder):
            continue
        batch_dirs_to_check.add(batch_folder)
        filename = inv.get('filename')
        if filename:
            pdf_path = safe_filepath(output_folder, f"batch_{batch_id}", filename)
            if pdf_path and os.path.isfile(pdf_path):
                os.remove(pdf_path)
        detail_filename = inv.get('detail_filename')
        if detail_filename:
            detail_path = safe_filepath(output_folder, f"batch_{batch_id}", detail_filename)
            if detail_path and os.path.isfile(detail_path):
                os.remove(detail_path)

    for batch_dir in batch_dirs_to_check:
        if not os.path.isdir(batch_dir):
            continue
        remaining = os.listdir(batch_dir)
        if not remaining:
            os.rmdir(batch_dir)
