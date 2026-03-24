"""
Blueprint History : historique factures, paiement, relances, opérations en masse.
"""

import os
import csv
import json
import uuid
import zipfile
import logging
from io import BytesIO
from datetime import datetime
from flask import Blueprint, jsonify, request, send_file, current_app
from flask_login import login_required

from common.config import BATCH_DATA_FILE
from common.database import invoice_history_collection, init_invoice_counter
from common.helpers import safe_filepath
from common.client_matching import load_clients_config, get_client_info
from common.invoice_helpers import (
    load_invoice_history, update_invoice_in_history, cleanup_invoice_files
)
from common.email_service import (
    load_email_config, send_invoice_email, send_reminder_email
)
from invoice_generator import parse_csv, InvoicePDFGenerator

logger = logging.getLogger(__name__)

history_bp = Blueprint('history', __name__)


# =============================================================================
# Numéro de facture
# =============================================================================

@history_bp.route('/api/history/next-invoice-number')
@login_required
def get_next_invoice_number():
    """Retourne le prochain numéro de séquence disponible"""
    prefix_base = request.args.get('prefix', 'PP')
    year = request.args.get('year', str(datetime.now().year))
    prefix = f"{prefix_base}-{year}-"

    seq = init_invoice_counter(prefix)
    return jsonify({'next_number': seq + 1})


# =============================================================================
# Liste & Filtres
# =============================================================================

@history_bp.route('/api/history', methods=['GET'])
@login_required
def get_invoice_history():
    """Récupère l'historique des factures avec pagination et filtres avancés"""
    search = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 200)

    filter_siret = request.args.get('siret', '').strip()
    filter_company = request.args.get('company', '').strip()
    filter_emission_from = request.args.get('emission_from', '').strip()
    filter_emission_to = request.args.get('emission_to', '').strip()
    filter_due_from = request.args.get('due_from', '').strip()
    filter_due_to = request.args.get('due_to', '').strip()

    query = {}
    conditions = []

    if search:
        regex = {'$regex': search, '$options': 'i'}
        conditions.append({'$or': [
            {'invoice_number': regex},
            {'client_name': regex},
            {'shipper': regex}
        ]})

    if filter_siret:
        conditions.append({'client_siret': {'$regex': filter_siret, '$options': 'i'}})

    if filter_company:
        company_regex = {'$regex': filter_company, '$options': 'i'}
        conditions.append({'$or': [
            {'client_name': company_regex},
            {'shipper': company_regex}
        ]})

    if filter_emission_from:
        conditions.append({'$or': [
            {'emission_date': {'$gte': filter_emission_from}},
            {'emission_date': {'$exists': False}, 'created_at': {'$gte': filter_emission_from}}
        ]})
    if filter_emission_to:
        conditions.append({'$or': [
            {'emission_date': {'$lte': filter_emission_to + 'T23:59:59'}},
            {'emission_date': {'$exists': False}, 'created_at': {'$lte': filter_emission_to + 'T23:59:59'}}
        ]})

    if filter_due_from:
        conditions.append({'due_date': {'$gte': filter_due_from}})
    if filter_due_to:
        conditions.append({'due_date': {'$lte': filter_due_to + 'T23:59:59'}})

    if conditions:
        query = {'$and': conditions} if len(conditions) > 1 else conditions[0]

    total = invoice_history_collection.count_documents(query)
    skip = (page - 1) * per_page

    history = list(
        invoice_history_collection.find(query)
        .sort('created_at', -1)
        .skip(skip)
        .limit(per_page)
    )

    for h in history:
        h['_id'] = str(h['_id']) if '_id' in h else h.get('id')

    return jsonify({
        'success': True,
        'history': history,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })


# =============================================================================
# CRUD facture
# =============================================================================

@history_bp.route('/api/history/<invoice_id>', methods=['DELETE'])
@login_required
def delete_from_history(invoice_id):
    """Supprime une facture de l'historique et ses fichiers"""
    invoice = invoice_history_collection.find_one({'id': invoice_id})
    if invoice:
        cleanup_invoice_files([invoice], current_app.config['OUTPUT_FOLDER'])
    invoice_history_collection.delete_one({'id': invoice_id})
    return jsonify({'success': True})


@history_bp.route('/api/history/<invoice_id>/upload-pdf', methods=['POST'])
@login_required
def upload_pdf_for_history(invoice_id):
    """Recharge le PDF d'une facture de l'historique"""
    invoice = invoice_history_collection.find_one({'id': invoice_id})
    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'Aucun fichier fourni'}), 400
    if not file.filename.lower().endswith('.pdf'):
        return jsonify({'error': 'Le fichier doit être un PDF'}), 400

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')
    batch_folder = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    if not batch_folder:
        return jsonify({'error': 'Chemin de batch invalide'}), 400
    os.makedirs(batch_folder, exist_ok=True)
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath:
        return jsonify({'error': 'Chemin de fichier invalide'}), 400
    file.save(filepath)

    return jsonify({'success': True})


@history_bp.route('/api/history/<invoice_id>/regenerate-pdf', methods=['POST'])
@login_required
def regenerate_pdf_from_csv(invoice_id):
    """Régénère le PDF d'une facture depuis un CSV re-uploadé"""
    invoice = invoice_history_collection.find_one({'id': invoice_id})
    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    tmp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], f"regen_{uuid.uuid4().hex}.csv")
    file.save(tmp_path)

    try:
        data_by_shipper = parse_csv(tmp_path)
        shipper_name = invoice.get('shipper', '')

        rows = data_by_shipper.get(shipper_name)
        if not rows:
            if len(data_by_shipper) == 1:
                rows = list(data_by_shipper.values())[0]
            else:
                available = ', '.join(data_by_shipper.keys())
                return jsonify({'error': f'Expéditeur "{shipper_name}" non trouvé dans le CSV. Disponibles : {available}'}), 400

        clients_config = load_clients_config()
        csv_siret = rows[0].get('SIRET', '') if rows else ''
        client_info = get_client_info(shipper_name, clients_config, csv_siret=csv_siret)

        batch_id = invoice.get('batch_id')
        invoice_number = invoice.get('invoice_number')
        emission_date_str = invoice.get('emission_date', '')
        try:
            emission_date = datetime.fromisoformat(emission_date_str)
        except Exception:
            emission_date = datetime.now()

        batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
        os.makedirs(batch_folder, exist_ok=True)

        generator = InvoicePDFGenerator(output_dir=batch_folder)
        generator.generate_invoice(shipper_name, rows, client_info, invoice_number, emission_date=emission_date)

        return jsonify({'success': True})

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


# =============================================================================
# Téléchargement / Visualisation depuis l'historique
# =============================================================================

@history_bp.route('/api/history/download/<invoice_id>')
@login_required
def download_from_history(invoice_id):
    """Télécharge une facture depuis l'historique (ZIP si détail CSV existe)"""
    history = load_invoice_history()
    invoice = next((h for h in history if h.get('id') == invoice_id), None)

    if not invoice:
        return jsonify({'error': 'Facture non trouvée dans l\'historique'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    detail_filename = invoice.get('detail_filename')
    detail_path = None
    if detail_filename:
        detail_path = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", detail_filename)
        if not detail_path or not os.path.exists(detail_path):
            detail_path = None

    if not detail_path:
        return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.write(filepath, os.path.basename(filepath))
        zip_file.write(detail_path, os.path.basename(detail_path))

    zip_buffer.seek(0)
    invoice_number = invoice.get('invoice_number', 'facture').replace('-', '_')
    zip_name = f"{invoice_number}.zip"

    return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=zip_name)


@history_bp.route('/api/history/view/<invoice_id>')
@login_required
def view_from_history(invoice_id):
    """Affiche le PDF d'une facture depuis l'historique"""
    history = load_invoice_history()
    invoice = next((h for h in history if h.get('id') == invoice_id), None)
    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    return send_file(filepath, as_attachment=False, mimetype='application/pdf')


@history_bp.route('/api/history/detail/<invoice_id>')
@login_required
def detail_from_history(invoice_id):
    """Retourne les lignes du CSV de détail d'une facture sous forme JSON"""
    history = load_invoice_history()
    invoice = next((h for h in history if h.get('id') == invoice_id), None)
    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    if not invoice.get('has_detail'):
        return jsonify({'error': 'Pas de détail pour cette facture'}), 404

    batch_id = invoice.get('batch_id')
    detail_filename = invoice.get('detail_filename')
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", detail_filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier de détail non trouvé'}), 404

    rows = []
    with open(filepath, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f, delimiter=';')
        for row in reader:
            rows.append(dict(row))

    return jsonify({'success': True, 'rows': rows, 'invoice_number': invoice.get('invoice_number')})


@history_bp.route('/api/history/clear', methods=['DELETE'])
@login_required
def clear_history():
    """Vide l'historique des factures"""
    invoice_history_collection.delete_many({})
    return jsonify({'success': True})


# =============================================================================
# Paiement
# =============================================================================

@history_bp.route('/api/history/<invoice_id>/payment', methods=['PUT'])
@login_required
def update_payment_status(invoice_id):
    """Met à jour le statut de paiement d'une facture"""
    data = request.json
    status = data.get('status', 'pending')

    if status not in ['pending', 'paid']:
        return jsonify({'error': 'Statut invalide'}), 400

    result = update_invoice_in_history(invoice_id, {'payment_status': status})

    if result:
        return jsonify({'success': True, 'invoice': result})
    return jsonify({'error': 'Facture non trouvée'}), 404


# =============================================================================
# Envoi email / relances depuis l'historique
# =============================================================================

@history_bp.route('/api/history/<invoice_id>/send-email', methods=['POST'])
@login_required
def send_email_from_history(invoice_id):
    """Envoie l'email initial de facturation depuis l'historique"""
    history = load_invoice_history()

    invoice = next((h for h in history if h.get('id') == invoice_id), None)
    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    if invoice.get('email_sent'):
        return jsonify({'error': 'L\'email a déjà été envoyé'}), 400

    if not invoice.get('client_email'):
        return jsonify({'error': 'Pas d\'adresse email pour ce client'}), 400

    email_config = load_email_config()

    invoice_data = {
        **invoice,
        'company_name': invoice.get('client_name', invoice.get('shipper', ''))
    }

    batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

    result = send_invoice_email(invoice_data, email_config, batch_folder)

    if result['success']:
        now = datetime.now().isoformat()
        update_invoice_in_history(invoice_id, {
            'email_sent': True,
            'email_sent_at': now
        })

        batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)
        if os.path.exists(batch_data_path):
            try:
                with open(batch_data_path, 'r', encoding='utf-8') as f:
                    batch_data = json.load(f)
                for inv in batch_data.get('invoices', []):
                    if inv.get('invoice_number') == invoice.get('invoice_number'):
                        inv['email_sent'] = True
                        inv['email_sent_at'] = now
                        break
                with open(batch_data_path, 'w', encoding='utf-8') as f:
                    json.dump(batch_data, f, indent=2, ensure_ascii=False)
            except Exception:
                pass

        return jsonify({'success': True})

    return jsonify(result), 500


@history_bp.route('/api/history/<invoice_id>/reminder/<int:reminder_type>', methods=['POST'])
@login_required
def send_single_reminder(invoice_id, reminder_type):
    """Envoie un email de relance pour une facture spécifique"""
    if reminder_type not in [1, 2, 3, 4]:
        return jsonify({'error': 'Type de relance invalide (1, 2, 3 ou 4)'}), 400

    history = load_invoice_history()
    invoice = next((h for h in history if h.get('id') == invoice_id), None)

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    if invoice.get('payment_status') == 'paid':
        return jsonify({'error': 'Cette facture est déjà marquée comme payée'}), 400

    if not invoice.get('client_email'):
        return jsonify({'error': 'Pas d\'adresse email pour ce client'}), 400

    reminder_sent_key = f'reminder_{reminder_type}_sent'
    if invoice.get(reminder_sent_key):
        return jsonify({'error': f'La relance {reminder_type} a déjà été envoyée'}), 400

    email_config = load_email_config()

    invoice_data = {
        **invoice,
        'company_name': invoice.get('client_name', invoice.get('shipper', ''))
    }

    batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

    result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type)

    if result['success']:
        reminder_at_key = f'reminder_{reminder_type}_at'
        update_invoice_in_history(invoice_id, {
            reminder_sent_key: True,
            reminder_at_key: datetime.now().isoformat()
        })
        return jsonify({'success': True, 'reminder_type': reminder_type})

    return jsonify(result), 500


@history_bp.route('/api/history/reminders/send-all/<int:reminder_type>', methods=['POST'])
@login_required
def send_all_reminders(reminder_type):
    """Envoie des relances pour toutes les factures impayées"""
    if reminder_type not in [1, 2, 3, 4]:
        return jsonify({'error': 'Type de relance invalide (1, 2, 3 ou 4)'}), 400

    data = request.json or {}
    invoice_ids = data.get('invoice_ids', [])

    history = load_invoice_history()
    email_config = load_email_config()

    reminder_sent_key = f'reminder_{reminder_type}_sent'
    reminder_at_key = f'reminder_{reminder_type}_at'
    reminder_names = {1: '1ère relance', 2: '2ème relance (avertissement)', 3: '3ème relance (dernier avis)', 4: '4ème relance (coupure)'}

    results = {
        'total': 0,
        'sent': 0,
        'failed': 0,
        'skipped': 0,
        'details': []
    }

    for invoice in history:
        invoice_id = invoice.get('id')

        if invoice_ids and invoice_id not in invoice_ids:
            continue

        results['total'] += 1

        if invoice.get('payment_status') == 'paid':
            results['skipped'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'skipped',
                'message': 'Déjà payée'
            })
            continue

        if invoice.get(reminder_sent_key):
            results['skipped'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'skipped',
                'message': f'{reminder_names.get(reminder_type, "Relance")} déjà envoyée'
            })
            continue

        if not invoice.get('client_email'):
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'failed',
                'message': 'Pas d\'adresse email'
            })
            continue

        invoice_data = {
            **invoice,
            'company_name': invoice.get('client_name', invoice.get('shipper', ''))
        }

        batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

        result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type)

        if result['success']:
            results['sent'] += 1
            update_invoice_in_history(invoice_id, {
                reminder_sent_key: True,
                reminder_at_key: datetime.now().isoformat()
            })
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'sent',
                'message': f'{reminder_names.get(reminder_type, "Relance")} envoyée'
            })
        else:
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'failed',
                'message': result.get('error', 'Erreur inconnue')
            })

    return jsonify({'success': True, 'results': results})


# =============================================================================
# Opérations en masse
# =============================================================================

@history_bp.route('/api/history/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_from_history():
    """Supprime plusieurs factures de l'historique et leurs fichiers"""
    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))
    cleanup_invoice_files(invoices, current_app.config['OUTPUT_FOLDER'])

    result = invoice_history_collection.delete_many({'id': {'$in': invoice_ids}})
    deleted_count = result.deleted_count

    return jsonify({
        'success': True,
        'deleted': deleted_count,
        'message': f'{deleted_count} facture(s) supprimée(s)'
    })


@history_bp.route('/api/history/bulk-info', methods=['POST'])
@login_required
def bulk_get_info():
    """Récupère les informations détaillées de plusieurs factures"""
    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    total_ht = sum(inv.get('total_ht', 0) for inv in invoices)
    total_ttc = sum(inv.get('total_ttc', 0) for inv in invoices)
    total_tva = sum(inv.get('total_tva', inv.get('total_ttc', 0) - inv.get('total_ht', 0)) for inv in invoices)
    paid_count = sum(1 for inv in invoices if inv.get('payment_status') == 'paid')
    unpaid_count = len(invoices) - paid_count

    for inv in invoices:
        if '_id' in inv:
            del inv['_id']

    return jsonify({
        'success': True,
        'invoices': invoices,
        'summary': {
            'count': len(invoices),
            'total_ht': round(total_ht, 2),
            'total_tva': round(total_tva, 2),
            'total_ttc': round(total_ttc, 2),
            'paid_count': paid_count,
            'unpaid_count': unpaid_count
        }
    })


@history_bp.route('/api/history/bulk-download', methods=['POST'])
@login_required
def bulk_download():
    """Télécharge plusieurs factures dans un fichier ZIP"""
    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    if not invoices:
        return jsonify({'error': 'Aucune facture trouvée'}), 404

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for invoice in invoices:
            batch_id = invoice.get('batch_id')
            filename = invoice.get('filename')

            if not batch_id or not filename:
                continue

            filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
            if filepath and os.path.exists(filepath):
                zip_file.write(filepath, os.path.basename(filepath))

            detail_filename = invoice.get('detail_filename')
            if detail_filename:
                detail_path = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", detail_filename)
                if detail_path and os.path.exists(detail_path):
                    zip_file.write(detail_path, os.path.basename(detail_path))

    zip_buffer.seek(0)
    zip_filename = f"factures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_filename
    )


@history_bp.route('/api/history/bulk-payment', methods=['POST'])
@login_required
def bulk_update_payment():
    """Met à jour le statut de paiement de plusieurs factures"""
    data = request.json
    invoice_ids = data.get('ids', [])
    status = data.get('status', 'paid')

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    if status not in ['pending', 'paid']:
        return jsonify({'error': 'Statut invalide'}), 400

    result = invoice_history_collection.update_many(
        {'id': {'$in': invoice_ids}},
        {'$set': {'payment_status': status}}
    )
    updated_count = result.modified_count

    status_text = 'payée(s)' if status == 'paid' else 'impayée(s)'
    return jsonify({
        'success': True,
        'updated': updated_count,
        'message': f'{updated_count} facture(s) marquée(s) comme {status_text}'
    })


@history_bp.route('/api/history/bulk-reminder', methods=['POST'])
@login_required
def bulk_send_reminder():
    """Envoie une relance pour plusieurs factures sélectionnées"""
    data = request.json
    invoice_ids = data.get('ids', [])
    reminder_type = data.get('reminder_type', 1)

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    if reminder_type not in [1, 2, 3, 4]:
        return jsonify({'error': 'Type de relance invalide'}), 400

    email_config = load_email_config()

    reminder_sent_key = f'reminder_{reminder_type}_sent'
    reminder_at_key = f'reminder_{reminder_type}_at'
    reminder_names = {1: 'Relance 1', 2: 'Relance 2', 3: 'Relance 3', 4: 'Relance 4'}

    results = {'sent': 0, 'failed': 0, 'skipped': 0, 'details': []}

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    for invoice in invoices:
        invoice_id = invoice.get('id')

        if invoice.get('payment_status') == 'paid':
            results['skipped'] += 1
            continue

        if invoice.get(reminder_sent_key):
            results['skipped'] += 1
            continue

        if not invoice.get('client_email'):
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'failed',
                'message': 'Pas d\'adresse email'
            })
            continue

        invoice_data = {
            **invoice,
            'company_name': invoice.get('client_name', invoice.get('shipper', ''))
        }

        batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

        result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type)

        if result['success']:
            results['sent'] += 1
            update_invoice_in_history(invoice_id, {
                reminder_sent_key: True,
                reminder_at_key: datetime.now().isoformat()
            })
        else:
            results['failed'] += 1

    return jsonify({
        'success': True,
        'results': results,
        'message': f'{results["sent"]} relance(s) envoyée(s), {results["skipped"]} ignorée(s), {results["failed"]} échec(s)'
    })
