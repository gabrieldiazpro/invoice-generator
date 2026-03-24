"""
Blueprint Email : configuration, envoi simple/masse, statut, preview.
"""

import os
import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, Response, stream_with_context, current_app
from flask_login import login_required, current_user

from common.config import BATCH_DATA_FILE
from common.auth import super_admin_required
from common.database import invoice_history_collection
from common.email_service import (
    load_email_config, save_email_config, send_email_via_api,
    send_invoice_email, format_email_body, create_html_email_preview
)
from common.invoice_helpers import update_invoice_in_history

logger = logging.getLogger(__name__)

email_bp = Blueprint('email', __name__)


# =============================================================================
# Configuration
# =============================================================================

@email_bp.route('/api/email/config', methods=['GET'])
@login_required
def get_email_config():
    """Récupère la configuration email (sans le mot de passe)"""
    config = load_email_config()
    safe_config = {k: v for k, v in config.items() if k != 'smtp_password'}
    safe_config['smtp_password_set'] = bool(config.get('smtp_password'))
    return jsonify(safe_config)


@email_bp.route('/api/email/config', methods=['PUT'])
@login_required
def update_email_config():
    """Met à jour la configuration email"""
    data = request.json
    config = load_email_config()

    smtp_fields = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password']

    smtp_modified = any(key in data for key in smtp_fields)
    if smtp_modified and not current_user.is_super_admin():
        return jsonify({'error': 'Seul le super admin peut modifier la configuration SMTP'}), 403

    for key in ['sender_email', 'sender_name', 'email_subject', 'email_template',
                'reminder_1_subject', 'reminder_1_template',
                'reminder_2_subject', 'reminder_2_template',
                'reminder_3_subject', 'reminder_3_template',
                'reminder_4_subject', 'reminder_4_template']:
        if key in data:
            config[key] = data[key]

    if current_user.is_super_admin():
        for key in ['smtp_server', 'smtp_port', 'smtp_username']:
            if key in data:
                config[key] = data[key]
        if data.get('smtp_password'):
            config['smtp_password'] = data['smtp_password']

    save_email_config(config)

    safe_config = {k: v for k, v in config.items() if k != 'smtp_password'}
    safe_config['smtp_password_set'] = bool(config.get('smtp_password'))
    return jsonify({'success': True, 'config': safe_config})


# =============================================================================
# Test
# =============================================================================

@email_bp.route('/api/email/test', methods=['POST'])
@login_required
@super_admin_required
def test_email():
    """Envoie un email de test via l'API Brevo"""
    data = request.get_json() or {}
    test_email_addr = data.get('email', current_user.email)

    email_config = load_email_config()

    if not email_config.get('smtp_password'):
        return jsonify({'success': False, 'error': 'Clé API Brevo non configurée'}), 400

    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #3026f0;">Test - Configuration Email Peoples Post</h2>
        <p>Bonjour,</p>
        <p>Ceci est un email de test envoyé depuis le Générateur de Factures Peoples Post.</p>
        <p><strong>Si vous recevez cet email, la configuration est correcte !</strong></p>
        <hr style="border: 1px solid #eee; margin: 20px 0;">
        <p style="color: #666; font-size: 12px;">
            Configuration utilisée:<br>
            - Serveur: {email_config.get('smtp_server')}<br>
            - Expéditeur: {email_config.get('sender_email') or email_config.get('smtp_username')}
        </p>
        <p>Cordialement,<br>L'équipe Peoples Post</p>
    </body>
    </html>
    """

    text_content = """Bonjour,

Ceci est un email de test envoyé depuis le Générateur de Factures Peoples Post.

Si vous recevez cet email, la configuration est correcte !

Cordialement,
L'équipe Peoples Post
"""

    result = send_email_via_api(
        to_email=test_email_addr,
        to_name=current_user.name or test_email_addr,
        subject="Test - Configuration Email Peoples Post",
        html_content=html_content,
        text_content=text_content
    )

    if result.get('success'):
        return jsonify({'success': True, 'message': f'Email de test envoyé à {test_email_addr}'})
    else:
        return jsonify({'success': False, 'error': result.get('error', 'Erreur inconnue')}), 400


# =============================================================================
# Envoi simple
# =============================================================================

@email_bp.route('/api/email/send/<batch_id>/<invoice_number>', methods=['POST'])
@login_required
def send_single_email(batch_id, invoice_number):
    """Envoie un email pour une facture spécifique"""
    batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    invoice_data = None
    invoice_index = None
    for i, inv in enumerate(batch_data.get('invoices', [])):
        if inv.get('invoice_number') == invoice_number:
            invoice_data = inv
            invoice_index = i
            break

    if not invoice_data:
        return jsonify({'error': 'Facture non trouvée'}), 404

    email_config = load_email_config()

    include_detail = (request.json or {}).get('include_detail', False)

    result = send_invoice_email(invoice_data, email_config, batch_folder, include_detail=include_detail)

    if result['success']:
        now = datetime.now().isoformat()
        batch_data['invoices'][invoice_index]['email_sent'] = True
        batch_data['invoices'][invoice_index]['email_sent_at'] = now
        with open(batch_data_path, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)

        invoice_id = f"{batch_id}_{invoice_number}"
        update_invoice_in_history(invoice_id, {
            'email_sent': True,
            'email_sent_at': now
        })

    return jsonify(result)


# =============================================================================
# Envoi en masse (SSE)
# =============================================================================

@email_bp.route('/api/email/send-all/<batch_id>', methods=['POST'])
@login_required
def send_all_emails(batch_id):
    """Envoie les emails pour toutes les factures du batch avec streaming SSE"""
    batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    req_body = request.json or {}
    only_pending = req_body.get('only_pending', True)
    detail_invoices = set(req_body.get('detail_invoices', []))

    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    invoices = batch_data.get('invoices', [])
    invoice_ids = [f"{batch_id}_{inv.get('invoice_number')}" for inv in invoices]
    sent_in_db = set()
    for doc in invoice_history_collection.find({'id': {'$in': invoice_ids}, 'email_sent': True}, {'id': 1}):
        sent_in_db.add(doc['id'])

    email_config = load_email_config()

    def email_stream():
        results = {'total': 0, 'sent': 0, 'failed': 0, 'skipped': 0, 'details': []}
        total = len(invoices)

        for i, invoice_data in enumerate(invoices):
            results['total'] += 1
            invoice_number = invoice_data.get('invoice_number', '')
            client_name = invoice_data.get('company_name', invoice_data.get('shipper', ''))

            inv_id = f"{batch_id}_{invoice_number}"
            if only_pending and inv_id in sent_in_db:
                results['skipped'] += 1
                results['details'].append({
                    'invoice_number': invoice_number,
                    'status': 'skipped',
                    'message': 'Déjà envoyé'
                })
                progress = json.dumps({
                    'type': 'progress',
                    'current': i + 1,
                    'total': total,
                    'invoice_number': invoice_number,
                    'client_name': client_name,
                    'status': 'skipped'
                }, ensure_ascii=False)
                yield f"data: {progress}\n\n"
                continue

            if not invoice_data.get('client_email'):
                results['failed'] += 1
                results['details'].append({
                    'invoice_number': invoice_number,
                    'status': 'failed',
                    'message': 'Pas d\'adresse email'
                })
                progress = json.dumps({
                    'type': 'progress',
                    'current': i + 1,
                    'total': total,
                    'invoice_number': invoice_number,
                    'client_name': client_name,
                    'status': 'failed',
                    'error': 'Pas d\'adresse email'
                }, ensure_ascii=False)
                yield f"data: {progress}\n\n"
                continue

            include_detail = invoice_number in detail_invoices
            result = send_invoice_email(invoice_data, email_config, batch_folder, include_detail=include_detail)

            if result['success']:
                results['sent'] += 1
                now = datetime.now().isoformat()
                batch_data['invoices'][i]['email_sent'] = True
                batch_data['invoices'][i]['email_sent_at'] = now
                results['details'].append({
                    'invoice_number': invoice_number,
                    'status': 'sent',
                    'message': 'Envoyé avec succès'
                })
                update_invoice_in_history(inv_id, {
                    'email_sent': True,
                    'email_sent_at': now
                })
                progress = json.dumps({
                    'type': 'progress',
                    'current': i + 1,
                    'total': total,
                    'invoice_number': invoice_number,
                    'client_name': client_name,
                    'status': 'sent'
                }, ensure_ascii=False)
                yield f"data: {progress}\n\n"
            else:
                results['failed'] += 1
                error_msg = result.get('error', 'Erreur inconnue')
                results['details'].append({
                    'invoice_number': invoice_number,
                    'status': 'failed',
                    'message': error_msg
                })
                progress = json.dumps({
                    'type': 'progress',
                    'current': i + 1,
                    'total': total,
                    'invoice_number': invoice_number,
                    'client_name': client_name,
                    'status': 'failed',
                    'error': error_msg
                }, ensure_ascii=False)
                yield f"data: {progress}\n\n"

        with open(batch_data_path, 'w', encoding='utf-8') as f_out:
            json.dump(batch_data, f_out, indent=2, ensure_ascii=False)

        done_data = json.dumps({
            'type': 'done',
            'results': results
        }, ensure_ascii=False)
        yield f"data: {done_data}\n\n"

    return Response(
        stream_with_context(email_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


# =============================================================================
# Statut & Preview
# =============================================================================

@email_bp.route('/api/email/status/<batch_id>', methods=['GET'])
@login_required
def get_email_status(batch_id):
    """Récupère le statut d'envoi des emails pour un batch depuis MongoDB"""
    batch_folder = os.path.join(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    invoices = batch_data.get('invoices', [])
    invoice_ids = [f"{batch_id}_{inv.get('invoice_number')}" for inv in invoices]
    history_map = {}
    for doc in invoice_history_collection.find({'id': {'$in': invoice_ids}}, {'id': 1, 'email_sent': 1, 'email_sent_at': 1}):
        history_map[doc['id']] = doc

    for inv in invoices:
        inv_id = f"{batch_id}_{inv.get('invoice_number')}"
        hist = history_map.get(inv_id)
        if hist:
            inv['email_sent'] = hist.get('email_sent', False)
            inv['email_sent_at'] = hist.get('email_sent_at')

    return jsonify({
        'success': True,
        'invoices': invoices
    })


@email_bp.route('/api/email/preview/<email_type>', methods=['GET'])
@login_required
def preview_email(email_type):
    """Génère une prévisualisation de l'email HTML"""
    if email_type not in ['invoice', 'reminder_1', 'reminder_2', 'reminder_3', 'reminder_4']:
        return jsonify({'error': 'Type d\'email invalide'}), 400

    email_config = load_email_config()

    sample_invoice = {
        'invoice_number': 'PP-2025-0001',
        'company_name': 'Entreprise Exemple SARL',
        'client_name': 'Jean Dupont',
        'client_email': 'client@example.com',
        'shipper': 'Entreprise Exemple',
        'period': 'Janvier 2025',
        'total_ht': 1000.00,
        'total_ttc': 1200.00,
        'total_ht_formatted': '1 000,00 €',
        'total_ttc_formatted': '1 200,00 €'
    }

    if email_type == 'invoice':
        template = email_config.get('email_template', '')
    else:
        template = email_config.get(f'{email_type}_template', '')

    body_text = format_email_body(template, sample_invoice)

    html = create_html_email_preview(body_text, sample_invoice, email_type)

    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}
