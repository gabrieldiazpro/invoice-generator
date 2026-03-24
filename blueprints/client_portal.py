"""
Blueprint Portail Client : dashboard, factures, profil.
Routes pour les utilisateurs avec le rôle 'client'.
"""

import os
import logging
from flask import Blueprint, jsonify, request, render_template, redirect, url_for, send_file
from flask_login import login_required, current_user

from common.auth import client_required
from common.database import invoice_history_collection, clients_collection
from common.helpers import safe_filepath

logger = logging.getLogger(__name__)

client_portal_bp = Blueprint('client_portal', __name__)


@client_portal_bp.route('/client')
@login_required
def client_portal():
    """Page du portail client"""
    if not current_user.is_client():
        return redirect(url_for('invoices.index'))
    return render_template('client_portal.html', user=current_user)


@client_portal_bp.route('/api/client/dashboard')
@login_required
@client_required
def get_client_dashboard():
    """Récupère les données du dashboard client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    pipeline = [
        {'$match': {'shipper': client_id}},
        {'$group': {
            '_id': None,
            'total_invoices': {'$sum': 1},
            'total_ht': {'$sum': {'$ifNull': ['$total_ht', 0]}},
            'total_ttc': {'$sum': {'$ifNull': ['$total_ttc', 0]}},
            'paid_count': {'$sum': {'$cond': [{'$eq': ['$payment_status', 'paid']}, 1, 0]}},
            'total_paid_ht': {'$sum': {'$cond': [{'$eq': ['$payment_status', 'paid']}, {'$ifNull': ['$total_ht', 0]}, 0]}},
            'total_paid_ttc': {'$sum': {'$cond': [{'$eq': ['$payment_status', 'paid']}, {'$ifNull': ['$total_ttc', 0]}, 0]}},
            'total_pending_ht': {'$sum': {'$cond': [{'$ne': ['$payment_status', 'paid']}, {'$ifNull': ['$total_ht', 0]}, 0]}},
            'total_pending_ttc': {'$sum': {'$cond': [{'$ne': ['$payment_status', 'paid']}, {'$ifNull': ['$total_ttc', 0]}, 0]}},
        }}
    ]
    result = list(invoice_history_collection.aggregate(pipeline))
    stats = result[0] if result else {
        'total_invoices': 0, 'total_ht': 0, 'total_ttc': 0,
        'paid_count': 0, 'total_paid_ht': 0, 'total_paid_ttc': 0,
        'total_pending_ht': 0, 'total_pending_ttc': 0
    }
    pending_count = stats['total_invoices'] - stats['paid_count']

    client_info = clients_collection.find_one({'_id': client_id})

    return jsonify({
        'success': True,
        'client': {
            'name': client_info.get('nom', client_id) if client_info else client_id,
            'email': client_info.get('email', '') if client_info else '',
            'siret': client_info.get('siret', '') if client_info else '',
            'adresse': client_info.get('adresse', '') if client_info else '',
            'code_postal': client_info.get('code_postal', '') if client_info else '',
            'ville': client_info.get('ville', '') if client_info else ''
        },
        'summary': {
            'total_invoices': stats['total_invoices'],
            'total_ht': stats['total_ht'],
            'total_ttc': stats['total_ttc'],
            'total_paid_ht': stats['total_paid_ht'],
            'total_paid_ttc': stats['total_paid_ttc'],
            'total_pending_ht': stats['total_pending_ht'],
            'total_pending_ttc': stats['total_pending_ttc'],
            'paid_count': stats['paid_count'],
            'pending_count': pending_count
        }
    })


@client_portal_bp.route('/api/client/invoices')
@login_required
@client_required
def get_client_invoices():
    """Récupère la liste des factures du client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    status = request.args.get('status')
    search = request.args.get('search', '').lower()

    query = {'shipper': client_id}
    if status == 'paid':
        query['payment_status'] = 'paid'
    elif status == 'pending':
        query['payment_status'] = {'$ne': 'paid'}

    invoices = list(invoice_history_collection.find(query).sort('created_at', -1))

    if search:
        invoices = [
            inv for inv in invoices
            if search in inv.get('invoice_number', '').lower()
            or search in inv.get('period', '').lower()
        ]

    formatted_invoices = []
    for inv in invoices:
        formatted_invoices.append({
            'id': inv.get('id'),
            'invoice_number': inv.get('invoice_number', ''),
            'period': inv.get('period', ''),
            'created_at': inv.get('created_at').isoformat() if inv.get('created_at') else None,
            'total_ht': inv.get('total_ht', 0),
            'total_ttc': inv.get('total_ttc', 0),
            'total_ht_formatted': inv.get('total_ht_formatted', ''),
            'total_ttc_formatted': inv.get('total_ttc_formatted', ''),
            'payment_status': inv.get('payment_status', 'pending'),
            'email_sent': inv.get('email_sent', False),
            'batch_id': inv.get('batch_id'),
            'filename': inv.get('filename')
        })

    return jsonify({
        'success': True,
        'invoices': formatted_invoices,
        'total': len(formatted_invoices)
    })


@client_portal_bp.route('/api/client/invoices/<invoice_id>/download')
@login_required
@client_required
def download_client_invoice(invoice_id):
    """Télécharge une facture du client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    invoice = invoice_history_collection.find_one({
        'id': invoice_id,
        'shipper': client_id
    })

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    if not batch_id or not filename:
        return jsonify({'error': 'Informations de fichier manquantes'}), 400

    from flask import current_app
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


@client_portal_bp.route('/api/client/invoices/<invoice_id>/view')
@login_required
@client_required
def view_client_invoice(invoice_id):
    """Affiche une facture du client dans le navigateur"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    invoice = invoice_history_collection.find_one({
        'id': invoice_id,
        'shipper': client_id
    })

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    if not batch_id or not filename:
        return jsonify({'error': 'Informations de fichier manquantes'}), 400

    from flask import current_app
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    return send_file(filepath, as_attachment=False, mimetype='application/pdf')


@client_portal_bp.route('/api/client/profile')
@login_required
@client_required
def get_client_profile():
    """Récupère le profil du client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    client_info = clients_collection.find_one({'_id': client_id})

    if not client_info:
        return jsonify({'error': 'Informations client non trouvées'}), 404

    return jsonify({
        'success': True,
        'profile': {
            'name': client_info.get('nom', client_id),
            'email': client_info.get('email', ''),
            'siret': client_info.get('siret', ''),
            'adresse': client_info.get('adresse', ''),
            'code_postal': client_info.get('code_postal', ''),
            'ville': client_info.get('ville', ''),
            'pays': client_info.get('pays', 'France')
        }
    })
