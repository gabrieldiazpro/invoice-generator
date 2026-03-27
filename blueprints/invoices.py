"""
Blueprint Invoices : upload CSV, génération factures, téléchargement.
"""

import os
import json
import uuid
import shutil
import logging
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request, render_template, send_file, Response, stream_with_context, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from common.config import DEBUG, BATCH_DATA_FILE
from common.database import invoice_history_collection, init_invoice_counter, reserve_invoice_numbers
from common.helpers import (
    allowed_file, safe_filepath, get_parsed_csv,
    calculate_total_ht, clean_siret, extract_period
)
from common.client_matching import load_clients_config, save_clients_config, get_client_info
from common.csv_helpers import parse_details_csv, save_detail_csv
from common.invoice_helpers import _build_history_entry
from invoice_generator import InvoicePDFGenerator, generate_invoice_number, format_currency

logger = logging.getLogger(__name__)

invoices_bp = Blueprint('invoices', __name__)


# =============================================================================
# Page d'accueil
# =============================================================================

@invoices_bp.route('/')
@login_required
def index():
    """Page d'accueil"""
    header_color = 'red' if DEBUG else 'white'
    dev_email = os.environ.get('DEV_RECIPIENT_EMAIL', '') if DEBUG else ''
    return render_template('index.html', user=current_user, now=datetime.now(), header_color=header_color, dev_email=dev_email)


# =============================================================================
# Upload & Preview
# =============================================================================

def _build_shippers_summary(data_by_shipper, clients_config):
    """Construit le résumé des shippers pour upload et refresh"""
    shippers_summary = []
    for shipper_name, rows in data_by_shipper.items():
        csv_siret = rows[0].get('SIRET', '') if rows else ''
        client_info = get_client_info(shipper_name, clients_config, csv_siret=csv_siret)

        total_ht = calculate_total_ht(rows)

        siret = client_info.get('siret', '00000000000000')
        email = client_info.get('email', 'email@example.com')
        is_configured = (siret != '00000000000000' and siret != '') and (email != 'email@example.com' and email != '' and '@' in email)

        display_name = client_info.get('nom', shipper_name)
        period = extract_period(rows)

        already_invoiced = False
        existing_invoice = None
        clean_siret_check = clean_siret(siret)
        if period and invoice_history_collection is not None:
            query_conditions = []
            if clean_siret_check and clean_siret_check != '00000000000000':
                query_conditions.append({'client_siret': clean_siret_check, 'period': period})
            query_conditions.append({'shipper': shipper_name, 'period': period})

            for query in query_conditions:
                existing = invoice_history_collection.find_one(query)
                if existing:
                    already_invoiced = True
                    existing_invoice = existing.get('invoice_number', '')
                    break

        shippers_summary.append({
            'name': display_name,
            'csv_name': shipper_name,
            'lines_count': len(rows),
            'total_ht': round(total_ht, 2),
            'client_configured': is_configured,
            'client_email': email if email != 'email@example.com' else '',
            'period': period,
            'already_invoiced': already_invoiced,
            'existing_invoice': existing_invoice,
            'csv_siret': csv_siret,
            'csv_siret_valid': len(clean_siret(csv_siret)) == 14
        })

    return shippers_summary


@invoices_bp.route('/api/upload', methods=['POST'])
@login_required
def upload_csv():
    """Upload et analyse d'un fichier CSV"""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Format de fichier non supporté. Utilisez un fichier CSV.'}), 400

    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)

    details_file_id = None
    details_file = request.files.get('details_file')
    logger.debug(f"[upload] details_file reçu: {details_file}, filename: {details_file.filename if details_file else 'None'}")
    if details_file and details_file.filename and allowed_file(details_file.filename):
        details_filename = secure_filename(details_file.filename)
        details_unique = f"details_{uuid.uuid4().hex}_{details_filename}"
        details_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], details_unique)
        details_file.save(details_filepath)
        details_file_id = details_unique
        logger.debug(f"[upload] Fichier détail sauvegardé: {details_unique}")
    else:
        logger.debug("[upload] Pas de fichier détail")

    try:
        data_by_shipper = get_parsed_csv(filepath)

        if not data_by_shipper:
            os.remove(filepath)
            return jsonify({'error': 'Aucune donnée trouvée dans le fichier CSV'}), 400

        clients_config = load_clients_config()
        shippers_summary = _build_shippers_summary(data_by_shipper, clients_config)
        save_clients_config(clients_config)

        return jsonify({
            'success': True,
            'file_id': unique_filename,
            'details_file_id': details_file_id,
            'shippers': shippers_summary,
            'total_shippers': len(shippers_summary)
        })

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Erreur lors du traitement: {str(e)}'}), 500


@invoices_bp.route('/api/refresh-preview/<file_id>')
@login_required
def refresh_preview(file_id):
    """Rafraîchit les données de prévisualisation après mise à jour d'un client"""
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_id)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    try:
        data_by_shipper = get_parsed_csv(filepath)

        if not data_by_shipper:
            return jsonify({'error': 'Aucune donnée trouvée dans le fichier CSV'}), 400

        clients_config = load_clients_config()
        shippers_summary = _build_shippers_summary(data_by_shipper, clients_config)

        return jsonify({
            'success': True,
            'file_id': file_id,
            'shippers': shippers_summary,
            'total_shippers': len(shippers_summary)
        })

    except Exception as e:
        return jsonify({'error': f'Erreur lors du traitement: {str(e)}'}), 500


# =============================================================================
# Génération (SSE)
# =============================================================================

@invoices_bp.route('/api/generate', methods=['POST'])
@login_required
def generate_invoices():
    """Génère les factures PDF avec streaming SSE pour la progression"""
    data = request.json
    file_id = data.get('file_id')
    prefix = data.get('prefix', 'PP')
    selected_shippers = data.get('shippers', [])
    details_file_id = data.get('details_file_id')

    if not file_id:
        return jsonify({'error': 'Aucun fichier spécifié'}), 400

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], file_id)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    # Pré-charger avant le streaming
    try:
        data_by_shipper = get_parsed_csv(filepath)
        clients_config = load_clients_config()

        details_by_siret = {}
        details_by_name = {}
        logger.debug(f"[generate] details_file_id reçu: '{details_file_id}'")
        if details_file_id:
            details_filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], details_file_id)
            file_exists = os.path.exists(details_filepath)
            logger.debug(f"[generate] Fichier détail: {details_filepath}, existe={file_exists}")
            if file_exists:
                details_by_siret, details_by_name = parse_details_csv(details_filepath)
                logger.debug(f"[generate] CSV de détail chargé: {len(details_by_siret)} SIRETs, {len(details_by_name)} noms")
            else:
                logger.warning(f"[generate] Fichier détail introuvable: {details_filepath}")
        else:
            logger.debug("[generate] Pas de details_file_id")
    except Exception as e:
        return jsonify({'error': f'Erreur lors du traitement: {str(e)}'}), 500

    shippers_to_process = [
        (name, rows) for name, rows in data_by_shipper.items()
        if not selected_shippers or name in selected_shippers
    ]
    total_to_generate = len(shippers_to_process)

    init_invoice_counter(prefix)
    first_number = reserve_invoice_numbers(prefix, total_to_generate)

    # Capturer les configs pour la closure
    upload_folder = current_app.config['UPLOAD_FOLDER']
    output_folder = current_app.config['OUTPUT_FOLDER']

    def generate_stream():
        batch_id = uuid.uuid4().hex[:8]
        batch_folder = os.path.join(output_folder, f"batch_{batch_id}")
        os.makedirs(batch_folder, exist_ok=True)

        generator = InvoicePDFGenerator(output_dir=batch_folder)
        generated = []

        for idx, (shipper_name, rows) in enumerate(shippers_to_process):
            try:
                csv_siret = rows[0].get('SIRET', '') if rows else ''
                cleaned_siret = clean_siret(csv_siret)
                client_info = get_client_info(shipper_name, clients_config, csv_siret=csv_siret)
                invoice_number = generate_invoice_number(prefix, sequence=first_number + idx)

                period = extract_period(rows)

                filepath_pdf, total_ttc = generator.generate_invoice(
                    shipper_name, rows, client_info, invoice_number
                )

                total_ht = calculate_total_ht(rows)

                client_email = client_info.get('email', '')
                if client_email == 'email@example.com':
                    client_email = ''

                emission_date = datetime.now()
                if emission_date.month == 12:
                    next_month = emission_date.replace(year=emission_date.year + 1, month=1, day=1)
                else:
                    next_month = emission_date.replace(month=emission_date.month + 1, day=1)
                due_date = next_month - timedelta(days=1)

                # Matching détail
                detail_rows = None
                if cleaned_siret and cleaned_siret in details_by_siret:
                    detail_rows = details_by_siret[cleaned_siret]
                    logger.debug(f"[generate] {shipper_name}: match SIRET exact '{cleaned_siret}'")
                elif shipper_name in details_by_name:
                    detail_rows = details_by_name[shipper_name]
                    logger.debug(f"[generate] {shipper_name}: match nom exact")
                else:
                    clean_name = shipper_name.lower().replace(' via pp', '').replace(' via peoples post', '').strip()
                    for detail_name, detail_name_rows in details_by_name.items():
                        if detail_name.lower().strip() == clean_name:
                            detail_rows = detail_name_rows
                            logger.debug(f"[generate] {shipper_name}: match nom nettoyé → '{detail_name}'")
                            break
                    if not detail_rows:
                        logger.debug(f"[generate] {shipper_name}: pas de match détail (siret='{csv_siret}' → '{cleaned_siret}')")

                detail_filename = None
                if detail_rows:
                    detail_filename = f"detail_{invoice_number}.csv"
                    detail_csv_path = os.path.join(batch_folder, detail_filename)
                    save_detail_csv(detail_rows, detail_csv_path)

                invoice_data = {
                    'shipper': shipper_name,
                    'invoice_number': invoice_number,
                    'filename': os.path.basename(filepath_pdf),
                    'total_ttc': float(total_ttc),
                    'total_ht': float(total_ht),
                    'total_ttc_formatted': format_currency(total_ttc),
                    'total_ht_formatted': format_currency(total_ht),
                    'client_name': shipper_name,
                    'company_name': client_info.get('nom', shipper_name),
                    'client_email': client_email,
                    'period': period,
                    'email_sent': False,
                    'emission_date': emission_date.isoformat(),
                    'due_date': due_date.isoformat(),
                    'client_siret': cleaned_siret,
                    'detail_filename': detail_filename,
                    'has_detail': bool(detail_filename)
                }

                generated.append(invoice_data)

                progress_data = json.dumps({
                    'type': 'progress',
                    'current': idx + 1,
                    'total': total_to_generate,
                    'invoice_number': invoice_number,
                    'client_name': client_info.get('nom', shipper_name)
                }, ensure_ascii=False)
                yield f"data: {progress_data}\n\n"

            except Exception as e:
                logger.error(f"Erreur génération facture {shipper_name}: {e}")
                error_data = json.dumps({
                    'type': 'progress',
                    'current': idx + 1,
                    'total': total_to_generate,
                    'error': f"Erreur pour {shipper_name}: {str(e)}"
                }, ensure_ascii=False)
                yield f"data: {error_data}\n\n"

        # Sauvegarder les données du batch
        batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)
        with open(batch_data_path, 'w', encoding='utf-8') as f:
            json.dump({'invoices': generated, 'created_at': datetime.now().isoformat()}, f, indent=2, ensure_ascii=False)

        # Historique MongoDB
        if generated:
            history_entries = []
            for inv_data in generated:
                history_entries.append(_build_history_entry(inv_data, batch_id))
            invoice_history_collection.insert_many(history_entries)

        # Nettoyer les fichiers uploadés
        for fid in [file_id, details_file_id]:
            if fid:
                tmp = os.path.join(upload_folder, fid)
                if os.path.exists(tmp):
                    os.remove(tmp)
                    logger.debug(f"Fichier upload supprimé: {fid}")

        done_data = json.dumps({
            'type': 'done',
            'batch_id': batch_id,
            'invoices': generated,
            'total_generated': len(generated)
        }, ensure_ascii=False)
        yield f"data: {done_data}\n\n"

    return Response(
        stream_with_context(generate_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )


# =============================================================================
# Téléchargement / Visualisation
# =============================================================================

@invoices_bp.route('/api/download/<batch_id>/<filename>')
@login_required
def download_invoice(batch_id, filename):
    """Télécharge une facture individuelle"""
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


@invoices_bp.route('/api/view/<batch_id>/<filename>')
@login_required
def view_invoice(batch_id, filename):
    """Visualise une facture dans le navigateur"""
    filepath = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}", filename)
    if not filepath or not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    return send_file(filepath, as_attachment=False, mimetype='application/pdf')


@invoices_bp.route('/api/download-all/<batch_id>')
@login_required
def download_all_invoices(batch_id):
    """Télécharge toutes les factures en ZIP"""
    batch_folder = safe_filepath(current_app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    if not batch_folder or not os.path.exists(batch_folder):
        return jsonify({'error': 'Batch non trouvé'}), 404

    zip_path = os.path.join(current_app.config['OUTPUT_FOLDER'], f"factures_{batch_id}")
    shutil.make_archive(zip_path, 'zip', batch_folder)

    return send_file(
        f"{zip_path}.zip",
        as_attachment=True,
        download_name=f"factures_{batch_id}.zip"
    )
