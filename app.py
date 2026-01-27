#!/usr/bin/env python3
"""
Peoples Post - Application web de génération de factures
"""

import os
import json
import uuid
import shutil
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from werkzeug.utils import secure_filename
from invoice_generator import (
    parse_csv, load_clients_config, save_clients_config,
    get_client_info, InvoicePDFGenerator, generate_invoice_number, format_currency
)

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(os.path.dirname(__file__), 'output')

# Créer les dossiers si nécessaires
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'csv'}
EMAIL_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'email_config.json')
INVOICE_HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'invoice_history.json')
BATCH_DATA_FILE = 'batch_data.json'
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo.png')
LOGO_EMAIL_PATH = os.path.join(os.path.dirname(__file__), 'logo_email.png')


def create_html_email(body_text, invoice_data, email_type='invoice'):
    """Crée un email HTML stylisé avec le branding Peoples Post

    Args:
        body_text: Le contenu texte de l'email
        invoice_data: Les données de la facture
        email_type: 'invoice', 'reminder_1', 'reminder_2', 'reminder_3'
    """
    # Couleurs selon le type d'email
    header_colors = {
        'invoice': '#3026f0',      # Bleu principal
        'reminder_1': '#f59e0b',   # Jaune/Orange
        'reminder_2': '#f97316',   # Orange
        'reminder_3': '#ef4444'    # Rouge
    }

    header_titles = {
        'invoice': 'Votre Facture',
        'reminder_1': 'Rappel de Paiement',
        'reminder_2': 'Action Requise',
        'reminder_3': 'Dernier Avis'
    }

    header_color = header_colors.get(email_type, '#3026f0')
    header_title = header_titles.get(email_type, 'Votre Facture')

    # Convertir les sauts de ligne en <br>
    body_html = body_text.replace('\n', '<br>')

    # Badge pour les relances
    badge_html = ''
    if email_type == 'reminder_2':
        badge_html = '<span style="display: inline-block; background-color: #fff3cd; color: #856404; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">URGENT</span><br>'
    elif email_type == 'reminder_3':
        badge_html = '<span style="display: inline-block; background-color: #f8d7da; color: #721c24; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">SUSPENSION IMMINENTE</span><br>'

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f0f2f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f0f2f5;">
        <tr>
            <td style="padding: 40px 20px;">
                <!-- Container principal -->
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="margin: 0 auto;">

                    <!-- Header avec logo -->
                    <tr>
                        <td style="background: linear-gradient(135deg, {header_color} 0%, {'#1a1aad' if email_type == 'invoice' else header_color} 100%); padding: 30px 40px; text-align: center; border-radius: 16px 16px 0 0;">
                            <img src="cid:logo" alt="Peoples Post" style="height: 90px; margin: 0 auto 12px auto; display: block;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">{header_title}</h1>
                        </td>
                    </tr>

                    <!-- Carte principale -->
                    <tr>
                        <td style="background-color: #ffffff; padding: 0; border-radius: 0 0 16px 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">

                            <!-- Bandeau montant -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding: 30px 40px; border-bottom: 1px solid #eef0f2;">
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="text-align: left; vertical-align: middle;">
                                                    <span style="color: #8b8e94; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Facture</span><br>
                                                    <span style="color: #1a1a2e; font-size: 20px; font-weight: 700;">{invoice_data.get('invoice_number', '')}</span>
                                                </td>
                                                <td style="text-align: right; vertical-align: middle;">
                                                    <span style="color: #8b8e94; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Total TTC</span><br>
                                                    <span style="color: {header_color}; font-size: 32px; font-weight: 800;">{invoice_data.get('total_ttc_formatted', '')}</span>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>

                            <!-- Contenu -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding: 40px;">
                                        {badge_html}
                                        <div style="color: #4a4a5a; font-size: 15px; line-height: 1.8;">
                                            {body_html}
                                        </div>
                                    </td>
                                </tr>
                            </table>

                            <!-- Bouton (pour les relances) -->
                            {'<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td style="padding: 0 40px 40px; text-align: center;"><a href="mailto:victor.estines@peoplespost.fr?subject=Paiement facture ' + invoice_data.get('invoice_number', '') + '" style="display: inline-block; background-color: ' + header_color + '; color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 50px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 15px ' + header_color + '40;">Nous contacter</a></td></tr></table>' if email_type != 'invoice' else ''}

                            <!-- Footer -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="background-color: #f8f9fb; padding: 30px 40px; border-radius: 0 0 16px 16px; border-top: 1px solid #eef0f2;">
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="text-align: center;">
                                                    <p style="color: #1a1a2e; font-size: 14px; font-weight: 700; margin: 0 0 8px 0;">
                                                        Peoples Post SAS
                                                    </p>
                                                    <p style="color: #8b8e94; font-size: 13px; margin: 0; line-height: 1.7;">
                                                        22 rue Emeriau, 75015 Paris<br>
                                                        <a href="mailto:victor.estines@peoplespost.fr" style="color: {header_color}; text-decoration: none;">victor.estines@peoplespost.fr</a><br>
                                                        SIRET 98004432500010
                                                    </p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Mention légale -->
                    <tr>
                        <td style="padding: 25px 20px; text-align: center;">
                            <p style="color: #a0a3a8; font-size: 11px; margin: 0; line-height: 1.6;">
                                Ce message et ses pièces jointes sont confidentiels et destinés exclusivement au destinataire.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>'''

    return html


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_email_config():
    """Charge la configuration email"""
    if os.path.exists(EMAIL_CONFIG_FILE):
        with open(EMAIL_CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def save_email_config(config):
    """Sauvegarde la configuration email"""
    with open(EMAIL_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def load_invoice_history():
    """Charge l'historique des factures"""
    if os.path.exists(INVOICE_HISTORY_FILE):
        with open(INVOICE_HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []


def save_invoice_history(history):
    """Sauvegarde l'historique des factures"""
    with open(INVOICE_HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def add_to_invoice_history(invoice_data, batch_id):
    """Ajoute une facture à l'historique"""
    history = load_invoice_history()
    history_entry = {
        'id': f"{batch_id}_{invoice_data['invoice_number']}",
        'invoice_number': invoice_data['invoice_number'],
        'client_name': invoice_data.get('company_name', invoice_data.get('shipper', '')),
        'shipper': invoice_data.get('shipper', ''),
        'total_ht': invoice_data.get('total_ht', 0),
        'total_ttc': invoice_data.get('total_ttc', 0),
        'total_ht_formatted': invoice_data.get('total_ht_formatted', ''),
        'total_ttc_formatted': invoice_data.get('total_ttc_formatted', ''),
        'filename': invoice_data.get('filename', ''),
        'batch_id': batch_id,
        'period': invoice_data.get('period', ''),
        'client_email': invoice_data.get('client_email', ''),
        'email_sent': invoice_data.get('email_sent', False),
        'created_at': datetime.now().isoformat(),
        'payment_status': 'pending',  # pending, paid
        'reminder_1_sent': False,
        'reminder_1_at': None,
        'reminder_2_sent': False,
        'reminder_2_at': None,
        'reminder_3_sent': False,
        'reminder_3_at': None
    }
    history.insert(0, history_entry)  # Ajouter en premier (plus récent)
    save_invoice_history(history)
    return history_entry


def update_invoice_in_history(invoice_id, updates):
    """Met à jour une facture dans l'historique"""
    history = load_invoice_history()
    for i, inv in enumerate(history):
        if inv.get('id') == invoice_id:
            history[i].update(updates)
            save_invoice_history(history)
            return history[i]
    return None


def format_email_body(template, invoice_data):
    """Formate le corps de l'email avec les données de la facture"""
    return template.format(
        client_name=invoice_data.get('client_name', ''),
        company_name=invoice_data.get('company_name', ''),
        invoice_number=invoice_data.get('invoice_number', ''),
        total_ttc=invoice_data.get('total_ttc_formatted', ''),
        total_ht=invoice_data.get('total_ht_formatted', ''),
        period=invoice_data.get('period', ''),
        reminder_count=invoice_data.get('reminder_count', 1)
    )


def send_invoice_email(invoice_data, email_config, batch_folder):
    """Envoie un email HTML stylisé avec la facture en pièce jointe"""
    recipient_email = invoice_data.get('client_email', '')

    if not recipient_email:
        return {'success': False, 'error': 'Pas d\'adresse email pour ce client'}

    if not email_config.get('smtp_username') or not email_config.get('smtp_password'):
        return {'success': False, 'error': 'Configuration SMTP incomplète'}

    try:
        # Créer le message multipart/related pour le HTML avec images inline
        msg = MIMEMultipart('related')
        msg['From'] = f"{email_config.get('sender_name', 'Peoples Post')} <{email_config.get('sender_email', '')}>"
        msg['To'] = recipient_email
        msg['Subject'] = email_config.get('email_subject', 'Votre facture Peoples Post').format(
            invoice_number=invoice_data.get('invoice_number', ''),
            client_name=invoice_data.get('client_name', ''),
            company_name=invoice_data.get('company_name', '')
        )

        # Créer la partie alternative (HTML + texte)
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)

        # Corps de l'email en texte brut (fallback)
        body_text = format_email_body(
            email_config.get('email_template', ''),
            invoice_data
        )
        msg_alternative.attach(MIMEText(body_text, 'plain', 'utf-8'))

        # Corps de l'email en HTML
        body_html = create_html_email(body_text, invoice_data, 'invoice')
        msg_alternative.attach(MIMEText(body_html, 'html', 'utf-8'))

        # Ajouter le logo comme image intégrée
        if os.path.exists(LOGO_EMAIL_PATH):
            with open(LOGO_EMAIL_PATH, 'rb') as f:
                logo = MIMEImage(f.read())
                logo.add_header('Content-ID', '<logo>')
                logo.add_header('Content-Disposition', 'inline', filename='logo.png')
                msg.attach(logo)

        # Pièce jointe PDF
        pdf_path = os.path.join(batch_folder, invoice_data.get('filename', ''))
        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                pdf_attachment.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename=invoice_data.get('filename', 'facture.pdf')
                )
                msg.attach(pdf_attachment)

        # Connexion SMTP et envoi
        server = smtplib.SMTP(
            email_config.get('smtp_server', 'smtp.gmail.com'),
            email_config.get('smtp_port', 587)
        )
        server.starttls()
        server.login(
            email_config.get('smtp_username', ''),
            email_config.get('smtp_password', '')
        )
        server.send_message(msg)
        server.quit()

        return {'success': True}

    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'Échec d\'authentification SMTP. Vérifiez vos identifiants.'}
    except smtplib.SMTPException as e:
        return {'success': False, 'error': f'Erreur SMTP: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Erreur: {str(e)}'}


def send_reminder_email(invoice_data, email_config, batch_folder, reminder_type=1):
    """Envoie un email HTML stylisé de relance avec la facture en pièce jointe

    Args:
        reminder_type: 1 = première relance (48h), 2 = avertissement (7j), 3 = dernier avis
    """
    recipient_email = invoice_data.get('client_email', '')

    if not recipient_email:
        return {'success': False, 'error': 'Pas d\'adresse email pour ce client'}

    if not email_config.get('smtp_username') or not email_config.get('smtp_password'):
        return {'success': False, 'error': 'Configuration SMTP incomplète'}

    try:
        # Créer le message multipart/related pour le HTML avec images inline
        msg = MIMEMultipart('related')
        msg['From'] = f"{email_config.get('sender_name', 'Peoples Post')} <{email_config.get('sender_email', '')}>"
        msg['To'] = recipient_email

        # Utiliser le template de relance approprié
        subject_key = f'reminder_{reminder_type}_subject'
        template_key = f'reminder_{reminder_type}_template'

        subject_template = email_config.get(subject_key, email_config.get('reminder_1_subject', 'RELANCE - Facture {invoice_number}'))
        msg['Subject'] = subject_template.format(
            invoice_number=invoice_data.get('invoice_number', ''),
            client_name=invoice_data.get('client_name', ''),
            company_name=invoice_data.get('company_name', '')
        )

        # Créer la partie alternative (HTML + texte)
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)

        # Corps de l'email avec template de relance approprié
        body_template = email_config.get(template_key, '')
        if not body_template:
            body_template = email_config.get('email_template', '')

        body_text = format_email_body(body_template, invoice_data)
        msg_alternative.attach(MIMEText(body_text, 'plain', 'utf-8'))

        # Corps de l'email en HTML
        email_type = f'reminder_{reminder_type}'
        body_html = create_html_email(body_text, invoice_data, email_type)
        msg_alternative.attach(MIMEText(body_html, 'html', 'utf-8'))

        # Ajouter le logo comme image intégrée
        if os.path.exists(LOGO_EMAIL_PATH):
            with open(LOGO_EMAIL_PATH, 'rb') as f:
                logo = MIMEImage(f.read())
                logo.add_header('Content-ID', '<logo>')
                logo.add_header('Content-Disposition', 'inline', filename='logo.png')
                msg.attach(logo)

        # Pièce jointe PDF
        pdf_path = os.path.join(batch_folder, invoice_data.get('filename', ''))
        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as f:
                pdf_attachment = MIMEApplication(f.read(), _subtype='pdf')
                pdf_attachment.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename=invoice_data.get('filename', 'facture.pdf')
                )
                msg.attach(pdf_attachment)

        # Connexion SMTP et envoi
        server = smtplib.SMTP(
            email_config.get('smtp_server', 'smtp.gmail.com'),
            email_config.get('smtp_port', 587)
        )
        server.starttls()
        server.login(
            email_config.get('smtp_username', ''),
            email_config.get('smtp_password', '')
        )
        server.send_message(msg)
        server.quit()

        return {'success': True}

    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'Échec d\'authentification SMTP. Vérifiez vos identifiants.'}
    except smtplib.SMTPException as e:
        return {'success': False, 'error': f'Erreur SMTP: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Erreur: {str(e)}'}


@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_csv():
    """Upload et analyse d'un fichier CSV"""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Format de fichier non supporté. Utilisez un fichier CSV.'}), 400

    # Sauvegarder le fichier
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)

    try:
        # Parser le CSV
        data_by_shipper = parse_csv(filepath)

        if not data_by_shipper:
            os.remove(filepath)
            return jsonify({'error': 'Aucune donnée trouvée dans le fichier CSV'}), 400

        # Charger la config des clients
        clients_config = load_clients_config()

        # Préparer le résumé
        shippers_summary = []
        for shipper_name, rows in data_by_shipper.items():
            client_info = get_client_info(shipper_name, clients_config)

            # Calculer le total estimé
            total_ht = sum(
                float(row.get('Prix', '0').replace(',', '.') or '0') *
                int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
                for row in rows
            )

            shippers_summary.append({
                'name': shipper_name,
                'lines_count': len(rows),
                'total_ht': round(total_ht, 2),
                'client_configured': client_info.get('siret', '') != '00000000000000',
                'client_email': client_info.get('email', '')
            })

        save_clients_config(clients_config)

        return jsonify({
            'success': True,
            'file_id': unique_filename,
            'shippers': shippers_summary,
            'total_shippers': len(shippers_summary)
        })

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Erreur lors du traitement: {str(e)}'}), 500


@app.route('/api/generate', methods=['POST'])
def generate_invoices():
    """Génère les factures PDF"""
    data = request.json
    file_id = data.get('file_id')
    start_number = data.get('start_number', 1)
    prefix = data.get('prefix', 'PP')
    selected_shippers = data.get('shippers', [])

    if not file_id:
        return jsonify({'error': 'Aucun fichier spécifié'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    try:
        # Parser le CSV
        data_by_shipper = parse_csv(filepath)
        clients_config = load_clients_config()

        # Créer un dossier unique pour cette génération
        batch_id = uuid.uuid4().hex[:8]
        batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
        os.makedirs(batch_folder, exist_ok=True)

        # Générer les factures
        generator = InvoicePDFGenerator(output_dir=batch_folder)
        year = datetime.now().year
        invoice_num = int(start_number)

        generated = []

        for shipper_name, rows in data_by_shipper.items():
            # Si une sélection est spécifiée, filtrer
            if selected_shippers and shipper_name not in selected_shippers:
                continue

            client_info = get_client_info(shipper_name, clients_config)
            invoice_number = generate_invoice_number(prefix, year, invoice_num)

            # Extraire la période depuis les données
            start_date = rows[0].get('Invoice Staring date', '') if rows else ''
            end_date = rows[0].get('Invoice Ending date', '') if rows else ''
            period = f"du {start_date} au {end_date}" if start_date and end_date else ''

            filepath_pdf, total_ttc = generator.generate_invoice(
                shipper_name,
                rows,
                client_info,
                invoice_number
            )

            # Calculer le total HT
            total_ht = sum(
                float(row.get('Prix', '0').replace(',', '.') or '0') *
                int(float(row.get('Quantité', '1').replace(',', '.') or '1'))
                for row in rows
            )

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
                'client_email': client_info.get('email', ''),
                'period': period,
                'email_sent': False
            }

            generated.append(invoice_data)

            # Ajouter à l'historique
            add_to_invoice_history(invoice_data, batch_id)

            invoice_num += 1

        # Sauvegarder les données du batch pour l'envoi d'emails
        batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)
        with open(batch_data_path, 'w', encoding='utf-8') as f:
            json.dump({'invoices': generated, 'created_at': datetime.now().isoformat()}, f, indent=2, ensure_ascii=False)

        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'invoices': generated,
            'total_generated': len(generated)
        })

    except Exception as e:
        return jsonify({'error': f'Erreur lors de la génération: {str(e)}'}), 500


@app.route('/api/download/<batch_id>/<filename>')
def download_invoice(batch_id, filename):
    """Télécharge une facture individuelle"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route('/api/download-all/<batch_id>')
def download_all_invoices(batch_id):
    """Télécharge toutes les factures en ZIP"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")

    if not os.path.exists(batch_folder):
        return jsonify({'error': 'Batch non trouvé'}), 404

    # Créer le ZIP
    zip_path = os.path.join(app.config['OUTPUT_FOLDER'], f"factures_{batch_id}")
    shutil.make_archive(zip_path, 'zip', batch_folder)

    return send_file(
        f"{zip_path}.zip",
        as_attachment=True,
        download_name=f"factures_{batch_id}.zip"
    )


# ============================================================================
# Routes Email
# ============================================================================

@app.route('/api/email/config', methods=['GET'])
def get_email_config():
    """Récupère la configuration email (sans le mot de passe)"""
    config = load_email_config()
    # Ne pas renvoyer le mot de passe
    safe_config = {k: v for k, v in config.items() if k != 'smtp_password'}
    safe_config['smtp_password_set'] = bool(config.get('smtp_password'))
    return jsonify(safe_config)


@app.route('/api/email/config', methods=['PUT'])
def update_email_config():
    """Met à jour la configuration email"""
    data = request.json
    config = load_email_config()

    # Mettre à jour les champs fournis
    for key in ['smtp_server', 'smtp_port', 'smtp_username', 'sender_email',
                'sender_name', 'email_subject', 'email_template',
                'reminder_1_subject', 'reminder_1_template',
                'reminder_2_subject', 'reminder_2_template',
                'reminder_3_subject', 'reminder_3_template']:
        if key in data:
            config[key] = data[key]

    # Mot de passe uniquement s'il est fourni et non vide
    if data.get('smtp_password'):
        config['smtp_password'] = data['smtp_password']

    save_email_config(config)

    # Retourner la config sans le mot de passe
    safe_config = {k: v for k, v in config.items() if k != 'smtp_password'}
    safe_config['smtp_password_set'] = bool(config.get('smtp_password'))
    return jsonify({'success': True, 'config': safe_config})


@app.route('/api/email/send/<batch_id>/<invoice_number>', methods=['POST'])
def send_single_email(batch_id, invoice_number):
    """Envoie un email pour une facture spécifique"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    # Charger les données du batch
    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    # Trouver la facture
    invoice_data = None
    invoice_index = None
    for i, inv in enumerate(batch_data.get('invoices', [])):
        if inv.get('invoice_number') == invoice_number:
            invoice_data = inv
            invoice_index = i
            break

    if not invoice_data:
        return jsonify({'error': 'Facture non trouvée'}), 404

    # Charger la config email
    email_config = load_email_config()

    # Envoyer l'email
    result = send_invoice_email(invoice_data, email_config, batch_folder)

    if result['success']:
        # Marquer comme envoyé
        batch_data['invoices'][invoice_index]['email_sent'] = True
        batch_data['invoices'][invoice_index]['email_sent_at'] = datetime.now().isoformat()
        with open(batch_data_path, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)

    return jsonify(result)


@app.route('/api/email/send-all/<batch_id>', methods=['POST'])
def send_all_emails(batch_id):
    """Envoie les emails pour toutes les factures du batch"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    # Option: seulement les non-envoyés
    only_pending = request.json.get('only_pending', True) if request.json else True

    # Charger les données du batch
    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    # Charger la config email
    email_config = load_email_config()

    results = {
        'total': 0,
        'sent': 0,
        'failed': 0,
        'skipped': 0,
        'details': []
    }

    for i, invoice_data in enumerate(batch_data.get('invoices', [])):
        results['total'] += 1

        # Vérifier si déjà envoyé
        if only_pending and invoice_data.get('email_sent'):
            results['skipped'] += 1
            results['details'].append({
                'invoice_number': invoice_data.get('invoice_number'),
                'status': 'skipped',
                'message': 'Déjà envoyé'
            })
            continue

        # Vérifier si email présent
        if not invoice_data.get('client_email'):
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice_data.get('invoice_number'),
                'status': 'failed',
                'message': 'Pas d\'adresse email'
            })
            continue

        # Envoyer l'email
        result = send_invoice_email(invoice_data, email_config, batch_folder)

        if result['success']:
            results['sent'] += 1
            batch_data['invoices'][i]['email_sent'] = True
            batch_data['invoices'][i]['email_sent_at'] = datetime.now().isoformat()
            results['details'].append({
                'invoice_number': invoice_data.get('invoice_number'),
                'status': 'sent',
                'message': 'Envoyé avec succès'
            })
        else:
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice_data.get('invoice_number'),
                'status': 'failed',
                'message': result.get('error', 'Erreur inconnue')
            })

    # Sauvegarder les mises à jour
    with open(batch_data_path, 'w', encoding='utf-8') as f:
        json.dump(batch_data, f, indent=2, ensure_ascii=False)

    return jsonify({'success': True, 'results': results})


@app.route('/api/email/status/<batch_id>', methods=['GET'])
def get_email_status(batch_id):
    """Récupère le statut d'envoi des emails pour un batch"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    batch_data_path = os.path.join(batch_folder, BATCH_DATA_FILE)

    if not os.path.exists(batch_data_path):
        return jsonify({'error': 'Batch non trouvé'}), 404

    with open(batch_data_path, 'r', encoding='utf-8') as f:
        batch_data = json.load(f)

    return jsonify({
        'success': True,
        'invoices': batch_data.get('invoices', [])
    })


@app.route('/api/email/preview/<email_type>', methods=['GET'])
def preview_email(email_type):
    """Génère une prévisualisation de l'email HTML"""
    if email_type not in ['invoice', 'reminder_1', 'reminder_2', 'reminder_3']:
        return jsonify({'error': 'Type d\'email invalide'}), 400

    email_config = load_email_config()

    # Données fictives pour la prévisualisation
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

    # Sélectionner le template approprié
    if email_type == 'invoice':
        template = email_config.get('email_template', '')
    else:
        template = email_config.get(f'{email_type}_template', '')

    body_text = format_email_body(template, sample_invoice)

    # Générer le HTML avec logo en base64 pour la prévisualisation
    html = create_html_email_preview(body_text, sample_invoice, email_type)

    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


def create_html_email_preview(body_text, invoice_data, email_type='invoice'):
    """Crée un email HTML pour prévisualisation (avec logo en base64)"""
    # Couleurs selon le type d'email
    header_colors = {
        'invoice': '#3026f0',
        'reminder_1': '#f59e0b',
        'reminder_2': '#f97316',
        'reminder_3': '#ef4444'
    }

    header_titles = {
        'invoice': 'Votre Facture',
        'reminder_1': 'Rappel de Paiement',
        'reminder_2': 'Action Requise',
        'reminder_3': 'Dernier Avis'
    }

    header_color = header_colors.get(email_type, '#3026f0')
    header_title = header_titles.get(email_type, 'Votre Facture')

    # Charger le logo en base64
    logo_src = '/static/logo_email.png'
    if os.path.exists(LOGO_EMAIL_PATH):
        with open(LOGO_EMAIL_PATH, 'rb') as f:
            logo_base64 = base64.b64encode(f.read()).decode('utf-8')
            logo_src = f'data:image/png;base64,{logo_base64}'

    body_html = body_text.replace('\n', '<br>')

    # Badge pour les relances
    badge_html = ''
    if email_type == 'reminder_2':
        badge_html = '<span style="display: inline-block; background-color: #fff3cd; color: #856404; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">URGENT</span><br>'
    elif email_type == 'reminder_3':
        badge_html = '<span style="display: inline-block; background-color: #f8d7da; color: #721c24; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">SUSPENSION IMMINENTE</span><br>'

    html = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prévisualisation Email - {header_title}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f0f2f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f0f2f5;">
        <tr>
            <td style="padding: 40px 20px;">
                <!-- Container principal -->
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="margin: 0 auto;">

                    <!-- Header avec logo -->
                    <tr>
                        <td style="background: linear-gradient(135deg, {header_color} 0%, {'#1a1aad' if email_type == 'invoice' else header_color} 100%); padding: 30px 40px; text-align: center; border-radius: 16px 16px 0 0;">
                            <img src="{logo_src}" alt="Peoples Post" style="height: 90px; margin: 0 auto 12px auto; display: block;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">{header_title}</h1>
                        </td>
                    </tr>

                    <!-- Carte principale -->
                    <tr>
                        <td style="background-color: #ffffff; padding: 0; border-radius: 0 0 16px 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">

                            <!-- Bandeau montant -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding: 30px 40px; border-bottom: 1px solid #eef0f2;">
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="text-align: left; vertical-align: middle;">
                                                    <span style="color: #8b8e94; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Facture</span><br>
                                                    <span style="color: #1a1a2e; font-size: 20px; font-weight: 700;">{invoice_data.get('invoice_number', '')}</span>
                                                </td>
                                                <td style="text-align: right; vertical-align: middle;">
                                                    <span style="color: #8b8e94; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Total TTC</span><br>
                                                    <span style="color: {header_color}; font-size: 32px; font-weight: 800;">{invoice_data.get('total_ttc_formatted', '')}</span>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>

                            <!-- Contenu -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding: 40px;">
                                        {badge_html}
                                        <div style="color: #4a4a5a; font-size: 15px; line-height: 1.8;">
                                            {body_html}
                                        </div>
                                    </td>
                                </tr>
                            </table>

                            <!-- Bouton (pour les relances) -->
                            {'<table role="presentation" width="100%" cellspacing="0" cellpadding="0"><tr><td style="padding: 0 40px 40px; text-align: center;"><a href="#" style="display: inline-block; background-color: ' + header_color + '; color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 50px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 15px ' + header_color + '40;">Nous contacter</a></td></tr></table>' if email_type != 'invoice' else ''}

                            <!-- Footer -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="background-color: #f8f9fb; padding: 30px 40px; border-radius: 0 0 16px 16px; border-top: 1px solid #eef0f2;">
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="text-align: center;">
                                                    <p style="color: #1a1a2e; font-size: 14px; font-weight: 700; margin: 0 0 8px 0;">
                                                        Peoples Post SAS
                                                    </p>
                                                    <p style="color: #8b8e94; font-size: 13px; margin: 0; line-height: 1.7;">
                                                        22 rue Emeriau, 75015 Paris<br>
                                                        <a href="mailto:victor.estines@peoplespost.fr" style="color: {header_color}; text-decoration: none;">victor.estines@peoplespost.fr</a><br>
                                                        SIRET 98004432500010
                                                    </p>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Mention légale -->
                    <tr>
                        <td style="padding: 25px 20px; text-align: center;">
                            <p style="color: #a0a3a8; font-size: 11px; margin: 0; line-height: 1.6;">
                                Ce message et ses pièces jointes sont confidentiels et destinés exclusivement au destinataire.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>'''

    return html


# ============================================================================
# Routes Historique
# ============================================================================

@app.route('/api/history', methods=['GET'])
def get_invoice_history():
    """Récupère l'historique des factures"""
    history = load_invoice_history()

    # Paramètres de filtrage optionnels
    search = request.args.get('search', '').lower()
    limit = request.args.get('limit', type=int)

    if search:
        history = [
            h for h in history
            if search in h.get('invoice_number', '').lower()
            or search in h.get('client_name', '').lower()
            or search in h.get('shipper', '').lower()
        ]

    if limit:
        history = history[:limit]

    return jsonify({
        'success': True,
        'history': history,
        'total': len(history)
    })


@app.route('/api/history/<invoice_id>', methods=['DELETE'])
def delete_from_history(invoice_id):
    """Supprime une facture de l'historique"""
    history = load_invoice_history()
    history = [h for h in history if h.get('id') != invoice_id]
    save_invoice_history(history)
    return jsonify({'success': True})


@app.route('/api/history/download/<invoice_id>')
def download_from_history(invoice_id):
    """Télécharge une facture depuis l'historique"""
    history = load_invoice_history()

    # Trouver la facture
    invoice = next((h for h in history if h.get('id') == invoice_id), None)

    if not invoice:
        return jsonify({'error': 'Facture non trouvée dans l\'historique'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    """Vide l'historique des factures"""
    save_invoice_history([])
    return jsonify({'success': True})


@app.route('/api/history/<invoice_id>/payment', methods=['PUT'])
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


@app.route('/api/history/<invoice_id>/reminder/<int:reminder_type>', methods=['POST'])
def send_single_reminder(invoice_id, reminder_type):
    """Envoie un email de relance pour une facture spécifique

    Args:
        reminder_type: 1 = première relance (48h), 2 = avertissement (7j), 3 = dernier avis
    """
    if reminder_type not in [1, 2, 3]:
        return jsonify({'error': 'Type de relance invalide (1, 2 ou 3)'}), 400

    history = load_invoice_history()

    # Trouver la facture
    invoice = next((h for h in history if h.get('id') == invoice_id), None)

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    if invoice.get('payment_status') == 'paid':
        return jsonify({'error': 'Cette facture est déjà marquée comme payée'}), 400

    if not invoice.get('client_email'):
        return jsonify({'error': 'Pas d\'adresse email pour ce client'}), 400

    # Vérifier si cette relance a déjà été envoyée
    reminder_sent_key = f'reminder_{reminder_type}_sent'
    if invoice.get(reminder_sent_key):
        return jsonify({'error': f'La relance {reminder_type} a déjà été envoyée'}), 400

    # Charger config email
    email_config = load_email_config()

    # Préparer les données
    invoice_data = {
        **invoice,
        'company_name': invoice.get('client_name', invoice.get('shipper', ''))
    }

    # Trouver le dossier batch
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

    # Envoyer l'email de relance
    result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type)

    if result['success']:
        # Mettre à jour l'historique
        reminder_at_key = f'reminder_{reminder_type}_at'
        update_invoice_in_history(invoice_id, {
            reminder_sent_key: True,
            reminder_at_key: datetime.now().isoformat()
        })
        return jsonify({'success': True, 'reminder_type': reminder_type})

    return jsonify(result), 500


@app.route('/api/history/reminders/send-all/<int:reminder_type>', methods=['POST'])
def send_all_reminders(reminder_type):
    """Envoie des relances de type spécifique pour toutes les factures impayées"""
    if reminder_type not in [1, 2, 3]:
        return jsonify({'error': 'Type de relance invalide (1, 2 ou 3)'}), 400

    data = request.json or {}
    invoice_ids = data.get('invoice_ids', [])  # Liste optionnelle d'IDs spécifiques

    history = load_invoice_history()
    email_config = load_email_config()

    reminder_sent_key = f'reminder_{reminder_type}_sent'
    reminder_at_key = f'reminder_{reminder_type}_at'
    reminder_names = {1: '1ère relance', 2: '2ème relance (avertissement)', 3: '3ème relance (dernier avis)'}

    results = {
        'total': 0,
        'sent': 0,
        'failed': 0,
        'skipped': 0,
        'details': []
    }

    for invoice in history:
        invoice_id = invoice.get('id')

        # Si des IDs spécifiques sont fournis, filtrer
        if invoice_ids and invoice_id not in invoice_ids:
            continue

        results['total'] += 1

        # Vérifier si déjà payé
        if invoice.get('payment_status') == 'paid':
            results['skipped'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'skipped',
                'message': 'Déjà payée'
            })
            continue

        # Vérifier si cette relance a déjà été envoyée
        if invoice.get(reminder_sent_key):
            results['skipped'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'skipped',
                'message': f'{reminder_names[reminder_type]} déjà envoyée'
            })
            continue

        # Vérifier si email présent
        if not invoice.get('client_email'):
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'failed',
                'message': 'Pas d\'adresse email'
            })
            continue

        # Préparer les données
        invoice_data = {
            **invoice,
            'company_name': invoice.get('client_name', invoice.get('shipper', ''))
        }

        batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

        # Envoyer la relance
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
                'message': f'{reminder_names[reminder_type]} envoyée'
            })
        else:
            results['failed'] += 1
            results['details'].append({
                'invoice_number': invoice.get('invoice_number'),
                'status': 'failed',
                'message': result.get('error', 'Erreur inconnue')
            })

    return jsonify({'success': True, 'results': results})


# ============================================================================
# Routes Clients
# ============================================================================

@app.route('/api/clients', methods=['GET'])
def get_clients():
    """Récupère la liste des clients"""
    clients = load_clients_config()
    return jsonify(clients)


@app.route('/api/clients/<client_name>', methods=['PUT'])
def update_client(client_name):
    """Met à jour les informations d'un client"""
    clients = load_clients_config()
    data = request.json

    if client_name not in clients:
        clients[client_name] = {}

    clients[client_name].update({
        'nom': data.get('nom', client_name),
        'adresse': data.get('adresse', ''),
        'code_postal': data.get('code_postal', ''),
        'ville': data.get('ville', ''),
        'pays': data.get('pays', 'France'),
        'email': data.get('email', ''),
        'siret': data.get('siret', '')
    })

    save_clients_config(clients)

    return jsonify({'success': True, 'client': clients[client_name]})


@app.route('/api/clients/<client_name>', methods=['DELETE'])
def delete_client(client_name):
    """Supprime un client"""
    clients = load_clients_config()

    if client_name in clients:
        del clients[client_name]
        save_clients_config(clients)

    return jsonify({'success': True})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port)
