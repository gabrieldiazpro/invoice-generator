"""
Blueprint Clients : CRUD, doublons, import/export, création de comptes.
"""

import os
import io
import csv
import json
import uuid
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from pymongo import ReplaceOne

from common.auth import admin_required
from common.database import clients_collection, users_collection
from common.helpers import validate_email
from common.client_matching import (
    load_clients_config, calculate_similarity, find_best_client_match
)
from common.email_service import send_client_welcome_email, generate_temp_password

logger = logging.getLogger(__name__)

clients_bp = Blueprint('clients', __name__)


# =============================================================================
# CRUD
# =============================================================================

@clients_bp.route('/api/clients', methods=['GET'])
@login_required
def get_clients():
    """Récupère la liste des clients avec statut des comptes"""
    clients = load_clients_config()

    if current_user.is_admin():
        client_accounts = list(users_collection.find(
            {'role': 'client'},
            {'client_id': 1, 'email': 1, 'last_login': 1, 'created_at': 1}
        ))

        accounts_by_client = {
            acc['client_id']: {
                'has_account': True,
                'email': acc.get('email'),
                'last_login': acc.get('last_login').isoformat() if acc.get('last_login') else None,
                'created_at': acc.get('created_at').isoformat() if acc.get('created_at') else None
            }
            for acc in client_accounts if acc.get('client_id')
        }

        for client_key in clients:
            if client_key in accounts_by_client:
                clients[client_key]['account_status'] = accounts_by_client[client_key]
            else:
                clients[client_key]['account_status'] = {'has_account': False}

    return jsonify(clients)


@clients_bp.route('/api/clients/<client_name>', methods=['PUT'])
@login_required
def update_client(client_name):
    """Met à jour les informations d'un client dans MongoDB"""
    data = request.json

    client_data = {
        '_id': client_name,
        'nom': data.get('nom', client_name),
        'adresse': data.get('adresse', ''),
        'code_postal': data.get('code_postal', ''),
        'ville': data.get('ville', ''),
        'pays': data.get('pays', 'France'),
        'email': data.get('email', ''),
        'siret': data.get('siret', '')
    }

    clients_collection.replace_one({'_id': client_name}, client_data, upsert=True)

    client_data.pop('_id')
    return jsonify({'success': True, 'client': client_data})


@clients_bp.route('/api/clients/<client_name>', methods=['DELETE'])
@login_required
def delete_client(client_name):
    """Supprime un client de MongoDB"""
    clients_collection.delete_one({'_id': client_name})
    return jsonify({'success': True})


# =============================================================================
# Doublons
# =============================================================================

@clients_bp.route('/api/clients/duplicates', methods=['GET'])
@login_required
def get_duplicate_clients():
    """Détecte les clients en doublon basé sur la similarité des noms"""
    clients = load_clients_config()
    client_names = list(clients.keys())

    duplicates = []
    processed = set()

    for i, name1 in enumerate(client_names):
        if name1 in processed:
            continue

        group = [name1]
        for name2 in client_names[i+1:]:
            if name2 in processed:
                continue
            if calculate_similarity(name1, name2) >= 0.65:
                group.append(name2)
                processed.add(name2)

        if len(group) > 1:
            processed.add(name1)
            best_client = None
            best_score = -1
            for name in group:
                client = clients[name]
                score = 0
                if client.get('siret', '00000000000000') != '00000000000000':
                    score += 10
                if client.get('email', 'email@example.com') != 'email@example.com':
                    score += 5
                if client.get('adresse', 'Adresse à compléter') != 'Adresse à compléter':
                    score += 3
                if score > best_score:
                    best_score = score
                    best_client = name

            duplicates.append({
                'names': group,
                'recommended_keep': best_client,
                'clients': {name: clients[name] for name in group}
            })

    return jsonify({
        'success': True,
        'duplicates': duplicates,
        'total_groups': len(duplicates)
    })


@clients_bp.route('/api/clients/duplicate-keys', methods=['GET'])
@login_required
def get_duplicate_client_keys():
    """Retourne uniquement les clés des clients en doublon"""
    clients = load_clients_config()
    client_names = list(clients.keys())
    duplicate_keys = set()
    processed = set()

    for i, name1 in enumerate(client_names):
        if name1 in processed:
            continue
        for name2 in client_names[i+1:]:
            if name2 in processed:
                continue
            if calculate_similarity(name1, name2) >= 0.65:
                duplicate_keys.add(name1)
                duplicate_keys.add(name2)
                processed.add(name2)
        if name1 in duplicate_keys:
            processed.add(name1)

    return jsonify({'keys': list(duplicate_keys)})


@clients_bp.route('/api/clients/merge', methods=['POST'])
@login_required
def merge_clients():
    """Fusionne des clients en doublon"""
    data = request.json
    keep_name = data.get('keep')
    delete_names = data.get('delete', [])

    if not keep_name or not delete_names:
        return jsonify({'error': 'Paramètres manquants (keep et delete requis)'}), 400

    deleted_count = 0
    for name in delete_names:
        if name != keep_name:
            result = clients_collection.delete_one({'_id': name})
            if result.deleted_count > 0:
                deleted_count += 1

    return jsonify({
        'success': True,
        'kept': keep_name,
        'deleted': deleted_count,
        'message': f'{deleted_count} doublon(s) supprimé(s), "{keep_name}" conservé'
    })


@clients_bp.route('/api/clients/cleanup-duplicates', methods=['POST'])
@login_required
def cleanup_all_duplicates():
    """Nettoie automatiquement tous les doublons"""
    clients = load_clients_config()
    client_names = list(clients.keys())

    processed = set()
    total_deleted = 0
    names_to_delete = []

    for i, name1 in enumerate(client_names):
        if name1 in processed:
            continue

        group = [name1]
        for name2 in client_names[i+1:]:
            if name2 in processed:
                continue
            if calculate_similarity(name1, name2) >= 0.65:
                group.append(name2)
                processed.add(name2)

        if len(group) > 1:
            processed.add(name1)

            best_client = None
            best_score = -1
            for name in group:
                client = clients[name]
                score = 0
                if client.get('siret', '00000000000000') != '00000000000000':
                    score += 10
                if client.get('email', 'email@example.com') != 'email@example.com':
                    score += 5
                if client.get('adresse', 'Adresse à compléter') != 'Adresse à compléter':
                    score += 3
                if score > best_score:
                    best_score = score
                    best_client = name

            for name in group:
                if name != best_client:
                    names_to_delete.append(name)
                    total_deleted += 1

    if names_to_delete:
        clients_collection.delete_many({'_id': {'$in': names_to_delete}})

    return jsonify({
        'success': True,
        'deleted': total_deleted,
        'message': f'{total_deleted} doublon(s) supprimé(s) automatiquement'
    })


# =============================================================================
# Opérations en masse
# =============================================================================

@clients_bp.route('/api/clients/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_clients():
    """Supprime plusieurs clients en une seule opération"""
    data = request.get_json()
    keys = data.get('keys', [])

    if not keys:
        return jsonify({'success': False, 'error': 'Aucun client sélectionné'}), 400

    try:
        result = clients_collection.delete_many({'_id': {'$in': keys}})
        return jsonify({
            'success': True,
            'message': f'{result.deleted_count} client(s) supprimé(s)',
            'deleted_count': result.deleted_count
        })
    except Exception as e:
        logger.error(f"Erreur suppression en masse: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@clients_bp.route('/api/clients/bulk-export', methods=['POST'])
@login_required
def bulk_export_clients():
    """Exporte plusieurs clients en CSV"""
    data = request.get_json()
    keys = data.get('keys', [])

    if not keys:
        return jsonify({'success': False, 'error': 'Aucun client sélectionné'}), 400

    try:
        clients = list(clients_collection.find({'_id': {'$in': keys}}))

        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')

        writer.writerow(['Nom', 'Adresse', 'Code Postal', 'Ville', 'Pays', 'Email', 'SIRET'])

        for client in clients:
            writer.writerow([
                client.get('nom', ''),
                client.get('adresse', ''),
                client.get('code_postal', ''),
                client.get('ville', ''),
                client.get('pays', 'France'),
                client.get('email', ''),
                client.get('siret', '')
            ])

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8-sig')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'clients_export_{datetime.now().strftime("%Y%m%d")}.csv'
        )
    except Exception as e:
        logger.error(f"Erreur export en masse: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Import
# =============================================================================

def _parse_import_file(filepath, ext):
    """Parse un fichier d'import (CSV ou Excel) et retourne un DataFrame"""
    import pandas as pd

    if ext == 'csv':
        df = None
        for sep in [';', ',', '\t']:
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    df = pd.read_csv(filepath, sep=sep, encoding=encoding)
                    if len(df.columns) > 1:
                        break
                except (UnicodeDecodeError, pd.errors.ParserError, ValueError):
                    continue
            if df is not None and len(df.columns) > 1:
                break

        if df is None or len(df.columns) <= 1:
            return None, "Impossible de lire le fichier CSV"
    else:
        best_df = None
        best_unnamed = float('inf')
        best_header = 0

        for header_row in [0, 1, 2, 3, 4, 5]:
            try:
                df = pd.read_excel(filepath, header=header_row)
                unnamed = sum(1 for col in df.columns if 'unnamed' in str(col).lower())
                if unnamed < best_unnamed:
                    best_unnamed = unnamed
                    best_df = df
                    best_header = header_row
                if unnamed <= 2:
                    break
            except (ValueError, KeyError, pd.errors.ParserError):
                continue

        df = best_df
        logger.info(f"Excel import: using header row {best_header} with {best_unnamed} unnamed columns")

        if df is None:
            return None, "Impossible de lire le fichier Excel"

    return df, None


def _get_import_column_mappings():
    """Retourne le mapping des colonnes pour l'import"""
    return {
        'nom': ['official company name', 'used customer name', 'company name', 'customer name', 'customer',
                'nom', 'name', 'raison_sociale', 'raison sociale', 'société', 'societe', 'client', 'shipper'],
        'adresse': ['billing address', 'adresse', 'address', 'rue', 'street'],
        'code_postal': ['code_postal', 'cp', 'postal_code', 'zip', 'zipcode', 'code postal'],
        'ville': ['ville', 'city', 'town'],
        'pays': ['pays', 'country'],
        'email': ['billing email address', 'email', 'mail', 'e-mail', 'courriel'],
        'siret': ['siret', 'numero de siret', 'siren', 'numero_siret', 'n° siret', 'n siret']
    }


def _extract_client_from_row(row, found_columns):
    """Extrait les données client d'une ligne du fichier"""
    nom_col = found_columns['nom']
    nom = str(row.get(nom_col, '')).strip()

    if not nom or nom == 'nan':
        return None, None

    def get_value(field, default=''):
        if field not in found_columns:
            return default
        val = str(row.get(found_columns[field], '')).strip()
        return default if val == 'nan' else val

    client_data = {
        '_id': nom,
        'nom': nom,
        'adresse': get_value('adresse', 'Adresse à compléter'),
        'code_postal': get_value('code_postal', '00000'),
        'ville': get_value('ville', 'Ville'),
        'pays': get_value('pays', 'France'),
        'email': get_value('email', 'email@example.com'),
        'siret': get_value('siret', '00000000000000')
    }

    siret = ''.join(c for c in client_data['siret'] if c.isdigit())
    client_data['siret'] = siret[:14] if len(siret) > 14 else (siret if siret else '00000000000000')

    return nom, client_data


@clients_bp.route('/api/clients/import', methods=['POST'])
@login_required
def import_clients():
    """Importe des clients depuis un fichier CSV ou Excel"""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext not in ['csv', 'xlsx', 'xls']:
        return jsonify({'error': 'Format non supporté. Utilisez CSV ou Excel (.xlsx, .xls)'}), 400

    mode = request.form.get('mode', 'auto')
    decisions_json = request.form.get('decisions', '{}')
    try:
        decisions = json.loads(decisions_json)
    except (json.JSONDecodeError, ValueError):
        decisions = {}

    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)

    try:
        df, error = _parse_import_file(filepath, ext)
        if error:
            os.remove(filepath)
            return jsonify({'error': error}), 400

        df.columns = [str(col).lower().strip() for col in df.columns]

        column_mappings = _get_import_column_mappings()
        found_columns = {}
        for target_col, variants in column_mappings.items():
            for variant in variants:
                if variant in df.columns:
                    found_columns[target_col] = variant
                    break

        if 'nom' not in found_columns:
            os.remove(filepath)
            return jsonify({
                'error': 'Colonne "nom" non trouvée. Colonnes détectées: ' + ', '.join(df.columns.tolist())
            }), 400

        all_existing_clients = {doc['_id']: doc for doc in clients_collection.find()}

        duplicates = []
        new_clients = []

        for index, row in df.iterrows():
            nom, client_data = _extract_client_from_row(row, found_columns)
            if not nom:
                continue

            existing = all_existing_clients.get(nom)
            existing_key = nom

            if not existing:
                matched_key, matched_info, score = find_best_client_match(nom, all_existing_clients, threshold=0.6)
                if matched_info and score >= 0.6:
                    existing = matched_info
                    existing_key = matched_key
                    logger.info(f"Import fuzzy match: '{nom}' → '{matched_key}' (score: {score:.2f})")

            if existing:
                duplicates.append({
                    'nom': nom,
                    'existing_key': existing_key,
                    'new_data': client_data,
                    'existing_data': {k: v for k, v in existing.items() if k != '_id'},
                    'is_fuzzy_match': existing_key != nom
                })
            else:
                new_clients.append(client_data)

        if mode == 'preview' or (mode == 'auto' and duplicates and not decisions):
            os.remove(filepath)
            return jsonify({
                'success': True,
                'needs_confirmation': True,
                'duplicates': duplicates,
                'new_count': len(new_clients),
                'duplicate_count': len(duplicates)
            })

        results = {
            'total': len(new_clients) + len(duplicates),
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': []
        }

        if new_clients:
            ops = [ReplaceOne({'_id': c['_id']}, c, upsert=True) for c in new_clients]
            try:
                bulk_result = clients_collection.bulk_write(ops, ordered=False)
                results['created'] += bulk_result.upserted_count + bulk_result.modified_count
            except Exception as e:
                results['errors'].append({'nom': 'batch', 'error': str(e)})

        dup_ops = []
        for dup in duplicates:
            nom = dup['nom']
            existing_key = dup.get('existing_key', nom)
            decision = decisions.get(nom, 'skip')

            if decision == 'add':
                client_data = dup['new_data'].copy()
                dup_ops.append(('add', nom, client_data))
            elif decision == 'update':
                update_data = dup['new_data'].copy()
                update_data['_id'] = existing_key
                dup_ops.append(('update', nom, update_data, existing_key))

        update_ops = []
        for op in dup_ops:
            if op[0] == 'update':
                _, nom, update_data, existing_key = op
                update_ops.append(ReplaceOne({'_id': existing_key}, update_data, upsert=True))
                results['updated'] += 1

        for op in dup_ops:
            if op[0] == 'add':
                _, nom, client_data = op
                try:
                    clients_collection.insert_one(client_data)
                    results['created'] += 1
                except Exception:
                    client_data['_id'] = f"{nom} (import)"
                    client_data['nom'] = f"{nom} (import)"
                    try:
                        clients_collection.insert_one(client_data)
                        results['created'] += 1
                    except Exception:
                        results['skipped'] += 1

        if update_ops:
            try:
                clients_collection.bulk_write(update_ops, ordered=False)
            except Exception as e:
                results['errors'].append({'nom': 'batch_update', 'error': str(e)})
            else:
                results['skipped'] += 1

        os.remove(filepath)

        return jsonify({
            'success': True,
            'results': results,
            'message': f"{results['created']} créé(s), {results['updated']} mis à jour, {results['skipped']} ignoré(s)"
        })

    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        logger.error(f"Erreur import clients: {e}")
        return jsonify({'error': f'Erreur lors du traitement: {str(e)}'}), 500


@clients_bp.route('/api/clients/template')
@login_required
def download_clients_template():
    """Génère et télécharge un template CSV pour l'import de clients"""
    csv_content = "Official company name;Billing Address;Billing email address;Siret\n"
    csv_content += "EXEMPLE SARL;12 rue de la Paix, 75001 Paris;contact@exemple.com;12345678901234\n"
    csv_content += "AUTRE CLIENT SAS;5 avenue des Champs, 69001 Lyon;info@autre.fr;98765432109876\n"

    buffer = io.BytesIO()
    buffer.write(csv_content.encode('utf-8-sig'))
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name='template_clients.csv'
    )


# =============================================================================
# Comptes clients
# =============================================================================

@clients_bp.route('/api/clients/<client_name>/create-account', methods=['POST'])
@login_required
@admin_required
def create_client_account(client_name):
    """Crée un compte utilisateur pour un client existant"""
    client = clients_collection.find_one({'_id': client_name})
    if not client:
        return jsonify({'error': 'Client non trouvé'}), 404

    client_email = client.get('email', '').strip().lower()
    if not client_email:
        return jsonify({'error': 'Ce client n\'a pas d\'adresse email configurée'}), 400

    if not validate_email(client_email):
        return jsonify({'error': 'L\'adresse email du client est invalide'}), 400

    existing_user = users_collection.find_one({'email': client_email})
    if existing_user:
        return jsonify({'error': 'Un compte existe déjà pour cette adresse email'}), 400

    existing_client_account = users_collection.find_one({'client_id': client_name})
    if existing_client_account:
        return jsonify({'error': 'Un compte client existe déjà pour ce client'}), 400

    temp_password = generate_temp_password()

    client_name_display = client.get('nom', client_name)
    user_data = {
        'email': client_email,
        'password': generate_password_hash(temp_password, method='pbkdf2:sha256'),
        'name': client_name_display,
        'role': 'client',
        'client_id': client_name,
        'created_at': datetime.now(),
        'created_by': current_user.email
    }

    result = users_collection.insert_one(user_data)

    clients_collection.update_one(
        {'_id': client_name},
        {'$set': {'user_id': result.inserted_id}}
    )

    data = request.get_json() or {}
    send_welcome = data.get('send_welcome_email', True)

    email_sent = False
    if send_welcome:
        try:
            email_result = send_client_welcome_email(client_email, client_name_display, temp_password)
            email_sent = email_result.get('success', False)
            if not email_sent:
                logger.warning(f"Échec envoi email bienvenue client: {email_result.get('error', 'Erreur inconnue')}")
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email de bienvenue: {e}")

    logger.info(f"Compte client créé: {client_email} pour {client_name} par {current_user.email}")

    return jsonify({
        'success': True,
        'message': 'Compte client créé avec succès',
        'user_id': str(result.inserted_id),
        'email': client_email,
        'email_sent': email_sent,
        'temp_password': temp_password if not send_welcome else None
    })


@clients_bp.route('/api/clients/<client_name>/account-status')
@login_required
@admin_required
def get_client_account_status(client_name):
    """Vérifie si un client a un compte utilisateur"""
    client_account = users_collection.find_one({
        'client_id': client_name,
        'role': 'client'
    })

    if client_account:
        return jsonify({
            'success': True,
            'has_account': True,
            'account': {
                'email': client_account.get('email'),
                'name': client_account.get('name'),
                'created_at': client_account.get('created_at').isoformat() if client_account.get('created_at') else None,
                'last_login': client_account.get('last_login').isoformat() if client_account.get('last_login') else None
            }
        })

    return jsonify({
        'success': True,
        'has_account': False
    })
