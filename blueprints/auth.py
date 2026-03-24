"""
Blueprint Auth : login, logout, gestion utilisateurs, impersonation, /api/me.
"""

import os
import logging
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request, render_template, redirect, url_for, session
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId

from common.config import LOGIN_LIMIT
from common.database import users_collection
from common.auth import User, admin_required, super_admin_required
from common.helpers import sanitize_string, validate_email, validate_password
from common.email_service import send_welcome_email

logger = logging.getLogger(__name__)

auth_bp = Blueprint('auth', __name__)


# =============================================================================
# Rate limiting (appliqué dans create_app si disponible)
# =============================================================================

def _get_optional_limit():
    """Retourne le décorateur optional_limit depuis l'app courante"""
    from flask import current_app
    return getattr(current_app, 'optional_limit', lambda x: lambda f: f)


# =============================================================================
# Login / Logout
# =============================================================================

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Route de connexion"""
    title = os.environ.get('LOGIN_TITLE')
    if current_user.is_authenticated:
        if current_user.is_client():
            return redirect(url_for('client_portal.client_portal'))
        return redirect(url_for('invoices.index'))

    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = sanitize_string(data.get('email', '')).lower()
        password = data.get('password', '')

        if not email or not password:
            logger.warning(f"Tentative de connexion avec données manquantes - IP: {request.remote_addr}")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Email et mot de passe requis'}), 400
            return render_template('login.html', error='Email et mot de passe requis', title=title)

        if users_collection is None:
            logger.error("users_collection est None - pas de connexion DB")
            return render_template('login.html', error='Service temporairement indisponible', title=title)

        user_data = users_collection.find_one({'email': email})
        logger.info(f"User lookup for {email}: {'found' if user_data else 'not found'}")

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user, remember=True)
            logger.info(f"Connexion réussie: {email} (role: {user.role}) - IP: {request.remote_addr}")

            users_collection.update_one(
                {'_id': user_data['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            if user.is_client():
                redirect_url = url_for('client_portal.client_portal')
            else:
                redirect_url = request.args.get('next') or url_for('invoices.index')

            if request.is_json:
                return jsonify({'success': True, 'redirect': redirect_url})
            return redirect(redirect_url)

        logger.warning(f"Échec de connexion: {email} - IP: {request.remote_addr}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Email ou mot de passe incorrect'}), 401
        return render_template('login.html', error='Email ou mot de passe incorrect', title=title)

    return render_template('login.html', title=title)


@auth_bp.route('/logout')
@login_required
def logout():
    """Route de déconnexion"""
    logger.info(f"Déconnexion: {current_user.email}")
    logout_user()
    return redirect(url_for('auth.login'))


# =============================================================================
# Gestion des utilisateurs (admin)
# =============================================================================

@auth_bp.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    users = list(users_collection.find({}, {'password': 0}))
    for user in users:
        user['_id'] = str(user['_id'])
    return jsonify({'success': True, 'users': users})


@auth_bp.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Crée un nouvel utilisateur"""
    data = request.get_json()

    email = sanitize_string(data.get('email', '')).lower()
    password = data.get('password', '')
    name = sanitize_string(data.get('name', ''))
    role = data.get('role', 'user')
    send_welcome = data.get('send_welcome_email', True)

    if not validate_email(email):
        logger.warning(f"Création utilisateur: email invalide - {email}")
        return jsonify({'error': 'Format d\'email invalide'}), 400

    if not validate_password(password):
        return jsonify({'error': 'Le mot de passe doit contenir au moins 6 caractères'}), 400

    if users_collection.find_one({'email': email}):
        logger.warning(f"Création utilisateur: email déjà existant - {email}")
        return jsonify({'error': 'Cet email existe déjà'}), 400

    if role in ['admin', 'super_admin'] and not current_user.is_super_admin():
        logger.warning(f"Tentative de création admin non autorisée par {current_user.email}")
        return jsonify({'error': 'Seul le super admin peut créer des administrateurs'}), 403

    if role not in ['user', 'admin', 'super_admin']:
        role = 'user'

    temp_password = password

    result = users_collection.insert_one({
        'email': email,
        'password': generate_password_hash(password),
        'name': name,
        'role': role,
        'created_at': datetime.now(),
        'created_by': current_user.email
    })

    logger.info(f"Utilisateur créé: {email} (rôle: {role}) par {current_user.email}")

    response_data = {
        'success': True,
        'user': {'_id': str(result.inserted_id), 'email': email, 'name': name, 'role': role}
    }

    if send_welcome:
        def send_email_background():
            try:
                email_result = send_welcome_email(email, name, temp_password)
                if email_result.get('success'):
                    logger.info(f"Email de bienvenue envoyé à {email}")
                else:
                    logger.warning(f"Échec envoi email bienvenue à {email}: {email_result.get('error')}")
            except Exception as e:
                logger.error(f"Erreur envoi email bienvenue à {email}: {e}")

        email_thread = threading.Thread(target=send_email_background)
        email_thread.daemon = True
        email_thread.start()
        response_data['welcome_email_sent'] = 'pending'

    return jsonify(response_data)


@auth_bp.route('/api/users/<user_id>', methods=['PUT'])
@login_required
@admin_required
def update_user(user_id):
    data = request.get_json()
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        if user.get('role') == 'super_admin' and not current_user.is_super_admin():
            return jsonify({'error': 'Vous ne pouvez pas modifier le super admin'}), 403
        update_data = {}
        if 'name' in data:
            update_data['name'] = data['name']
        if 'email' in data:
            update_data['email'] = data['email'].lower().strip()
        if 'password' in data and data['password']:
            update_data['password'] = generate_password_hash(data['password'])
        if 'role' in data:
            if data['role'] in ['admin', 'super_admin'] and not current_user.is_super_admin():
                return jsonify({'error': 'Seul le super admin peut attribuer ce rôle'}), 403
            update_data['role'] = data['role']
        if update_data:
            users_collection.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/users/<user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
        if user.get('role') == 'super_admin':
            return jsonify({'error': 'Impossible de supprimer le super admin'}), 403
        if str(user['_id']) == current_user.id:
            return jsonify({'error': 'Vous ne pouvez pas supprimer votre propre compte'}), 403
        users_collection.delete_one({'_id': ObjectId(user_id)})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Impersonation (Super Admin seulement)
# =============================================================================

@auth_bp.route('/api/users/<user_id>/impersonate', methods=['POST'])
@login_required
@super_admin_required
def impersonate_user(user_id):
    """Permet au super admin de se connecter en tant qu'un autre utilisateur"""
    try:
        target_user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not target_user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404

        if str(target_user['_id']) == current_user.id:
            return jsonify({'error': 'Vous ne pouvez pas vous impersonner vous-même'}), 400

        original_admin_id = session.get('impersonated_by') or current_user.id
        session['impersonated_by'] = original_admin_id

        impersonated_user = User(target_user, impersonated_by=original_admin_id)
        login_user(impersonated_user)

        logger.info(f"Super admin {original_admin_id} impersonne l'utilisateur {target_user['email']}")

        return jsonify({
            'success': True,
            'message': f"Vous êtes maintenant connecté en tant que {target_user['email']}",
            'user': {
                'id': str(target_user['_id']),
                'email': target_user['email'],
                'name': target_user.get('name', ''),
                'role': target_user.get('role', 'user')
            }
        })
    except Exception as e:
        logger.error(f"Erreur impersonation: {e}")
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/api/stop-impersonate', methods=['POST'])
@login_required
def stop_impersonation():
    """Arrête l'impersonation et revient au compte super admin"""
    try:
        original_admin_id = session.get('impersonated_by')

        if not original_admin_id:
            return jsonify({'error': 'Vous n\'êtes pas en mode impersonation'}), 400

        admin_data = users_collection.find_one({'_id': ObjectId(original_admin_id)})
        if not admin_data:
            session.pop('impersonated_by', None)
            logout_user()
            return jsonify({'error': 'Compte administrateur non trouvé, déconnexion'}), 400

        session.pop('impersonated_by', None)

        admin_user = User(admin_data)
        login_user(admin_user)

        logger.info(f"Super admin {admin_data['email']} a arrêté l'impersonation")

        return jsonify({
            'success': True,
            'message': f"Vous êtes de retour sur votre compte ({admin_data['email']})",
            'user': {
                'id': str(admin_data['_id']),
                'email': admin_data['email'],
                'name': admin_data.get('name', ''),
                'role': admin_data.get('role', 'super_admin')
            }
        })
    except Exception as e:
        logger.error(f"Erreur arrêt impersonation: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Profil utilisateur (/api/me)
# =============================================================================

@auth_bp.route('/api/me', methods=['GET'])
@login_required
def get_current_user():
    user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})

    response = {
        'success': True,
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'name': current_user.name,
            'role': current_user.role,
            'sender_name': user_data.get('sender_name', ''),
            'sender_email': user_data.get('sender_email', '')
        }
    }

    if current_user.is_impersonating():
        original_admin = users_collection.find_one({'_id': ObjectId(current_user.impersonated_by)})
        response['impersonation'] = {
            'active': True,
            'original_admin_id': current_user.impersonated_by,
            'original_admin_email': original_admin['email'] if original_admin else 'Unknown'
        }

    return jsonify(response)


@auth_bp.route('/api/me/password', methods=['PUT'])
@login_required
def change_my_password():
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    if not current_password or not new_password:
        return jsonify({'error': 'Mot de passe actuel et nouveau requis'}), 400
    user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
    if not check_password_hash(user_data['password'], current_password):
        return jsonify({'error': 'Mot de passe actuel incorrect'}), 401
    users_collection.update_one({'_id': ObjectId(current_user.id)}, {'$set': {'password': generate_password_hash(new_password)}})
    return jsonify({'success': True})


@auth_bp.route('/api/me/sender', methods=['PUT'])
@login_required
def update_my_sender():
    """Met à jour le nom et email d'expéditeur de l'utilisateur"""
    data = request.get_json()
    sender_name = data.get('sender_name', '')
    sender_email = data.get('sender_email', '')

    users_collection.update_one(
        {'_id': ObjectId(current_user.id)},
        {'$set': {'sender_name': sender_name, 'sender_email': sender_email}}
    )
    return jsonify({'success': True})
