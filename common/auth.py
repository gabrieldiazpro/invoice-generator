"""
User model, login manager et décorateurs d'authentification.
"""

import os
import logging
from datetime import datetime
from functools import wraps
from flask import jsonify, request, session
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash
from bson.objectid import ObjectId

from common.database import users_collection, db, invoice_history_collection, clients_collection, counters_collection

logger = logging.getLogger(__name__)

# =============================================================================
# Login Manager (init_app appelé depuis l'app factory)
# =============================================================================

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'warning'


# =============================================================================
# User Model
# =============================================================================

class User(UserMixin):
    def __init__(self, user_data, impersonated_by=None):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.role = user_data.get('role', 'user')
        self.client_id = user_data.get('client_id')
        self.impersonated_by = impersonated_by

    def is_admin(self):
        return self.role in ['admin', 'super_admin']

    def is_super_admin(self):
        return self.role == 'super_admin'

    def is_client(self):
        return self.role == 'client'

    def is_impersonating(self):
        return self.impersonated_by is not None


@login_manager.user_loader
def load_user(user_id):
    """Charge un utilisateur depuis son ID"""
    try:
        if users_collection is None:
            return None
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            impersonated_by = session.get('impersonated_by')
            return User(user_data, impersonated_by=impersonated_by)
    except Exception as e:
        logger.error(f"Erreur lors du chargement de l'utilisateur {user_id}: {e}")
    return None


# =============================================================================
# Décorateurs d'accès
# =============================================================================

def admin_required(f):
    """Décorateur pour restreindre l'accès aux administrateurs"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            logger.warning(f"Accès admin refusé: {getattr(current_user, 'email', 'anonymous')} sur {request.path}")
            return jsonify({'error': 'Accès non autorisé'}), 403
        return f(*args, **kwargs)
    return decorated_function


def super_admin_required(f):
    """Décorateur pour restreindre l'accès aux super administrateurs"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin():
            logger.warning(f"Accès super admin refusé: {getattr(current_user, 'email', 'anonymous')} sur {request.path}")
            return jsonify({'error': 'Accès réservé au super administrateur'}), 403
        return f(*args, **kwargs)
    return decorated_function


def client_required(f):
    """Décorateur pour restreindre l'accès aux clients"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_client():
            logger.warning(f"Accès client refusé: {getattr(current_user, 'email', 'anonymous')} sur {request.path}")
            return jsonify({'error': 'Accès réservé aux clients'}), 403
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# Initialisation
# =============================================================================

def init_super_admin():
    """Crée le super admin si il n'existe pas"""
    if users_collection is None:
        logger.warning("Impossible de créer le super admin: base de données non disponible")
        return

    try:
        existing = users_collection.find_one({'email': 'gabriel@peoplespost.fr'})
        if existing is None:
            users_collection.insert_one({
                'email': 'gabriel@peoplespost.fr',
                'password': generate_password_hash(os.environ.get('ADMIN_PASSWORD'), method='pbkdf2:sha256'),
                'name': 'Gabriel',
                'role': 'super_admin',
                'created_at': datetime.now()
            })
            logger.info("Super admin créé: gabriel@peoplespost.fr")
        else:
            logger.debug("Super admin déjà existant")
    except Exception as e:
        logger.error(f"Erreur lors de la création du super admin: {e}")


def get_user_sender_info():
    """Récupère le nom et email d'expéditeur de l'utilisateur courant"""
    if current_user.is_authenticated:
        user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
        if user_data:
            return user_data.get('sender_name', ''), user_data.get('sender_email', '')
    return '', ''


def init_db_indexes():
    """Crée les index MongoDB pour de meilleures performances"""
    if db is None:
        return
    try:
        invoice_history_collection.create_index('created_at')
        invoice_history_collection.create_index('shipper')
        invoice_history_collection.create_index('payment_status')
        invoice_history_collection.create_index('id')
        invoice_history_collection.create_index('email_sent')
        invoice_history_collection.create_index([('email_sent', 1), ('id', 1)])
        invoice_history_collection.create_index([('payment_status', 1), ('created_at', -1)])
        invoice_history_collection.create_index([('shipper', 1), ('created_at', -1)])
        invoice_history_collection.create_index([('shipper', 1), ('period', 1)])
        invoice_history_collection.create_index([('client_siret', 1), ('period', 1)])
        invoice_history_collection.create_index('client_siret')
        invoice_history_collection.create_index('client_name')
        invoice_history_collection.create_index('emission_date')
        invoice_history_collection.create_index('due_date')

        users_collection.create_index('email', unique=True)
        users_collection.create_index('client_id')
        users_collection.create_index('role')

        clients_collection.create_index('email')

        logger.info("Index MongoDB créés avec succès")
    except Exception as e:
        logger.warning(f"Impossible de créer les index MongoDB: {e}")
