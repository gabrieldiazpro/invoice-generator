#!/usr/bin/env python3
"""
Peoples Post - Application web de génération de factures

Version: 1.0.0
Author: Peoples Post Team
"""

import os
import sys
import json
import uuid
import shutil
import smtplib
import base64
import logging
import traceback
import re
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from pymongo import MongoClient, ReturnDocument

# Flask-Limiter (optionnel)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    Limiter = None
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from bson.objectid import ObjectId
from invoice_generator import (
    parse_csv, load_clients_config as load_clients_config_file,
    save_clients_config as save_clients_config_file,
    get_client_info as get_client_info_original,
    InvoicePDFGenerator, generate_invoice_number, format_currency,
    CLIENTS_CONFIG_FILE
)

# =============================================================================
# Configuration
# =============================================================================

# Environment
ENV = os.environ.get('FLASK_ENV', 'production')
DEBUG = ENV == 'development'
VERSION = '1.0.0'

# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(app):
    """Configure le logging structuré pour l'application"""
    log_format = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    log_level = logging.DEBUG if DEBUG else logging.INFO

    # Console handler uniquement
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(log_format)
    handler.setLevel(log_level)

    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)
    app.logger.propagate = False

    return app.logger


# =============================================================================
# Flask App Initialization
# =============================================================================

app = Flask(__name__, static_folder='static', template_folder='templates')

# Vérification SECRET_KEY en production
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if DEBUG:
        secret_key = 'dev-secret-key-for-development-only'
    else:
        # Générer une clé temporaire en production si non définie (non recommandé)
        secret_key = secrets.token_hex(32)
        print("ATTENTION: SECRET_KEY non défini en production! Sessions invalides après redémarrage.")

# Configuration
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max
    UPLOAD_FOLDER=os.path.join(os.path.dirname(__file__), 'uploads'),
    OUTPUT_FOLDER=os.path.join(os.path.dirname(__file__), 'output'),
    SECRET_KEY=secret_key,
    SESSION_COOKIE_SECURE=not DEBUG,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
    JSON_AS_ASCII=False,
    JSON_SORT_KEYS=False,
)

# Setup logging
logger = setup_logging(app)

# =============================================================================
# Rate Limiting (optionnel)
# =============================================================================

if LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
        strategy="fixed-window"
    )
    LOGIN_LIMIT = "5 per minute"
    EMAIL_LIMIT = "10 per minute"
    API_LIMIT = "60 per minute"
    logger.info("Rate limiting activé")
else:
    limiter = None
    LOGIN_LIMIT = None
    EMAIL_LIMIT = None
    API_LIMIT = None
    logger.warning("Flask-Limiter non disponible - rate limiting désactivé")


def optional_limit(limit_string):
    """Décorateur de rate limiting optionnel"""
    def decorator(f):
        if LIMITER_AVAILABLE and limiter and limit_string:
            return limiter.limit(limit_string)(f)
        return f
    return decorator

# =============================================================================
# MongoDB Configuration
# =============================================================================

# Configuration MongoDB
# En production, MONGO_URI devrait être défini comme variable d'environnement
MONGO_URI = os.environ.get('MONGO_URI', '').strip()

if not MONGO_URI:
    # Fallback temporaire - À SUPPRIMER en production finale
    MONGO_URI = 'mongodb+srv://gabrieldiazpro_db_user:gabrieldiazpro_db_password@peoples-post.dabmazu.mongodb.net/?appName=peoples-post'
    if not DEBUG:
        logger.warning("MONGO_URI non défini - utilisation du fallback")

try:
    mongo_client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000,
        socketTimeoutMS=10000
    )
    # Test connection
    mongo_client.admin.command('ping')
    logger.info("Connexion MongoDB établie avec succès")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.critical(f"Erreur connexion MongoDB: {e}")
    mongo_client = None
except Exception as e:
    logger.critical(f"Erreur MongoDB (vérifiez MONGO_URI): {e}")
    mongo_client = None

db = mongo_client['invoice_generator'] if mongo_client is not None else None
users_collection = db['users'] if db is not None else None
email_config_collection = db['email_config'] if db is not None else None
invoice_history_collection = db['invoice_history'] if db is not None else None
clients_collection = db['clients'] if db is not None else None


def require_db(f):
    """Décorateur pour vérifier la connexion à la base de données"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if mongo_client is None or db is None:
            logger.error("Base de données non disponible")
            return jsonify({'error': 'Service temporairement indisponible'}), 503
        return f(*args, **kwargs)
    return decorated_function


def load_clients_config():
    """Charge la configuration des clients depuis MongoDB"""
    clients = {}
    for client in clients_collection.find():
        client_name = client.pop('_id')
        clients[client_name] = client
    if not clients:
        # Migration: charger depuis le fichier JSON si existe
        if os.path.exists(CLIENTS_CONFIG_FILE):
            clients = load_clients_config_file()
            if clients:
                save_clients_config(clients)
    return clients


def save_clients_config(clients):
    """Sauvegarde la configuration des clients dans MongoDB"""
    for client_name, client_data in clients.items():
        client_doc = dict(client_data)
        client_doc['_id'] = client_name
        clients_collection.replace_one({'_id': client_name}, client_doc, upsert=True)


def get_client_info(shipper_name, clients_config):
    """Récupère les informations d'un client ou crée une entrée par défaut"""
    if shipper_name in clients_config:
        return clients_config[shipper_name]

    # Vérifier dans MongoDB
    client = clients_collection.find_one({'_id': shipper_name})
    if client:
        client.pop('_id', None)
        clients_config[shipper_name] = client
        return client

    # Créer une entrée par défaut
    default_client = {
        "nom": shipper_name,
        "adresse": "Adresse à compléter",
        "code_postal": "00000",
        "ville": "Ville",
        "pays": "France",
        "email": "email@example.com",
        "siret": "00000000000000"
    }
    clients_config[shipper_name] = default_client
    # Sauvegarder dans MongoDB
    client_doc = dict(default_client)
    client_doc['_id'] = shipper_name
    clients_collection.replace_one({'_id': shipper_name}, client_doc, upsert=True)
    return default_client

# =============================================================================
# Validation Helpers
# =============================================================================

def validate_email(email):
    """Valide le format d'une adresse email"""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Valide la force d'un mot de passe (min 6 caractères)"""
    return password and len(password) >= 6


def sanitize_string(value, max_length=500):
    """Nettoie et limite la longueur d'une chaîne"""
    if not isinstance(value, str):
        return ''
    return value.strip()[:max_length]


# =============================================================================
# Request Middleware
# =============================================================================

@app.before_request
def before_request():
    """Middleware exécuté avant chaque requête"""
    g.request_start_time = datetime.now()
    g.request_id = str(uuid.uuid4())[:8]

    # Log la requête (sauf pour les assets statiques)
    if not request.path.startswith('/static'):
        logger.debug(f"[{g.request_id}] {request.method} {request.path} - IP: {request.remote_addr}")


@app.after_request
def after_request(response):
    """Middleware exécuté après chaque requête"""
    # Calcul du temps de réponse
    if hasattr(g, 'request_start_time'):
        duration = (datetime.now() - g.request_start_time).total_seconds() * 1000
        response.headers['X-Response-Time'] = f"{duration:.2f}ms"

        # Log la réponse (sauf pour les assets statiques)
        if not request.path.startswith('/static'):
            logger.debug(
                f"[{getattr(g, 'request_id', '-')}] "
                f"{request.method} {request.path} -> {response.status_code} "
                f"({duration:.2f}ms)"
            )

    # Security Headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    if not DEBUG:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    return response


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad Request: {request.path} - {error}")
    return jsonify({'error': 'Requête invalide', 'code': 400}), 400


@app.errorhandler(401)
def unauthorized(error):
    logger.warning(f"Unauthorized: {request.path} - IP: {request.remote_addr}")
    return jsonify({'error': 'Non autorisé', 'code': 401}), 401


@app.errorhandler(403)
def forbidden(error):
    logger.warning(f"Forbidden: {request.path} - User: {getattr(current_user, 'email', 'anonymous')}")
    return jsonify({'error': 'Accès interdit', 'code': 403}), 403


@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Ressource non trouvée', 'code': 404}), 404
    return render_template('404.html'), 404


@app.errorhandler(413)
def request_entity_too_large(error):
    logger.warning(f"File too large: {request.path}")
    return jsonify({'error': 'Fichier trop volumineux (max 16MB)', 'code': 413}), 413


@app.errorhandler(429)
def rate_limit_exceeded(error):
    logger.warning(f"Rate limit exceeded: {request.remote_addr}")
    return jsonify({'error': 'Trop de requêtes, veuillez réessayer plus tard', 'code': 429}), 429


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal Error: {request.path} - {error}\n{traceback.format_exc()}")
    return jsonify({'error': 'Erreur interne du serveur', 'code': 500}), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """Gestionnaire global des exceptions non gérées"""
    # Laisser passer les erreurs HTTP
    if isinstance(e, HTTPException):
        return e

    # Log l'erreur
    logger.error(f"Unhandled Exception: {type(e).__name__}: {str(e)}\n{traceback.format_exc()}")

    # Retourner une erreur générique
    return jsonify({
        'error': 'Une erreur inattendue s\'est produite',
        'code': 500,
        'details': str(e) if DEBUG else None
    }), 500


# =============================================================================
# Health Check & Status
# =============================================================================

@app.route('/health')
def health_check():
    """Endpoint de health check pour Railway et monitoring"""
    health = {
        'status': 'healthy',
        'version': VERSION,
        'environment': ENV,
        'timestamp': datetime.now().isoformat()
    }

    # Check MongoDB
    try:
        if mongo_client:
            mongo_client.admin.command('ping')
            health['database'] = 'connected'
        else:
            health['database'] = 'disconnected'
            health['status'] = 'degraded'
    except Exception as e:
        health['database'] = 'error'
        health['database_error'] = str(e)
        health['status'] = 'unhealthy'

    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code


@app.route('/api/status')
@login_required
def api_status():
    """Endpoint de status détaillé (authentifié)"""
    status = {
        'version': VERSION,
        'environment': ENV,
        'user': current_user.email,
        'timestamp': datetime.now().isoformat()
    }

    # Stats MongoDB
    try:
        if db:
            status['stats'] = {
                'users': users_collection.count_documents({}),
                'invoices': invoice_history_collection.count_documents({}),
                'clients': clients_collection.count_documents({})
            }
    except Exception as e:
        status['stats_error'] = str(e)

    return jsonify(status)


# =============================================================================
# Flask-Login Configuration
# =============================================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'warning'

# Créer les dossiers si nécessaires
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)


# ============================================================================
# User Model & Authentication
# ============================================================================

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.role = user_data.get('role', 'user')

    def is_admin(self):
        return self.role in ['admin', 'super_admin']

    def is_super_admin(self):
        return self.role == 'super_admin'


@login_manager.user_loader
def load_user(user_id):
    """Charge un utilisateur depuis son ID"""
    try:
        if users_collection is None:
            return None
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            return User(user_data)
    except Exception as e:
        logger.error(f"Erreur lors du chargement de l'utilisateur {user_id}: {e}")
    return None


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


def init_super_admin():
    """Crée le super admin si il n'existe pas"""
    if users_collection is None:
        logger.warning("Impossible de créer le super admin: base de données non disponible")
        return

    try:
        if users_collection.find_one({'email': 'gabriel@peoplespost.fr'}) is None:
            users_collection.insert_one({
                'email': 'gabriel@peoplespost.fr',
                'password': generate_password_hash('admin123'),
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


init_super_admin()

ALLOWED_EXTENSIONS = {'csv'}
EMAIL_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'email_config.json')
INVOICE_HISTORY_FILE = os.path.join(os.path.dirname(__file__), 'invoice_history.json')
BATCH_DATA_FILE = 'batch_data.json'
LOGO_PATH = os.path.join(os.path.dirname(__file__), 'logo.png')
LOGO_EMAIL_PATH = os.path.join(os.path.dirname(__file__), 'logo_email.png')


def create_welcome_email_html(user_name, user_email, temp_password):
    """Crée un email HTML de bienvenue pour les nouveaux utilisateurs"""

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
                        <td style="background: linear-gradient(135deg, #3026f0 0%, #1a1aad 100%); padding: 30px 40px; text-align: center; border-radius: 16px 16px 0 0;">
                            <img src="cid:logo" alt="Peoples Post" style="height: 90px; margin: 0 auto 12px auto; display: block;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 700; letter-spacing: -0.5px;">Bienvenue !</h1>
                        </td>
                    </tr>

                    <!-- Carte principale -->
                    <tr>
                        <td style="background-color: #ffffff; padding: 0; border-radius: 0 0 16px 16px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);">

                            <!-- Message de bienvenue -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td style="padding: 40px;">
                                        <p style="color: #1a1a2e; font-size: 18px; font-weight: 600; margin: 0 0 20px 0;">
                                            Bonjour {user_name or 'et bienvenue'} !
                                        </p>
                                        <p style="color: #4a4a5a; font-size: 15px; line-height: 1.8; margin: 0 0 25px 0;">
                                            Votre compte a été créé sur le <strong>Générateur de Factures Peoples Post</strong>.
                                            Vous pouvez maintenant vous connecter et commencer à générer vos factures.
                                        </p>

                                        <!-- Encadré identifiants -->
                                        <div style="background-color: #f8f9fb; border-radius: 12px; padding: 25px; margin: 25px 0; border-left: 4px solid #3026f0;">
                                            <p style="color: #1a1a2e; font-size: 14px; font-weight: 600; margin: 0 0 15px 0; text-transform: uppercase; letter-spacing: 0.5px;">
                                                Vos identifiants de connexion
                                            </p>
                                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                                <tr>
                                                    <td style="padding: 8px 0;">
                                                        <span style="color: #8b8e94; font-size: 13px;">Email :</span><br>
                                                        <span style="color: #1a1a2e; font-size: 16px; font-weight: 600;">{user_email}</span>
                                                    </td>
                                                </tr>
                                                <tr>
                                                    <td style="padding: 8px 0;">
                                                        <span style="color: #8b8e94; font-size: 13px;">Mot de passe temporaire :</span><br>
                                                        <span style="color: #3026f0; font-size: 16px; font-weight: 600; font-family: monospace; background-color: #eef0ff; padding: 4px 10px; border-radius: 4px;">{temp_password}</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </div>

                                        <p style="color: #ef4444; font-size: 14px; line-height: 1.6; margin: 0 0 25px 0; padding: 12px; background-color: #fef2f2; border-radius: 8px;">
                                            <strong>Important :</strong> Pour des raisons de sécurité, nous vous recommandons de changer votre mot de passe dès votre première connexion.
                                        </p>

                                        <!-- Bouton connexion -->
                                        <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td style="text-align: center; padding: 10px 0;">
                                                    <a href="https://pp-invoces-generator.up.railway.app/login" style="display: inline-block; background-color: #3026f0; color: #ffffff; text-decoration: none; padding: 16px 40px; border-radius: 50px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 15px rgba(48, 38, 240, 0.3);">
                                                        Se connecter
                                                    </a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>

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
                                                        <a href="mailto:victor.estines@peoplespost.fr" style="color: #3026f0; text-decoration: none;">victor.estines@peoplespost.fr</a>
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


def send_welcome_email(user_email, user_name, temp_password):
    """Envoie un email de bienvenue au nouvel utilisateur"""
    email_config = load_email_config()

    if not email_config.get('smtp_username') or not email_config.get('smtp_password'):
        return {'success': False, 'error': 'Configuration SMTP incomplète'}

    try:
        # Créer le message multipart/related pour le HTML avec images inline
        msg = MIMEMultipart('related')
        msg['From'] = f"Peoples Post <{email_config.get('smtp_username', '')}>"
        msg['To'] = user_email
        msg['Subject'] = "Bienvenue sur le Générateur de Factures Peoples Post"

        # Créer la partie alternative (HTML + texte)
        msg_alternative = MIMEMultipart('alternative')
        msg.attach(msg_alternative)

        # Corps de l'email en texte brut (fallback)
        body_text = f"""Bonjour {user_name or 'et bienvenue'} !

Votre compte a été créé sur le Générateur de Factures Peoples Post.

Vos identifiants de connexion :
- Email : {user_email}
- Mot de passe temporaire : {temp_password}

Important : Pour des raisons de sécurité, nous vous recommandons de changer votre mot de passe dès votre première connexion.

Connectez-vous sur : https://pp-invoces-generator.up.railway.app/login

Cordialement,
L'équipe Peoples Post
"""
        msg_alternative.attach(MIMEText(body_text, 'plain', 'utf-8'))

        # Corps de l'email en HTML
        body_html = create_welcome_email_html(user_name, user_email, temp_password)
        msg_alternative.attach(MIMEText(body_html, 'html', 'utf-8'))

        # Ajouter le logo comme image intégrée
        if os.path.exists(LOGO_EMAIL_PATH):
            with open(LOGO_EMAIL_PATH, 'rb') as f:
                logo = MIMEImage(f.read())
                logo.add_header('Content-ID', '<logo>')
                logo.add_header('Content-Disposition', 'inline', filename='logo.png')
                msg.attach(logo)

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
        return {'success': False, 'error': 'Échec d\'authentification SMTP'}
    except smtplib.SMTPException as e:
        return {'success': False, 'error': f'Erreur SMTP: {str(e)}'}
    except Exception as e:
        return {'success': False, 'error': f'Erreur: {str(e)}'}


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
    """Charge la configuration email depuis MongoDB"""
    config = email_config_collection.find_one({'_id': 'main'})
    if config:
        config.pop('_id', None)
        return config
    # Migration: charger depuis le fichier JSON si existe
    if os.path.exists(EMAIL_CONFIG_FILE):
        with open(EMAIL_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            save_email_config(config)
            return config
    return {}


def save_email_config(config):
    """Sauvegarde la configuration email dans MongoDB"""
    config_copy = dict(config)
    config_copy['_id'] = 'main'
    email_config_collection.replace_one({'_id': 'main'}, config_copy, upsert=True)


def load_invoice_history():
    """Charge l'historique des factures depuis MongoDB"""
    history = list(invoice_history_collection.find().sort('created_at', -1))
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


def add_to_invoice_history(invoice_data, batch_id):
    """Ajoute une facture à l'historique dans MongoDB"""
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


def send_invoice_email(invoice_data, email_config, batch_folder, sender_name=None, sender_email=None):
    """Envoie un email HTML stylisé avec la facture en pièce jointe

    Args:
        invoice_data: Les données de la facture
        email_config: La configuration SMTP et templates
        batch_folder: Le dossier du batch contenant les PDFs
        sender_name: Nom de l'expéditeur (optionnel, priorité sur email_config)
        sender_email: Email de l'expéditeur (optionnel, priorité sur email_config)
    """
    recipient_email = invoice_data.get('client_email', '')

    if not recipient_email:
        return {'success': False, 'error': 'Pas d\'adresse email pour ce client'}

    if not email_config.get('smtp_username') or not email_config.get('smtp_password'):
        return {'success': False, 'error': 'Configuration SMTP incomplète'}

    # Utiliser l'identité de l'utilisateur si fournie, sinon celle de la config globale
    actual_sender_name = sender_name or email_config.get('sender_name', 'Peoples Post')
    actual_sender_email = sender_email or email_config.get('sender_email', '')

    try:
        # Créer le message multipart/related pour le HTML avec images inline
        msg = MIMEMultipart('related')
        msg['From'] = f"{actual_sender_name} <{actual_sender_email}>"
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

        logger.info(f"Email facture envoyé: {invoice_data.get('invoice_number')} -> {recipient_email}")
        return {'success': True}

    except smtplib.SMTPAuthenticationError:
        logger.error(f"Échec auth SMTP pour facture {invoice_data.get('invoice_number')}")
        return {'success': False, 'error': 'Échec d\'authentification SMTP. Vérifiez vos identifiants.'}
    except smtplib.SMTPException as e:
        logger.error(f"Erreur SMTP envoi facture {invoice_data.get('invoice_number')}: {e}")
        return {'success': False, 'error': f'Erreur SMTP: {str(e)}'}
    except Exception as e:
        logger.error(f"Erreur envoi facture {invoice_data.get('invoice_number')}: {e}")
        return {'success': False, 'error': f'Erreur: {str(e)}'}


def send_reminder_email(invoice_data, email_config, batch_folder, reminder_type=1, sender_name=None, sender_email=None):
    """Envoie un email HTML stylisé de relance avec la facture en pièce jointe

    Args:
        invoice_data: Les données de la facture
        email_config: La configuration SMTP et templates
        batch_folder: Le dossier du batch contenant les PDFs
        reminder_type: 1 = première relance (48h), 2 = avertissement (7j), 3 = dernier avis
        sender_name: Nom de l'expéditeur (optionnel, priorité sur email_config)
        sender_email: Email de l'expéditeur (optionnel, priorité sur email_config)
    """
    recipient_email = invoice_data.get('client_email', '')

    if not recipient_email:
        return {'success': False, 'error': 'Pas d\'adresse email pour ce client'}

    if not email_config.get('smtp_username') or not email_config.get('smtp_password'):
        return {'success': False, 'error': 'Configuration SMTP incomplète'}

    # Utiliser l'identité de l'utilisateur si fournie, sinon celle de la config globale
    actual_sender_name = sender_name or email_config.get('sender_name', 'Peoples Post')
    actual_sender_email = sender_email or email_config.get('sender_email', '')

    try:
        # Créer le message multipart/related pour le HTML avec images inline
        msg = MIMEMultipart('related')
        msg['From'] = f"{actual_sender_name} <{actual_sender_email}>"
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

        logger.info(f"Relance R{reminder_type} envoyée: {invoice_data.get('invoice_number')} -> {recipient_email}")
        return {'success': True}

    except smtplib.SMTPAuthenticationError:
        logger.error(f"Échec auth SMTP pour relance {invoice_data.get('invoice_number')}")
        return {'success': False, 'error': 'Échec d\'authentification SMTP. Vérifiez vos identifiants.'}
    except smtplib.SMTPException as e:
        logger.error(f"Erreur SMTP relance {invoice_data.get('invoice_number')}: {e}")
        return {'success': False, 'error': f'Erreur SMTP: {str(e)}'}
    except Exception as e:
        logger.error(f"Erreur relance {invoice_data.get('invoice_number')}: {e}")
        return {'success': False, 'error': f'Erreur: {str(e)}'}


# ============================================================================
# Routes Authentification
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
@optional_limit(LOGIN_LIMIT)
def login():
    """Route de connexion"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = sanitize_string(data.get('email', '')).lower()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            logger.warning(f"Tentative de connexion avec données manquantes - IP: {request.remote_addr}")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Email et mot de passe requis'}), 400
            return render_template('login.html', error='Email et mot de passe requis')

        # Vérification
        user_data = users_collection.find_one({'email': email}) if users_collection else None

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user, remember=True)
            logger.info(f"Connexion réussie: {email} - IP: {request.remote_addr}")

            # Mettre à jour la dernière connexion
            users_collection.update_one(
                {'_id': user_data['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            if request.is_json:
                return jsonify({'success': True, 'redirect': url_for('index')})
            return redirect(request.args.get('next') or url_for('index'))

        logger.warning(f"Échec de connexion: {email} - IP: {request.remote_addr}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Email ou mot de passe incorrect'}), 401
        return render_template('login.html', error='Email ou mot de passe incorrect')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Route de déconnexion"""
    logger.info(f"Déconnexion: {current_user.email}")
    logout_user()
    return redirect(url_for('login'))


@app.route('/api/users', methods=['GET'])
@login_required
@admin_required
def get_users():
    users = list(users_collection.find({}, {'password': 0}))
    for user in users:
        user['_id'] = str(user['_id'])
    return jsonify({'success': True, 'users': users})


@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    """Crée un nouvel utilisateur"""
    data = request.get_json()

    # Validation et nettoyage des entrées
    email = sanitize_string(data.get('email', '')).lower()
    password = data.get('password', '')
    name = sanitize_string(data.get('name', ''))
    role = data.get('role', 'user')
    send_welcome = data.get('send_welcome_email', True)

    # Validation email
    if not validate_email(email):
        logger.warning(f"Création utilisateur: email invalide - {email}")
        return jsonify({'error': 'Format d\'email invalide'}), 400

    # Validation mot de passe
    if not validate_password(password):
        return jsonify({'error': 'Le mot de passe doit contenir au moins 6 caractères'}), 400

    # Vérifier si l'email existe déjà
    if users_collection.find_one({'email': email}):
        logger.warning(f"Création utilisateur: email déjà existant - {email}")
        return jsonify({'error': 'Cet email existe déjà'}), 400

    # Vérification des droits pour les rôles admin
    if role in ['admin', 'super_admin'] and not current_user.is_super_admin():
        logger.warning(f"Tentative de création admin non autorisée par {current_user.email}")
        return jsonify({'error': 'Seul le super admin peut créer des administrateurs'}), 403

    # Valider le rôle
    if role not in ['user', 'admin', 'super_admin']:
        role = 'user'

    # Sauvegarder le mot de passe en clair pour l'email avant le hash
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

    # Envoyer l'email de bienvenue
    if send_welcome:
        email_result = send_welcome_email(email, name, temp_password)
        response_data['welcome_email_sent'] = email_result.get('success', False)
        if email_result.get('success'):
            logger.info(f"Email de bienvenue envoyé à {email}")
        else:
            response_data['welcome_email_error'] = email_result.get('error', 'Erreur inconnue')
            logger.warning(f"Échec envoi email bienvenue à {email}: {email_result.get('error')}")

    return jsonify(response_data)


@app.route('/api/users/<user_id>', methods=['PUT'])
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


@app.route('/api/users/<user_id>', methods=['DELETE'])
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


@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user():
    user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
    return jsonify({'success': True, 'user': {
        'id': current_user.id,
        'email': current_user.email,
        'name': current_user.name,
        'role': current_user.role,
        'sender_name': user_data.get('sender_name', ''),
        'sender_email': user_data.get('sender_email', '')
    }})


@app.route('/api/me/password', methods=['PUT'])
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


@app.route('/api/me/sender', methods=['PUT'])
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


# ============================================================================
# Routes Principales
# ============================================================================

@app.route('/')
@login_required
def index():
    """Page d'accueil"""
    return render_template('index.html', user=current_user)


@app.route('/api/upload', methods=['POST'])
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
@login_required
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
@login_required
def download_invoice(batch_id, filename):
    """Télécharge une facture individuelle"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route('/api/download-all/<batch_id>')
@login_required
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
@login_required
def get_email_config():
    """Récupère la configuration email (sans le mot de passe)"""
    config = load_email_config()
    # Ne pas renvoyer le mot de passe
    safe_config = {k: v for k, v in config.items() if k != 'smtp_password'}
    safe_config['smtp_password_set'] = bool(config.get('smtp_password'))
    return jsonify(safe_config)


@app.route('/api/email/config', methods=['PUT'])
@login_required
def update_email_config():
    """Met à jour la configuration email"""
    data = request.json
    config = load_email_config()

    # Champs SMTP réservés au super admin
    smtp_fields = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password']

    # Vérifier si des champs SMTP sont modifiés
    smtp_modified = any(key in data for key in smtp_fields)
    if smtp_modified and not current_user.is_super_admin():
        return jsonify({'error': 'Seul le super admin peut modifier la configuration SMTP'}), 403

    # Mettre à jour les champs fournis (non-SMTP pour tous, SMTP pour super admin)
    for key in ['sender_email', 'sender_name', 'email_subject', 'email_template',
                'reminder_1_subject', 'reminder_1_template',
                'reminder_2_subject', 'reminder_2_template',
                'reminder_3_subject', 'reminder_3_template']:
        if key in data:
            config[key] = data[key]

    # Champs SMTP uniquement pour super admin
    if current_user.is_super_admin():
        for key in ['smtp_server', 'smtp_port', 'smtp_username']:
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
@optional_limit(EMAIL_LIMIT)
@login_required
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

    # Récupérer l'identité d'expéditeur de l'utilisateur
    sender_name, sender_email = get_user_sender_info()

    # Envoyer l'email
    result = send_invoice_email(invoice_data, email_config, batch_folder, sender_name, sender_email)

    if result['success']:
        # Marquer comme envoyé
        batch_data['invoices'][invoice_index]['email_sent'] = True
        batch_data['invoices'][invoice_index]['email_sent_at'] = datetime.now().isoformat()
        with open(batch_data_path, 'w', encoding='utf-8') as f:
            json.dump(batch_data, f, indent=2, ensure_ascii=False)

    return jsonify(result)


@app.route('/api/email/send-all/<batch_id>', methods=['POST'])
@optional_limit(EMAIL_LIMIT)
@login_required
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

    # Récupérer l'identité d'expéditeur de l'utilisateur
    sender_name, sender_email = get_user_sender_info()

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
        result = send_invoice_email(invoice_data, email_config, batch_folder, sender_name, sender_email)

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
@login_required
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
@login_required
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
@login_required
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
@login_required
def delete_from_history(invoice_id):
    """Supprime une facture de l'historique"""
    invoice_history_collection.delete_one({'id': invoice_id})
    return jsonify({'success': True})


@app.route('/api/history/download/<invoice_id>')
@login_required
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
@login_required
def clear_history():
    """Vide l'historique des factures"""
    invoice_history_collection.delete_many({})
    return jsonify({'success': True})


@app.route('/api/history/<invoice_id>/payment', methods=['PUT'])
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


@app.route('/api/history/<invoice_id>/reminder/<int:reminder_type>', methods=['POST'])
@login_required
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

    # Récupérer l'identité d'expéditeur de l'utilisateur
    sender_name, sender_email = get_user_sender_info()

    # Préparer les données
    invoice_data = {
        **invoice,
        'company_name': invoice.get('client_name', invoice.get('shipper', ''))
    }

    # Trouver le dossier batch
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{invoice.get('batch_id')}")

    # Envoyer l'email de relance
    result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type, sender_name, sender_email)

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
@login_required
def send_all_reminders(reminder_type):
    """Envoie des relances de type spécifique pour toutes les factures impayées"""
    if reminder_type not in [1, 2, 3]:
        return jsonify({'error': 'Type de relance invalide (1, 2 ou 3)'}), 400

    data = request.json or {}
    invoice_ids = data.get('invoice_ids', [])  # Liste optionnelle d'IDs spécifiques

    history = load_invoice_history()
    email_config = load_email_config()

    # Récupérer l'identité d'expéditeur de l'utilisateur
    sender_name, sender_email = get_user_sender_info()

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
        result = send_reminder_email(invoice_data, email_config, batch_folder, reminder_type, sender_name, sender_email)

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
@login_required
def get_clients():
    """Récupère la liste des clients"""
    clients = load_clients_config()
    return jsonify(clients)


@app.route('/api/clients/<client_name>', methods=['PUT'])
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


@app.route('/api/clients/<client_name>', methods=['DELETE'])
@login_required
def delete_client(client_name):
    """Supprime un client de MongoDB"""
    clients_collection.delete_one({'_id': client_name})
    return jsonify({'success': True})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port)
