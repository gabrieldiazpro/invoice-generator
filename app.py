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
import urllib.request
import urllib.error
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, g, session
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
    SEND_FILE_MAX_AGE_DEFAULT=31536000,  # Cache fichiers statiques 1 an
)

# Compression GZIP
try:
    from flask_compress import Compress
    Compress(app)
    print("Compression GZIP activée")
except ImportError:
    print("flask-compress non installé - compression désactivée")

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
MONGO_URI_ENV = os.environ.get('MONGO_URI', '').strip()

# URI standard (non-SRV) pour compatibilité Railway
MONGO_URI_FALLBACK = 'mongodb://gabrieldiazpro_db_user:gabrieldiazpro_db_password@ac-jcx3ul9-shard-00-00.dabmazu.mongodb.net:27017,ac-jcx3ul9-shard-00-01.dabmazu.mongodb.net:27017,ac-jcx3ul9-shard-00-02.dabmazu.mongodb.net:27017/?authSource=admin&replicaSet=atlas-eawm13-shard-0&tls=true'

def validate_mongo_uri(uri):
    """Vérifie si l'URI MongoDB semble valide"""
    if not uri:
        return False
    # Doit commencer par mongodb:// ou mongodb+srv://
    if not uri.startswith('mongodb://') and not uri.startswith('mongodb+srv://'):
        return False
    # Ne doit pas avoir de labels DNS vides (// consécutifs ou ..)
    if '//' in uri.split('://')[1].split('?')[0] or '..' in uri or '@.' in uri or './' in uri:
        return False
    # Doit avoir au moins un host
    try:
        after_protocol = uri.split('://')[1]
        host_part = after_protocol.split('@')[1].split('/')[0] if '@' in after_protocol else after_protocol.split('/')[0]
        if not host_part or host_part.startswith('.') or host_part.endswith('.'):
            return False
    except:
        return False
    return True

# Utiliser l'URI de l'environnement seulement si elle est valide
if MONGO_URI_ENV and validate_mongo_uri(MONGO_URI_ENV):
    MONGO_URI = MONGO_URI_ENV
    logger.info("Utilisation de MONGO_URI depuis l'environnement")
else:
    MONGO_URI = MONGO_URI_FALLBACK
    if MONGO_URI_ENV:
        logger.warning(f"MONGO_URI invalide dans l'environnement, utilisation du fallback")
    else:
        logger.warning("MONGO_URI non défini - utilisation du fallback")

logger.info(f"Tentative de connexion MongoDB...")
logger.info(f"URI format: {'SRV' if '+srv' in MONGO_URI else 'standard'}")

# Variable globale pour stocker l'erreur de connexion (pour diagnostics)
MONGO_CONNECTION_ERROR = None

def resolve_srv_to_standard(srv_uri):
    """Résout une URI SRV MongoDB en format standard"""
    try:
        import dns.resolver
        from urllib.parse import urlparse, parse_qs

        # Parse SRV URI
        parsed = urlparse(srv_uri.replace('mongodb+srv://', 'https://'))
        username = parsed.username
        password = parsed.password
        host = parsed.hostname

        logger.info(f"Résolution SRV pour: {host}")

        # Résoudre les enregistrements SRV
        srv_records = dns.resolver.resolve(f'_mongodb._tcp.{host}', 'SRV')
        hosts = []
        for srv in srv_records:
            target = str(srv.target).rstrip('.')
            port = srv.port
            hosts.append(f"{target}:{port}")

        logger.info(f"Hosts trouvés: {hosts}")

        # Construire l'URI standard
        hosts_str = ','.join(hosts)
        standard_uri = f"mongodb://{username}:{password}@{hosts_str}/admin?authSource=admin&ssl=true&replicaSet=atlas-{host.split('.')[0].split('-')[-1]}-shard-0"

        return standard_uri
    except Exception as e:
        logger.error(f"Erreur résolution SRV: {type(e).__name__}: {e}")
        return None

def connect_mongodb(uri, use_srv=True):
    """Tente de se connecter à MongoDB avec fallback sur format standard"""
    global MONGO_CONNECTION_ERROR
    try:
        logger.info(f"Connexion MongoDB avec format {'SRV' if use_srv else 'standard'}...")
        logger.info(f"URI hosts: {uri.split('@')[1].split('/')[0] if '@' in uri else 'unknown'}")
        client = MongoClient(
            uri,
            serverSelectionTimeoutMS=15000,
            connectTimeoutMS=15000,
            socketTimeoutMS=30000,
            retryWrites=True,
            w='majority',
            tls=True
        )
        # Test connection
        client.admin.command('ping')
        logger.info("Connexion MongoDB établie avec succès!")
        MONGO_CONNECTION_ERROR = None
        return client
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        logger.error(f"Erreur connexion MongoDB: {error_msg}")
        MONGO_CONNECTION_ERROR = error_msg

        # Si c'était une URI SRV, essayer avec le format standard
        if use_srv and '+srv' in uri:
            logger.info("Tentative avec format standard (résolution manuelle SRV)...")
            standard_uri = resolve_srv_to_standard(uri)
            if standard_uri:
                return connect_mongodb(standard_uri, use_srv=False)

        return None

mongo_client = connect_mongodb(MONGO_URI)

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


# =============================================================================
# Matching intelligent des clients
# =============================================================================

def normalize_client_name(name):
    """
    Normalise un nom de client pour la comparaison.
    - Minuscules
    - Supprime accents
    - Supprime ponctuation et espaces multiples
    - Supprime les formes juridiques courantes
    """
    import unicodedata

    if not name:
        return ""

    # Minuscules
    normalized = name.lower().strip()

    # Supprime les accents
    normalized = unicodedata.normalize('NFD', normalized)
    normalized = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')

    # Supprime la ponctuation sauf espaces
    normalized = re.sub(r'[^\w\s]', ' ', normalized)

    # Supprime les suffixes "via PP", "via Peoples Post", etc.
    via_patterns = [
        r'\s*via\s+peoples?\s*post\s*$',
        r'\s*via\s+pp\s*$',
        r'\s*via\s+pp\s*$',
        r'\s*-\s*pp\s*$',
        r'\s*pp\s*$'
    ]
    for pattern in via_patterns:
        normalized = re.sub(pattern, '', normalized, flags=re.IGNORECASE)

    # Supprime les formes juridiques courantes (à la fin ou au début)
    legal_forms = [
        r'\bsarl\b', r'\bsas\b', r'\bsa\b', r'\beurl\b', r'\bsasu\b',
        r'\bsei\b', r'\bsnc\b', r'\bsci\b', r'\bauto entrepreneur\b',
        r'\bautoentrepreneur\b', r'\bei\b', r'\bme\b', r'\bscp\b',
        r'\bgmbh\b', r'\bltd\b', r'\bllc\b', r'\binc\b', r'\bcorp\b'
    ]
    for form in legal_forms:
        normalized = re.sub(form, '', normalized)

    # Supprime les espaces multiples
    normalized = re.sub(r'\s+', ' ', normalized).strip()

    return normalized


def calculate_similarity(s1, s2):
    """
    Calcule un score de similarité entre deux chaînes (0 à 1).
    Utilise une combinaison de métriques.
    """
    if not s1 or not s2:
        return 0.0

    # Normalise les deux chaînes
    n1 = normalize_client_name(s1)
    n2 = normalize_client_name(s2)

    if n1 == n2:
        return 1.0

    # Comparer aussi sans espaces (pour "essentielsisabelle" vs "essentiels isabelle")
    n1_nospace = n1.replace(' ', '')
    n2_nospace = n2.replace(' ', '')

    if n1_nospace == n2_nospace:
        return 0.98  # Match quasi-parfait

    # Si l'un contient l'autre (avec ou sans espaces)
    if n1 in n2 or n2 in n1 or n1_nospace in n2_nospace or n2_nospace in n1_nospace:
        shorter = min(len(n1_nospace), len(n2_nospace))
        longer = max(len(n1_nospace), len(n2_nospace))
        ratio = shorter / longer if longer > 0 else 0
        if ratio > 0.8:
            return 0.95

    # Score basé sur les mots communs
    words1 = set(n1.split())
    words2 = set(n2.split())

    if not words1 or not words2:
        return 0.0

    common_words = words1 & words2
    all_words = words1 | words2

    jaccard = len(common_words) / len(all_words) if all_words else 0

    # Score basé sur les caractères communs (pour les typos)
    common_chars = sum(1 for c in n1_nospace if c in n2_nospace)
    char_score = (2.0 * common_chars) / (len(n1_nospace) + len(n2_nospace)) if (len(n1_nospace) + len(n2_nospace)) > 0 else 0

    # Score de préfixe commun (important pour les noms)
    prefix_len = 0
    for c1, c2 in zip(n1_nospace, n2_nospace):
        if c1 == c2:
            prefix_len += 1
        else:
            break
    prefix_score = prefix_len / max(len(n1_nospace), len(n2_nospace)) if max(len(n1_nospace), len(n2_nospace)) > 0 else 0

    # Combinaison pondérée
    return (jaccard * 0.3) + (char_score * 0.4) + (prefix_score * 0.3)


def find_best_client_match(shipper_name, clients_config, threshold=0.55):
    """
    Trouve le meilleur client correspondant dans la config.

    Args:
        shipper_name: Nom du client à chercher
        clients_config: Dict des clients existants
        threshold: Score minimum de similarité (0-1)

    Returns:
        (matched_name, client_info, score) ou (None, None, 0) si non trouvé
    """
    if not shipper_name or not clients_config:
        return None, None, 0

    # 1. Match exact sur la clé
    if shipper_name in clients_config:
        return shipper_name, clients_config[shipper_name], 1.0

    # 2. Match insensible à la casse sur la clé
    shipper_lower = shipper_name.lower().strip()
    for client_name, client_info in clients_config.items():
        if client_name.lower().strip() == shipper_lower:
            return client_name, client_info, 1.0

    # 3. Match exact sur le champ 'nom' du client
    for client_name, client_info in clients_config.items():
        client_nom = client_info.get('nom', '')
        if client_nom.lower().strip() == shipper_lower:
            return client_name, client_info, 1.0

    # 4. Match normalisé exact
    shipper_normalized = normalize_client_name(shipper_name)
    for client_name, client_info in clients_config.items():
        if normalize_client_name(client_name) == shipper_normalized:
            return client_name, client_info, 0.95
        # Aussi vérifier le champ 'nom'
        client_nom = client_info.get('nom', '')
        if normalize_client_name(client_nom) == shipper_normalized:
            return client_name, client_info, 0.95

    # 5. Match par similarité (sur clé ET sur nom)
    best_match = None
    best_score = threshold
    best_info = None

    for client_name, client_info in clients_config.items():
        # Score sur la clé
        score_key = calculate_similarity(shipper_name, client_name)
        # Score sur le nom
        client_nom = client_info.get('nom', '')
        score_nom = calculate_similarity(shipper_name, client_nom) if client_nom else 0
        # Prendre le meilleur score
        score = max(score_key, score_nom)

        if score > best_score:
            best_score = score
            best_match = client_name
            best_info = client_info

    if best_match:
        print(f"✓ Client fuzzy match: '{shipper_name}' → '{best_match}' (score: {best_score:.2f})")
        return best_match, best_info, best_score

    return None, None, 0


def get_client_info(shipper_name, clients_config):
    """
    Récupère les informations d'un client avec matching intelligent.

    - Match exact
    - Match insensible à la casse
    - Match normalisé (sans accents, ponctuation, formes juridiques)
    - Match par similarité (typos, abréviations)

    IMPORTANT: Ne crée PAS de doublons - utilise le nom original du client existant.
    """
    # Essayer le matching intelligent d'abord (dans le cache local)
    matched_name, client_info, score = find_best_client_match(shipper_name, clients_config)

    if client_info:
        # Retourner les infos du client existant sans créer de doublon
        # On ne sauvegarde PAS le nom alternatif dans la config
        return client_info

    # Vérifier dans MongoDB avec matching intelligent
    all_db_clients = {doc['_id']: doc for doc in clients_collection.find()}
    shipper_lower = shipper_name.lower().strip()
    shipper_normalized = normalize_client_name(shipper_name)

    for db_name, db_client in all_db_clients.items():
        client_nom = db_client.get('nom', '')

        # Match exact sur la clé
        if db_name == shipper_name:
            db_client.pop('_id', None)
            clients_config[db_name] = db_client
            return db_client

        # Match insensible à la casse sur clé ou nom
        if db_name.lower().strip() == shipper_lower or client_nom.lower().strip() == shipper_lower:
            db_client.pop('_id', None)
            clients_config[db_name] = db_client
            return db_client

        # Match normalisé
        if normalize_client_name(db_name) == shipper_normalized or normalize_client_name(client_nom) == shipper_normalized:
            db_client.pop('_id', None)
            clients_config[db_name] = db_client
            print(f"✓ Client DB normalized match: '{shipper_name}' → '{db_name}'")
            return db_client

        # Match par similarité (sur clé et nom)
        score_key = calculate_similarity(shipper_name, db_name)
        score_nom = calculate_similarity(shipper_name, client_nom) if client_nom else 0
        if max(score_key, score_nom) >= 0.55:
            db_client.pop('_id', None)
            clients_config[db_name] = db_client
            print(f"✓ Client DB fuzzy match: '{shipper_name}' → '{db_name}' (score: {max(score_key, score_nom):.2f})")
            return db_client

    # Aucun match trouvé - créer une nouvelle entrée
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

    # Cache headers pour fichiers statiques (CSS, JS, images)
    if request.path.startswith('/static'):
        response.headers['Cache-Control'] = 'public, max-age=31536000'  # 1 an
    elif request.path.startswith('/api'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'

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
            if MONGO_CONNECTION_ERROR:
                health['startup_error'] = MONGO_CONNECTION_ERROR
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
    def __init__(self, user_data, impersonated_by=None):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.role = user_data.get('role', 'user')
        self.client_id = user_data.get('client_id')  # Nom du shipper associé (pour les clients)
        # Impersonation: ID du super admin qui impersonne cet utilisateur
        self.impersonated_by = impersonated_by

    def is_admin(self):
        return self.role in ['admin', 'super_admin']

    def is_super_admin(self):
        return self.role == 'super_admin'

    def is_client(self):
        """Retourne True si l'utilisateur est un client"""
        return self.role == 'client'

    def is_impersonating(self):
        """Retourne True si l'utilisateur actuel est impersonné par un super admin"""
        return self.impersonated_by is not None


@login_manager.user_loader
def load_user(user_id):
    """Charge un utilisateur depuis son ID"""
    try:
        if users_collection is None:
            return None
        user_data = users_collection.find_one({'_id': ObjectId(user_id)})
        if user_data:
            # Vérifier si on est en mode impersonation
            impersonated_by = session.get('impersonated_by')
            return User(user_data, impersonated_by=impersonated_by)
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


def client_required(f):
    """Décorateur pour restreindre l'accès aux clients"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_client():
            logger.warning(f"Accès client refusé: {getattr(current_user, 'email', 'anonymous')} sur {request.path}")
            return jsonify({'error': 'Accès réservé aux clients'}), 403
        return f(*args, **kwargs)
    return decorated_function


def init_super_admin():
    """Crée le super admin si il n'existe pas"""
    if users_collection is None:
        logger.warning("Impossible de créer le super admin: base de données non disponible")
        return

    try:
        existing = users_collection.find_one({'email': 'gabriel@peoplespost.fr'})
        if existing is None:
            # Utiliser pbkdf2 pour compatibilité
            users_collection.insert_one({
                'email': 'gabriel@peoplespost.fr',
                'password': generate_password_hash('admin123', method='pbkdf2:sha256'),
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


def init_db_indexes():
    """Crée les index MongoDB pour de meilleures performances"""
    if db is None:
        return
    try:
        # Index sur invoice_history pour les requêtes fréquentes
        invoice_history_collection.create_index('created_at')
        invoice_history_collection.create_index('shipper')
        invoice_history_collection.create_index('payment_status')
        invoice_history_collection.create_index('id')

        # Index sur users
        users_collection.create_index('email', unique=True)
        users_collection.create_index('client_id')
        users_collection.create_index('role')

        # Index sur clients
        clients_collection.create_index('email')

        logger.info("Index MongoDB créés avec succès")
    except Exception as e:
        logger.warning(f"Impossible de créer les index MongoDB: {e}")


init_db_indexes()

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
                            <img src="https://pp-invoces-generator.up.railway.app/static/logo.png" alt="Peoples Post" style="height: 90px; margin: 0 auto 12px auto; display: block;">
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


def send_email_via_api(to_email, to_name, subject, html_content, text_content=None, attachment=None, attachment_name=None):
    """Envoie un email via l'API HTTP de Brevo (contourne les restrictions SMTP de Railway)"""
    email_config = load_email_config()

    # Récupérer la clé API (utilise smtp_password comme API key)
    api_key = email_config.get('smtp_password', '')
    if not api_key:
        return {'success': False, 'error': 'Clé API Brevo non configurée'}

    # Préparer les données pour l'API Brevo
    sender_email = email_config.get('sender_email') or email_config.get('smtp_username', '')
    sender_name = email_config.get('sender_name', 'Peoples Post')

    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email, "name": to_name or to_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    if text_content:
        payload["textContent"] = text_content

    # Ajouter la pièce jointe si présente
    if attachment and attachment_name:
        payload["attachment"] = [{
            "name": attachment_name,
            "content": base64.b64encode(attachment).decode('utf-8')
        }]

    try:
        # Appel à l'API Brevo
        req = urllib.request.Request(
            'https://api.brevo.com/v3/smtp/email',
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'accept': 'application/json',
                'api-key': api_key,
                'content-type': 'application/json'
            },
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            logger.info(f"Email envoyé via API Brevo à {to_email}: {result}")
            return {'success': True, 'message_id': result.get('messageId')}

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        logger.error(f"Erreur API Brevo: {e.code} - {error_body}")
        return {'success': False, 'error': f'Erreur API Brevo: {error_body}'}
    except urllib.error.URLError as e:
        logger.error(f"Erreur connexion API Brevo: {e}")
        return {'success': False, 'error': f'Erreur connexion: {str(e)}'}
    except Exception as e:
        logger.error(f"Erreur envoi email API: {e}")
        return {'success': False, 'error': str(e)}


def send_welcome_email(user_email, user_name, temp_password):
    """Envoie un email de bienvenue au nouvel utilisateur via l'API Brevo"""

    # Corps de l'email en texte brut
    text_content = f"""Bonjour {user_name or 'et bienvenue'} !

Votre compte a été créé sur le Générateur de Factures Peoples Post.

Vos identifiants de connexion :
- Email : {user_email}
- Mot de passe temporaire : {temp_password}

Important : Pour des raisons de sécurité, nous vous recommandons de changer votre mot de passe dès votre première connexion.

Connectez-vous sur : https://pp-invoces-generator.up.railway.app/login

Cordialement,
L'équipe Peoples Post
"""

    # Corps de l'email en HTML
    html_content = create_welcome_email_html(user_name, user_email, temp_password)

    # Envoyer via l'API Brevo
    return send_email_via_api(
        to_email=user_email,
        to_name=user_name or user_email,
        subject="Bienvenue sur le Générateur de Factures Peoples Post",
        html_content=html_content,
        text_content=text_content
    )


def create_html_email(body_text, invoice_data, email_type='invoice'):
    """Crée un email HTML stylisé avec le branding Peoples Post

    Args:
        body_text: Le contenu texte de l'email
        invoice_data: Les données de la facture
        email_type: 'invoice', 'reminder_1', 'reminder_2', 'reminder_3', 'reminder_4'
    """
    # Couleurs selon le type d'email
    header_colors = {
        'invoice': '#3026f0',      # Bleu principal
        'reminder_1': '#f59e0b',   # Jaune/Orange
        'reminder_2': '#f97316',   # Orange
        'reminder_3': '#ef4444',   # Rouge
        'reminder_4': '#7f1d1d'    # Rouge foncé (coupure)
    }

    header_titles = {
        'invoice': 'Votre Facture',
        'reminder_1': 'Rappel de Paiement',
        'reminder_2': 'Action Requise',
        'reminder_3': 'Dernier Avis',
        'reminder_4': 'Suspension de Compte'
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
    elif email_type == 'reminder_4':
        badge_html = '<span style="display: inline-block; background-color: #7f1d1d; color: #ffffff; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">COMPTE SUSPENDU</span><br>'

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
                            <img src="https://pp-invoces-generator.up.railway.app/static/logo.png" alt="Peoples Post" style="height: 90px; margin: 0 auto 12px auto; display: block;">
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
        'reminder_3_at': None,
        'reminder_4_sent': False,
        'reminder_4_at': None
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

        # Connexion SMTP et envoi avec timeout
        smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
        smtp_port = int(email_config.get('smtp_port', 465))
        smtp_username = email_config.get('smtp_username', '')
        smtp_password = email_config.get('smtp_password', '')

        # Utiliser SSL pour port 465, STARTTLS pour 587
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
            server.starttls()

        server.login(smtp_username, smtp_password)
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
        reminder_type: 1 = première relance (48h), 2 = avertissement (7j), 3 = dernier avis, 4 = coupure compte
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

        # Connexion SMTP et envoi avec timeout
        smtp_server = email_config.get('smtp_server', 'smtp.gmail.com')
        smtp_port = int(email_config.get('smtp_port', 465))
        smtp_username = email_config.get('smtp_username', '')
        smtp_password = email_config.get('smtp_password', '')

        # Utiliser SSL pour port 465, STARTTLS pour 587
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
            server.starttls()

        server.login(smtp_username, smtp_password)
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
        # Rediriger les clients vers le portail client
        if current_user.is_client():
            return redirect(url_for('client_portal'))
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
        if users_collection is None:
            logger.error("users_collection est None - pas de connexion DB")
            return render_template('login.html', error='Service temporairement indisponible')

        user_data = users_collection.find_one({'email': email})
        logger.info(f"User lookup for {email}: {'found' if user_data else 'not found'}")

        if user_data:
            logger.info(f"Hash method: {user_data['password'][:20]}")
            pwd_ok = check_password_hash(user_data['password'], password)
            logger.info(f"Password check: {pwd_ok}")

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user, remember=True)
            logger.info(f"Connexion réussie: {email} (role: {user.role}) - IP: {request.remote_addr}")

            # Mettre à jour la dernière connexion
            users_collection.update_one(
                {'_id': user_data['_id']},
                {'$set': {'last_login': datetime.now()}}
            )

            # Rediriger les clients vers le portail client
            if user.is_client():
                redirect_url = url_for('client_portal')
            else:
                redirect_url = request.args.get('next') or url_for('index')

            if request.is_json:
                return jsonify({'success': True, 'redirect': redirect_url})
            return redirect(redirect_url)

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

    # Envoyer l'email de bienvenue en arrière-plan pour éviter les timeouts
    if send_welcome:
        import threading
        def send_email_background():
            try:
                email_result = send_welcome_email(email, name, temp_password)
                if email_result.get('success'):
                    logger.info(f"Email de bienvenue envoyé à {email}")
                else:
                    logger.warning(f"Échec envoi email bienvenue à {email}: {email_result.get('error')}")
            except Exception as e:
                logger.error(f"Erreur envoi email bienvenue à {email}: {e}")

        # Lancer l'envoi en thread séparé
        email_thread = threading.Thread(target=send_email_background)
        email_thread.daemon = True
        email_thread.start()
        response_data['welcome_email_sent'] = 'pending'  # Email en cours d'envoi

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


# =============================================================================
# Impersonation (Super Admin seulement)
# =============================================================================

@app.route('/api/users/<user_id>/impersonate', methods=['POST'])
@login_required
@super_admin_required
def impersonate_user(user_id):
    """Permet au super admin de se connecter en tant qu'un autre utilisateur"""
    try:
        # Vérifier que l'utilisateur existe
        target_user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not target_user:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404

        # Ne pas permettre d'impersonner soi-même
        if str(target_user['_id']) == current_user.id:
            return jsonify({'error': 'Vous ne pouvez pas vous impersonner vous-même'}), 400

        # Stocker l'ID du super admin original dans la session
        original_admin_id = session.get('impersonated_by') or current_user.id
        session['impersonated_by'] = original_admin_id

        # Se connecter en tant que l'utilisateur cible
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


@app.route('/api/stop-impersonate', methods=['POST'])
@login_required
def stop_impersonation():
    """Arrête l'impersonation et revient au compte super admin"""
    try:
        original_admin_id = session.get('impersonated_by')

        if not original_admin_id:
            return jsonify({'error': 'Vous n\'êtes pas en mode impersonation'}), 400

        # Charger le super admin original
        admin_data = users_collection.find_one({'_id': ObjectId(original_admin_id)})
        if not admin_data:
            # Fallback: déconnecter l'utilisateur
            session.pop('impersonated_by', None)
            logout_user()
            return jsonify({'error': 'Compte administrateur non trouvé, déconnexion'}), 400

        # Supprimer le flag d'impersonation de la session
        session.pop('impersonated_by', None)

        # Reconnecter le super admin
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


@app.route('/api/me', methods=['GET'])
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

    # Ajouter les informations d'impersonation si applicable
    if current_user.is_impersonating():
        original_admin = users_collection.find_one({'_id': ObjectId(current_user.impersonated_by)})
        response['impersonation'] = {
            'active': True,
            'original_admin_id': current_user.impersonated_by,
            'original_admin_email': original_admin['email'] if original_admin else 'Unknown'
        }

    return jsonify(response)


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

            # Vérifier si le client est configuré (SIRET valide ET email valide)
            siret = client_info.get('siret', '00000000000000')
            email = client_info.get('email', 'email@example.com')
            is_configured = (siret != '00000000000000' and siret != '') and (email != 'email@example.com' and email != '' and '@' in email)

            shippers_summary.append({
                'name': shipper_name,
                'lines_count': len(rows),
                'total_ht': round(total_ht, 2),
                'client_configured': is_configured,
                'client_email': email if email != 'email@example.com' else ''
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


@app.route('/api/refresh-preview/<file_id>')
@login_required
def refresh_preview(file_id):
    """Rafraîchit les données de prévisualisation après mise à jour d'un client"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file_id)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    try:
        # Parser le CSV
        data_by_shipper = parse_csv(filepath)

        if not data_by_shipper:
            return jsonify({'error': 'Aucune donnée trouvée dans le fichier CSV'}), 400

        # Recharger la config des clients (avec les mises à jour)
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

            # Vérifier si le client est configuré
            siret = client_info.get('siret', '00000000000000')
            email = client_info.get('email', 'email@example.com')
            is_configured = (siret != '00000000000000' and siret != '') and (email != 'email@example.com' and email != '' and '@' in email)

            shippers_summary.append({
                'name': shipper_name,
                'lines_count': len(rows),
                'total_ht': round(total_ht, 2),
                'client_configured': is_configured,
                'client_email': email if email != 'email@example.com' else ''
            })

        return jsonify({
            'success': True,
            'file_id': file_id,
            'shippers': shippers_summary,
            'total_shippers': len(shippers_summary)
        })

    except Exception as e:
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
        invoice_num = int(start_number)

        generated = []

        for shipper_name, rows in data_by_shipper.items():
            # Si une sélection est spécifiée, filtrer
            if selected_shippers and shipper_name not in selected_shippers:
                continue

            client_info = get_client_info(shipper_name, clients_config)
            invoice_number = generate_invoice_number(prefix, sequence=invoice_num)

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

            # Récupérer l'email (filtrer les placeholders)
            client_email = client_info.get('email', '')
            if client_email == 'email@example.com':
                client_email = ''

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


@app.route('/api/view/<batch_id>/<filename>')
@login_required
def view_invoice(batch_id, filename):
    """Visualise une facture dans le navigateur (sans téléchargement)"""
    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier non trouvé'}), 404

    return send_file(filepath, as_attachment=False, mimetype='application/pdf')


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
                'reminder_3_subject', 'reminder_3_template',
                'reminder_4_subject', 'reminder_4_template']:
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


@app.route('/api/email/test', methods=['POST'])
@login_required
@super_admin_required
def test_email():
    """Envoie un email de test via l'API Brevo"""
    data = request.get_json() or {}
    test_email_addr = data.get('email', current_user.email)

    email_config = load_email_config()

    if not email_config.get('smtp_password'):
        return jsonify({'success': False, 'error': 'Clé API Brevo non configurée'}), 400

    # Contenu de l'email de test
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

    text_content = f"""Bonjour,

Ceci est un email de test envoyé depuis le Générateur de Factures Peoples Post.

Si vous recevez cet email, la configuration est correcte !

Cordialement,
L'équipe Peoples Post
"""

    # Envoyer via l'API Brevo
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
        return jsonify({'success': False, 'error': f'Erreur: {str(e)}'}), 500


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
    if email_type not in ['invoice', 'reminder_1', 'reminder_2', 'reminder_3', 'reminder_4']:
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
        'reminder_3': '#ef4444',
        'reminder_4': '#7f1d1d'
    }

    header_titles = {
        'invoice': 'Votre Facture',
        'reminder_1': 'Rappel de Paiement',
        'reminder_2': 'Action Requise',
        'reminder_3': 'Dernier Avis',
        'reminder_4': 'Suspension de Compte'
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
    elif email_type == 'reminder_4':
        badge_html = '<span style="display: inline-block; background-color: #7f1d1d; color: #ffffff; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-bottom: 15px;">COMPTE SUSPENDU</span><br>'

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
    # Paramètres de filtrage optionnels
    search = request.args.get('search', '').lower()
    limit = request.args.get('limit', 100, type=int)  # Limite par défaut à 100

    # Charger avec limite
    history = load_invoice_history(limit=limit if not search else 500)

    if search:
        history = [
            h for h in history
            if search in h.get('invoice_number', '').lower()
            or search in h.get('client_name', '').lower()
            or search in h.get('shipper', '').lower()
        ][:limit]

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
        reminder_type: 1 = première relance (48h), 2 = avertissement (7j), 3 = dernier avis, 4 = coupure compte
    """
    if reminder_type not in [1, 2, 3, 4]:
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
    if reminder_type not in [1, 2, 3, 4]:
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
# Routes Historique - Opérations en masse
# ============================================================================

@app.route('/api/history/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_from_history():
    """Supprime plusieurs factures de l'historique"""
    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    deleted_count = 0
    for invoice_id in invoice_ids:
        result = invoice_history_collection.delete_one({'id': invoice_id})
        if result.deleted_count > 0:
            deleted_count += 1

    return jsonify({
        'success': True,
        'deleted': deleted_count,
        'message': f'{deleted_count} facture(s) supprimée(s)'
    })


@app.route('/api/history/bulk-info', methods=['POST'])
@login_required
def bulk_get_info():
    """Récupère les informations détaillées de plusieurs factures"""
    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    # Calculer les totaux
    total_ht = sum(inv.get('total_ht', 0) for inv in invoices)
    total_tva = sum(inv.get('total_tva', 0) for inv in invoices)
    total_ttc = sum(inv.get('total_ttc', 0) for inv in invoices)
    paid_count = sum(1 for inv in invoices if inv.get('payment_status') == 'paid')
    unpaid_count = len(invoices) - paid_count

    # Nettoyer les ObjectId pour JSON
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


@app.route('/api/history/bulk-download', methods=['POST'])
@login_required
def bulk_download():
    """Télécharge plusieurs factures dans un fichier ZIP"""
    import zipfile
    from io import BytesIO

    data = request.json
    invoice_ids = data.get('ids', [])

    if not invoice_ids:
        return jsonify({'error': 'Aucune facture sélectionnée'}), 400

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    if not invoices:
        return jsonify({'error': 'Aucune facture trouvée'}), 404

    # Créer le ZIP en mémoire
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for invoice in invoices:
            batch_id = invoice.get('batch_id')
            filename = invoice.get('filename')

            if not batch_id or not filename:
                continue

            batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
            filepath = os.path.join(batch_folder, filename)

            if os.path.exists(filepath):
                zip_file.write(filepath, filename)

    zip_buffer.seek(0)

    # Nom du fichier ZIP avec date
    zip_filename = f"factures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"

    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_filename
    )


@app.route('/api/history/bulk-payment', methods=['POST'])
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

    updated_count = 0
    for invoice_id in invoice_ids:
        result = invoice_history_collection.update_one(
            {'id': invoice_id},
            {'$set': {'payment_status': status}}
        )
        if result.modified_count > 0:
            updated_count += 1

    status_text = 'payée(s)' if status == 'paid' else 'impayée(s)'
    return jsonify({
        'success': True,
        'updated': updated_count,
        'message': f'{updated_count} facture(s) marquée(s) comme {status_text}'
    })


@app.route('/api/history/bulk-reminder', methods=['POST'])
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

    # Récupérer la config email
    email_config = get_email_config()

    # Récupérer les infos de l'utilisateur
    user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
    sender_name = user_data.get('sender_name', '') if user_data else ''
    sender_email = user_data.get('sender_email', '') if user_data else ''

    reminder_sent_key = f'reminder_{reminder_type}_sent'
    reminder_at_key = f'reminder_{reminder_type}_at'
    reminder_names = {1: 'Relance 1', 2: 'Relance 2', 3: 'Relance 3', 4: 'Relance 4'}

    results = {'sent': 0, 'failed': 0, 'skipped': 0, 'details': []}

    invoices = list(invoice_history_collection.find({'id': {'$in': invoice_ids}}))

    for invoice in invoices:
        invoice_id = invoice.get('id')

        # Vérifier si payée
        if invoice.get('payment_status') == 'paid':
            results['skipped'] += 1
            continue

        # Vérifier si déjà envoyée
        if invoice.get(reminder_sent_key):
            results['skipped'] += 1
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
        else:
            results['failed'] += 1

    return jsonify({
        'success': True,
        'results': results,
        'message': f'{results["sent"]} relance(s) envoyée(s), {results["skipped"]} ignorée(s), {results["failed"]} échec(s)'
    })


# ============================================================================
# Routes Clients
# ============================================================================

@app.route('/api/clients', methods=['GET'])
@login_required
def get_clients():
    """Récupère la liste des clients avec statut des comptes"""
    clients = load_clients_config()

    # Pour les admins, ajouter le statut des comptes clients
    if current_user.is_admin():
        # Récupérer tous les comptes clients en une seule requête
        client_accounts = list(users_collection.find(
            {'role': 'client'},
            {'client_id': 1, 'email': 1, 'last_login': 1, 'created_at': 1}
        ))

        # Créer un dictionnaire pour accès rapide
        accounts_by_client = {
            acc['client_id']: {
                'has_account': True,
                'email': acc.get('email'),
                'last_login': acc.get('last_login').isoformat() if acc.get('last_login') else None,
                'created_at': acc.get('created_at').isoformat() if acc.get('created_at') else None
            }
            for acc in client_accounts if acc.get('client_id')
        }

        # Ajouter le statut à chaque client
        for client_key in clients:
            if client_key in accounts_by_client:
                clients[client_key]['account_status'] = accounts_by_client[client_key]
            else:
                clients[client_key]['account_status'] = {'has_account': False}

    return jsonify(clients)


@app.route('/api/clients/duplicates', methods=['GET'])
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
            # Trouver le client avec le plus d'infos (siret rempli, email, etc.)
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


@app.route('/api/clients/merge', methods=['POST'])
@login_required
def merge_clients():
    """Fusionne des clients en doublon - garde un seul, supprime les autres"""
    data = request.json
    keep_name = data.get('keep')  # Le nom du client à garder
    delete_names = data.get('delete', [])  # Les noms à supprimer

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


@app.route('/api/clients/cleanup-duplicates', methods=['POST'])
@login_required
def cleanup_all_duplicates():
    """Nettoie automatiquement tous les doublons (garde le plus complet)"""
    clients = load_clients_config()
    client_names = list(clients.keys())

    processed = set()
    total_deleted = 0

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

            # Trouver le meilleur client à garder
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

            # Supprimer les autres
            for name in group:
                if name != best_client:
                    clients_collection.delete_one({'_id': name})
                    total_deleted += 1

    return jsonify({
        'success': True,
        'deleted': total_deleted,
        'message': f'{total_deleted} doublon(s) supprimé(s) automatiquement'
    })


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


@app.route('/api/clients/bulk-delete', methods=['POST'])
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


@app.route('/api/clients/bulk-export', methods=['POST'])
@login_required
def bulk_export_clients():
    """Exporte plusieurs clients en CSV"""
    import io
    import csv

    data = request.get_json()
    keys = data.get('keys', [])

    if not keys:
        return jsonify({'success': False, 'error': 'Aucun client sélectionné'}), 400

    try:
        # Récupérer les clients sélectionnés
        clients = list(clients_collection.find({'_id': {'$in': keys}}))

        # Créer le CSV
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';')

        # En-têtes
        writer.writerow(['Nom', 'Adresse', 'Code Postal', 'Ville', 'Pays', 'Email', 'SIRET'])

        # Données
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

        # Retourner le fichier
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


def parse_import_file(filepath, ext):
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
                except:
                    continue
            if df is not None and len(df.columns) > 1:
                break

        if df is None or len(df.columns) <= 1:
            return None, "Impossible de lire le fichier CSV"
    else:
        # Essayer plusieurs lignes d'en-tête et choisir la meilleure
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
                # Si on a trouvé une ligne avec très peu d'unnamed, on s'arrête
                if unnamed <= 2:
                    break
            except:
                continue

        df = best_df
        logger.info(f"Excel import: using header row {best_header} with {best_unnamed} unnamed columns")

        if df is None:
            return None, "Impossible de lire le fichier Excel"

    return df, None


def get_import_column_mappings():
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


def extract_client_from_row(row, found_columns):
    """Extrait les données client d'une ligne du fichier"""
    nom_col = found_columns['nom']
    nom = str(row.get(nom_col, '')).strip()

    if not nom or nom == 'nan':
        return None, None

    # Construire les données du client
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

    # Nettoyer le SIRET
    siret = ''.join(c for c in client_data['siret'] if c.isdigit())
    client_data['siret'] = siret[:14] if len(siret) > 14 else (siret if siret else '00000000000000')

    return nom, client_data


@app.route('/api/clients/import', methods=['POST'])
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

    # Mode: 'preview' pour détecter les doublons, 'confirm' pour importer avec décisions
    mode = request.form.get('mode', 'auto')
    decisions_json = request.form.get('decisions', '{}')
    try:
        decisions = json.loads(decisions_json)  # {nom: 'add'|'update'|'skip'}
    except:
        decisions = {}

    # Sauvegarder temporairement le fichier
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    file.save(filepath)

    try:
        df, error = parse_import_file(filepath, ext)
        if error:
            os.remove(filepath)
            return jsonify({'error': error}), 400

        # Normaliser les colonnes
        df.columns = [str(col).lower().strip() for col in df.columns]

        # Mapper les colonnes
        column_mappings = get_import_column_mappings()
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

        # Charger tous les clients existants pour le matching fuzzy
        all_existing_clients = {doc['_id']: doc for doc in clients_collection.find()}

        # Analyser les données et détecter les doublons (avec matching intelligent)
        duplicates = []
        new_clients = []

        for index, row in df.iterrows():
            nom, client_data = extract_client_from_row(row, found_columns)
            if not nom:
                continue

            # 1. Vérifier match exact
            existing = all_existing_clients.get(nom)
            existing_key = nom

            # 2. Si pas de match exact, chercher par similarité
            if not existing:
                matched_key, matched_info, score = find_best_client_match(nom, all_existing_clients, threshold=0.6)
                if matched_info and score >= 0.6:
                    existing = matched_info
                    existing_key = matched_key
                    logger.info(f"Import fuzzy match: '{nom}' → '{matched_key}' (score: {score:.2f})")

            if existing:
                duplicates.append({
                    'nom': nom,
                    'existing_key': existing_key,  # Clé du client existant (peut être différente)
                    'new_data': client_data,
                    'existing_data': {k: v for k, v in existing.items() if k != '_id'},
                    'is_fuzzy_match': existing_key != nom  # Indique si c'est un match approximatif
                })
            else:
                new_clients.append(client_data)

        # Mode preview ou auto avec doublons: retourner les doublons pour confirmation
        if mode == 'preview' or (mode == 'auto' and duplicates and not decisions):
            os.remove(filepath)
            return jsonify({
                'success': True,
                'needs_confirmation': True,
                'duplicates': duplicates,
                'new_count': len(new_clients),
                'duplicate_count': len(duplicates)
            })

        # Mode confirm ou auto sans doublons: procéder à l'import
        results = {
            'total': len(new_clients) + len(duplicates),
            'created': 0,
            'updated': 0,
            'skipped': 0,
            'errors': []
        }

        # Importer les nouveaux clients
        for client_data in new_clients:
            try:
                clients_collection.replace_one({'_id': client_data['_id']}, client_data, upsert=True)
                results['created'] += 1
            except Exception as e:
                results['errors'].append({'nom': client_data['nom'], 'error': str(e)})

        # Traiter les doublons selon les décisions
        for dup in duplicates:
            nom = dup['nom']
            existing_key = dup.get('existing_key', nom)  # Utiliser la clé existante si disponible
            decision = decisions.get(nom, 'skip')  # Par défaut: ignorer

            if decision == 'add':
                # Ajouter comme nouveau (avec le nom de l'import)
                client_data = dup['new_data'].copy()
                try:
                    clients_collection.insert_one(client_data)
                    results['created'] += 1
                except:
                    # Si le nom existe déjà, ajouter un suffixe
                    client_data['_id'] = f"{nom} (import)"
                    client_data['nom'] = f"{nom} (import)"
                    try:
                        clients_collection.insert_one(client_data)
                        results['created'] += 1
                    except:
                        results['skipped'] += 1
            elif decision == 'update':
                # Mettre à jour l'existant (utiliser la clé existante, pas le nom importé)
                try:
                    update_data = dup['new_data'].copy()
                    update_data['_id'] = existing_key  # Garder la clé existante
                    clients_collection.replace_one({'_id': existing_key}, update_data, upsert=True)
                    results['updated'] += 1
                except Exception as e:
                    results['errors'].append({'nom': nom, 'error': str(e)})
            else:  # skip
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


@app.route('/api/clients/template')
@login_required
def download_clients_template():
    """Génère et télécharge un template CSV pour l'import de clients"""
    import io

    # Créer le contenu CSV (compatible avec le format "Liste client.xlsx")
    csv_content = "Official company name;Billing Address;Billing email address;Siret\n"
    csv_content += "EXEMPLE SARL;12 rue de la Paix, 75001 Paris;contact@exemple.com;12345678901234\n"
    csv_content += "AUTRE CLIENT SAS;5 avenue des Champs, 69001 Lyon;info@autre.fr;98765432109876\n"

    # Créer le fichier en mémoire
    buffer = io.BytesIO()
    buffer.write(csv_content.encode('utf-8-sig'))  # UTF-8 avec BOM pour Excel
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name='template_clients.csv'
    )


# ============================================================================
# Portail Client - Routes et fonctions
# ============================================================================

def generate_temp_password(length=12):
    """Génère un mot de passe temporaire aléatoire"""
    import random
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def send_client_welcome_email(client_email, client_name, temp_password):
    """Envoie un email de bienvenue au nouveau compte client via l'API Brevo"""

    text_content = f"""Bonjour {client_name} !

Votre espace client a été créé sur le portail Peoples Post.

Vos identifiants de connexion :
- Email : {client_email}
- Mot de passe temporaire : {temp_password}

Vous pouvez désormais accéder à votre espace client pour :
- Consulter vos factures
- Suivre votre historique de facturation
- Voir votre situation financière

Important : Pour des raisons de sécurité, nous vous recommandons de changer votre mot de passe dès votre première connexion.

Connectez-vous sur : https://pp-invoces-generator.up.railway.app/login

Cordialement,
L'équipe Peoples Post
"""

    html_content = f'''<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f0f2f5;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #f0f2f5;">
        <tr>
            <td style="padding: 40px 20px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" align="center" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <!-- En-tête -->
                    <tr>
                        <td style="background: linear-gradient(135deg, #3026f0 0%, #5046e5 100%); padding: 30px 40px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">Bienvenue sur votre Espace Client</h1>
                        </td>
                    </tr>
                    <!-- Contenu -->
                    <tr>
                        <td style="padding: 40px;">
                            <p style="font-size: 16px; color: #333; line-height: 1.6; margin: 0 0 20px 0;">
                                Bonjour <strong>{client_name}</strong>,
                            </p>
                            <p style="font-size: 16px; color: #333; line-height: 1.6; margin: 0 0 20px 0;">
                                Votre espace client a été créé sur le portail Peoples Post.
                            </p>

                            <!-- Encadré identifiants -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin: 25px 0;">
                                <tr>
                                    <td style="background-color: #f8f9fa; border-radius: 8px; padding: 20px; border-left: 4px solid #3026f0;">
                                        <p style="font-size: 14px; color: #666; margin: 0 0 10px 0; font-weight: 600;">Vos identifiants de connexion :</p>
                                        <p style="font-size: 14px; color: #333; margin: 0 0 5px 0;"><strong>Email :</strong> {client_email}</p>
                                        <p style="font-size: 14px; color: #333; margin: 0;"><strong>Mot de passe temporaire :</strong> <code style="background-color: #e9ecef; padding: 2px 8px; border-radius: 4px; font-family: monospace;">{temp_password}</code></p>
                                    </td>
                                </tr>
                            </table>

                            <p style="font-size: 16px; color: #333; line-height: 1.6; margin: 0 0 20px 0;">
                                Vous pouvez désormais accéder à votre espace client pour :
                            </p>
                            <ul style="font-size: 14px; color: #555; line-height: 1.8; padding-left: 20px; margin: 0 0 25px 0;">
                                <li>Consulter vos factures</li>
                                <li>Suivre votre historique de facturation</li>
                                <li>Voir votre situation financière</li>
                            </ul>

                            <!-- Bouton -->
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td align="center" style="padding: 10px 0 25px 0;">
                                        <a href="https://pp-invoces-generator.up.railway.app/login" style="display: inline-block; background-color: #3026f0; color: #ffffff; text-decoration: none; padding: 14px 40px; border-radius: 8px; font-weight: 600; font-size: 16px;">Accéder à mon espace</a>
                                    </td>
                                </tr>
                            </table>

                            <p style="font-size: 14px; color: #888; line-height: 1.6; margin: 0; border-top: 1px solid #eee; padding-top: 20px;">
                                <strong>Important :</strong> Pour des raisons de sécurité, nous vous recommandons de changer votre mot de passe dès votre première connexion.
                            </p>
                        </td>
                    </tr>
                    <!-- Pied de page -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 25px 40px; text-align: center;">
                            <p style="font-size: 12px; color: #888; margin: 0;">Peoples Post - Votre partenaire logistique</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>'''

    return send_email_via_api(
        to_email=client_email,
        to_name=client_name or client_email,
        subject="Bienvenue sur votre Espace Client Peoples Post",
        html_content=html_content,
        text_content=text_content
    )


@app.route('/api/clients/<client_name>/create-account', methods=['POST'])
@login_required
@admin_required
def create_client_account(client_name):
    """Crée un compte utilisateur pour un client existant"""

    # Vérifier que le client existe
    client = clients_collection.find_one({'_id': client_name})
    if not client:
        return jsonify({'error': 'Client non trouvé'}), 404

    # Vérifier que le client a un email
    client_email = client.get('email', '').strip().lower()
    if not client_email:
        return jsonify({'error': 'Ce client n\'a pas d\'adresse email configurée'}), 400

    if not validate_email(client_email):
        return jsonify({'error': 'L\'adresse email du client est invalide'}), 400

    # Vérifier qu'un compte n'existe pas déjà pour cet email
    existing_user = users_collection.find_one({'email': client_email})
    if existing_user:
        return jsonify({'error': 'Un compte existe déjà pour cette adresse email'}), 400

    # Vérifier qu'un compte client n'est pas déjà lié à ce client
    existing_client_account = users_collection.find_one({'client_id': client_name})
    if existing_client_account:
        return jsonify({'error': 'Un compte client existe déjà pour ce client'}), 400

    # Générer un mot de passe temporaire
    temp_password = generate_temp_password()

    # Créer le compte utilisateur avec le rôle client
    client_name_display = client.get('nom', client_name)
    user_data = {
        'email': client_email,
        'password': generate_password_hash(temp_password, method='pbkdf2:sha256'),
        'name': client_name_display,
        'role': 'client',
        'client_id': client_name,  # Lien vers le client (shipper name)
        'created_at': datetime.now(),
        'created_by': current_user.email
    }

    result = users_collection.insert_one(user_data)

    # Mettre à jour le client avec le lien vers le compte utilisateur
    clients_collection.update_one(
        {'_id': client_name},
        {'$set': {'user_id': result.inserted_id}}
    )

    # Envoyer l'email de bienvenue
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
        'temp_password': temp_password if not send_welcome else None  # Renvoyer le mdp si pas d'email
    })


@app.route('/client')
@login_required
def client_portal():
    """Page du portail client"""
    if not current_user.is_client():
        return redirect(url_for('index'))
    return render_template('client_portal.html', user=current_user)


@app.route('/api/client/dashboard')
@login_required
@client_required
def get_client_dashboard():
    """Récupère les données du dashboard client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    # Récupérer les factures du client
    invoices = list(invoice_history_collection.find({'shipper': client_id}))

    # Calculer les totaux
    total_ht = sum(inv.get('total_ht', 0) or 0 for inv in invoices)
    total_ttc = sum(inv.get('total_ttc', 0) or 0 for inv in invoices)

    # Séparer par statut de paiement
    paid_invoices = [inv for inv in invoices if inv.get('payment_status') == 'paid']
    pending_invoices = [inv for inv in invoices if inv.get('payment_status') != 'paid']

    total_paid_ht = sum(inv.get('total_ht', 0) or 0 for inv in paid_invoices)
    total_paid_ttc = sum(inv.get('total_ttc', 0) or 0 for inv in paid_invoices)
    total_pending_ht = sum(inv.get('total_ht', 0) or 0 for inv in pending_invoices)
    total_pending_ttc = sum(inv.get('total_ttc', 0) or 0 for inv in pending_invoices)

    # Récupérer les infos du client
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
            'total_invoices': len(invoices),
            'total_ht': total_ht,
            'total_ttc': total_ttc,
            'total_paid_ht': total_paid_ht,
            'total_paid_ttc': total_paid_ttc,
            'total_pending_ht': total_pending_ht,
            'total_pending_ttc': total_pending_ttc,
            'paid_count': len(paid_invoices),
            'pending_count': len(pending_invoices)
        }
    })


@app.route('/api/client/invoices')
@login_required
@client_required
def get_client_invoices():
    """Récupère la liste des factures du client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    # Paramètres de filtrage
    status = request.args.get('status')  # 'paid', 'pending', ou None pour toutes
    search = request.args.get('search', '').lower()

    # Construire la requête
    query = {'shipper': client_id}
    if status == 'paid':
        query['payment_status'] = 'paid'
    elif status == 'pending':
        query['payment_status'] = {'$ne': 'paid'}

    # Récupérer les factures
    invoices = list(invoice_history_collection.find(query).sort('created_at', -1))

    # Filtrer par recherche si nécessaire
    if search:
        invoices = [
            inv for inv in invoices
            if search in inv.get('invoice_number', '').lower()
            or search in inv.get('period', '').lower()
        ]

    # Formatter les données pour le frontend
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


@app.route('/api/client/invoices/<invoice_id>/download')
@login_required
@client_required
def download_client_invoice(invoice_id):
    """Télécharge une facture du client"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    # Trouver la facture - IMPORTANT: vérifier qu'elle appartient au client
    invoice = invoice_history_collection.find_one({
        'id': invoice_id,
        'shipper': client_id  # Sécurité: ne peut télécharger que ses propres factures
    })

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    if not batch_id or not filename:
        return jsonify({'error': 'Informations de fichier manquantes'}), 400

    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    return send_file(filepath, as_attachment=True, download_name=filename)


@app.route('/api/client/invoices/<invoice_id>/view')
@login_required
@client_required
def view_client_invoice(invoice_id):
    """Affiche une facture du client dans le navigateur"""
    client_id = current_user.client_id

    if not client_id:
        return jsonify({'error': 'Client non configuré'}), 400

    # Trouver la facture - IMPORTANT: vérifier qu'elle appartient au client
    invoice = invoice_history_collection.find_one({
        'id': invoice_id,
        'shipper': client_id  # Sécurité: ne peut voir que ses propres factures
    })

    if not invoice:
        return jsonify({'error': 'Facture non trouvée'}), 404

    batch_id = invoice.get('batch_id')
    filename = invoice.get('filename')

    if not batch_id or not filename:
        return jsonify({'error': 'Informations de fichier manquantes'}), 400

    batch_folder = os.path.join(app.config['OUTPUT_FOLDER'], f"batch_{batch_id}")
    filepath = os.path.join(batch_folder, filename)

    if not os.path.exists(filepath):
        return jsonify({'error': 'Fichier PDF non trouvé'}), 404

    # Ouvrir dans le navigateur (inline) au lieu de télécharger
    return send_file(filepath, as_attachment=False, mimetype='application/pdf')


@app.route('/api/client/profile')
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


@app.route('/api/clients/<client_name>/account-status')
@login_required
@admin_required
def get_client_account_status(client_name):
    """Vérifie si un client a un compte utilisateur"""

    # Vérifier si un compte existe pour ce client
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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port)
