"""
App factory : crée et configure l'application Flask.
"""

import os
import sys
import uuid
import logging
import secrets
import traceback
from datetime import datetime, timedelta
from flask import Flask, g, request, jsonify, render_template
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from common.config import ENV, DEBUG, VERSION


def create_app():
    """Crée et configure l'application Flask"""

    app = Flask(__name__, static_folder='static', template_folder='templates')

    # ==========================================================================
    # Configuration
    # ==========================================================================

    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        if DEBUG:
            secret_key = 'dev-secret-key-for-development-only'
        else:
            secret_key = secrets.token_hex(32)
            sys.stderr.write("ATTENTION: SECRET_KEY non défini en production! Sessions invalides après redémarrage.\n")

    app.config.update(
        MAX_CONTENT_LENGTH=int(os.environ.get('MAX_UPLOAD_MB', '64')) * 1024 * 1024,
        UPLOAD_FOLDER=os.path.join(os.path.dirname(__file__), 'uploads'),
        OUTPUT_FOLDER=os.path.join(os.path.dirname(__file__), 'output'),
        SECRET_KEY=secret_key,
        SESSION_COOKIE_SECURE=not DEBUG,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
        JSON_AS_ASCII=False,
        JSON_SORT_KEYS=False,
        SEND_FILE_MAX_AGE_DEFAULT=31536000,
        COMPRESS_MIMETYPES=['text/html', 'text/css', 'application/json', 'application/javascript'],
        COMPRESS_MIN_SIZE=500,
    )

    # Créer les dossiers
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

    # ==========================================================================
    # Logging
    # ==========================================================================

    log_format = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    log_level = logging.DEBUG if DEBUG else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(log_format)
    handler.setLevel(log_level)

    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)
    app.logger.propagate = False

    logger = app.logger

    # ==========================================================================
    # Compression GZIP
    # ==========================================================================

    try:
        from flask_compress import Compress
        Compress(app)
        logger.info("Compression GZIP activée")
    except ImportError:
        logger.warning("flask-compress non installé - compression désactivée")

    # ==========================================================================
    # Rate Limiting
    # ==========================================================================

    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        from common.config import LOGIN_LIMIT, EMAIL_LIMIT, API_LIMIT

        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri="memory://",
            strategy="fixed-window"
        )
        app.limiter = limiter
        logger.info("Rate limiting activé")
    except ImportError:
        app.limiter = None
        logger.warning("Flask-Limiter non disponible - rate limiting désactivé")

    # ==========================================================================
    # Flask-Login
    # ==========================================================================

    from common.auth import login_manager, init_super_admin, init_db_indexes

    login_manager.init_app(app)

    # ==========================================================================
    # Middleware
    # ==========================================================================

    @app.before_request
    def before_request():
        g.request_start_time = datetime.now()
        g.request_id = str(uuid.uuid4())[:8]
        if not request.path.startswith('/static'):
            logger.debug(f"[{g.request_id}] {request.method} {request.path} - IP: {request.remote_addr}")

    @app.after_request
    def after_request(response):
        if hasattr(g, 'request_start_time'):
            duration = (datetime.now() - g.request_start_time).total_seconds() * 1000
            response.headers['X-Response-Time'] = f"{duration:.2f}ms"
            if not request.path.startswith('/static'):
                logger.debug(
                    f"[{getattr(g, 'request_id', '-')}] "
                    f"{request.method} {request.path} -> {response.status_code} "
                    f"({duration:.2f}ms)"
                )

        if request.path.startswith('/static'):
            response.headers['Cache-Control'] = 'public, max-age=31536000'
        elif request.path.startswith('/api'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'

        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        if not DEBUG:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    # ==========================================================================
    # Error Handlers
    # ==========================================================================

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
        max_mb = int(os.environ.get('MAX_UPLOAD_MB', '64'))
        return jsonify({'error': f'Fichier trop volumineux (max {max_mb}MB)', 'code': 413}), 413

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
        if isinstance(e, HTTPException):
            return e
        logger.error(f"Unhandled Exception: {type(e).__name__}: {str(e)}\n{traceback.format_exc()}")
        return jsonify({
            'error': 'Une erreur inattendue s\'est produite',
            'code': 500,
            'details': str(e) if DEBUG else None
        }), 500

    # ==========================================================================
    # Blueprints
    # ==========================================================================

    from blueprints.system import system_bp
    from blueprints.auth import auth_bp
    from blueprints.invoices import invoices_bp
    from blueprints.email import email_bp
    from blueprints.history import history_bp
    from blueprints.clients import clients_bp
    from blueprints.client_portal import client_portal_bp

    app.register_blueprint(system_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(invoices_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(client_portal_bp)

    # ==========================================================================
    # Initialisation DB (dans le contexte de l'app)
    # ==========================================================================

    with app.app_context():
        init_super_admin()
        init_db_indexes()

    logger.info(f"Application initialisée: env={ENV}, version={VERSION}")

    return app
