"""
Matching intelligent des clients : normalisation, similarité, recherche fuzzy.
"""

import os
import re
import logging
from flask import g
from pymongo import ReplaceOne

from common.database import clients_collection
from common.helpers import clean_siret

logger = logging.getLogger(__name__)

# =============================================================================
# Chargement / sauvegarde config clients
# =============================================================================


def load_clients_config(use_cache=True):
    """Charge la configuration des clients depuis MongoDB (avec cache par requête)"""
    from invoice_generator import load_clients_config as load_clients_config_file, CLIENTS_CONFIG_FILE

    if use_cache:
        try:
            cached = getattr(g, '_clients_config', None)
            if cached is not None:
                return cached
        except RuntimeError:
            pass

    clients = {}
    for client in clients_collection.find():
        client_name = client.pop('_id')
        clients[client_name] = client
    if not clients:
        if os.path.exists(CLIENTS_CONFIG_FILE):
            clients = load_clients_config_file()
            if clients:
                save_clients_config(clients)

    try:
        g._clients_config = clients
    except RuntimeError:
        pass

    return clients


def save_clients_config(clients):
    """Sauvegarde la configuration des clients dans MongoDB (batch)"""
    if not clients:
        return
    ops = []
    for client_name, client_data in clients.items():
        client_doc = dict(client_data)
        client_doc['_id'] = client_name
        ops.append(ReplaceOne({'_id': client_name}, client_doc, upsert=True))
    if ops:
        clients_collection.bulk_write(ops, ordered=False)
    try:
        g._clients_config = None
    except RuntimeError:
        pass


# =============================================================================
# Normalisation
# =============================================================================


def normalize_client_name(name):
    """Normalise un nom de client pour la comparaison."""
    import unicodedata

    if not name:
        return ""

    normalized = name.lower().strip()
    normalized = unicodedata.normalize('NFD', normalized)
    normalized = ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
    normalized = re.sub(r'[^\w\s]', ' ', normalized)

    via_patterns = [
        r'\s*via\s+peoples?\s*post',
        r'\s*via\s+pp',
        r'\s*peoples?\s*post',
        r'\s*-\s*pp',
    ]
    for pattern in via_patterns:
        normalized = re.sub(pattern, ' ', normalized, flags=re.IGNORECASE)

    legal_forms = [
        r'\bsarl\b', r'\bsas\b', r'\bsa\b', r'\beurl\b', r'\bsasu\b',
        r'\bsei\b', r'\bsnc\b', r'\bsci\b', r'\bauto entrepreneur\b',
        r'\bautoentrepreneur\b', r'\bei\b', r'\bme\b', r'\bscp\b',
        r'\bgmbh\b', r'\bltd\b', r'\bllc\b', r'\binc\b', r'\bcorp\b'
    ]
    for form in legal_forms:
        normalized = re.sub(form, '', normalized)

    normalized = re.sub(r'\s+', ' ', normalized).strip()
    return normalized


# =============================================================================
# Similarité
# =============================================================================


def calculate_similarity(s1, s2):
    """Calcule un score de similarité entre deux chaînes (0 à 1)."""
    if not s1 or not s2:
        return 0.0

    n1 = normalize_client_name(s1)
    n2 = normalize_client_name(s2)

    if n1 == n2:
        return 1.0

    n1_nospace = n1.replace(' ', '')
    n2_nospace = n2.replace(' ', '')

    if n1_nospace == n2_nospace:
        return 0.98

    if n1 in n2 or n2 in n1 or n1_nospace in n2_nospace or n2_nospace in n1_nospace:
        shorter = min(len(n1_nospace), len(n2_nospace))
        longer = max(len(n1_nospace), len(n2_nospace))
        ratio = shorter / longer if longer > 0 else 0
        if ratio > 0.7:
            return 0.90 + (ratio * 0.1)

    words1 = set(n1.split())
    words2 = set(n2.split())

    if not words1 or not words2:
        return 0.0

    common_words = words1 & words2
    all_words = words1 | words2

    jaccard = len(common_words) / len(all_words) if all_words else 0

    common_chars = sum(1 for c in n1_nospace if c in n2_nospace)
    char_score = (2.0 * common_chars) / (len(n1_nospace) + len(n2_nospace)) if (len(n1_nospace) + len(n2_nospace)) > 0 else 0

    prefix_len = 0
    for c1, c2 in zip(n1_nospace, n2_nospace):
        if c1 == c2:
            prefix_len += 1
        else:
            break
    prefix_score = prefix_len / max(len(n1_nospace), len(n2_nospace)) if max(len(n1_nospace), len(n2_nospace)) > 0 else 0

    return (jaccard * 0.3) + (char_score * 0.4) + (prefix_score * 0.3)


# =============================================================================
# Recherche de correspondance
# =============================================================================


def find_best_client_match(shipper_name, clients_config, threshold=0.45):
    """Trouve le meilleur client correspondant dans la config."""
    if not shipper_name or not clients_config:
        return None, None, 0

    if shipper_name in clients_config:
        return shipper_name, clients_config[shipper_name], 1.0

    shipper_lower = shipper_name.lower().strip()
    for client_name, client_info in clients_config.items():
        if client_name.lower().strip() == shipper_lower:
            return client_name, client_info, 1.0

    for client_name, client_info in clients_config.items():
        client_nom = client_info.get('nom', '')
        if client_nom.lower().strip() == shipper_lower:
            return client_name, client_info, 1.0

    shipper_normalized = normalize_client_name(shipper_name)
    shipper_nospace = shipper_normalized.replace(' ', '')

    for client_name, client_info in clients_config.items():
        client_normalized = normalize_client_name(client_name)
        client_nospace = client_normalized.replace(' ', '')

        if client_normalized == shipper_normalized:
            return client_name, client_info, 0.95

        if client_nospace == shipper_nospace:
            return client_name, client_info, 0.95

        client_nom = client_info.get('nom', '')
        nom_normalized = normalize_client_name(client_nom)
        nom_nospace = nom_normalized.replace(' ', '')

        if nom_normalized == shipper_normalized or nom_nospace == shipper_nospace:
            return client_name, client_info, 0.95

    best_match = None
    best_score = threshold
    best_info = None

    for client_name, client_info in clients_config.items():
        score_key = calculate_similarity(shipper_name, client_name)
        client_nom = client_info.get('nom', '')
        score_nom = calculate_similarity(shipper_name, client_nom) if client_nom else 0
        score = max(score_key, score_nom)

        if score > best_score:
            best_score = score
            best_match = client_name
            best_info = client_info

    if best_match:
        logger.debug(f"Client fuzzy match: '{shipper_name}' → '{best_match}' (score: {best_score:.2f})")
        return best_match, best_info, best_score

    return None, None, 0


def get_client_info(shipper_name, clients_config, csv_siret=None):
    """Récupère les informations d'un client avec matching intelligent."""
    if csv_siret:
        cleaned = clean_siret(csv_siret)
        if len(cleaned) >= 9:
            for client_name, client_data in clients_config.items():
                client_siret_val = clean_siret(client_data.get('siret', ''))
                if client_siret_val and client_siret_val == cleaned:
                    logger.debug(f"Client SIRET match: '{shipper_name}' → '{client_name}' (SIRET: {cleaned})")
                    return client_data

    matched_name, client_info, score = find_best_client_match(shipper_name, clients_config)
    if client_info:
        return client_info

    shipper_lower = shipper_name.lower().strip()
    shipper_normalized = normalize_client_name(shipper_name)
    shipper_nospace = shipper_normalized.replace(' ', '')

    best_fuzzy_match = None
    best_fuzzy_score = 0

    for cfg_name, cfg_data in clients_config.items():
        client_nom = cfg_data.get('nom', '')
        cfg_normalized = normalize_client_name(cfg_name)
        nom_normalized = normalize_client_name(client_nom)
        cfg_nospace = cfg_normalized.replace(' ', '')
        nom_nospace = nom_normalized.replace(' ', '')

        if cfg_name == shipper_name:
            return cfg_data

        if cfg_name.lower().strip() == shipper_lower or client_nom.lower().strip() == shipper_lower:
            return cfg_data

        if cfg_normalized == shipper_normalized or nom_normalized == shipper_normalized:
            logger.debug(f"Client normalized match: '{shipper_name}' → '{cfg_name}'")
            return cfg_data

        if cfg_nospace == shipper_nospace or nom_nospace == shipper_nospace:
            logger.debug(f"Client nospace match: '{shipper_name}' → '{cfg_name}'")
            return cfg_data

        score_key = calculate_similarity(shipper_name, cfg_name)
        score_nom = calculate_similarity(shipper_name, client_nom) if client_nom else 0
        best = max(score_key, score_nom)
        if best >= 0.45 and best > best_fuzzy_score:
            best_fuzzy_score = best
            best_fuzzy_match = cfg_data

    if best_fuzzy_match:
        logger.debug(f"Client fuzzy match: '{shipper_name}' (score: {best_fuzzy_score:.2f})")
        return best_fuzzy_match

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
    client_doc = dict(default_client)
    client_doc['_id'] = shipper_name
    clients_collection.replace_one({'_id': shipper_name}, client_doc, upsert=True)
    return default_client
