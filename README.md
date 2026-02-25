# Peoples Post - Générateur de Factures

Application web de génération de factures PDF professionnelles pour Peoples Post.

**Production**: https://pp-invoces-generator.up.railway.app

---

## Fonctionnalités

### Gestion des factures
- **Import CSV**: Glissez-déposez ou sélectionnez votre fichier CSV d'expéditions
- **Aperçu intelligent**: Matching automatique des clients avec la base de données
- **Génération PDF**: Factures professionnelles avec logo et mentions légales
- **Numérotation**: Format PP-YYYY-XXXX (ex: PP-2026-0001)
- **Multi-TVA**: Gestion des différents taux (20%, 5.5%, 0%)
- **Téléchargement**: Téléchargez individuellement ou en ZIP
- **Envoi par email**: Envoyez les factures directement aux clients via Brevo API

### Format des factures
- **Numéro**: PP-[Année]-[4 chiffres] (configurable)
- **Date d'émission**: Date de génération
- **Date d'échéance**: Toujours le 15 du mois suivant
- **TVA**: Calcul automatique par taux avec détail dans les totaux

### Gestion des clients
- Configuration des informations de facturation (adresse, SIRET, email)
- Matching intelligent des noms (gère accents, espaces, "via PP", etc.)
- Import/Export des configurations clients
- Historique des factures par client

### Gestion des utilisateurs
- **Authentification sécurisée** avec sessions
- **Rôles**: User, Admin, Super Admin
- **Expéditeur personnalisé**: Chaque utilisateur peut configurer son identité d'envoi
- **Emails de bienvenue** automatiques pour les nouveaux utilisateurs

### Configuration
- Préfixe des factures personnalisable
- Année de facturation sélectionnable
- Configuration email via API Brevo (contourne les restrictions SMTP)

---

## Installation locale

### Prérequis
- Python 3.8+
- MongoDB (local ou Atlas)

### Démarrage

```bash
# Cloner le repository
git clone https://github.com/gabrieldiazpro/invoice-generator.git
cd invoice-generator

# Créer un environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou: venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur
python app.py
```

Puis ouvrez **http://localhost:5000**

---

## Déploiement (Railway)

### Variables d'environnement requises

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | URI de connexion MongoDB Atlas |
| `SECRET_KEY` | Clé secrète pour les sessions Flask |

### Configuration Email (dans l'app)

La configuration email se fait via l'interface d'administration:
- **API Key Brevo**: Clé commençant par `xkeysib-...`
- **Sender Email**: Doit être vérifié dans Brevo
- **Domaine**: Le domaine d'envoi doit être authentifié (DKIM, DMARC)

### Déploiement automatique

Le déploiement se fait automatiquement via GitHub push sur la branche `main`.

---

## Format du CSV

Le CSV doit contenir les colonnes suivantes (séparateur `;` ou `,`):

| Colonne | Description | Exemple |
|---------|-------------|---------|
| Shipper | Nom du client (expéditeur) | "Ma Boutique" |
| Carrier name or Supplement | Transporteur ou supplément | "GLS" |
| PP Shipping method | Méthode d'expédition | "Standard" |
| Weight range | Tranche de poids | "0-1kg" |
| Shipper Service | Service utilisé | "Express" |
| Quantité | Nombre d'expéditions | "5" |
| Prix | Prix unitaire HT | "12,50" |
| TVA en % | Taux de TVA | "20" |
| Invoice Staring date | Date de début | "01/01/2026" |
| Invoice Ending date | Date de fin | "31/01/2026" |

---

## Structure du projet

```
invoice-generator/
├── app.py                 # Application Flask principale (routes, API, auth)
├── invoice_generator.py   # Moteur de génération PDF (ReportLab)
├── requirements.txt       # Dépendances Python
├── Procfile               # Configuration Railway (gunicorn)
├── templates/
│   ├── index.html         # Interface principale (dashboard)
│   └── login.html         # Page de connexion
├── static/
│   ├── css/style.css      # Styles CSS
│   ├── js/app.js          # JavaScript frontend
│   ├── logo.png           # Logo pour PDF
│   └── logo_email.png     # Logo pour emails
├── uploads/               # Fichiers CSV uploadés (temporaire)
└── output/                # Factures PDF générées (par batch)
```

---

## Base de données (MongoDB)

### Collections

| Collection | Description |
|------------|-------------|
| `users` | Utilisateurs et authentification |
| `clients` | Configuration des clients (SIRET, adresse, email) |
| `email_config` | Configuration SMTP/API Brevo |
| `invoice_history` | Historique des factures générées |

---

## Technologies

- **Backend**: Flask 3.1, Python 3.11
- **Base de données**: MongoDB Atlas
- **Frontend**: HTML5, CSS3, JavaScript ES6
- **PDF**: ReportLab 4.x
- **Email**: Brevo API (HTTP)
- **Hébergement**: Railway
- **CI/CD**: GitHub → Railway (auto-deploy)

---

## Sécurité

- Authentification par sessions Flask-Login
- Mots de passe hashés (pbkdf2:sha256)
- Protection CSRF
- Rate limiting sur login et emails
- Validation des fichiers uploadés

---

## Support

Pour toute question ou problème:
- **Email**: victor.estines@peoplespost.fr
- **GitHub Issues**: https://github.com/gabrieldiazpro/invoice-generator/issues

---

## Licence

Propriétaire - Peoples Post SAS - Tous droits réservés
