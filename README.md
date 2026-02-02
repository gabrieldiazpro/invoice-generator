# Peoples Post - Générateur de Factures

Application web de génération de factures PDF professionnelles pour Peoples Post.

**Production**: https://pp-invoces-generator.up.railway.app

## Fonctionnalités

### Gestion des factures
- **Import CSV**: Glissez-déposez ou sélectionnez votre fichier CSV d'expéditions
- **Aperçu**: Visualisez les clients et montants avant génération
- **Génération PDF**: Factures professionnelles avec logo et mentions légales
- **Téléchargement**: Téléchargez individuellement ou en ZIP
- **Envoi par email**: Envoyez les factures directement aux clients

### Gestion des clients
- Configuration des informations de facturation (adresse, SIRET, email)
- Import/Export des configurations clients
- Historique des factures par client

### Gestion des utilisateurs
- **Authentification sécurisée** avec sessions
- **Rôles**: Utilisateur standard et Super Admin
- **Super Admin**: Peut gérer les utilisateurs et accéder à tous les comptes
- **Emails de bienvenue** automatiques pour les nouveaux utilisateurs

### Configuration
- Personnalisation du préfixe et numéro de facture
- Configuration SMTP/API pour l'envoi d'emails
- Informations société personnalisables

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
| `BREVO_API_KEY` | Clé API Brevo pour l'envoi d'emails |

### Déploiement automatique

Le déploiement se fait automatiquement via GitHub push sur la branche `main`.

---

## Format du CSV

Le CSV doit contenir les colonnes suivantes (séparateur `;` ou `,`):

| Colonne | Description |
|---------|-------------|
| Shipper | Nom du client (expéditeur) |
| Carrier name or Supplement | Nom du transporteur ou type de supplément |
| PP Shipping method | Méthode d'expédition |
| Weight range | Tranche de poids |
| Shipper Service | Service utilisé |
| Quantité | Nombre d'expéditions |
| Prix | Prix unitaire HT |
| Invoice Staring date | Date de début de période |
| Invoice Ending date | Date de fin de période |
| TVA en % | Taux de TVA |

---

## Structure du projet

```
invoice-generator/
├── app.py                 # Application Flask principale
├── invoice_generator.py   # Moteur de génération PDF
├── requirements.txt       # Dépendances Python
├── Procfile               # Configuration Railway
├── templates/
│   ├── index.html         # Interface principale
│   └── login.html         # Page de connexion
├── static/
│   ├── css/style.css      # Styles CSS
│   ├── js/app.js          # JavaScript frontend
│   └── logo.png           # Logo Peoples Post
├── uploads/               # Fichiers CSV uploadés (temporaire)
└── output/                # Factures PDF générées
```

---

## Technologies

- **Backend**: Flask, Python 3.11
- **Base de données**: MongoDB Atlas
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **PDF**: ReportLab
- **Email**: Brevo API
- **Hébergement**: Railway

---

## Licence

Propriétaire - Peoples Post SAS
