# Peoples Post - Générateur de Factures

Outil pour convertir les fichiers CSV d'expédition en factures PDF professionnelles.

## Interface Web

### Démarrage rapide

```bash
cd /Users/gabrielgetir/peoples-post/tools/invoice-generator
./start_server.sh
```

Puis ouvrez **http://localhost:5000** dans votre navigateur.

### Fonctionnalités

- **Import CSV**: Glissez-déposez ou sélectionnez votre fichier CSV
- **Aperçu**: Visualisez les clients et montants avant génération
- **Configuration**: Personnalisez le préfixe et numéro de départ des factures
- **Téléchargement**: Téléchargez les factures individuellement ou en ZIP
- **Gestion des clients**: Configurez les informations de facturation (adresse, SIRET, email)

---

## Utilisation en ligne de commande

```bash
# Utilisation basique
./generate_invoices.sh chemin/vers/fichier.csv

# Avec dossier de sortie personnalisé
./generate_invoices.sh fichier.csv -o mes_factures/

# Avec préfixe et numéro de départ personnalisés
./generate_invoices.sh fichier.csv --prefix PP-2025 --start-number 100
```

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

## Configuration des clients

Les informations des clients (adresse, SIRET, email) sont stockées dans `clients.json`.

Vous pouvez les modifier:
- Via l'interface web (onglet "Clients")
- Directement dans le fichier `clients.json`

Exemple de structure:
```json
{
  "NomClient": {
    "nom": "NOM COMPLET DU CLIENT",
    "adresse": "123 rue de la Paix",
    "code_postal": "75001",
    "ville": "Paris",
    "pays": "France",
    "email": "contact@client.fr",
    "siret": "12345678900000"
  }
}
```

---

## Structure des fichiers

```
invoice-generator/
├── app.py                 # Application Flask (interface web)
├── invoice_generator.py   # Moteur de génération PDF
├── clients.json           # Configuration des clients
├── logo.png               # Logo Peoples Post
├── requirements.txt       # Dépendances Python
├── start_server.sh        # Script de démarrage du serveur web
├── generate_invoices.sh   # Script CLI
├── templates/
│   └── index.html         # Template HTML
├── static/
│   ├── css/style.css      # Styles CSS
│   ├── js/app.js          # JavaScript frontend
│   └── logo.png           # Logo pour le web
├── uploads/               # Fichiers CSV uploadés (temporaire)
└── output/                # Factures PDF générées
```

---

## Support

En cas de problème, vérifiez que:
1. Python 3.8+ est installé
2. Les dépendances sont installées (`pip install -r requirements.txt`)
3. Le fichier `clients.json` contient les informations de vos clients
