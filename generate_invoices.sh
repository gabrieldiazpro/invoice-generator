#!/bin/bash
# Peoples Post - Script de génération de factures
# Usage: ./generate_invoices.sh chemin/vers/fichier.csv

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Vérifie si l'environnement virtuel existe
if [ ! -d "$VENV_DIR" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install reportlab --quiet
else
    source "$VENV_DIR/bin/activate"
fi

# Vérifie les arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <fichier_csv> [options]"
    echo ""
    echo "Options:"
    echo "  -o, --output DIR     Dossier de sortie (défaut: output)"
    echo "  --prefix PREFIX      Préfixe facture (défaut: PP)"
    echo "  --start-number N     Numéro de départ (défaut: 1)"
    echo ""
    echo "Exemple:"
    echo "  $0 export.csv -o factures_janvier --start-number 100"
    exit 1
fi

# Lance le générateur
python "$SCRIPT_DIR/invoice_generator.py" "$@"

echo ""
echo "Pour ouvrir les factures générées:"
echo "  open $SCRIPT_DIR/output/*.pdf"
