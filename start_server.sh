#!/bin/bash
# Peoples Post - Démarrage du serveur de génération de factures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Vérifie si l'environnement virtuel existe
if [ ! -d "$VENV_DIR" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
else
    source "$VENV_DIR/bin/activate"
fi

echo "======================================"
echo "  Peoples Post - Générateur de Factures"
echo "======================================"
echo ""
echo "Serveur démarré sur: http://localhost:5001"
echo "Appuyez sur Ctrl+C pour arrêter"
echo ""

# Lance le serveur
cd "$SCRIPT_DIR"
python app.py
