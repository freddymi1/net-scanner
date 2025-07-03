# Création et activation d'un environnement virtuel Python
python3 -m venv venv
source venv/bin/activate

# Installation des dépendances nécessaires
pip install scapy flask netifaces

# (Optionnel) Pour un développement plus confortable
pip install ipython

# Pour lancer l'application :
# python main.py