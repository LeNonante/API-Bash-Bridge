from flask import jsonify, request, Blueprint
from services.config import getApiPrefix
import os
import json

# On définit le nom du blueprint ('api_dynamique') et le module (__name__)
api_bp = Blueprint('api_dynamique', __name__)

        
@api_bp.route('/<path:full_path>', methods=['GET']) # Route pour gérer toutes les requêtes sous le préfixe API
def api_dynamique_path(full_path):
    prefix = getApiPrefix().strip('/')  # Supprimer le '/' de début et de la fin
    
    if not full_path.startswith(prefix):
        # Si le chemin ne commence pas par le préfixe, renvoyer 404
        return jsonify({"error": "Not Found"}), 404
    
    # Charger les données du fichier commandes.json
    with open('commandes.json', 'r') as f:
        routes_data = json.load(f)
    
    # On enlève la longueur du prefix + 1 pour le slash suivant
    # Ex: "monapi/test1/r1" -> "test1/r1"
    real_route_part = full_path[len(prefix)+1:].strip('/')
    
    for route in routes_data:
        if route['active']:
            route_path = route['path'].strip('/')
            if route_path == real_route_part and request.method == route['method']:
                # Exécuter la commande associée
                return route['command'], 200