from flask import jsonify, request, Blueprint
from services.config import getApiPrefix
from werkzeug.security import check_password_hash
import os
import json
import subprocess
# On définit le nom du blueprint ('api_dynamique') et le module (__name__)
api_bp = Blueprint('api_dynamique', __name__)

        
@api_bp.route('/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) # Route pour gérer toutes les requêtes sous le préfixe API
def api_dynamique_path(full_path):
    prefix = getApiPrefix().strip('/')  # Supprimer le '/' de début et de la fin
    
    if not full_path.startswith(prefix+'/'):
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
            if route_path == real_route_part and request.method.upper() == route['method']:
                #On récupère le token d'authorization dans les headers
                auth_header = request.headers.get('Authorization')
                token_recu = None
                if auth_header:
                    # Le header ressemble à "Bearer mon_token_abc"
                    # On coupe pour garder juste la partie après "Bearer "
                    parts = auth_header.split(" ")
                    if len(parts) == 2 and parts[0] == "Bearer":
                        token_recu = parts[1]
                        token_route_hashed = route['hashed_token']
                        if check_password_hash(token_route_hashed, token_recu):
                            stocked_command = route['command'] # Récupérer la commande stockée
                            lines=stocked_command.splitlines() #séparation en lignes
                            shell_command = "" #On prépare la commande shell
                            for line in lines:
                                line_clean = line.split('#')[0].strip() #On enlève les commentaires et les espaces de début/fin
                                if line_clean != "": #Si la ligne n'est pas vide après nettoyage
                                    if shell_command != "": #Si ce n'est pas la première commande
                                        shell_command += " && " #On ajoute le séparateur entre les commandes
                                    shell_command += line_clean # On ajoute la commande nettoyée
                            subprocess.run(shell_command, shell=True)
                            return jsonify({"message": f"Commande exécutée: {stocked_command}"}), 200
                        else:
                            return jsonify({"error": "Unauthorized"}), 401
                else:
                    return jsonify({"error": "Unauthorized"}), 401
        return jsonify({"error": "Not Found"}), 404