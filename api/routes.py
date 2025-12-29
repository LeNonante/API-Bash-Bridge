from flask import jsonify, request, Blueprint, current_app
from services.config import getApiPrefix, getMode
from werkzeug.security import check_password_hash
import os
import json
import subprocess
# On définit le nom du blueprint ('api_dynamique') et le module (__name__)
api_bp = Blueprint('api_dynamique', __name__)

        
@api_bp.route('/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) # Route pour gérer toutes les requêtes sous le préfixe API
def api_dynamique_path(full_path):
    prefix = getApiPrefix().strip('/')  # Supprimer le '/' de début et de la fin
    current_app.logger.info(f"Appel API recu : {full_path} | Methode: {request.method} | IP: {request.remote_addr}")
    if not full_path.startswith(prefix+'/'):
        # Si le chemin ne commence pas par le préfixe, renvoyer 404
        return jsonify({"error": "Not Found"}), 404
    
    try:
        with open('commandes.json', 'r') as f:
            routes_data = json.load(f)
    except Exception as e:
        current_app.logger.error(f"Erreur lecture commandes.json : {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
    
    try:
        with open('blacklist.json', 'r') as f:
            blacklist_data = json.load(f)
    except Exception as e:
        current_app.logger.error(f"Erreur lecture blacklist.json : {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
    
    blacklist_ips = []  # Liste des IPs en blacklist
    whitelist_ips = []  # Liste des IPs en whitelist
    
    for item in blacklist_data:
        if item['active']:
            blacklist_ips.append(item['ip'])
    
    try:
        with open('whitelist.json', 'r') as f:
            whitelist_data = json.load(f)
    except Exception as e:
        current_app.logger.error(f"Erreur lecture whitelist.json : {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

    for item in whitelist_data:
        if item['active']:
            whitelist_ips.append(item['ip'])

    mode= getMode()
    
    if mode == 'BLACKLIST' and request.remote_addr in blacklist_ips:
        current_app.logger.warning(f"[ECHEC] Mode BLACKLIST actif - Acces refuse | IP: {request.remote_addr}")
        return jsonify({"error": "Service Unavailable"}), 503
    elif mode == 'WHITELIST' and request.remote_addr not in whitelist_ips:
        current_app.logger.warning(f"[ECHEC] Mode WHITELIST actif - Acces refuse | IP: {request.remote_addr}")
        return jsonify({"error": "Service Unavailable"}), 503
    # On enlève la longueur du prefix + 1 pour le slash suivant
    # Ex: "monapi/test1/r1" -> "test1/r1"
    real_route_part = full_path[len(prefix)+1:].strip('/')
    for route in routes_data:
        if route['active']:
            route_path = route['path'].strip('/')
            print(route_path, real_route_part)
            if route_path == real_route_part and request.method.upper() == route['method']:
                print('er')
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
                            current_app.logger.info(f"[SUCCES] Execution route: /{route_path} | IP: {request.remote_addr}")
                            lines=stocked_command.splitlines() #séparation en lignes
                            shell_command = "" #On prépare la commande shell
                            for line in lines:
                                line_clean = line.split('#')[0].strip() #On enlève les commentaires et les espaces de début/fin
                                if line_clean != "": #Si la ligne n'est pas vide après nettoyage
                                    if shell_command != "": #Si ce n'est pas la première commande
                                        shell_command += " && " #On ajoute le séparateur entre les commandes
                                    shell_command += line_clean # On ajoute la commande nettoyée
                            try:
                                subprocess.run(shell_command, shell=True, timeout=60) # Exécuter la commande shell avec un timeout de 60 secondes
                                return jsonify({"message": f"Commande exécutée: {stocked_command}"}), 200
                            except Exception as e:
                                current_app.logger.error(f"Erreur execution bash: {str(e)}")
                                return jsonify({"error": "Internal Server Error"}), 500
                        else:
                            current_app.logger.warning(f"[ECHEC] Token invalide pour /{route_path} | IP: {request.remote_addr}")
                            return jsonify({"error": "Unauthorized"}), 401
                else:
                    current_app.logger.warning(f"[ECHEC] Pas de token fourni pour /{route_path} | IP: {request.remote_addr}")
                    return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"error": "Not Found"}), 404