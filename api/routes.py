from flask import jsonify, request, Blueprint, current_app
from services.config import getApiPrefix, getMode
from werkzeug.security import check_password_hash
import os
import subprocess
from database.models import Route, AccessRule

# On définit le nom du blueprint ('api_dynamique') et le module (__name__)
api_bp = Blueprint('api_dynamique', __name__)

        
@api_bp.route('/<path:full_path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) # Route pour gérer toutes les requêtes sous le préfixe API
def api_dynamique_path(full_path):
    prefix = getApiPrefix().strip('/')  # Supprimer le '/' de début et de la fin
    client_ip = request.remote_addr
    current_app.logger.info(f"Appel API recu : {full_path} | Methode: {request.method} | IP: {client_ip}")
    if not full_path.startswith(prefix+'/'):
        # Si le chemin ne commence pas par le préfixe, renvoyer 404
        return jsonify({"error": "Not Found"}), 404
    
    mode = getMode()
    
    if mode == 'BLACKLIST':
        # On cherche si l'IP est dans la blacklist et active
        is_blacklisted = AccessRule.query.filter_by(
            rule_type='blacklist', 
            ip_address=client_ip, 
            is_active=True
        ).first()
        
        if is_blacklisted:
            current_app.logger.warning(f"[ECHEC] Mode BLACKLIST actif - Acces refuse | IP: {client_ip}")
            return jsonify({"error": "Service Unavailable"}), 503

    elif mode == 'WHITELIST':
        # On cherche si l'IP est dans la whitelist et active
        is_whitelisted = AccessRule.query.filter_by(
            rule_type='whitelist', 
            ip_address=client_ip, 
            is_active=True
        ).first()
        
        if not is_whitelisted:
            current_app.logger.warning(f"[ECHEC] Mode WHITELIST actif - Acces refuse | IP: {client_ip}")
            return jsonify({"error": "Service Unavailable"}), 503

    # On enlève la longueur du prefix + 1 pour le slash suivant
    # Ex: "monapi/test1/r1" -> "test1/r1"
    real_route_part = full_path[len(prefix)+1:].strip('/')
    
    route = Route.query.filter_by(
        path=real_route_part, 
        method=request.method.upper(), 
        is_active=True
    ).first()

    if route:
        # 4. Vérification du Token
        auth_header = request.headers.get('Authorization')
        token_recu = None
        
        if auth_header and auth_header.startswith("Bearer "):
            token_recu = auth_header.split(" ")[1]
            
            if check_password_hash(route.hashed_token, token_recu):
                current_app.logger.info(f"[SUCCES] Execution route: /{real_route_part} | IP: {client_ip}")
                
                # Préparation de la commande (nettoyage commentaires)
                lines = route.command.splitlines()
                shell_command = " && ".join([line.split('#')[0].strip() for line in lines if line.split('#')[0].strip()])
                
                if not shell_command:
                     return jsonify({"message": "Aucune commande à exécuter", "status": 0}), 200

                try:
                    # Gestion des variables d'environnement
                    env_vars = os.environ.copy()
                    
                    # Paramètres URL
                    for key, value in request.args.items():
                        env_vars[f"PARAM_{key.upper()}"] = str(value)
                        
                    # Paramètres JSON
                    if request.is_json and request.json:
                        for key, value in request.json.items():
                            env_vars[f"PARAM_{key.upper()}"] = str(value)
                                                    
                    # Exécution
                    result = subprocess.run(
                        shell_command, 
                        shell=True, 
                        env=env_vars, 
                        timeout=60,
                        capture_output=route.return_output, # Lecture depuis l'objet SQL
                        text=True
                    )
                    
                    response = {
                        "message": f"Commande exécutée", # On évite de renvoyer la commande brute par sécurité
                        "status": result.returncode
                    }
                    
                    if route.return_output:
                        output_content = ""
                        if result.stdout: output_content += result.stdout
                        if result.stderr: output_content += "\n[STDERR]\n" + result.stderr
                        response["output"] = output_content.strip()
                        
                    return jsonify(response), 200
                    
                except Exception as e:
                    current_app.logger.error(f"Erreur execution bash: {str(e)}")
                    return jsonify({"error": "Internal Server Error"}), 500
            else:
                current_app.logger.warning(f"[ECHEC] Token invalide pour /{real_route_part} | IP: {client_ip}")
                return jsonify({"error": "Unauthorized"}), 401
        else:
            current_app.logger.warning(f"[ECHEC] Pas de token fourni pour /{real_route_part} | IP: {client_ip}")
            return jsonify({"error": "Unauthorized"}), 401
            
    # Si aucune route trouvée en SQL
    return jsonify({"error": "Not Found"}), 404