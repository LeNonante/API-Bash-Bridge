from flask import Flask, flash, jsonify, request, redirect, session, url_for, render_template, send_file, g
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from services.config import *
import json
import re
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from api.routes import api_bp
import subprocess
import os
import uuid
import logging
from logging.handlers import RotatingFileHandler
import zipfile
from io import BytesIO
import ipaddress
from markdown import markdown
import time
import sys
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from filelock import FileLock
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from database.extensions import db
from database.models import Route, AccessRule
import io
from sqlalchemy.exc import IntegrityError


basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
csrf = CSRFProtect(app) # Active la protection sur toute l'app. Permet d'ajouter des tokens CSRF uniques dans les formulaires.

# Configuration de Talisman
# content_security_policy=None : On désactive la CSP stricte pour ne pas casser nos scripts inline actuels (ex: login.html, settings.html)
# force_https=False : À mettre sur True uniquement si on a un certificat SSL/HTTPS actif.
#Talisman(app, content_security_policy=None, force_https=False)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'bash-api.db') # Le fichier sera créé dansu n dossier instance/
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Pour économiser de la mémoire

# Initialisation de la db avec l'app Flask
db.init_app(app)

# Création des tables
with app.app_context():
    # S'assure que le dossier instance existe
    if not os.path.exists(os.path.join(basedir, 'instance')):
        os.makedirs(os.path.join(basedir, 'instance'))
    db.create_all()
    
# On utilise get_remote_address pour identifier l'utilisateur par son IP.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"], # Limites globales par défaut (optionnel)
    storage_uri="memory://" # Stockage en mémoire RAM (suffisant pour une instance unique)
)

# Création d'un filtre qui injecte l'ID dans chaque log
class RequestIdFilter(logging.Filter):
    def filter(self, record):
        # Récupère l'ID stocké dans 'g', ou met 'SYSTEM' si hors requête
        record.request_id = getattr(g, 'request_id', 'SYSTEM')
        return True

# Chemin du fichier log
log_file_path = os.path.join(os.path.dirname(__file__), "api-activity.log")

# Configuration : Max 1 Mo (1 000 000 octets), 1 fichier de backup
handler = RotatingFileHandler(log_file_path, maxBytes=1000000, backupCount=1)

# On ajoute le filtre au handler
handler.addFilter(RequestIdFilter())

# Format : Date - ID - Niveau - Message
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] [%(request_id)s] %(levelname)s in %(module)s: %(message)s'
))

# Niveau minimum : INFO (pour voir les exécutions et les erreurs)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

pattern_prefix_api = r'^[a-zA-Z0-9]+$'
pattern_path_route = r'^[a-zA-Z0-9/_-]+$'
load_dotenv()

# On dit à Flask : "Fais confiance au proxy qui est juste devant toi (Cloudflare)" Permet de résoudre les problèmes de détection du protocole et du nom de domaine réel.
# x_proto=1 : Fais confiance à 1 proxy pour le protocole (http/https)
# x_host=1  : Fais confiance à 1 proxy pour le nom de domaine
app.wsgi_app = ProxyFix(
    app.wsgi_app, 
    x_for=1, 
    x_proto=1, 
    x_host=1, 
    x_prefix=1
)
app.register_blueprint(api_bp) #Enregistrement du blueprint de l'API dynamique. Comme on veut un prefixe qui peut changer sans redemarrer l'app, on le gère dans le blueprint lui mêmeet pas ici (qui est plus porpre pour un prefixe fixe).
app.config["APP_VERSION"] = get_git_version()
limiter.limit("60 per minute")(api_bp) # Limite spécifique pour l'API dynamique : 60 requêtes par minute par IP


if not isThereASecretKey(): #Si pas de clef secrete (utilisée pour les sessions)
    # Générer une clé secrète aléatoire et la stocker dans le .env
    secret_key = os.urandom(24).hex()
    setSecretKey(".env",secret_key)#Enregistrer la clef dans le .env
    app.secret_key=secret_key #Enregistrer la clef dans l'app
else :
    app.secret_key=getSecretKey() #Lire la clef dans le .env et l'enregistrer dans l'app
    

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"      # page vers laquelle rediriger si pas connecté
class User(UserMixin):
    def __init__(self, username):
        self.id = username
        
#Avant chaque requete, on verifie si l'application est initialisée        
@app.before_request
def check_initialisation():
    # Génère un ID unique court (8 caractères)
    g.request_id = str(uuid.uuid4())[:8]
    
    # Empêcher boucle infinie : on laisse accéder à /register, /login et /logout
    if request.endpoint in ["static", "login", "logout"]:
        return
    if request.endpoint=="register" and not (isThereAdmin()):
        return
    
    if request.endpoint == "documentation": # Permet d'accéder à la doc même sans configurer l'app
        return
    
    # Si pas d'admin on force vers /register
    if not isThereAdmin():
        return redirect(url_for('register'))

    # Si admin existe déjà, on empêche d'accéder à /register
    if isThereAdmin() and request.endpoint == "register": 
        return redirect(url_for('login'))
    
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)



@app.route('/')
@login_required
def index():
    routes = []    
    try:
        routes=get_commands()
    except Exception as e:
        app.logger.error(f"Erreur lecture commandes: {e}")
        # En cas d'erreur critique, on garde routes = [] pour ne pas crasher

    nb_etats={False:0,True:0}
    for route in routes:
            nb_etats[route["active"]]+=1
            
    return render_template('index.html', routes=routes, api_prefix=getApiPrefix(), total_routes=len(routes), active_routes=nb_etats[True], inactive_routes=nb_etats[False])


@app.route('/register', methods=["GET", "POST"])
def register():
    if not isThere2FASecret(): #Si pas de clef 2FA
        # Génération de la clé secrète 2FA
        secret_2fa = pyotp.random_base32()
        set2FASecret(".env", secret_2fa)
        create_qr_code(secret_2fa)
    if request.method == "POST":
        if request.form.get("action")=="createAdminAccount":
            # Traitement du formulaire d'inscription
            admin_password = request.form.get("password1")
            admin_password_confirm = request.form.get("password2")
            if admin_password != admin_password_confirm: #Si les mots de passe ne correspondent pas
                return render_template('register.html', erreur="Les mots de passe ne correspondent pas. Veuillez réessayer.")
            
            else :        
                setAdminPassword(".env",admin_password)
                if request.form.get("enable_2fa") :
                    activate_2fa(".env", True)
                else :
                    activate_2fa(".env", False)
                api_prefix = request.form.get("prefix")
                if api_prefix:
                    if not re.match(pattern_prefix_api, api_prefix):
                        return render_template('register.html', erreur="Le préfixe API contient des caractères invalides. Seules les lettres (min, maj) et les chiffres sont autorisés.")
                    setApiPrefix(".env", api_prefix)
                else :
                    setApiPrefix(".env", "/bashapi")
                initMode(".env", "WHITELIST") #Initialisation du mode en WHITELIST par défaut
                return redirect(url_for('login'))  # Rediriger vers la page de connexion après
            
    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # Limite uniquement les tentatives de connexion (POST)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    A2F_enabled = is2FAEnabled()
    if request.method == "POST":
        if request.form.get("action")=="loginUser":
            # Traitement du formulaire d'inscription
            password = request.form.get("password")
            if checkAdminPassword(password):
                if A2F_enabled:
                    code_2fa = request.form.get("2fa_code")
                    if not verify_code(code_2fa):
                        return render_template('login.html', erreur="Code 2FA incorrect.", A2F_enabled=A2F_enabled)
                login_user(User("admin"))
                return redirect(url_for('index'))  # Rediriger vers la page d'accueil après la connexion
            else:
                return render_template('login.html', erreur="Mot de passe administrateur incorrect.", A2F_enabled=A2F_enabled)
            
    return render_template('login.html', A2F_enabled=A2F_enabled)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Nettoie complètement la session
    response = redirect(url_for('login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/settings', methods=["GET", "POST"])
@login_required
def settings():
    context = {}
    context["api_prefix"] = getApiPrefix()[:-1]
    context["current_mode"] = getMode()
    
    context["whitelist"] = get_whitelist()
    context["blacklist"] = get_blacklist()
    context["a2f_enabled"] = is2FAEnabled()
    
    if request.method == "POST":
        # Ici, on ne met PAS de verrou, car les fonctions appelées le font déjà.
        action = request.form.get("action")
        
        if action == "changePassword":
            current_password = request.form.get("current_password")
            new_password1 = request.form.get("new_password1")
            new_password2 = request.form.get("new_password2")

            # Vérifier l'ancien mot de passe
            if not checkAdminPassword(current_password):
                context["erreur"] = "Ancien mot de passe incorrect."
                return render_template('settings.html', **context)

            # Vérifier la correspondance des nouveaux mots de passe
            if not new_password1 or not new_password2 or new_password1 != new_password2:
                context["erreur"] = "Les nouveaux mots de passe doivent correspondre."
                return render_template('settings.html', **context)

            # Mettre à jour le mot de passe admin
            setAdminPassword(".env", new_password1)
            context["success"] = "Mot de passe mis à jour avec succès."
            return render_template('settings.html', **context)

        if action == "importCommands":
            uploaded_file = request.files.get("commands_file")
            if uploaded_file is None or uploaded_file.filename == "":
                context["import_error"] = "Aucun fichier sélectionné."
                return render_template('settings.html', **context)

            if not uploaded_file.filename.lower().endswith(".json"):
                context["import_error"] = "Le fichier doit être au format JSON."
                return render_template('settings.html', **context)
 
            replace_existing = request.form.get("replace_existing") == "on"
            success, message = import_commands_from_json(uploaded_file, replace_existing)
            
            if not success:
                context["import_error"] = message
            else :
                context["import_success"] = message
            return render_template('settings.html', **context)
        
        if action == "changeApiPrefix":
            new_prefix = request.form.get("new_prefix")
            if not new_prefix:
                context["api_prefix_erreur"] = "Le préfixe API ne peut pas être vide."
                return render_template('settings.html', **context)
            
            if not re.match(pattern_prefix_api, new_prefix):
                context["api_prefix_erreur"] = "Le préfixe API contient des caractères invalides. Seules les lettres (min, maj) et les chiffres sont autorisés.)"
                return render_template('settings.html', **context)
            
            setApiPrefix(".env", new_prefix)
            context["api_prefix_success"] = "Préfixe API mis à jour avec succès."
            context["api_prefix"] = getApiPrefix()[:-1]
        
        if action == "changeMode":
            new_mode = request.form.get("mode")
            if setMode(".env", new_mode):
                context["mode_success"] = f"Mode changé en {new_mode} avec succès."
                context["current_mode"] = getMode()
            else:
                context["mode_erreur"] = "Mode invalide."
        
        if action == "addIp":
            list_type = request.form.get("list_type")  # "whitelist" ou "blacklist"
            ip_address = request.form.get("ip_address", "").strip()
            ip_description = request.form.get("ip_description", "").strip()
            
            if not ip_address:
                context[f"{list_type}_error"] = "L'adresse IP ne peut pas être vide."
            else:
                try:
                    # Valider l'IP
                    ipaddress.ip_address(ip_address)
                    add_access_rule(ip_address, ip_description, list_type)
                    context[f"{list_type}_success"] = "IP ajoutée avec succès"
                    context[list_type] = get_whitelist() if list_type == "whitelist" else get_blacklist()
                    
                except ValueError:
                    context[f"{list_type}_error"] = "L'adresse IP n'est pas valide."
        
        if action == "removeIp":
            list_type = request.form.get("list_type")
            ip_id = request.form.get("ip_id")
            try:
                ip_id = int(ip_id)
                remove_access_rule(ip_id)
                
                context[f"{list_type}_success"] = "IP supprimée avec succès"
                context[list_type] = get_whitelist() if list_type == "whitelist" else get_blacklist()
            except (ValueError, TypeError):
                context[f"{list_type}_error"] = "ID invalide."
        
        if action == "toggleIp":
            list_type = request.form.get("list_type")
            ip_id = request.form.get("ip_id")
            try:
                ip_id = int(ip_id)
                toggle_access_rule(ip_id)
                context[f"{list_type}_success"] = "État de l'IP modifié avec succès"
                context[list_type] = get_whitelist() if list_type == "whitelist" else get_blacklist()
            except (ValueError, TypeError):
                context[f"{list_type}_error"] = "ID invalide."
                
        if action == "importLists":
            uploaded_file = request.files.get("list_file")
            if uploaded_file is None or uploaded_file.filename == "":
                context["import_lists_error"] = "Aucun fichier sélectionné."
                return render_template('settings.html', **context)

            if not uploaded_file.filename.lower().endswith(".json"):
                context["import_lists_error"] = "Le fichier doit être au format JSON."
                return render_template('settings.html', **context)
            
            replace_existing = request.form.get("replace_existing") == "on"
            success, message = import_access_rules_from_json(uploaded_file, replace_existing)
            
            if not success:
                context["import_lists_error"] = message
            else :
                context["import_lists_success"] = message
                
            context["whitelist"] = get_whitelist()
            context["blacklist"] = get_blacklist()
            return render_template('settings.html', **context)
        
        if action == "manage2FA":
            sub_action = request.form.get("sub_action")
            current_password = request.form.get("current_password_2fa")

            # Pour désactiver ou régénérer, on vérifie le mot de passe par sécurité
            if sub_action in ["disable", "regenerate"]:
                if not current_password or not checkAdminPassword(current_password):
                    context["a2f_error"] = "Mot de passe incorrect. Impossible de modifier l'A2F."
                    return render_template('settings.html', **context)

            if sub_action == "enable":
                # Générer un secret s'il n'existe pas ou utiliser l'existant
                if not isThere2FASecret():
                    secret = pyotp.random_base32()
                    set2FASecret(".env", secret)
                else:
                    secret = get2FASecret() # On récupère via la fonction existante dans config.py
                
                create_qr_code(secret)
                activate_2fa(".env", True)
                context["a2f_success"] = "A2F Activée. Scannez le QR Code ci-dessous."
                context["show_qrcode"] = True
                
            elif sub_action == "disable":
                activate_2fa(".env", False)
                context["a2f_success"] = "Authentification à deux facteurs désactivée."
                
            elif sub_action == "regenerate":
                # On écrase l'ancien secret
                secret = pyotp.random_base32()
                set2FASecret(".env", secret)
                create_qr_code(secret)
                # On s'assure qu'elle est bien activée
                activate_2fa(".env", True)
                context["a2f_success"] = "Nouveau secret généré. Veuillez scanner le nouveau QR Code."
                context["show_qrcode"] = True

            # Mise à jour de l'état pour l'affichage
            context["a2f_enabled"] = is2FAEnabled()
            # Ajout d'un timestamp pour forcer le navigateur à recharger l'image du QR Code
            context["qr_timestamp"] = int(time.time())
    return render_template('settings.html', **context)


@app.route('/settings/export', methods=["GET"])
@login_required
def export_commands():
    json_str=export_commands_to_json()

    # On doit encoder la string en bytes (utf-8)
    mem_file = io.BytesIO()
    mem_file.write(json_str.encode('utf-8'))
    mem_file.seek(0)  # IMPORTANT : On remet le curseur au début du fichier

    # 4. Envoi au navigateur pour téléchargement
    return send_file(
        mem_file,
        as_attachment=True,          # Force le téléchargement
        download_name='export_commandes.json', # Nom du fichier reçu par l'utilisateur
        mimetype='application/json'  # Type MIME correct
    )

@app.route('/settings/export-lists', methods=["GET"])
@login_required
def export_lists():
    json_str=export_access_rules_to_json()

    mem_file = io.BytesIO()
    mem_file.write(json_str.encode('utf-8'))
    mem_file.seek(0)  # IMPORTANT : On remet le curseur au début du fichier

    # 4. Envoi au navigateur pour téléchargement
    return send_file(
        mem_file,
        mimetype='application/json',
        as_attachment=True,
        download_name="export_lists.json"
    )

@app.route('/settings/export-logs', methods=["GET"])
@login_required
def export_logs():
    logs_path = os.path.join(app.root_path, "api-activity.log")
    if not os.path.exists(logs_path):
        return "Aucun fichier de logs à exporter", 404
    # On regarde si il y a un autre fichier de logs (backup)
    if os.path.exists(logs_path + ".1"):
        # On crée un fichier zip contenant les deux fichiers de logs
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
            zip_file.write(logs_path, arcname="api-activity.log")
            zip_file.write(logs_path + ".1", arcname="api-activity.log.1")
        zip_buffer.seek(0)
        return send_file(zip_buffer, as_attachment=True, download_name="api-activity-logs.zip", mimetype='application/zip')
    return send_file(logs_path, as_attachment=True, download_name="api-activity.log")

@app.route('/toggle_route', methods=["POST"])
@login_required
def toggle_route():
    route_id = request.form.get("route_id")
    if route_id is None:
        return redirect(url_for('index'))

    try:
        route_id = int(route_id)
    except ValueError:
        return redirect(url_for('index'))

    toggle_command_active(route_id)
    return redirect(url_for('index'))


@app.route('/route/edit/<int:route_id>', methods=["GET", "POST"])
@login_required
def edit_route(route_id):
    api_prefix = getApiPrefix()
    
    route = get_command(route_id)
    if not route:
        return redirect(url_for('index'))
    
    context = {"route": route, "api_prefix": api_prefix, "new_token": secrets.token_urlsafe(32)}
    
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save":
            
            clean_path = request.form.get("path").strip('/').replace(" ", "") #On enlève les slashs de début et fin et les espaces
            
            clean_path = re.sub(r'/+', '/', clean_path) #Remplacement des blocs de slash (// ou /// par exemple) par un seul slash
            if not re.match(pattern_path_route, clean_path):
                context["error"] = "Le chemin de la route contient des caractères invalides. Seules les lettres (min, maj), chiffres, tirets (-), underscores (_) et slashs (/) sont autorisés."
                return render_template('edit_route.html', **context)
            
            route=get_command(route_id) # On relit la route pour s'assurer d'avoir la version la plus récente
                            
            route["path"] = clean_path
            route["method"] = request.form.get("method")
            route["description"] = request.form.get("description")
            route["command"] = request.form.get("command")         
            route["tags"] = [tag.strip() for tag in request.form.get("tags", "").split(",") if tag.strip()]
            route["return_output"] = request.form.get("return_output") == "on"

            edit_command(route)
            
            context["route"] = route  # Mise à jour de l'objet route dans le contexte
            context["success"] = "Route sauvegardée avec succès."
            return render_template('edit_route.html', **context)
        
        elif action == "test":
            try:
                
                stocked_command = route['command'] # Récupérer la commande stockée
                lines=stocked_command.splitlines() #séparation en lignes
                shell_command = "" #On prépare la commande shell
                for line in lines:
                    line_clean = line.split('#')[0].strip() #On enlève les commentaires et les espaces de début/fin
                    if line_clean != "": #Si la ligne n'est pas vide après nettoyage
                        if shell_command != "": #Si ce n'est pas la première commande
                            shell_command += " && " #On ajoute le séparateur entre les commandes
                        shell_command += line_clean # On ajoute la commande nettoyée
                result = subprocess.run(
                    shell_command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                output = ""
                if result.stdout:
                    output += result.stdout
                if result.stderr:
                    if output:
                        output += "\n"
                    output += result.stderr
                if not output.strip():
                    output = "Test effectué (aucune sortie)."
                context["test_output"] = output
                context["test_success"] = result.returncode == 0
            except subprocess.TimeoutExpired:
                context["test_output"] = "La commande a dépassé le délai d'exécution (10s)."
                context["test_success"] = False
            except Exception as e:
                context["test_output"] = f"Erreur: {str(e)}"
                context["test_success"] = False
            
            return render_template('edit_route.html', **context)
        
        elif action == "generate_token":
            token=request.form.get("token_value")
            hashed_token=generate_password_hash(token)
            set_command_hashed_token(route_id, hashed_token)

            # Mise à jour de l'objet local pour l'affichage (optionnel ici car on recharge la page souvent, mais propre)
            route["hashed_token"] = hashed_token
            return render_template('edit_route.html', **context)
    return render_template('edit_route.html', **context)
    
@app.route('/route/new', methods=["POST", "GET"])
@login_required
def create_route():
    if request.method == "POST":
        path=request.form.get("path").strip('/').replace(" ", "") #On enlève les slashs de début et fin et les espaces
        path = re.sub(r'/+', '/', path) #Remplacement des blocs de slash (// ou /// par exemple) par un seul slash
        
        new_route = {
            "method": request.form.get("method"),
            "path": path,
            "description": request.form.get("description"),
            "command": request.form.get("command"),
            "active": True,
            "hashed_token": generate_password_hash(request.form.get("token_value")),
            "tags": [tag.strip() for tag in request.form.get("tags", "").split(",") if tag.strip()],
            "return_output": request.form.get("return_output") == "on"
        }
        
        if not re.match(pattern_path_route, path):
            error = "Le chemin de la route contient des caractères invalides. Seules les lettres (min, maj), chiffres, tirets (-), underscores (_) et slashs (/) sont autorisés."
            return render_template('new_route.html', api_prefix=getApiPrefix(), new_token=request.form.get("token_value"), error=error, **request.form)
        
        new_id=add_command(new_route)
        return redirect(url_for('edit_route', route_id=new_id))

    else :
        token=secrets.token_urlsafe(32)    
        return render_template('new_route.html', api_prefix=getApiPrefix(), new_token=token)


@app.route('/route/delete/<int:route_id>', methods=["POST"])
@login_required
def delete_route(route_id):
    delete_command(route_id)        
    return redirect(url_for('index'))

@app.route('/docs')
def documentation():
    docs_path = os.path.join(app.root_path, "services/doc_utilisation.md")
    if not os.path.exists(docs_path):
        return "Documentation introuvable.", 404
    with open(docs_path, "r", encoding="utf-8") as f:
        md_content = f.read()
    html_content = markdown(md_content, extensions=['fenced_code', 'codehilite'])
    return render_template('docs.html', content=html_content)


@app.route('/update/check', methods=['GET'])
@login_required
def check_update():
    is_available = check_update_available()
    return jsonify({"update_available": is_available})

@app.route('/update/apply', methods=['POST'])
@login_required
def apply_update():
    # On lance la mise à jour
    # Note : Cette fonction va tuer le processus, donc le retour JSON peut ne jamais arriver au client
    # C'est pourquoi on gère ça côté JS.
    perform_update()
    return jsonify({"status": "updating"}), 200

@app.route('/logs')
@login_required
def view_logs():
    log_path = os.path.join(os.path.dirname(__file__), "api-activity.log")
    logs = []
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
                
            # On traite les lignes dans l'ordre chronologique (ancien -> récent)
            processed_logs = []
            for line in lines:
                if not line.strip(): continue # On saute les lignes vides
                
                # 1. On sécurise les caractères spéciaux (<, >) pour éviter les bugs d'affichage
                safe_line = line.replace("<", "&lt;").replace(">", "&gt;")
                
                # 2. On ajoute nos couleurs (HTML)
                safe_line = safe_line.replace("[ECHEC]", '<span class="tag-echec">[ECHEC]</span>')
                safe_line = safe_line.replace("[SUCCES]", '<span class="tag-succes">[SUCCES]</span>')
                
                # On ajoute à la liste
                processed_logs.append(safe_line)
            
            # 3. On inverse la liste À LA FIN pour avoir les derniers logs en premier
            processed_logs.reverse()
            logs = processed_logs
    except Exception as e:
        logs = [f"Erreur lors de la lecture des logs : {str(e)}"]
        
    return render_template('logs.html', logs=logs)

@app.errorhandler(429)
def ratelimit_handler(e):
    # On renvoie le template 429.html avec le code d'erreur 429
    # e.description contient le message "5 per minute" par exemple
    return render_template('429.html', error=e), 429

try:
    PORT=int(os.getenv("PORT", 5000))
except:
    PORT=5000

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)