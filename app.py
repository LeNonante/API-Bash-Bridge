from flask import Flask, flash, jsonify, request, redirect, url_for, render_template, send_file, g
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

app = Flask(__name__)

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

if not os.path.exists(os.path.join(os.path.dirname(__file__), "commandes.json")): #Si le fichier commandes.json n'existe pas, on le crée avec un tableau vide
    with open(os.path.join(os.path.dirname(__file__), "commandes.json"), "w", encoding="utf-8") as f:
        json.dump([], f)



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
    
    # Empêcher boucle infinie : on laisse accéder à /register
    if request.endpoint=="static":
        return
    if request.endpoint=="register" and not (isThereAdmin()):
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
    routes=json.load(open(os.path.join(app.root_path, "commandes.json"),"r",encoding="utf-8"))
    nb_etats={False:0,True:0}
    for route in routes:
        nb_etats[route["active"]]+=1
    return render_template('index.html', routes=routes, api_prefix=getApiPrefix(), total_routes=len(routes), active_routes=nb_etats[True], inactive_routes=nb_etats[False])


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if request.form.get("action")=="createAdminAccount":
            # Traitement du formulaire d'inscription
            admin_password = request.form.get("password1")
            admin_password_confirm = request.form.get("password2")
            if admin_password != admin_password_confirm: #Si les mots de passe ne correspondent pas
                return render_template('register.html', erreur="Les mots de passe ne correspondent pas. Veuillez réessayer.")
            
            else :        
                setAdminPassword(".env",admin_password)
                api_prefix = request.form.get("prefix")
                if api_prefix:
                    if not re.match(pattern_prefix_api, api_prefix):
                        return render_template('register.html', erreur="Le préfixe API contient des caractères invalides. Seules les lettres (min, maj) et les chiffres sont autorisés.")
                    setApiPrefix(".env", api_prefix)
                else :
                    setApiPrefix(".env", "/bashapi")
                    return redirect(url_for('login'))  # Rediriger vers la page de connexion après
            
    return render_template('register.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        if request.form.get("action")=="loginUser":
            # Traitement du formulaire d'inscription
            password = request.form.get("password")
            if checkAdminPassword(password):
                #session.permanent = True  # Rendre la session permanente (12h définies plus haut)
                login_user(User("admin"))
                return redirect(url_for('index'))  # Rediriger vers la page d'accueil après la connexion
            else:
                return render_template('login.html', erreur="Mot de passe administrateur incorrect.")
            
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/settings', methods=["GET", "POST"])
@login_required
def settings():
    context = {}
    context["api_prefix"] = getApiPrefix()[:-1]
    if request.method == "POST":
        if request.form.get("action") == "changePassword":
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

        if request.form.get("action") == "importCommands":
            uploaded_file = request.files.get("commands_file")
            if uploaded_file is None or uploaded_file.filename == "":
                context["import_error"] = "Aucun fichier sélectionné."
                return render_template('settings.html', **context)

            if not uploaded_file.filename.lower().endswith(".json"):
                context["import_error"] = "Le fichier doit être au format JSON."
                return render_template('settings.html', **context)

            save_path = os.path.join(app.root_path, "commandes.json")
            uploaded_file.save(save_path)
            context["import_success"] = "Fichier importé et sauvegardé."
            return render_template('settings.html', **context)
        
        if request.form.get("action") == "changeApiPrefix":
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
    return render_template('settings.html', **context)


@app.route('/settings/export', methods=["GET"])
@login_required
def export_commands():
    commands_path = os.path.join(app.root_path, "commandes.json")
    if not os.path.exists(commands_path):
        return "Aucun fichier commandes.json à exporter", 404
    return send_file(commands_path, as_attachment=True, download_name="commandes.json")

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

    routes = json.load(open(os.path.join(app.root_path, "commandes.json"), "r", encoding="utf-8"))
    for route in routes:
        if route["id"] == route_id:
            route["active"] = not route["active"]
            break

    with open(os.path.join(app.root_path, "commandes.json"), "w", encoding="utf-8") as f:
        json.dump(routes, f, indent=4, ensure_ascii=False)

    return redirect(url_for('index'))


@app.route('/route/edit/<int:route_id>', methods=["GET", "POST"])
@login_required
def edit_route(route_id):
    commands_path = os.path.join(app.root_path, "commandes.json")
    api_prefix = getApiPrefix()
    routes = json.load(open(commands_path, "r", encoding="utf-8"))
    
    route = next((r for r in routes if r["id"] == route_id), None)
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
            route["path"] = clean_path
            route["method"] = request.form.get("method")
            route["description"] = request.form.get("description")
            route["command"] = request.form.get("command")
            with open(commands_path, "w", encoding="utf-8") as f:
                json.dump(routes, f, indent=4, ensure_ascii=False)
            
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
            route["hashed_token"] = hashed_token
            with open(commands_path, "w", encoding="utf-8") as f:
                json.dump(routes, f, indent=4, ensure_ascii=False)
    return render_template('edit_route.html', **context)

@app.route('/route/new', methods=["POST", "GET"])
@login_required
def create_route():
    if request.method == "POST":
        commands_path = os.path.join(app.root_path, "commandes.json")
        routes = json.load(open(commands_path, "r", encoding="utf-8"))
        path=request.form.get("path").strip('/').replace(" ", "") #On enlève les slashs de début et fin et les espaces
        path = re.sub(r'/+', '/', path) #Remplacement des blocs de slash (// ou /// par exemple) par un seul slash
        
        new_route = {
            "method": request.form.get("method"),
            "path": path,
            "description": request.form.get("description"),
            "command": request.form.get("command"),
            "active": True,
            "hashed_token": generate_password_hash(request.form.get("token_value"))
        }
        
        if not re.match(pattern_path_route, path):
            error = "Le chemin de la route contient des caractères invalides. Seules les lettres (min, maj), chiffres, tirets (-), underscores (_) et slashs (/) sont autorisés."
            return render_template('new_route.html', api_prefix=getApiPrefix(), new_token=request.form.get("token_value"), error=error, **request.form)
        new_id = max((route["id"] for route in routes), default=0) + 1
        new_route["id"] = new_id
        routes.append(new_route)
        
        with open(commands_path, "w", encoding="utf-8") as f:
            json.dump(routes, f, indent=4, ensure_ascii=False)
        
        return redirect(url_for('edit_route', route_id=new_id))
    else :
        token=secrets.token_urlsafe(32)    
        return render_template('new_route.html', api_prefix=getApiPrefix(), new_token=token)


@app.route('/route/delete/<int:route_id>', methods=["POST"])
@login_required
def delete_route(route_id):
    commands_path = os.path.join(app.root_path, "commandes.json")
    routes = json.load(open(commands_path, "r", encoding="utf-8"))
    
    routes = [r for r in routes if r["id"] != route_id]
    
    with open(commands_path, "w", encoding="utf-8") as f:
        json.dump(routes, f, indent=4, ensure_ascii=False)
    
    return redirect(url_for('index'))

try:
    PORT=int(os.getenv("PORT", 5000))
except:
    PORT=5000

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)