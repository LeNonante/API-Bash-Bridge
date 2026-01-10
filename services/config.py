import os
from dotenv import load_dotenv, set_key, dotenv_values
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import json
import pyotp
import qrcode
import sys
import time
from filelock import FileLock
from database.extensions import db
from database.models import Route, AccessRule, User
from sqlalchemy.exc import IntegrityError
import io
import base64
import secrets


# Variables globales pour le cache
LAST_CHECK_TIME = 0
UPDATE_CACHE_RESULT = False
CHECK_INTERVAL = 3600  # 1 heure en secondes

def isThereASecretKey() :
    return os.getenv("SECRET_KEY") is not None

def setSecretKey(env_file,key) :
    #Enregistrement de la clef secrete
    set_key(env_file, "SECRET_KEY", key)
    load_dotenv(override=True)

def getSecretKey() :
    return os.getenv("SECRET_KEY")

def isThereAdmin() :
    admin = User.query.filter_by(username="admin").first()
    return admin is not None

def setAdminPassword(password) :
    hashed_password=generate_password_hash(password)
    if isThereAdmin() :
        #Modification du mot de passe admin existant
        admin = User.query.filter_by(username="admin").first()
        admin.password_hash = hashed_password
        db.session.commit()
    else :
        #Création du compte admin
        admin = User(
            username="admin",
            password_hash=hashed_password
        )
        db.session.add(admin)
        db.session.commit()

def setUserPassword(username, password) :
    hashed_password=generate_password_hash(password)
    user = User.query.filter_by(username=username).first()
    if user:
        user.password_hash = hashed_password
        db.session.commit()
        return True
    return False

def checkUserPassword(username, password) :
    user = User.query.filter_by(username=username).first()
    if user:
        return check_password_hash(user.password_hash, password)
    return False

def getApiPrefix():
    prefix = os.getenv("API_PREFIX")
    return prefix

def setApiPrefix(env_file, prefix):
    if prefix[-1] != '/':
        prefix += '/'
    if not prefix.startswith('/'):
        prefix = '/' + prefix
    set_key(env_file, "API_PREFIX", prefix)
    load_dotenv(override=True)
    
def get_git_version():
    try:
        return subprocess.check_output(
            ["git", "describe", "--tags", "--dirty", "--always"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"
    
def check_update_available():
    """
    Vérifie les mises à jour avec un cache.
    Ne fait le vrai 'git fetch' que si le délai est dépassé.
    """
    global LAST_CHECK_TIME, UPDATE_CACHE_RESULT
    
    current_time = time.time()
    if current_time - LAST_CHECK_TIME < CHECK_INTERVAL:
        return UPDATE_CACHE_RESULT
    
    try:
        # On met à jour les infos du remote sans modifier les fichiers locaux
        subprocess.run(["git", "fetch"], cwd=os.getcwd(), timeout=10, check=True)
        
        # On récupère le hash local et le hash distant
        local = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=os.getcwd()).decode().strip()
        remote = subprocess.check_output(["git", "rev-parse", "@{u}"], cwd=os.getcwd()).decode().strip()
        
        # On met à jour le cache
        if local != remote:
            UPDATE_CACHE_RESULT = True
        else:
            UPDATE_CACHE_RESULT = False
            
        LAST_CHECK_TIME = current_time
        return UPDATE_CACHE_RESULT
    except Exception as e:
        print(f"Erreur vérification update: {e}")
        return False

def perform_update():
    """Télécharge la mise à jour, installe les dépendances et redémarre l'application."""
    try:
        # 1. Pull du code
        subprocess.run(["git", "pull"], cwd=os.getcwd(), check=True)
        
        # 2. Mise à jour des dépendances (pip)
        # On utilise sys.executable pour être sûr d'utiliser le pip du venv actuel
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=os.getcwd(), check=True)
        
        # 3. On quitte l'application. 
        # Grâce à Restart=always dans le fichier .service, Systemd la relancera tout seul.
        print("Mise à jour réussie, redémarrage...")
        subprocess.run(["sudo", "systemctl", "restart", "api-bash-bridge"], check=True)
        
    except Exception as e:
        print(f"Erreur lors de la mise à jour: {e}")
        return False

def toggleMode(env_file):
    current_mode = os.getenv("MODE", "WHITELIST")
    new_mode = "WHITELIST" if current_mode == "BLACKLIST" else "BLACKLIST"
    set_key(env_file, "MODE", new_mode)
    load_dotenv(override=True)
    return new_mode

def setMode(env_file, mode):
    """Définit le mode (WHITELIST ou BLACKLIST)"""
    if mode not in ["WHITELIST", "BLACKLIST"]:
        return False
    set_key(env_file, "MODE", mode)
    load_dotenv(override=True)
    return True

def initMode(env_file, mode):
    set_key(env_file, "MODE", mode)
    load_dotenv(override=True)

def getMode():
    return os.getenv("MODE", "WHITELIST")


def create_qr_code(secret_key):
    # On prépare les infos pour Google Authenticator
    totp_auth = pyotp.TOTP(secret_key)
    
    # Création de l'URI (le lien qui contient la clé, le nom de l'app, et l'user)
    uri = totp_auth.provisioning_uri( 
        issuer_name="API-Bash Bridge"
    )
    

    img = qrcode.make(uri)

    # 1. On crée un tampon mémoire (comme un fichier virtuel)
    buffer = io.BytesIO()
    
    # 2. On sauvegarde l'image dans ce tampon au format PNG
    img.save(buffer, format="PNG")
    
    # 3. On récupère les bytes, on encode en base64, et on decode en string utf-8
    img_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    
    return img_str

def get2FASecret(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user.two_fa_secret
    return None

def verify_code(username, code_entre):
    secret_key = get2FASecret(username)
    totp = pyotp.TOTP(secret_key)
    # verify() retourne True ou False. 
    # Il gère automatiquement la fenêtre de temps (actuel +/- 30 secondes)
    return totp.verify(code_entre)

def set2FASecret(username, secret_key):
    user = User.query.filter_by(username=username).first()
    if user:
        user.two_fa_secret = secret_key
        db.session.commit()
        return True
    return False

def isThere2FASecret(username) :
    secret_key = get2FASecret(username)
    return secret_key is not None

def activate_2fa(username, activate=True):
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_2fa_enabled = activate
        if activate and not user.two_fa_secret:
            # Génération d'une nouvelle clé secrète si on active 2FA et qu'il n'y en a pas
            secret_2fa = pyotp.random_base32()
            user.two_fa_secret = secret_2fa
        db.session.commit()
        return True
    return False
    
def is2FAEnabled(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user.is_2fa_enabled
    return False
    
    
#SQL ALCHEMY FUNCTIONS---------------------------

def get_commands():
    # .all() récupère tout
    routes = Route.query.all()
    result = []
    for r in routes:
        result.append({
            "command": r.command,
            "description": r.description,
            "hashed_token": r.hashed_token,
            "id": r.id,
            "active": r.is_active,
            "path": r.path,
            "tags": r.tags.split(',') if r.tags else [],
            "method": r.method,
            "return_output": r.return_output
        })
    return result

def is_command_active(command_id):
    route = Route.query.filter_by(id=command_id).first()
    if route:
        return route.is_active
    return False

def toggle_command_active(command_id):
    route = Route.query.filter_by(id=command_id).first()
    if route:
        route.is_active = not route.is_active
        db.session.commit()
        return True
    return False

def set_command_hashed_token(command_id, token):
    route = Route.query.filter_by(id=command_id).first()
    if route:
        route.hashed_token = token
        db.session.commit()
        return True
    return False

def get_command(command_id):
    route = Route.query.filter_by(id=command_id).first()
    if route:
        return {
            "command": route.command,
            "description": route.description,
            "hashed_token": route.hashed_token,
            "id": route.id,
            "active": route.is_active,
            "path": route.path,
            "tags": route.tags.split(',') if route.tags else [],
            "method": route.method,
            "return_output": route.return_output
        }
    return None

def edit_command(new_route):
    route = Route.query.filter_by(id=new_route["id"]).first()
    if route:
        route.path = new_route["path"]
        route.command = new_route["command"]
        route.description = new_route["description"]
        route.is_active = new_route["active"]
        route.hashed_token = new_route["hashed_token"]
        route.return_output = new_route["return_output"]
        route.tags = ','.join(new_route["tags"]) if isinstance(new_route["tags"], list) else new_route["tags"]
        try :
            db.session.commit()
            return True, "Route sauvegardée avec succès."
        except IntegrityError as e:
            db.session.rollback()
            return False, f"La route {new_route["path"]} existe déja."
    return False, "La route demandée , n'a pas été trouvée."

def add_command(new_route):
    try:
        route = Route(
        path=new_route["path"],
        method=new_route["method"],
        command=new_route["command"],
        description=new_route["description"],
        is_active=new_route["active"],
        hashed_token=new_route["hashed_token"],
        return_output=new_route["return_output"],
        tags=','.join(new_route["tags"]) if isinstance(new_route["tags"], list) else new_route["tags"]
        )
        db.session.add(route)
        db.session.commit()
        return True, route.id
    
    except IntegrityError as e:
        db.session.rollback()
        return False, f"Impossible d'ajouter cette route, le chemin '{new_route["path"]} est déja utilisé'."


def delete_command(command_id):
    route = Route.query.filter_by(id=command_id).first()
    if route:
        db.session.delete(route)
        db.session.commit()
        return True
    return False

def get_whitelist():
    rules = AccessRule.query.filter_by(rule_type="whitelist").all()
    result = []
    for r in rules:
        result.append({
            "id": r.id,
            "ip": r.ip_address,
            "description": r.description,
            "active": r.is_active
        })
    return result

def get_blacklist():
    rules = AccessRule.query.filter_by(rule_type="blacklist").all()
    result = []
    for r in rules:
        result.append({
            "id": r.id,
            "ip": r.ip_address,
            "description": r.description,
            "active": r.is_active
        })
    return result

def add_access_rule(ip_address, description, rule_type):
    try :
        rule = AccessRule(
            ip_address=ip_address,
            description=description,
            rule_type=rule_type,
            is_active=True
        )
        db.session.add(rule)
        db.session.commit()
        return True, rule.id
    except IntegrityError as e:
        db.session.rollback()
        return False, "Impossible d'ajouter cette IP, elle existe déja dans ce mode."

def remove_access_rule(rule_id):
    rule = AccessRule.query.filter_by(id=rule_id).first()
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    return False

def toggle_access_rule(rule_id):
    rule = AccessRule.query.filter_by(id=rule_id).first()
    if rule:
        rule.is_active = not rule.is_active
        db.session.commit()
        return True
    return False

def export_commands_to_json():
    routes = Route.query.all()
    result = []
    for r in routes:
        result.append({
            "command": r.command,
            "description": r.description,
            "hashed_token": r.hashed_token,
            "id": r.id,
            "active": r.is_active,
            "path": r.path,
            "tags": r.tags.split(',') if r.tags else [],
            "method": r.method,
            "return_output": r.return_output
        })
    return json.dumps(result, indent=4, ensure_ascii=False)

def export_access_rules_to_json():
    rules = AccessRule.query.all()
    result = []
    for r in rules:
        result.append({
            "id": r.id,
            "ip": r.ip_address,
            "description": r.description,
            "active": r.is_active,
            "type": r.rule_type
        })
    return json.dumps(result, indent=4, ensure_ascii=False)

def import_commands_from_json(file_storage, replace_existing=True):
    """
    Vérifie et sauvegarde le fichier de commandes dans la base de données.
    Retourne (Succès: bool, Message: str)
    """
    try:
        # On charge le JSON en mémoire pour vérifier sa validité
        data = json.load(file_storage)
        # Vérification 1: Est-ce une liste ?
        if not isinstance(data, list):
            return False, "Le fichier doit contenir une liste d'objets JSON (tableau [])."
        
        # Vérification 2: Les clés obligatoires sont-elles présentes ?
        required_keys = {"id", "method", "path", "command", "active", "hashed_token", "tags", "return_output"}
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                return False, f"L'élément à l'index {index} n'est pas un objet JSON valide."
            
            # On vérifie si toutes les clés requises sont présentes dans les clés de l'item
            if not required_keys.issubset(item.keys()):
                missing = required_keys - item.keys()
                return False, f"Format invalide à l'index {index}. Clés manquantes: {missing}"
            
        # Si tout est bon, on import le fichier dans la base de données
        if replace_existing:
            db.session.query(Route).delete()
        count = 0
        for info in data:
            route = Route(
                path=info.get('path', ''),
                command=info.get('command', ''),
                description=info.get('description', ''),
                is_active=info.get('active', True),
                hashed_token=info.get('hashed_token', ''),
                return_output=info.get('return_output', False),
                tags=','.join(info.get('tags', [])),
                method=info.get('method', 'GET'),
            )
            db.session.add(route)
            count += 1
        db.session.commit()
        return True, f"Configuration importée et validée avec succès. {count} routes ajoutées."
    except json.JSONDecodeError:
        return False, "Le fichier fourni n'est pas un JSON valide."
    except IntegrityError as e:
        db.session.rollback()
        return False, "Une route importée possède une URL qui existe déjà."
    except Exception as e:
        return False, f"Erreur lors de l'import ({type(e).__name__}): {str(e)}"
    
def import_access_rules_from_json(file_storage, replace_existing=True):
    """
    Vérifie et sauvegarde le fichier de lists dans la base de données.
    Retourne (Succès: bool, Message: str)
    """
    try:
        # On charge le JSON en mémoire pour vérifier sa validité
        data = json.load(file_storage)
        # Vérification 1: Est-ce une liste ?
        if not isinstance(data, list):
            return False, "Le fichier doit contenir une liste d'objets JSON (tableau [])."
        
        # Vérification 2: Les clés obligatoires sont-elles présentes ?
        required_keys = {"id", "ip", "description", "active", "type"}
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                return False, f"L'élément à l'index {index} n'est pas un objet JSON valide."
            
            # On vérifie si toutes les clés requises sont présentes dans les clés de l'item
            if not required_keys.issubset(item.keys()):
                missing = required_keys - item.keys()
                return False, f"Format invalide à l'index {index}. Clés manquantes: {missing}"
            
        # Si tout est bon, on import le fichier dans la base de données
        if replace_existing:
            db.session.query(AccessRule).delete()
        count = 0
        for info in data:
            access_rule = AccessRule(
                ip_address=info.get('ip', ''),
                description=info.get('description', ''),
                is_active=info.get('active', True),
                rule_type=info.get('type', ''),
            )
            db.session.add(access_rule)
            count += 1
        db.session.commit()
        return True, f"Configuration importée et validée avec succès. {count} règles ajoutées."
    except json.JSONDecodeError:
        return False, "Le fichier fourni n'est pas un JSON valide."
    except IntegrityError as e:
        db.session.rollback()
        return False, "Le fichier contient une ou plusieurs adresses IP déjà présentes dans leur liste respective (blanche ou noire)."
    except Exception as e:
        return False, f"Erreur lors de l'import : {str(e)}"
    