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
    return os.getenv("ADMIN_PASSWORD") is not None

def setAdminPassword(env_file,password) :
    hashed_password=generate_password_hash(password)
    set_key(env_file, "ADMIN_PASSWORD", hashed_password)
    load_dotenv(override=True)

def checkAdminPassword(password) :
    registered_password = os.getenv("ADMIN_PASSWORD")
    return check_password_hash(registered_password, password)

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

def load_ip_list(filename):
    """Charge la liste des IPs depuis un fichier JSON"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"Erreur lecture {filename}: {e}")
        return []

def save_ip_list(filename, ip_list):
    """Sauvegarde la liste des IPs dans un fichier JSON"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(ip_list, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erreur sauvegarde {filename}: {e}")
        return False

def add_ip_to_list(filename, ip, description=""):
    """Ajoute une IP à la liste"""
    lock_path = filename + ".lock"  # Créera whitelist.json.lock
    with FileLock(lock_path, timeout=10):
        ip_list = load_ip_list(filename)
        
        # Vérifier que l'IP n'existe pas déjà
        if any(item['ip'] == ip for item in ip_list):
            return False, "Cette IP existe déjà"
        
        # Créer le nouvel ID
        new_id = max((item.get('id', 0) for item in ip_list), default=0) + 1
        
        new_item = {
            "ip": ip,
            "description": description,
            "active": True,
            "id": new_id
        }
        
        ip_list.append(new_item)
        if save_ip_list(filename, ip_list):
            return True, "IP ajoutée avec succès"
        return False, "Erreur lors de l'ajout"

def remove_ip_from_list(filename, ip_id):
    """Supprime une IP de la liste"""
    lock_path = filename + ".lock"  # Créera whitelist.json.lock
    with FileLock(lock_path, timeout=10):
        ip_list = load_ip_list(filename)
        ip_list = [item for item in ip_list if item['id'] != ip_id]
        
        if save_ip_list(filename, ip_list):
            return True, "IP supprimée avec succès"
        return False, "Erreur lors de la suppression"

def toggle_ip_in_list(filename, ip_id):
    """Active/désactive une IP dans la liste"""
    lock_path = filename + ".lock"  # Créera whitelist.json.lock
    with FileLock(lock_path, timeout=10):
        ip_list = load_ip_list(filename)
        
        for item in ip_list:
            if item['id'] == ip_id:
                item['active'] = not item['active']
                if save_ip_list(filename, ip_list):
                    return True, item['active']
                return False, None
        
        return False, None

def update_ip_in_list(filename, ip_id, description=""):
    """Met à jour la description d'une IP"""
    lock_path = filename + ".lock"  # Créera whitelist.json.lock
    with FileLock(lock_path, timeout=10):
        ip_list = load_ip_list(filename)
        
        for item in ip_list:
            if item['id'] == ip_id:
                item['description'] = description
                if save_ip_list(filename, ip_list):
                    return True, "IP mise à jour avec succès"
                return False, "Erreur lors de la mise à jour"
        
        return False, "IP non trouvée"

def create_qr_code(secret_key):
    # On prépare les infos pour Google Authenticator
    totp_auth = pyotp.TOTP(secret_key)
    
    # Création de l'URI (le lien qui contient la clé, le nom de l'app, et l'user)
    uri = totp_auth.provisioning_uri( 
        issuer_name="API-Bash Bridge"
    )
    

    img = qrcode.make(uri)
    nom_fichier = "static/img/qrcode_2fa.png"
    img.save(nom_fichier)
    return nom_fichier

def get2FASecret():
    return os.getenv("2FA_SECRET")

def verify_code(code_entre):
    secret_key = get2FASecret()
    totp = pyotp.TOTP(secret_key)
    # verify() retourne True ou False. 
    # Il gère automatiquement la fenêtre de temps (actuel +/- 30 secondes)
    return totp.verify(code_entre)

def set2FASecret(env_file, secret_key):
    set_key(env_file, "2FA_SECRET", secret_key)
    load_dotenv(override=True)
    
def isThere2FASecret() :
    return os.getenv("2FA_SECRET") is not None

def activate_2fa(env_file, activate=True):
    value = "TRUE" if activate else "FALSE"
    set_key(env_file, "ENABLE_2FA", value)
    load_dotenv(override=True)
    
def is2FAEnabled():
    return os.getenv("ENABLE_2FA", "FALSE") == "TRUE"

def verify_and_save_commands_file(file_storage, save_path):
    """
    Vérifie et sauvegarde le fichier de commandes.
    Retourne (Succès: bool, Message: str)
    """
    lock_path = save_path + ".lock" # <--- AJOUT
    try:
        # On charge le JSON en mémoire pour vérifier sa validité
        data = json.load(file_storage)
        
        # Vérification 1: Est-ce une liste ?
        if not isinstance(data, list):
            return False, "Le fichier doit contenir une liste d'objets JSON (tableau [])."
        
        # Vérification 2: Les clés obligatoires sont-elles présentes ?
        required_keys = {"id", "method", "path", "command", "active", "hashed_token", "tags"}
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                return False, f"L'élément à l'index {index} n'est pas un objet JSON valide."
            
            # On vérifie si toutes les clés requises sont présentes dans les clés de l'item
            if not required_keys.issubset(item.keys()):
                missing = required_keys - item.keys()
                return False, f"Format invalide à l'index {index}. Clés manquantes: {missing}"

        # Si tout est bon, on sauvegarde proprement le fichier en le vérouillant pendant l'écriture
        # (Cela permet aussi de reformater le JSON correctement avec l'indentation)
        with FileLock(lock_path, timeout=10):
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
        return True, "Configuration importée et validée avec succès."
        
    except json.JSONDecodeError:
        return False, "Le fichier fourni n'est pas un JSON valide."
    except Exception as e:
        return False, f"Erreur lors de l'import : {str(e)}"
    
def verify_and_save_list_file(file_storage, save_path):
    """
    Vérifie et sauvegarde un fichier de liste (black/whitelist).
    Retourne (Succès: bool, Message: str)
    """
    lock_path = save_path + ".lock"
    try:
        # On charge le JSON en mémoire pour vérifier sa validité
        data = json.load(file_storage)
        
        # Vérification 1: Est-ce une liste ?
        if not isinstance(data, list):
            return False, "Le fichier doit contenir une liste d'objets JSON (tableau [])."
        
        # Vérification 2: Les clés obligatoires sont-elles présentes ?
        required_keys = {"id", "description", "ip", "active"}
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                return False, f"L'élément à l'index {index} n'est pas un objet JSON valide."
            
            # On vérifie si toutes les clés requises sont présentes dans les clés de l'item
            if not required_keys.issubset(item.keys()):
                missing = required_keys - item.keys()
                return False, f"Format invalide à l'index {index}. Clés manquantes: {missing}"

        # Si tout est bon, on sauvegarde proprement le fichier en le vérouillant pendant l'écriture
        # (Cela permet aussi de reformater le JSON correctement avec l'indentation)
        with FileLock(lock_path, timeout=10):
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            
        return True, "Configuration importée et validée avec succès."
        
    except json.JSONDecodeError:
        return False, "Le fichier fourni n'est pas un JSON valide."
    except Exception as e:
        return False, f"Erreur lors de l'import : {str(e)}"