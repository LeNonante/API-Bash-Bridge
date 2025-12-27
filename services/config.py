import os
from dotenv import load_dotenv, set_key, dotenv_values
from werkzeug.security import generate_password_hash, check_password_hash

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