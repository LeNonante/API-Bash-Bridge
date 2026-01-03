from .extensions import db
from datetime import datetime

# Table pour les routes (remplace commandes.json)
class Route(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    method = db.Column(db.String(10), nullable=False)      # ex: GET, POST
    path = db.Column(db.String(50), unique=True, nullable=False)  # ex: test
    command = db.Column(db.String(500), nullable=False)           # ex: ls -la
    description = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    hashed_token = db.Column(db.String(200), nullable=False)  # Token haché pour cette route
    return_output = db.Column(db.Boolean, default=False)  # Si True, retourne la sortie de la commande dans la réponse API
    tags = db.Column(db.String(200))  # Tags séparés par des virgules
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

"""
# Table pour les utilisateurs pour plus tard
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
"""

# Table pour la whitelist/blacklist
class AccessRule(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip_address = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    rule_type = db.Column(db.String(10)) # 'whitelist' ou 'blacklist'
    is_active = db.Column(db.Boolean, default=True)