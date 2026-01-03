import json
import os
from app import app
# --- MODIFICATION DES IMPORTS ---
from database.extensions import db
from database.models import Route
# --------------------------------

def migrer_donnees():
    json_path = 'commandes.json'
    
    if not os.path.exists(json_path):
        print("Fichier json non trouvé.")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    with app.app_context():
        # Attention : ceci vide la table existante
        db.session.query(Route).delete()
        
        count = 0
        for info in data:
            route = Route(
                path=info.get('path', ''),
                command=info.get('command', ''),
                description=info.get('description', ''),
                is_active=True,
                hashed_token=info.get('hashed_token', ''),
                return_output=info.get('return_output', False),
                tags=','.join(info.get('tags', [])),
                method=info.get('method', 'GET'),
            )
            db.session.add(route)
            count += 1
        
        db.session.commit()
        print(f"{count} routes migrées dans la base de données SQLite.")

if __name__ == '__main__':
    migrer_donnees()