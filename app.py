from flask import Flask, request, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from services.config import *



load_dotenv()

app = Flask(__name__)


if not isThereASecretKey(): #Si pas de clef secrete (utilisée pour les sessions)
    # Générer une clé secrète aléatoire et la stocker dans le .env
    secret_key = os.urandom(24).hex()
    setSecretKey(secret_key)#Enregistrer la clef dans le .env
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
    routes=[
        {"method":"GET","path":"/api","description":"Page d'accueil","active":True,"command":"echo 'hello world'"},
        {"method":"POST","path":"/api","description":"Page d'accueil","active":True,"command":"echo 'hello world'"},
        {"method":"PUT","path":"/api","description":"Page d'accueil","active":True,"command":"echo 'hello world'"},
        {"method":"DELETE","path":"/api","description":"Test","active":False,"command":"echo 'AURORE'"}
    ]
    nb_etats={False:0,True:0}
    for route in routes:
        nb_etats[route["active"]]+=1
    return render_template('index.html', routes=routes, total_routes=len(routes), active_routes=nb_etats[True], inactive_routes=nb_etats[False])



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
    if request.method == "POST":
        if request.form.get("action") == "changePassword":
            current_password = request.form.get("current_password")
            new_password1 = request.form.get("new_password1")
            new_password2 = request.form.get("new_password2")

            # Vérifier l'ancien mot de passe
            if not checkAdminPassword(current_password):
                return render_template('settings.html', erreur="Ancien mot de passe incorrect.")

            # Vérifier la correspondance des nouveaux mots de passe
            if not new_password1 or not new_password2 or new_password1 != new_password2:
                return render_template('settings.html', erreur="Les nouveaux mots de passe doivent correspondre.")

            # Mettre à jour le mot de passe admin
            setAdminPassword(".env", new_password1)
            return render_template('settings.html', success="Mot de passe mis à jour avec succès.")

    return render_template('settings.html')

if __name__ == "__main__":
    app.run(debug=True)