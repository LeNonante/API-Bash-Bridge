# API-Bash Bridge

**Transformez vos requêtes HTTP en commandes Shell.**

API-Bash Bridge est une application légère basée sur **Flask** qui permet d'exécuter des commandes système (Bash, Shell, CMD) via une API REST.

C'est l'outil idéal pour piloter un serveur, lancer des scripts de maintenance, ou redémarrer des services à distance, notamment via un **Elgato Stream Deck** (avec un plugin HTTP) ou des automatisations domotiques (Home Assistant, n8n, etc.).

---

## ✨ Fonctionnalités

* **Routing Dynamique :** Ajoutez ou modifiez des routes via une interface web moderne sans redémarrer le serveur.
* **Gestion fine des liaisons :** Activez et désactivez des liaisons routes API / commandes en un seul clic.
* **Sécurisé :**
    * Protection des routes sensibles via **Bearer Token** (hashé, jamais stocké en clair).
    * Interface d'administration protégée par un mot de passe (défini à la première connexion).
* **Multi-OS :** Fonctionne sur **Linux** (idéal serveur) et **Windows** (dev/local).
* **Prefix API Configurable :** Changez le préfixe de base (ex: `/api/v1`) depuis l'interface.
* **Backup facile :** Exportez votre configuration en JSON et réimportez-la sur une autre instance en quelques secondes.

---

## 🐧 Installation & Démarrage (Linux / Systemd)
L'application étant conçue pour piloter le système hôte, une installation "Bare Metal" via Systemd est recommandée plutôt que Docker.

L'installation se fera dans `/opt/api-bash-bridge`.

### 1. Prérequis
Assurez-vous d'avoir `python3`, `pip` et `git` installés.

### 2. Installation
Remplacez `VOTRE_USER` par votre nom d'utilisateur Linux actuel.

```bash
# 1. Création du dossier et permissions
sudo mkdir /opt/api-bash-bridge
sudo chown -R VOTRE_USER:VOTRE_USER /opt/api-bash-bridge

# 2. Clonage du projet
cd /opt/api-bash-bridge
git clone [https://github.com/LeNonante/Bash-API-Bridge.git](https://github.com/LeNonante/Bash-API-Bridge.git) .

# 3. Installation des dépendances dans un environnement virtuel
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```
### 3. Configuration du port (Facultatif)
Par défaut l'application est accessible sur le port 5000. Cependant, il est possible de changer ce port.

Pour ce faire, créez un fichier `.env` à la racine du projet (`/opt/api-bash-bridge`) puis remplissez le comme ceci :
```bash
PORT=XXXX #Remplacez XXXX par le port souhaité
```

### 4. Activation du Service Systemd

Le fichier `api-bash-bridge.service` inclus dans le repo doit être lié à systemd. 
***Note : Assurez-vous d'avoir édité le fichier `.service` pour qu'il pointe vers le bon User et le bon chemin si différent de /opt.***

```bash
# 1. Création du lien symbolique
sudo ln -s /opt/api-bash-bridge/api-bash-bridge.service /etc/systemd/system/api-bash-bridge.service

# 2. Rechargement et démarrage
sudo systemctl daemon-reload
sudo systemctl enable api-bash-bridge
sudo systemctl start api-bash-bridge

# 3. Vérifier que tout va bien
sudo systemctl status api-bash-bridge
```
> L'interface est maintenant accessible sur http://IP_DE_VOTRE_SERVEUR:5000 (ou le port défini dans .env).
---

## 🛡️ Avertissement de Sécurité
⚠️ ATTENTION : Cette application donne un pouvoir de contrôle sur votre machine.
- Exposition : Ne l'exposez JAMAIS directement sur internet (Port Forwarding) sans protection.
- Accès distant : Utilisez un VPN (Tailscale, Wireguard), un Tunnel Cloudflare (avec protection Access/Zero Trust) ou un Reverse Proxy (Nginx/Traefik) avec authentification forte.
- Commandes : Soyez prudent avec les commandes que vous configurez (évitez les rm -rf non contrôlés).
---

## 👤 Auteur
Projet créé et maintenu par LeNonante - Aurélien Musset.

---

## 📄 Licence
Projet distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.