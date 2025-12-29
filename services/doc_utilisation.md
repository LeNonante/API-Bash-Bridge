# Guide d'Utilisation - API-Bash Bridge

Bienvenue dans la documentation d'API-Bash Bridge. Cette application vous permet de déclencher des commandes système (Bash, Shell) via de simples requêtes HTTP sécurisées.
## 🚀 Première Connexion et Configuration

L'application se lance par défaut sur le port 5000. Pour changer ce port, veuillez ajouter la variable `PORT=XXXX` avec XXXX le port souhaité dans le fichier `.env` à la racine du projet. Si le fichier n'exxiste pas (application encore jamais éxécutée), vous pouvez le créer. 

Lors du tout premier lancement de l'application, vous serez automatiquement redirigé vers la page de création du compte administrateur.

![Image page d'enregistrement](/static/docs/register.png)

- **Préfixe API :** Définissez le préfixe de base pour toutes vos routes (par défaut : bashapi).

    Exemple : Si vous mettez v1, vos URLs ressembleront à http://serveur:5000/v1/ma-route.

- **Mot de passe Administrateur :** Choisissez un mot de passe fort. Il servira uniquement à accéder à l'interface web.

Cliquez sur Créer le compte.

Lors de sa création l'application est crée en mode "Whitelist". Plus de détails dans la section "Paramètres et Sécurité -> Filtrage IP" 

*Note : Une fois le compte créé, vous serez redirigé vers la page de connexion.*

## 🖥️ Le Tableau de Bord (Dashboard)

Une fois connecté, vous arrivez sur le tableau de bord principal. C'est ici que vous gérez vos endpoints.

![Image page principale](/static/docs/dashboard.png)

- **Statistiques :** Vue rapide sur le nombre de routes actives et inactives.

- **Barre de recherche :** Filtrez vos routes par nom, méthode ou commande.

- Liste des routes :

    - **Toggle (Interrupteur) :** Activez ou désactivez une route instantanément sans la supprimer.

    - **Bouton Copier :** Copie l'URL complète de l'endpoint dans votre presse-papier.

    - **Bouton Éditer :** Ouvre les détails de la route.

## 🛠️ Créer et Gérer des Routes
### Ajouter une nouvelle route

Cliquez sur le bouton Ajouter une route en haut à droite du dashboard.

![Image page de nouvelle route](/static/docs/new_path.png)

- **Méthode HTTP :** Choisissez le verbe HTTP qui déclenchera l'action (généralement POST ou GET).

- **Endpoint Path :** Le chemin de l'URL (ex: deploy/mon-site).

    - **Attention :** Ne mettez pas le préfixe API ici, il est ajouté automatiquement.

- **Script Bash :** Entrez les commandes à exécuter.

    - Vous pouvez écrire plusieurs lignes.

    - L'application enchaînera les commandes avec des && (l'exécution s'arrête si une commande échoue).

- **Description :** (Optionnel) Un mémo pour vous rappeler à quoi sert cette route.

- **Token :** Un token de sécurité est généré automatiquement (voir section Sécurité).

### Tester une route (Sandbox)

Dans la page d'édition d'une route, vous disposez d'un bouton Tester.

![Image sortie de test de commandes](/static/docs/test.png)

- Cela exécute réellement la commande sur le serveur.

- Le retour standard (stdout) et les erreurs (stderr) s'affichent directement dans l'interface web.

- Idéal pour débugger vos scripts sans ouvrir un terminal SSH.

### Zone de Danger

En bas de la page d'édition :

- **Générer un nouveau token :** Invalide l'ancien token immédiatement. N'oubliez pas de mettre à jour vos applications tierces (Stream Deck, n8n, etc.).

- **Supprimer la route :** Action irréversible.

## 🔌 Comment appeler l'API

Pour déclencher vos commandes depuis un outil externe, vous devez effectuer une requête HTTP avec les critères suivants :

- **URL :** Celle copiée depuis le dashboard.

- **Méthode :** Celle définie dans la route (GET, POST, etc.).

- **Authentification :** Obligatoire via un Bearer Token.

**Exemple avec cURL :**

Supposons une route /deploy avec le token mon_token.
```Bash
curl -X POST http://votre-serveur:5000/bashapi/deploy \
     -H "Authorization: Bearer mon_token"
```
### Où trouver le Token ?

Le token est récupérable uniquement dans la page Éditer la route ou lors de la création. Utilisez le bouton "Copier" situé dans la zone "Détails" ou "Zone de Danger".

- **Sécurité :** Les tokens sont stockés de manière hachée (chiffrée) dans la base de données. Il est impossible de retrouver un token enregistré. Ainsi, lorsque vous copiez un token depuis la page d'édition d'une route, un nouveau token est généré ce qui invalide les anciens tokens de cette route. (Cela n'est pas le cas sur la page de création d'une route. Vous pouvez copier le token autant de fois que vous le souhaitez).

### ⚙️ Paramètres et Sécurité

Accessible via le menu Paramètres.

![Image page de paramètres](/static/docs/settings.png)
1. **Sauvegarde et Migration**

    - **Exporter commandes.json :** Télécharge un fichier JSON contenant toute votre configuration (routes, commandes, hash des tokens).

    - **Importer :** Permet de restaurer une configuration ou de la dupliquer sur un autre serveur.

2. **Logs et Audit**

L'application enregistre toutes les tentatives d'accès.

- **Exporter logs :** Télécharge le fichier api-activity.log. (Une archive ZIP peut remplacer le fichier de logs plusieurs fichiers de logs existent).

- **Les logs contiennent :** Date, IP source, Route appelée, Statut (Succès/Échec/Non autorisé) et un ID de requête unique pour le traçage.

3. **Filtrage IP (Whitelist / Blacklist)**

Vous pouvez restreindre l'accès à l'API (et non à l'interface admin) selon l'adresse IP de l'appelant.

![Gestion de la Whitelist et Blacklist](/static/docs/list.png)

- **Mode Whitelist (Recommandé) :**

    - Seules les IPs listées peuvent appeler l'API.

    - Toutes les autres sont bloquées (Erreur 503).

    - Idéal si vous connaissez l'IP fixe de votre serveur domotique ou de votre poste de travail.

- **Mode Blacklist :**

    - Tout le monde peut accéder à l'API (si le token est bon).

    - Seules les IPs listées sont bloquées.

*Note : Vous pouvez ajouter une description pour chaque IP (ex: "Serveur Home Assistant") et les activer/désactiver individuellement via un interrupteur.*

### ⚠️ Bonnes Pratiques

- **Utilisateur Système :** Les commandes Bash sont exécutées avec les permissions de l'utilisateur Linux qui a lancé le service api-bash-bridge. Évitez de lancer l'application en tant que root.

- **Timeout :** Les commandes ont un timeout forcé de 60 secondes. Pour des tâches longues, lancez un script en arrière-plan (ex: nohup mon_script.sh &).

- **Exposition :** N'exposez jamais cette application directement sur Internet sans HTTPS (via un Reverse Proxy comme Nginx ou Apache).