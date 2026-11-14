# Détail des contrôles : comment vérifier, comment corriger

Les numéros correspondent aux 43 contrôles de `SKILL.md`. Les commandes sont des points de
départ : adapte-les à la technologie du projet.

## A. Secrets et clés (1 à 5)

**Vérifier**
- Chercher dans le code : `grep -rnE "sk_live_|sk-ant-|sk-proj-|service_role|AKIA|BEGIN .*PRIVATE KEY|ghp_" --exclude-dir=node_modules --exclude-dir=.git .`
- Chercher dans ce qui part au navigateur : construire l'appli, puis lancer la même recherche
  dans `dist/`, `build/`, `.next/static/`, `out/`.
- Variables publiques suspectes : `grep -rnE "(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_)\w*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)" .`
- `.env` suivi par Git ? `git ls-files | grep -E "(^|/)\.env"` ne doit rien renvoyer (sauf `.env.example`).
- Historique : `gitleaks git .` ou `trufflehog git file://.` ; à défaut
  `git log --all --diff-filter=A --name-only --format= | grep -E "\.env|\.pem|\.key|\.sql"`.

**Corriger**
1. Révoquer et régénérer la clé chez le fournisseur (action humaine). C'est l'étape qui protège.
2. Déplacer le secret dans une variable d'environnement côté serveur ; tout appel qui a besoin
   du secret passe par une route serveur, jamais par le navigateur.
3. Ajouter `.env*` au `.gitignore` (en gardant `!.env.example`), puis `git rm --cached .env`.
4. Nettoyer l'historique seulement si nécessaire (`git filter-repo`), avec accord : cela réécrit
   l'historique et impose un push forcé.
5. Valider les variables au démarrage par un schéma (zod, envalid, pydantic-settings…).
6. Chez chaque fournisseur : clé restreinte (domaines, IP, permissions), plafond de dépense, alerte.

## B. Authentification et sessions (6 à 10)

**Vérifier**
- Où l'identité est-elle vérifiée ? Si la seule vérification est dans le navigateur (un `if (user)`
  dans un composant), elle ne protège rien.
- Hachage : chercher `md5`, `sha1`, `sha256(` appliqués à un mot de passe ; chercher un mot de
  passe comparé en clair.
- Cookies : inspecter les attributs dans la configuration de session.
- JWT : `algorithms` imposé à la vérification ? Expiration présente ? Secret long et aléatoire ?
- Réinitialisation : le jeton a-t-il une date d'expiration et un marqueur « utilisé » ?
- Énumération : le message diffère-t-il entre « e-mail inconnu » et « mot de passe faux » ?

**Corriger**
- Préférer un fournisseur ou une bibliothèque éprouvée (Supabase Auth, Firebase Auth, Auth.js,
  Clerk, Better Auth, Django auth, Laravel Breeze/Fortify, Devise…).
- Hachage : argon2id en priorité, sinon bcrypt (coût ≥ 12) ou scrypt.
- Cookies : `HttpOnly; Secure; SameSite=Lax` (ou `Strict`), durée limitée.
- Réinitialisation : jeton de 32 octets aléatoires, stocké haché, valable 15 à 60 minutes,
  supprimé après usage ; réponse identique que l'e-mail existe ou non.
- Double authentification obligatoire pour les comptes admin.

## C. Autorisations (11 à 14)

C'est la catégorie n°1 du classement OWASP, et celle que l'IA oublie le plus : le code généré
vérifie souvent « est-il connecté ? » mais pas « a-t-il le droit sur cet objet ? ».

**Vérifier**
- Lister **toutes** les routes API, server actions et fonctions serverless. Pour chacune :
  où est le contrôle d'identité ? où est le contrôle de propriété ?
- Chercher les requêtes filtrées seulement par l'identifiant reçu :
  `where id = params.id` sans `and user_id = session.user.id`.
- Routes admin : le rôle vient-il de la session serveur ou d'une donnée envoyée par le client
  (corps de requête, `localStorage`, métadonnées modifiables par l'utilisateur) ?
- Mises à jour : le code passe-t-il `req.body` entier à la base (`update(req.body)`) ?

**Corriger**
- Un point central d'accès aux données qui exige l'utilisateur courant, plutôt qu'un contrôle
  recopié dans chaque route.
- Toujours filtrer par propriétaire ou organisation : `where id = ? and owner_id = ?`.
- Renvoyer 404 plutôt que 403 pour ne pas révéler l'existence d'une ressource.
- Rôles dans une table ou des claims que seul le serveur peut écrire.
- Schéma d'entrée qui n'accepte que les champs modifiables.
- Doubler par les règles de la base (RLS) : si une route est oubliée, la base refuse quand même.

## D. Base de données et stockage (15 à 20)

**Vérifier**
- Postgres/Supabase : `select tablename, rowsecurity from pg_tables where schemaname = 'public';`
  — toute ligne à `false` est une table ouverte. Lire aussi les politiques : `using (true)`
  revient à tout autoriser.
- Firebase : lire `firestore.rules`, `database.rules.json`, `storage.rules` ; chercher `if true`
  et les règles du « mode test ».
- Test réel : avec la clé publique et sans session, tenter de lire une table sensible.
- Concaténation : chercher des requêtes construites avec `+`, des gabarits `${}` ou des f-strings.
- Exposition : la base écoute-t-elle sur `0.0.0.0` ? Le port est-il ouvert au monde ?
- Sauvegardes : existent-elles, et quelqu'un en a-t-il déjà restauré une ?

**Corriger**
- Activer la RLS sur chaque table et écrire une politique par opération, fondée sur
  l'utilisateur connecté.
- Requêtes paramétrées (`$1`, `?`, paramètres nommés) ou ORM, y compris pour `ORDER BY` et les
  noms de colonnes (liste blanche).
- Base accessible seulement depuis l'application ; compte sans droits d'administration.
- Sauvegarde automatique quotidienne, conservée ailleurs, restauration testée une fois.
- Buckets privés, URL signées de courte durée.

## E. Entrées et sorties (21 à 26)

**Vérifier**
- Chaque route lit-elle ses entrées à travers un schéma ? Sinon, c'est une entrée non validée.
- `grep -rnE "dangerouslySetInnerHTML|v-html|innerHTML\s*=|\|\s*safe|\{!!|eval\(" .`
- CSRF : les actions qui modifient des données sont-elles en POST/PUT/DELETE avec jeton ou
  vérification d'origine ? Aucune modification par simple GET.
- Envois : limite de taille ? liste blanche ? le fichier atterrit-il dans un dossier servi
  publiquement et exécutable ?
- SSRF : le serveur télécharge-t-il une URL donnée par l'utilisateur (aperçu de lien, import
  d'image, webhook configurable) ?
- Redirections : `?next=` ou `?redirect=` acceptent-ils un domaine externe ?
- Erreurs : provoquer une erreur et lire la réponse.

**Corriger**
- Schémas : zod, valibot, yup, pydantic, règles de validation Laravel/Django.
- Laisser le framework échapper ; si du HTML utilisateur est indispensable, le nettoyer
  (DOMPurify, bleach) et ajouter une CSP.
- Envois : vérifier les premiers octets du fichier, limiter la taille côté serveur, générer un
  nouveau nom, stocker dans un bucket privé. Se méfier des SVG (ils peuvent contenir du script).
- URL utilisateur : liste blanche de domaines ; bloquer `localhost`, `127.0.0.0/8`, `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`.
- Redirections : n'accepter que des chemins relatifs commençant par un seul `/`.
- Gestionnaire d'erreurs global : message neutre, identifiant d'erreur, détail dans les journaux.

## F. Paiements et logique métier (27 à 29)

**Vérifier**
- Le montant facturé vient-il du corps de la requête ? Si oui : faille critique.
- Le webhook vérifie-t-il la signature avec le secret du prestataire, sur le corps brut ?
- Que se passe-t-il si le même événement arrive deux fois ? Si la page « succès » est ouverte
  sans avoir payé ?
- Quantités négatives, coupons cumulables, essais gratuits rejouables, deux requêtes simultanées.

**Corriger**
- Le client envoie un identifiant de produit ; le serveur lit le prix en base.
- La livraison (accès, crédits, commande) se déclenche sur le webhook vérifié ou sur une
  confirmation obtenue de serveur à serveur, jamais sur le retour du navigateur.
- Vérifier montant, devise et référence de commande ; enregistrer l'identifiant de
  transaction pour refuser les doublons.
- Transactions de base de données et contraintes d'unicité contre les requêtes simultanées.

## G. Configuration et transport (30 à 35)

**Vérifier**
- `curl -sI https://ton-domaine` : lire les en-têtes. `curl -sI http://ton-domaine` doit rediriger.
- CORS : `curl -sI -H "Origin: https://evil.example" https://ton-domaine/api/…` ne doit pas
  renvoyer `Access-Control-Allow-Origin: https://evil.example` ni `*` avec identifiants.
- Limite : une vingtaine de requêtes rapides sur la connexion doivent finir en 429.
- Debug : `DEBUG=True`, `APP_DEBUG=true`, `NODE_ENV` autre que `production`, source maps en ligne.
- Fichiers : `curl -s -o /dev/null -w "%{http_code}" https://ton-domaine/.env` (idem `/.git/config`,
  `/backup.sql`, `/.DS_Store`) doit renvoyer 404.

**Corriger**
- HTTPS et HSTS : `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- En-têtes via le framework ou l'hébergeur (helmet, `next.config`, `vercel.json`, `_headers`,
  `firebase.json`, serveur web). Commencer la CSP en mode `Report-Only`, puis l'activer.
- CORS : liste explicite d'origines de production.
- Limite de requêtes par IP et par compte, stockée hors mémoire si plusieurs instances.
- Configuration de production séparée ; routes de test et comptes de démonstration supprimés.

## H. Dépendances (36 à 38)

**Vérifier**
- `npm audit --omit=dev` · `pnpm audit` · `pip-audit` · `composer audit` · `bundle audit` · `cargo audit`.
- Paquets inutilisés : `npx depcheck` (JS), `deptry` (Python).
- Pour chaque paquet inconnu : existe-t-il sur le registre officiel, depuis quand, avec combien
  de téléchargements, et est-ce bien l'orthographe du paquet légitime ?
- Le fichier de verrouillage est-il versionné ?

**Corriger**
- Mettre à jour d'abord les vulnérabilités critiques et élevées ; relancer les tests.
- Supprimer ce qui ne sert pas : moins de code tiers, moins de surface d'attaque.
- Activer Dependabot (ou Renovate), la détection de secrets et la protection au push dans les
  réglages GitHub du dépôt ; double authentification sur tous les comptes techniques.

## I. Journalisation et réaction (39 et 40)

**Vérifier**
- Peut-on répondre à : qui s'est connecté, quand, d'où ? Qui a changé ce rôle ? Combien d'échecs
  de connexion hier ?
- Les journaux contiennent-ils des mots de passe, jetons, numéros de carte ?

**Corriger**
- Journal structuré des événements de sécurité, avec date, utilisateur, IP, action, résultat.
- Alertes simples : seuil d'échecs de connexion, pic d'erreurs 403/500, alerte de facturation.
- Plan d'incident d'une page : couper l'accès, révoquer les clés, restaurer la sauvegarde,
  prévenir les utilisateurs concernés et l'autorité de protection des données si la loi l'exige.

## J. IA et mobile (41 et 42)

- IA : l'appel au modèle part du serveur ; quota par utilisateur ; les outils et données fournis
  au modèle sont limités aux droits de l'utilisateur courant ; la sortie du modèle est validée
  avant d'être exécutée, affichée en HTML ou insérée en base.
- Mobile : tout ce qui est dans l'application peut être extrait. Aucune clé secrète, aucune règle
  de prix ou de droit décidée dans l'app ; jetons dans Keychain/Keystore.
