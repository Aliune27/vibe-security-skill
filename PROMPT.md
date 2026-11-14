# Prompt à copier-coller

Pour les assistants qui ne chargent pas de skill. Copie tout le bloc ci-dessous.

```
Je ne veux pas de hacker dans mon appli. Fais un audit de sécurité complet de ce projet, corrige
les failles, teste les protections et donne-moi un rapport.

Règles :
- Commence par lire le projet et me dire quelles technologies, quelles routes et quelles données
  sensibles tu as trouvées. Ne modifie rien avant de m'avoir montré ton plan.
- Cite un fichier et une ligne pour chaque faille. Si tu n'as pas pu vérifier un point, dis-le.
- N'affiche jamais un secret en entier. Corrige une chose à la fois, sans casser l'appli.
- Demande-moi avant toute action irréversible. Liste à part ce que je dois faire moi-même
  (révoquer une clé, régler l'hébergeur, activer la double authentification).
- Utilise les mécanismes de sécurité du framework ou de bibliothèques reconnues, pas du code maison.

Urgences d'abord :
1. Cherche les secrets dans le code, dans ce qui est envoyé au navigateur et dans l'historique
   Git. Dis-moi quelles clés révoquer et remplacer.
2. Vérifie que ma base de données n'est pas ouverte (RLS Supabase, règles Firebase, accès réseau).
3. Vérifie que le mode debug est désactivé en production.
4. Cherche les fichiers exposés (.env, .git, sauvegardes, dumps).

Puis contrôle et corrige :
- Authentification : vraie authentification vérifiée côté serveur, mots de passe hachés
  (argon2id ou bcrypt), limite sur la connexion, cookies de session HttpOnly/Secure/SameSite,
  liens de réinitialisation à usage unique qui expirent, double authentification pour les admins.
- Autorisations : chaque route et chaque API vérifie l'identité côté serveur ; un utilisateur ne
  peut jamais lire ou modifier les données d'un autre en changeant un identifiant ; routes admin
  verrouillées par un rôle vérifié côté serveur ; impossible de modifier son rôle ou un prix via
  un formulaire.
- Base de données : requêtes paramétrées partout, compte au privilège minimal, sauvegardes
  automatiques, fichiers stockés en privé.
- Entrées : validation de tous les formulaires côté serveur, protection XSS, protection CSRF,
  type et taille des fichiers envoyés limités, URL fournies par l'utilisateur contrôlées,
  messages d'erreur sans détail technique.
- Paiements : prix et montants calculés côté serveur, webhooks avec signature vérifiée, pas de
  livraison sans confirmation du prestataire.
- Configuration : HTTPS imposé avec HSTS, en-têtes de sécurité (CSP, nosniff, frame-ancestors,
  Referrer-Policy), CORS limité à mes domaines, limite de requêtes, variables d'environnement
  validées au démarrage.
- Dépendances : mets à jour les paquets vulnérables, supprime les paquets inutilisés, vérifie que
  chaque paquet existe vraiment et est le bon.
- Surveillance : enregistre les connexions, les échecs, les refus d'accès et les actions admin,
  sans secret dans les journaux ; propose des alertes sur les activités suspectes.
- Si l'appli appelle une IA : clé côté serveur, plafond de coût par utilisateur.

Pour finir : rejoue les attaques contre l'appli corrigée (accès sans connexion, accès aux données
d'un autre compte, route admin avec un compte normal, injection dans les formulaires, prix
modifié, rafale de connexions, fichier interdit) et donne-moi un rapport : failles trouvées
classées par gravité, corrections appliquées avec la preuve du test, ce qu'il me reste à faire,
et ce que tu n'as pas pu vérifier.
```
