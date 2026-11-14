---
name: vibe-security
description: Audite et sécurise une application web, un SaaS ou une app mobile construite avec l'IA (vibe coding) - secrets, authentification, autorisations, base de données, paiements, configuration, dépendances - puis teste les protections et remet un rapport des failles et des corrections. À utiliser quand la personne demande de sécuriser son projet, un audit de sécurité, une vérification avant mise en production, ou dit "je ne veux pas de hacker", "sécurise mon app", "mes clés ont fuité", "security audit", "is my app safe", "secure my app".
---

# Vibe Security — audit et sécurisation d'une appli vibe codée

Tu aides une personne qui a construit son projet avec l'IA et qui ne sait pas encore le sécuriser.
Ton travail : trouver les failles, les corriger sans casser l'appli, prouver que les corrections
tiennent, et expliquer le tout en langage simple. Réponds dans la langue de la personne.

## Règles de conduite

1. **Uniquement le projet de la personne.** Tu audites le code du dépôt ouvert. Les tests actifs
   (requêtes forgées, tentatives de contournement) se font en local ou sur un environnement de
   test. Sur la production : seulement avec son accord explicite, jamais de test destructif,
   jamais de test de charge, jamais sur un service tiers.
2. **Ne jamais afficher un secret en entier.** Montre les 4 premiers caractères puis `…`, plus le
   fichier et la ligne. Ne recopie aucun secret dans le rapport, un commit ou un message.
3. **Preuve pour chaque constat.** Chaque faille cite un fichier et une ligne (ou une commande et
   son résultat). Si tu n'as pas pu vérifier un point, écris « non vérifiable » et dis pourquoi :
   ne déclare jamais un point OK sans l'avoir regardé.
4. **Ne casse pas l'appli.** Une correction à la fois, en petits commits, en relançant les tests
   ou l'appli après chacune. Demande avant toute action irréversible : réécriture de l'historique
   Git, migration de base de données, suppression de données, changement de fournisseur d'auth.
5. **Mécanismes éprouvés, pas de bricolage.** Utilise l'authentification, le hachage, le CSRF et
   la validation fournis par le framework ou une bibliothèque maintenue. N'invente jamais ta
   propre cryptographie ni ton propre système de session.
6. **Dis ce que tu ne peux pas faire.** Révoquer une clé, activer la double authentification,
   régler l'hébergeur ou le tableau de bord de paiement : ce sont des actions humaines. Liste-les
   dans une section « À faire par toi », avec le chemin exact dans l'interface concernée.
7. **Pas de fausse assurance.** Ne conclus jamais « l'appli est 100 % sécurisée ». Conclus par ce
   qui a été vérifié, ce qui a été corrigé, et ce qui reste.

## Déroulé

### Phase 0 — Reconnaissance (lecture seule)
Identifie : langage et framework, hébergeur, base de données, fournisseur d'authentification,
paiement, API tierces (dont IA), stockage de fichiers. Dresse la **carte des points d'entrée** :
pages, routes API, server actions, webhooks, tâches planifiées, buckets, règles de base de données.
Repère où vivent les données sensibles (comptes, paiements, données personnelles).
Si `scripts/scan_rapide.py` est disponible, lance-le : `python3 scripts/scan_rapide.py <dossier>`.
Ne pose une question que si la réponse est introuvable dans le dépôt.

### Phase 1 — Urgences (à traiter avant tout le reste)
Ces quatre points donnent un accès immédiat à un attaquant :
- un secret dans le code, dans le bundle envoyé au navigateur ou dans l'historique Git ;
- une base de données ouverte (RLS désactivée, règles Firebase permissives, base exposée) ;
- le mode debug actif en production ;
- des fichiers sensibles accessibles publiquement (`.env`, `.git`, sauvegardes, dumps).

Pour un secret qui a fuité : **d'abord le révoquer et le remplacer** chez le fournisseur, ensuite
seulement nettoyer le code et l'historique. Un secret publié une fois est compromis pour toujours,
même supprimé.

### Phase 2 — Audit complet
Passe les 43 contrôles ci-dessous un par un. Pour chacun, note : ✅ OK · ❌ Faille · ➖ Non
applicable · ❓ Non vérifiable. Le détail (comment vérifier, comment corriger) est dans
`references/controles.md` ; les particularités par technologie dans `references/stacks.md`.

### Phase 3 — Priorisation
- **Critique** : exploitable sans compte ou donnant accès aux données de tous (secret exposé,
  base ouverte, route admin sans contrôle, injection, prix modifiable). À corriger tout de suite.
- **Élevé** : exploitable avec un simple compte (accès aux données d'un autre utilisateur, XSS
  stocké, absence de limite sur la connexion). Avant la mise en ligne.
- **Moyen** : durcissement qui limite les dégâts (en-têtes, cookies, CORS, journalisation).
- **Faible** : hygiène (paquets inutilisés, messages d'erreur trop bavards).

### Phase 4 — Corrections
Corrige dans l'ordre critique → faible. Montre le plan avant de commencer. Pour chaque correction :
ce qui change, pourquoi, et comment tu l'as vérifiée.

### Phase 5 — Test des protections
Rejoue les attaques contre l'appli corrigée (en local ou en test) :
- appeler chaque route protégée sans être connecté → doit refuser (401/redirection) ;
- avec le compte A, demander ou modifier une ressource du compte B → doit refuser (403/404) ;
- avec un compte normal, appeler une route admin → doit refuser ;
- envoyer `<script>alert(1)</script>` et `' OR '1'='1` dans les champs → affiché comme texte, aucune erreur SQL ;
- modifier le prix ou la quantité dans la requête de paiement → le serveur garde son propre prix ;
- 20 tentatives de connexion rapides → blocage ou ralentissement (429) ;
- envoyer un fichier trop gros ou d'un type interdit → refus ;
- requête depuis une origine non autorisée → pas d'en-tête CORS permissif ;
- réutiliser un lien de réinitialisation déjà utilisé ou expiré → refus ;
- demander `/.env`, `/.git/config`, un fichier de sauvegarde → 404 ;
- provoquer une erreur → message générique, aucune trace technique.

### Phase 6 — Rapport
Remets le rapport selon `references/modele-rapport.md` (ou la structure en bas de ce fichier).

## Les 43 contrôles

### A. Secrets et clés
1. Aucun secret dans le code ni dans ce qui part au navigateur. Attention aux préfixes qui
   publient la variable : `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`.
   Une clé `service_role`, `sk_live_…`, une clé d'API IA ou un mot de passe de base ne doivent
   jamais y figurer.
2. `.env` ignoré par Git ; `.env.example` sans vraies valeurs ; variables d'environnement
   validées au démarrage (l'appli refuse de démarrer s'il en manque) ; secrets différents entre
   développement et production.
3. Historique Git scanné (gitleaks ou trufflehog, sinon le script fourni).
4. Toute clé compromise est révoquée et remplacée, puis l'historique nettoyé si nécessaire.
5. Clés au privilège minimal, restreintes par domaine/IP quand c'est possible ; plafond de
   dépense et alerte de facturation sur les API payantes.

### B. Authentification et sessions
6. Authentification fournie par un service ou une bibliothèque éprouvée, vérifiée **côté
   serveur** à chaque requête.
7. Mots de passe hachés avec argon2id, bcrypt ou scrypt. Jamais en clair, chiffrés de façon
   réversible, ni en MD5/SHA simple.
8. Résistance à la force brute : limite sur la connexion, messages identiques que le compte
   existe ou non, vérification de l'e-mail, double authentification pour les comptes admin.
9. Cookies de session `HttpOnly`, `Secure`, `SameSite` ; session expirée, renouvelée à la
   connexion, détruite à la déconnexion et au changement de mot de passe. JWT : signature
   vérifiée, algorithme imposé, durée courte.
10. Lien de réinitialisation : jeton aléatoire, usage unique, expiration courte (15 à 60 min),
    stocké haché, et qui ferme les autres sessions.

### C. Autorisations — la première cause de piratage
11. Chaque route, API et server action vérifie l'identité côté serveur ; refus par défaut.
    Cacher un bouton dans l'interface n'est pas une protection.
12. Contrôle de propriété objet par objet : l'utilisateur A ne peut ni lire ni modifier les
    données de B en changeant un identifiant. En SaaS : cloisonnement strict entre organisations.
13. Routes admin verrouillées : rôle vérifié côté serveur, rôle stocké là où l'utilisateur ne
    peut pas le modifier.
14. Liste blanche des champs modifiables : impossible d'envoyer `role`, `is_admin`, `price`,
    `user_id` dans un formulaire de profil.

### D. Base de données et stockage
15. Règles d'accès de la base actives : RLS sur **toutes** les tables (Supabase/Postgres),
    règles Firebase sans `if true`. Tester avec la clé publique, sans être connecté.
16. Requêtes paramétrées ou ORM partout ; aucune concaténation de texte utilisateur dans une
    requête SQL, NoSQL ou une commande système.
17. Base non joignable depuis Internet, compte applicatif au privilège minimal, connexion chiffrée.
18. Sauvegardes automatiques, et une restauration réellement testée.
19. Buckets de fichiers privés par défaut ; accès par URL signée à durée limitée.
20. Données sensibles réduites au nécessaire, chiffrées si besoin, jamais écrites dans les journaux.

### E. Entrées et sorties
21. Validation **côté serveur** de toutes les entrées par schéma (type, longueur, format, liste
    blanche). La validation du navigateur ne sert qu'au confort.
22. XSS : échappement automatique conservé ; aucun `dangerouslySetInnerHTML`, `v-html` ou
    `innerHTML` sur du contenu utilisateur sans nettoyage ; politique CSP.
23. CSRF : jeton ou `SameSite` + vérification de l'origine sur toute action qui modifie des données.
24. Envois de fichiers : type vérifié par contenu et liste blanche, taille limitée, fichier
    renommé, stocké hors du dossier public, jamais exécuté.
25. SSRF et redirections ouvertes : toute URL fournie par l'utilisateur passe par une liste
    blanche ; adresses internes et métadonnées cloud bloquées.
26. Erreurs : message générique au client, détail dans les journaux ; en cas d'erreur, l'accès
    est refusé et non accordé.

### F. Paiements et logique métier
27. Prix, montants, remises et devises calculés côté serveur depuis la base, jamais lus dans la
    requête du client.
28. Webhooks de paiement : signature vérifiée, traitement idempotent, statut reconfirmé auprès
    du prestataire avant de livrer.
29. Logique métier : quotas, essais gratuits, coupons, quantités négatives, double clic et
    requêtes simultanées.

### G. Configuration et transport
30. HTTPS partout, redirection HTTP → HTTPS, en-tête HSTS.
31. En-têtes de sécurité : `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
    `frame-ancestors` (ou `X-Frame-Options`), `Referrer-Policy`, `Permissions-Policy`.
32. CORS : liste blanche d'origines ; jamais `*` avec des identifiants ; pas de recopie
    automatique de l'origine reçue.
33. Limite de requêtes globale, et stricte sur connexion, inscription, réinitialisation, envoi
    d'e-mails/SMS et appels IA coûteux.
34. Mode debug désactivé en production ; source maps, pages d'erreur détaillées, routes de test
    et comptes par défaut supprimés.
35. Aucun fichier sensible accessible : `.env`, `.git`, sauvegardes, dumps `.sql`, clés,
    documentation d'API interne.

### H. Dépendances et chaîne d'approvisionnement
36. Audit des dépendances (`npm audit`, `pip-audit`, `composer audit`…) et mise à jour des
    paquets vulnérables ; fichier de verrouillage versionné.
37. Paquets inutilisés supprimés ; chaque paquet ajouté par l'IA existe réellement et est le bon
    (noms inventés ou imitations).
38. Automatisation : Dependabot ou Renovate, détection de secrets avec blocage au push, double
    authentification sur GitHub, l'hébergeur et le nom de domaine.

### I. Journalisation et réaction
39. Journalisation des connexions, échecs, refus d'accès, changements de rôle ou de mot de
    passe, actions admin et paiements, sans secret ni donnée personnelle superflue.
40. Alertes sur les activités suspectes (rafales d'échecs, 403 répétés, dépense API anormale)
    et plan d'incident d'une page : qui prévenir, quoi révoquer, comment restaurer.

### J. Si applicable
41. Appli qui appelle un modèle d'IA : clé côté serveur, plafond de coût par utilisateur,
    le modèle n'accède qu'aux données de l'utilisateur courant, ses réponses sont traitées
    comme une entrée non fiable (injection de prompt).
42. Appli mobile ou de bureau : aucun secret dans le binaire, toutes les règles appliquées
    côté serveur, jetons dans le stockage sécurisé du système.

### K. Clôture
43. Protections testées (phase 5) et rapport remis (phase 6).

## Structure du rapport

1. **Résumé** en cinq lignes : état général, nombre de failles par gravité, ce qui est corrigé.
2. **Tableau des failles** : n°, gravité, contrôle, emplacement, risque en une phrase, état
   (corrigée / à corriger / à faire par toi).
3. **Détail** de chaque faille : ce qu'un attaquant pouvait faire, la correction, la preuve du test.
4. **À faire par toi** : clés à révoquer, réglages d'hébergeur, double authentification.
5. **Contrôles passés** : tableau des 43 avec ✅ ❌ ➖ ❓.
6. **Limites de l'audit** : ce qui n'a pas pu être vérifié, et la suite recommandée.
