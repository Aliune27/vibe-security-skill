# Particularités par technologie

Ne lis que les sections qui concernent le projet audité. Les outils évoluent vite : en cas de
doute sur un réglage, consulte la documentation officielle à jour avant de modifier.

## Supabase
- La clé publique (`anon` / `sb_publishable_…`) peut être dans le navigateur **seulement si la
  RLS est active sur toutes les tables**. Sans RLS, cette clé donne accès à toute la base.
- La clé `service_role` / `sb_secret_…` contourne la RLS : jamais dans le navigateur, jamais dans
  une variable `NEXT_PUBLIC_` / `VITE_`.
- Vérifier : `select tablename, rowsecurity from pg_tables where schemaname = 'public';`
- Une politique `using (true)` ouvre la table. Une bonne politique s'appuie sur `auth.uid()`.
- Ne jamais décider d'un rôle à partir de métadonnées que l'utilisateur peut modifier lui-même.
- Storage : buckets privés, politiques sur `storage.objects`.
- Fonctions `security definer` et vues : elles peuvent contourner la RLS, à relire une par une.

## Firebase
- La configuration web (`apiKey`, etc.) n'est pas un secret : la sécurité repose sur les
  **règles de sécurité** et sur App Check. Restreindre tout de même la clé dans Google Cloud.
- Chercher `allow read, write: if true;` et les règles du mode test dans `firestore.rules`,
  `storage.rules`, `database.rules.json`.
- Règle type : accès réservé à `request.auth != null && request.auth.uid == userId`.
- Valider aussi les données dans les règles (types, champs autorisés).
- Le fichier de compte de service (Admin SDK) ne doit jamais être dans le dépôt ni dans l'appli.
- Rôles admin par custom claims définis côté serveur.

## Next.js / React (Vercel, Netlify)
- Tout ce qui commence par `NEXT_PUBLIC_` est envoyé au navigateur.
- Les Server Actions et les routes `app/api` sont des points d'entrée publics : chacune vérifie
  l'identité et les droits elle-même. Le middleware seul ne suffit pas.
- Tenir Next.js et React à jour : des failles critiques ont touché le middleware
  (CVE-2025-29927) et les React Server Components (CVE-2025-55182).
- En-têtes dans `next.config` (`headers()`), `vercel.json` ou `_headers`.
- Désactiver les source maps de production (`productionBrowserSourceMaps` à `false`).
- Variables d'environnement distinctes pour Preview et Production.

## Vite, Create React App, Expo
- `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` : variables publiques. Une application sans serveur ne
  peut garder aucun secret : il faut une fonction serveur intermédiaire.

## Node.js / Express
- `helmet` (en-têtes), `express-rate-limit` (limite), `cors` avec liste d'origines,
  `app.disable('x-powered-by')`, limite de taille sur `express.json({ limit })`.
- Cookies : `httpOnly: true, secure: true, sameSite: 'lax'`.
- `csurf` est abandonné : utiliser une alternative maintenue ou `SameSite` + contrôle d'origine.
- `NODE_ENV=production` ; pas de `child_process.exec` avec du texte utilisateur.

## Python — Django, Flask, FastAPI
- Django : `DEBUG = False`, `ALLOWED_HOSTS`, `SECRET_KEY` hors du code, puis
  `python manage.py check --deploy` et corriger chaque avertissement.
- Flask : jamais `debug=True` en production ; `SECRET_KEY` aléatoire ; Flask-WTF (CSRF),
  Flask-Limiter, Flask-Talisman.
- FastAPI : dépendances d'authentification sur chaque routeur, modèles Pydantic en entrée **et**
  en sortie (pour ne pas renvoyer le hachage du mot de passe), `CORSMiddleware` restreint.

## PHP — Laravel, PHP classique
- Laravel : `APP_DEBUG=false`, `APP_ENV=production`, `$fillable` explicite (pas de
  `$guarded = []`), `{{ }}` plutôt que `{!! !!}`, policies et gates pour les droits.
- La racine web doit pointer sur `public/` : sinon `.env` est téléchargeable.
- PHP classique : PDO avec requêtes préparées, `password_hash()` / `password_verify()`,
  `htmlspecialchars()` à l'affichage, `session_regenerate_id()` à la connexion.

## Paiement
- Stripe : prix référencés par identifiants créés côté serveur ; webhook vérifié avec la
  signature et le corps brut ; clés `sk_live_` et secret de webhook côté serveur uniquement.
- Mobile money et agrégateurs (Wave, Orange Money, PayDunya, CinetPay, etc.) : suivre la
  documentation du prestataire pour vérifier la signature ou le jeton de la notification, puis
  **reconfirmer le statut par un appel de serveur à serveur** avant de livrer. Contrôler le
  montant, la devise et la référence ; refuser les notifications déjà traitées.

## Hébergement
- Plateformes gérées (Vercel, Netlify, Firebase Hosting, Render…) : HTTPS automatique ; régler
  les en-têtes, les variables d'environnement et la protection des déploiements de prévisualisation.
- Serveur privé (VPS) : pare-feu n'ouvrant que 80/443 et SSH, connexion SSH par clé sans compte
  root, mises à jour de sécurité automatiques, base de données liée à `localhost`, certificat
  renouvelé automatiquement.

## Outils sans code ou « prompt vers appli » (Lovable, Bolt, v0, Replit…)
- Le backend est presque toujours Supabase ou Firebase : appliquer les sections ci-dessus.
- Vérifier le bundle publié, pas seulement le projet : ouvrir le site, onglet Réseau/Sources,
  et y chercher des clés.
- Désactiver ou protéger les aperçus publics et les projets « remixables » contenant des secrets.
