# Vibe Security

**Un skill pour auditer et sécuriser une appli construite avec l'IA, quand on ne sait pas encore le faire soi-même.**

Tu as vibe codé un site, un SaaS ou une app, et tu ne veux pas de hacker dedans. Ce skill donne à
ton assistant IA une méthode complète : il trouve les failles, les corrige sans casser l'appli,
teste les protections et te remet un rapport en langage simple.

> *English:* an agent skill (written in French) that audits and hardens AI-built web apps, SaaS
> and mobile apps: 43 controls across secrets, auth, access control, database, payments,
> configuration and dependencies, followed by protection tests and a findings report.

## Ce qu'il fait

1. **Reconnaissance** — identifie les technologies et tous les points d'entrée de l'appli.
2. **Urgences** — secrets qui ont fuité, base de données ouverte, mode debug, fichiers exposés.
3. **Audit** — 43 contrôles répartis en 11 familles.
4. **Priorisation** — critique, élevé, moyen, faible.
5. **Corrections** — une par une, vérifiées, sans action irréversible sans ton accord.
6. **Tests et rapport** — rejoue les attaques, puis liste les failles, les corrections et ce
   qu'il te reste à faire toi-même (révoquer une clé, activer la double authentification…).

## Les 43 contrôles

| Famille | Contrôles |
|---|---|
| A. Secrets et clés | code et bundle sans secret · `.env` et variables d'environnement · historique Git · révocation des clés compromises · privilège minimal et plafond de dépense |
| B. Authentification et sessions | vraie authentification côté serveur · mots de passe hachés · anti force brute et 2FA admin · cookies de session · liens de réinitialisation qui expirent |
| C. Autorisations | contrôle sur chaque route · accès aux données des autres utilisateurs (IDOR) · routes admin · champs non modifiables |
| D. Base de données et stockage | RLS / règles Firebase · requêtes paramétrées · base non exposée · sauvegardes · buckets privés · données sensibles |
| E. Entrées et sorties | validation côté serveur · XSS · CSRF · envois de fichiers · SSRF et redirections · gestion des erreurs |
| F. Paiements et logique métier | prix calculés côté serveur · webhooks vérifiés · abus de logique |
| G. Configuration et transport | HTTPS · en-têtes de sécurité · CORS · limite de requêtes · debug désactivé · fichiers exposés |
| H. Dépendances | paquets vulnérables · paquets inutilisés ou inventés par l'IA · automatisation |
| I. Journalisation et réaction | journal des événements de sécurité · alertes et plan d'incident |
| J. Si applicable | applis qui appellent une IA · applis mobiles |
| K. Clôture | test des protections · rapport |

## Installation

### Claude Code

```bash
git clone https://github.com/Aliune27/vibe-security-skill.git

# pour tous tes projets
mkdir -p ~/.claude/skills && cp -r vibe-security-skill/skills/vibe-security ~/.claude/skills/

# ou pour un seul projet (depuis la racine du projet)
mkdir -p .claude/skills && cp -r /chemin/vers/vibe-security-skill/skills/vibe-security .claude/skills/
```

Ouvre ensuite ton projet et écris simplement : **« Fais un audit de sécurité complet de mon appli »**.

### Application Claude

Compresse le dossier `skills/vibe-security` en `.zip` et ajoute-le comme skill personnalisé.

### Cursor, Lovable, Bolt, Replit, autres assistants

Copie le contenu de [`PROMPT.md`](PROMPT.md) dans la conversation, ou ajoute `SKILL.md` aux
règles du projet.

## Scan rapide sans IA

Un script sans dépendance (Python 3.8+), en lecture seule, qui ne contacte aucun serveur :

```bash
python3 skills/vibe-security/scripts/scan_rapide.py /chemin/vers/ton/projet
```

Il repère les secrets dans le code, le bundle et l'historique Git, les fichiers `.env` suivis par
Git, les fichiers sensibles exposés et les motifs de code dangereux (SQL concaténé, debug actif,
CORS ouvert, règles Firebase permissives…). Les secrets trouvés sont masqués à l'affichage.
Options : `--json`, `--sans-git`.

## Contenu du dépôt

```
skills/vibe-security/
├── SKILL.md                    la méthode et les 43 contrôles
├── references/
│   ├── controles.md            comment vérifier et corriger chaque contrôle
│   ├── stacks.md               Supabase, Firebase, Next.js, Express, Django, Laravel, paiements…
│   └── modele-rapport.md       modèle du rapport final
└── scripts/
    └── scan_rapide.py          scan automatique
PROMPT.md                       version à copier-coller pour les autres assistants
```

## Limites

- Aucun outil ne rend une appli « inviolable ». Ce skill élimine les failles les plus courantes et
  les plus graves ; il ne remplace pas un test d'intrusion professionnel pour une appli qui
  manipule de l'argent ou des données sensibles.
- Le script automatique ne voit pas les failles d'autorisation ni de logique : c'est le rôle de
  l'audit complet.
- N'utilise ce skill que sur tes propres projets.

## Références

Les contrôles s'appuient sur l'[OWASP Top 10:2025](https://owasp.org/Top10/2025/), l'OWASP ASVS et
les failles les plus souvent relevées dans les applis générées par IA.

## Licence

MIT — libre d'utilisation, de modification et de partage. Les contributions sont bienvenues.
