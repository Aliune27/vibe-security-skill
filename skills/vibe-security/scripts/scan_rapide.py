#!/usr/bin/env python3
"""Scan rapide de sécurité pour un projet vibe codé.

Usage :  python3 scan_rapide.py [dossier] [--json] [--sans-git]

Cherche : secrets dans le code et le bundle, secrets dans l'historique Git, fichiers .env
suivis par Git, fichiers sensibles exposés, et motifs de code dangereux.
Aucune dépendance (Python 3.8+). Lecture seule : ne modifie rien, n'envoie rien sur le réseau.
Les secrets trouvés sont masqués dans la sortie.

Ce scan ne remplace pas l'audit : il ne voit pas les failles d'autorisation ni de logique.
"""
import base64
import json
import os
import re
import subprocess
import sys

DOSSIERS_IGNORES = {
    "node_modules", ".git", "vendor", "venv", ".venv", "env", "__pycache__", ".cache",
    ".turbo", "coverage", ".idea", ".vscode", "Pods", ".gradle", "target", ".dart_tool",
}
DOSSIERS_BUNDLE = {"dist", "build", "out", ".next", ".output", ".svelte-kit", "public", "static", "www"}
EXT_IGNOREES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".mov", ".pdf", ".zip", ".gz", ".tar", ".jar", ".exe", ".dll", ".so",
    ".lock", ".map", ".min.css",
}
FICHIERS_IGNORES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock"}
TAILLE_MAX = 3_000_000

# (nom, gravité, expression régulière)
SECRETS = [
    ("Clé privée (PEM)", "CRITIQUE", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    ("Clé secrète Stripe (production)", "CRITIQUE", r"\b[sr]k_live_[0-9a-zA-Z]{16,}"),
    ("Clé secrète Stripe (test)", "MOYEN", r"\bsk_test_[0-9a-zA-Z]{16,}"),
    ("Clé Anthropic", "CRITIQUE", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("Clé OpenAI", "CRITIQUE", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
    ("Clé d'accès AWS", "CRITIQUE", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Jeton GitHub", "CRITIQUE", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{40,}"),
    ("Jeton Slack", "CRITIQUE", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("Clé SendGrid", "CRITIQUE", r"\bSG\.[\w\-]{16,}\.[\w\-]{16,}"),
    ("Clé secrète Supabase", "CRITIQUE", r"\bsb_secret_[A-Za-z0-9_\-]{16,}"),
    ("URL de base de données avec mot de passe", "CRITIQUE",
     r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@'\"]+:[^\s@'\"]{3,}@[^\s'\"]+"),
    ("Clé Google / Firebase", "INFO", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Secret écrit en dur", "ELEVE",
     r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|private[_\-]?key)\b"
     r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
]
JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
VAR_PUBLIQUE = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_)\w*"
    r"(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|ADMIN_KEY)\w*")
FAUX = re.compile(
    r"(?i)(example|exemple|changeme|change_me|your[_\-]|xxxx|placeholder|dummy|<[^>]+>|\$\{|process\.env|"
    r"os\.environ|getenv|import\.meta|\*\*\*\*|\.\.\.|test1234|password123|motdepasse)")

# (nom, gravité, contrôle, expression régulière, extensions concernées ou None)
CODE = [
    ("HTML injecté sans échappement (risque XSS)", "ELEVE", 22,
     r"dangerouslySetInnerHTML|\bv-html\s*=|\.innerHTML\s*=|\{!!.*!!\}|\|\s*safe\b", None),
    ("eval() ou équivalent", "ELEVE", 22, r"\beval\s*\(|new Function\s*\(", {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}),
    ("Requête SQL construite par concaténation", "CRITIQUE", 16,
     r"(?i)(?:query|execute|raw|exec)\w*\s*\(\s*(?:f[\"']|[\"'`][^\"'`]*\b(?:select|insert|update|delete)\b[^\"'`]*"
     r"(?:\$\{|[\"']\s*\+|%s[\"']\s*%|\.format\())", None),
    ("Mode debug activé", "ELEVE", 34,
     r"(?i)\bDEBUG\s*=\s*True\b|\bAPP_DEBUG\s*=\s*true\b|debug\s*=\s*True\s*\)|FLASK_DEBUG\s*=\s*1", None),
    ("CORS ouvert à toutes les origines", "MOYEN", 32,
     r"(?i)Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|origin\s*:\s*['\"]\*['\"]|allow_origins\s*=\s*\[\s*['\"]\*|"
     r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True|origin\s*:\s*true\b", None),
    ("Hachage faible pour un mot de passe", "ELEVE", 7,
     r"(?i)(?:md5|sha1)\s*\(\s*\$?\w*pass\w*|createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\).{0,60}pass", None),
    ("Vérification TLS désactivée", "ELEVE", 30,
     r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", None),
    ("Règle Firebase ouverte à tous", "CRITIQUE", 15, r"allow\s+[\w,\s]+:\s*if\s+true\s*;", {".rules"}),
    ("Règle Firebase Realtime ouverte", "CRITIQUE", 15, r"\"\.(?:read|write)\"\s*:\s*(?:true|\"true\")", {".json"}),
    ("Politique RLS qui autorise tout", "ELEVE", 15, r"(?i)\b(?:using|with check)\s*\(\s*true\s*\)", {".sql"}),
    ("RLS désactivée", "CRITIQUE", 15, r"(?i)disable\s+row\s+level\s+security", {".sql"}),
    ("Commande système avec texte variable", "ELEVE", 16,
     r"shell\s*=\s*True|child_process['\"]?\)?\.exec\s*\(\s*`|\bexec(?:Sync)?\s*\(\s*`[^`]*\$\{|os\.system\s*\(\s*f[\"']", None),
    ("JWT décodé sans vérification de signature", "ELEVE", 9,
     r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|jwt\.decode\s*\([^)]*verify\s*=\s*False", None),
    ("Cookie sans protection", "MOYEN", 9, r"(?i)httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False", None),
]
SENSIBLES = re.compile(
    r"(?i)(^|/)(\.env(\.[\w\-]+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|.*\.pfx|.*\.keystore|.*(?:dump|backup|export|sauvegarde)[^/]*\.sql|.*\.sqlite3?|.*\.db|"
    r".*\.bak|.*\.dump|service[_\-]?account.*\.json|.*firebase-adminsdk.*\.json|credentials\.json|\.htpasswd|"
    r"phpinfo\.php|\.DS_Store)$")
SENSIBLES_PUBLICS = re.compile(r"(?i)\.(sql|bak|dump|zip|tar|gz|log)$")
ENV_OK = re.compile(r"(?i)\.env\.(example|sample|template|dist)$")
ORDRE = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "INFO": 3}


def masquer(valeur):
    valeur = valeur.strip()
    return (valeur[:4] + "…") if len(valeur) > 4 else "…"


def git(racine, *args):
    try:
        r = subprocess.run(["git", "-C", racine, *args], capture_output=True, text=True, errors="replace", timeout=120)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def role_jwt(jeton):
    try:
        charge = jeton.split(".")[1]
        charge += "=" * (-len(charge) % 4)
        return str(json.loads(base64.urlsafe_b64decode(charge)).get("role", ""))
    except Exception:
        return ""


def chercher_secrets(ligne):
    """Renvoie [(nom, gravité, extrait masqué)] pour une ligne de texte."""
    trouves = []
    for nom, gravite, motif in SECRETS:
        for m in re.finditer(motif, ligne):
            valeur = m.group(1) if m.groups() else m.group(0)
            if nom == "Secret écrit en dur" and (FAUX.search(valeur) or FAUX.search(ligne) or len(set(valeur)) < 5):
                continue
            trouves.append((nom, gravite, masquer(valeur)))
            break
    for m in JWT.finditer(ligne):
        if role_jwt(m.group(0)) == "service_role":
            trouves.append(("Clé Supabase service_role (contourne la RLS)", "CRITIQUE", masquer(m.group(0))))
    m = VAR_PUBLIQUE.search(ligne)
    if m:
        trouves.append(("Variable publique au nom de secret (envoyée au navigateur)", "CRITIQUE", m.group(0)))
    return trouves


def fichiers(racine):
    for dossier, sous, noms in os.walk(racine):
        sous[:] = [d for d in sous if d not in DOSSIERS_IGNORES]
        for nom in noms:
            chemin = os.path.join(dossier, nom)
            yield chemin, os.path.relpath(chemin, racine).replace(os.sep, "/")


def analyser(racine, avec_git=True):
    constats = []

    def ajouter(gravite, titre, lieu, detail="", controle=None):
        constats.append({"gravite": gravite, "titre": titre, "lieu": lieu, "detail": detail, "controle": controle})

    suivis = set(git(racine, "ls-files").splitlines()) if avec_git else set()
    est_depot = bool(git(racine, "rev-parse", "--git-dir")) if avec_git else False

    for chemin, rel in fichiers(racine):
        parties = rel.split("/")
        dans_bundle = bool(set(parties[:-1]) & DOSSIERS_BUNDLE)
        nom = parties[-1]

        if SENSIBLES.search(rel) and not ENV_OK.search(rel):
            if rel in suivis:
                ajouter("CRITIQUE", "Fichier sensible suivi par Git", rel,
                        "Le retirer du dépôt (git rm --cached) et considérer son contenu comme compromis.", 2)
            elif dans_bundle:
                ajouter("CRITIQUE", "Fichier sensible dans un dossier servi publiquement", rel,
                        "Tout visiteur peut le télécharger.", 35)
            elif est_depot and nom.startswith(".env") and not git(racine, "check-ignore", rel):
                ajouter("ELEVE", "Fichier .env non ignoré par Git", rel, "Ajouter .env* au .gitignore.", 2)

        elif dans_bundle and SENSIBLES_PUBLICS.search(rel):
            ajouter("ELEVE", "Sauvegarde, archive ou journal dans un dossier servi publiquement", rel,
                    "Vérifier son contenu ; le sortir du dossier public s'il n'a pas à être téléchargé.", 35)

        ext = os.path.splitext(nom)[1].lower()
        if ext in EXT_IGNOREES or nom in FICHIERS_IGNORES or nom.endswith(".min.js") and not dans_bundle:
            continue
        try:
            if os.path.getsize(chemin) > TAILLE_MAX:
                continue
            with open(chemin, "r", encoding="utf-8", errors="strict") as f:
                lignes = f.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        est_env_local = nom.startswith(".env") and rel not in suivis and not dans_bundle
        est_ce_script = nom == os.path.basename(__file__)
        for n, ligne in enumerate(lignes, 1):
            if len(ligne) > 20000:
                ligne = ligne[:20000]
            if not est_ce_script:
                for titre, gravite, extrait in chercher_secrets(ligne):
                    if est_env_local and "Variable publique" not in titre:
                        continue  # un secret dans un .env local non suivi est à sa place
                    if dans_bundle and gravite != "INFO":
                        gravite, titre = "CRITIQUE", titre + " — dans le bundle public"
                    ajouter(gravite, titre, f"{rel}:{n}", f"valeur : {extrait}", 1)
            if dans_bundle or est_ce_script or ext in {".md", ".txt"}:
                continue
            for titre, gravite, controle, motif, exts in CODE:
                if exts and ext not in exts:
                    continue
                if re.search(motif, ligne):
                    ajouter(gravite, titre, f"{rel}:{n}", ligne.strip()[:110], controle)

    if est_depot:
        deja = set()
        historique = git(racine, "log", "--all", "--diff-filter=A", "--name-only", "--format=")
        for rel in sorted(set(historique.splitlines())):
            if rel and SENSIBLES.search(rel) and not ENV_OK.search(rel) and rel not in suivis:
                ajouter("CRITIQUE", "Fichier sensible présent dans l'historique Git", rel,
                        "Supprimé depuis, mais toujours récupérable : révoquer les secrets qu'il contenait.", 3)
        commit = ""
        for ligne in git(racine, "log", "--all", "-p", "--no-color", "--format=commit %h").splitlines():
            if ligne.startswith("commit "):
                commit = ligne[7:]
            elif ligne.startswith("+") and not ligne.startswith("+++"):
                for titre, gravite, extrait in chercher_secrets(ligne[1:20000]):
                    if gravite != "CRITIQUE" or "Variable publique" in titre or (titre, extrait) in deja:
                        continue
                    deja.add((titre, extrait))
                    ajouter("CRITIQUE", titre + " — dans l'historique Git", f"commit {commit}",
                            f"valeur : {extrait} · à révoquer même si la ligne a été supprimée", 3)
        if not os.path.exists(os.path.join(racine, ".gitignore")):
            ajouter("MOYEN", "Aucun fichier .gitignore", ".gitignore", "Y ajouter au minimum .env* et node_modules.", 2)

    # dédoublonnage et tri
    vus, uniques = set(), []
    for c in constats:
        cle = (c["titre"], c["lieu"])
        if cle not in vus:
            vus.add(cle)
            uniques.append(c)
    uniques.sort(key=lambda c: (ORDRE[c["gravite"]], c["titre"], c["lieu"]))
    return uniques


def commandes_conseillees(racine):
    existe = lambda n: os.path.exists(os.path.join(racine, n))
    cmds = []
    if existe("package.json"):
        cmds += ["npm audit --omit=dev", "npx depcheck"]
    if existe("requirements.txt") or existe("pyproject.toml"):
        cmds += ["pip-audit", "deptry ."]
    if existe("composer.json"):
        cmds.append("composer audit")
    if existe("Gemfile"):
        cmds.append("bundle audit")
    if existe("manage.py"):
        cmds.append("python manage.py check --deploy")
    cmds.append("gitleaks git .   (scan d'historique plus complet que ce script)")
    return cmds


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    racine = os.path.abspath(args[0] if args else ".")
    if not os.path.isdir(racine):
        sys.exit(f"Dossier introuvable : {racine}")
    constats = analyser(racine, avec_git="--sans-git" not in sys.argv)

    if "--json" in sys.argv:
        print(json.dumps({"dossier": racine, "constats": constats}, ensure_ascii=False, indent=2))
    else:
        print(f"Scan rapide de sécurité — {racine}\n")
        libelles = {"CRITIQUE": "CRITIQUE", "ELEVE": "ÉLEVÉ", "MOYEN": "MOYEN", "INFO": "INFO"}
        if not constats:
            print("Aucun constat automatique. Cela ne prouve pas que le projet est sûr : poursuivre l'audit.")
        for gravite in ORDRE:
            groupe = [c for c in constats if c["gravite"] == gravite]
            if not groupe:
                continue
            print(f"── {libelles[gravite]} ({len(groupe)}) " + "─" * 40)
            for c in groupe:
                ctrl = f" [contrôle {c['controle']}]" if c["controle"] else ""
                print(f"  • {c['titre']}{ctrl}\n      {c['lieu']}")
                if c["detail"]:
                    print(f"      {c['detail']}")
            print()
        if any(c["titre"].startswith("Clé Google") for c in constats):
            print("Note : une clé Google/Firebase web est normale dans une appli Firebase ; vérifier qu'elle est\n"
                  "restreinte dans Google Cloud et que les règles de sécurité sont strictes.\n")
        print("Commandes à lancer ensuite :")
        for c in commandes_conseillees(racine):
            print(f"  $ {c}")
        print("\nCe scan ne détecte ni les failles d'autorisation (accès aux données d'un autre utilisateur),\n"
              "ni les failles de paiement ou de logique : elles demandent l'audit complet du skill.")
    sys.exit(1 if any(c["gravite"] == "CRITIQUE" for c in constats) else 0)


if __name__ == "__main__":
    main()
