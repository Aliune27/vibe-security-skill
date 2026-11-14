# Rapport de sécurité — [nom du projet]

Date : [date] · Périmètre : [dépôt, branche, environnement testé] · Technologies : [stack]

## 1. Résumé

[Trois à cinq phrases en langage simple : état général avant l'audit, ce qui était le plus grave,
ce qui est corrigé, ce qui reste.]

| Gravité | Trouvées | Corrigées | Restantes |
|---|---|---|---|
| Critique | | | |
| Élevée | | | |
| Moyenne | | | |
| Faible | | | |

## 2. Failles trouvées

| N° | Gravité | Contrôle | Emplacement | Risque en une phrase | État |
|---|---|---|---|---|---|
| F1 | Critique | 1 — Secrets | `src/lib/api.ts:12` | Clé de paiement lisible par tout visiteur | Corrigée |

## 3. Détail

### F1 — [titre court]
- **Gravité :** Critique
- **Ce qu'un attaquant pouvait faire :** [conséquence concrète, sans jargon]
- **Où :** `fichier:ligne` (secret masqué : `sk_l…`)
- **Correction appliquée :** [ce qui a changé, commit]
- **Preuve du test :** [commande ou manipulation, résultat avant, résultat après]

## 4. À faire par toi

Actions que seul le propriétaire des comptes peut réaliser :

- [ ] Révoquer et régénérer la clé [fournisseur] — [chemin dans le tableau de bord]
- [ ] Activer la double authentification sur [GitHub, hébergeur, nom de domaine]
- [ ] Définir un plafond de dépense sur [API]
- [ ] Activer Dependabot et la détection de secrets sur le dépôt

## 5. Contrôles passés

Légende : ✅ OK · ❌ Faille · ➖ Non applicable · ❓ Non vérifiable

| N° | Contrôle | Résultat | Remarque |
|---|---|---|---|
| 1 | Aucun secret dans le code ni le navigateur | | |
| … | … | | |
| 43 | Protections testées et rapport remis | | |

## 6. Limites de l'audit

- [Ce qui n'a pas été vérifié et pourquoi : pas d'accès à la console de l'hébergeur, production
  non testée, etc.]
- Un audit assisté par IA réduit fortement le risque mais ne remplace pas un test d'intrusion
  professionnel pour une appli qui manipule de l'argent ou des données sensibles.
- Prochaine vérification conseillée : avant chaque mise en ligne importante, et après tout ajout
  d'authentification, de paiement ou d'envoi de fichiers.
