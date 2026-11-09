# Procédure de rotation d'un secret exposé

Ordre obligatoire : **révoquer ou remplacer d'abord, nettoyer ensuite.**

## 1. Révoquer ou remplacer (immédiatement)
- Révoquer le secret chez le fournisseur (console API, base de données, etc.).
- Générer un nouveau secret et le stocker hors du dépôt : GitHub Secrets pour la CI,
  Secret Kubernetes ou fichier .env non versionné pour l'exécution.
- Tant que cette étape n'est pas faite, le secret reste exploitable par quiconque l'a copié.

## 2. Nettoyer le dépôt
- Supprimer le secret du code et le remplacer par une lecture d'environnement
  (os.environ.get).
- Si le secret a été commité : réécrire l'historique (git filter-repo) puis
  force-push, et demander aux collaborateurs de re-cloner.

## 3. Vérifier
- Lancer Gitleaks : aucune détection ne doit subsister.
- Le pipeline CI doit repasser au vert.

## Limite
Git est distribué : anciens clones, forks et caches peuvent garder l'ancien secret.
Un secret exposé doit toujours être considéré comme compromis, d'où la révocation d'abord.
