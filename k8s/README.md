# Déploiement Kubernetes Durci (HelpDesk)

Ce dossier contient l'ensemble des manifestes Kubernetes permettant de déployer l'application **HelpDesk** de manière isolée et sécurisée sur un cluster local **kind** avec le plugin réseau **Calico** (support complet des `NetworkPolicy`).

---

## 1. Architecture des fichiers

- `kind-config.yaml` : Définition du cluster kind avec CNI par défaut désactivé (`disableDefaultCNI: true`) pour permettre l'installation de Calico.
- `00-namespace.yaml` : Namespace dédié `helpdesk`.
- `10-postgres.yaml` : Déploiement et service ClusterIP de la base de données PostgreSQL.
- `20-web.yaml` : Déploiement et service ClusterIP de l'application Flask avec `securityContext` durci.
- `30-networkpolicy.yaml` : Segmentation réseau stricte (Default Deny Ingress/Egress, DNS, Ingress Web 5000, Web ➔ Postgres 5432).

---

## 2. Procédure de déploiement pas à pas

### Étape 1 : Création du cluster kind
```bash
kind create cluster --name helpdesk-cluster --config k8s/kind-config.yaml
```

### Étape 2 : Installation du CNI Calico
```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml
# Attente que les nœuds et pods Calico soient prêts
kubectl wait --for=condition=Ready nodes --all --timeout=180s
kubectl wait --namespace calico-system --for=condition=Ready pods --all --timeout=180s
```

### Étape 3 : Construction et chargement de l'image applicative
```bash
# Construction de l'image locale durcie
docker build -t helpdesk:fixed ./app

# Chargement direct dans les nœuds du cluster kind (évite un registre distant)
kind load docker-image helpdesk:fixed --name helpdesk-cluster
```

### Étape 4 : Création du Namespace et injection des Secrets hors-git
> [!IMPORTANT]
> **Aucun secret n'est commité dans les manifestes versionnés.**
> Les identifiants et clés d'API sont injectés directement dans le cluster depuis le fichier local `.env` (non suivi par Git) :

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl create secret generic helpdesk-secrets --from-env-file=.env -n helpdesk
```

### Étape 5 : Déploiement de l'application et des NetworkPolicies
```bash
kubectl apply -f k8s/10-postgres.yaml
kubectl apply -f k8s/20-web.yaml
kubectl apply -f k8s/30-networkpolicy.yaml

# Attente du démarrage complet des services
kubectl wait --namespace helpdesk --for=condition=Ready pods -l app=postgres --timeout=120s
kubectl wait --namespace helpdesk --for=condition=Ready pods -l app=web --timeout=120s
```

---

## 3. Durcissement de Sécurité Appliqué

### Conteneur Web (`app/app.py`)
- **`runAsNonRoot: true`** & **`runAsUser: 10001`** : Exécution exclusive sous le compte non-root `appuser`.
- **`allowPrivilegeEscalation: false`** : Interdiction absolue d'élever les privilèges via setuid/setgid.
- **`readOnlyRootFilesystem: true`** : Système de fichiers racine en lecture seule intégrale pour contrer toute persistance de malware ou modification de binaires.
- **`tmp (emptyDir)`** : Répertoire temporaire isolé monté sur `/tmp` pour les fichiers volatils indispensables.
- **`capabilities.drop: ["ALL"]`** : Révocation de toutes les capacités Linux du noyau (`CAP_NET_RAW`, etc.).
- **`seccompProfile: { type: RuntimeDefault }`** : Filtrage des appels système Linux via le profil restrictif standard.
- **`resources.limits`** : Plafonds CPU (500m) et Mémoire (256Mi) pour prévenir les dénis de service (DoS).
- **Probes** : `livenessProbe` et `readinessProbe` sur `/login`.

---

## 4. Preuves de Validation et Tests d'Isolation

### Test 1 : Accès applicatif légitime (Port-Forward)
```bash
kubectl port-forward svc/web 5000:5000 -n helpdesk
# Dans un terminal distinct :
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/login
# Résultat attendu : 200
```

### Test 2 : Preuve de blocage NetworkPolicy (Pod non autorisé)
Déploiement d'un pod espion/testeur dans le même namespace `helpdesk` sans les labels autorisés :
```bash
kubectl run rogue-pod --image=busybox:1.36 --restart=Never -n helpdesk -- sleep 3600
kubectl wait --namespace helpdesk --for=condition=Ready pod/rogue-pod --timeout=60s
```

1. **Tentative d'accès non autorisé à la base de données PostgreSQL** :
   ```bash
   kubectl exec -n helpdesk rogue-pod -- nc -zv -w 3 postgres 5432
   ```
   **Résultat attendu** : `nc: postgres (10.x.x.x:5432): Operation timed out` ➔ **Accès bloqué par Calico**.

2. **Accès autorisé depuis le pod Web officiel** :
   ```bash
   WEB_POD=$(kubectl get pod -n helpdesk -l app=web -o jsonpath="{.items[0].metadata.name}")
   kubectl exec -n helpdesk $WEB_POD -c web -- python -c "import socket; s = socket.socket(); s.settimeout(3); s.connect(('postgres', 5432)); print('Postgres connection SUCCESS')"
   ```
   **Résultat attendu** : `Postgres connection SUCCESS` ➔ **Trafic légitime préservé**.
