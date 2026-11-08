# Documentation des Vulnérabilités Volontaires (HelpDesk - Branche `vulnerable`)

Ce document recense les 5 vulnérabilités de sécurité introduites délibérément dans l'application HelpDesk pour le projet DevSecOps. Toutes les données et clés utilisées sont **100 % fictives**.

---

## Sommaire
- [1. Injection SQL (SQLi)](#1-injection-sql-sqli)
- [2. Contrôle d'accès défaillant (IDOR)](#2-contrôle-daccès-défaillant-idor)
- [3. Cross-Site Scripting stocké (XSS Stocké)](#3-cross-site-scripting-stocké-xss-stocké)
- [4. Secret fictif codé en dur (Hardcoded Secret)](#4-secret-fictif-codé-en-dur-hardcoded-secret)
- [5. Composant obsolète avec vulnérabilité connue (CVE)](#5-composant-obsolète-avec-vulnérabilité-connue-cve)

---

## 1. Injection SQL (SQLi)

- **Catégorie OWASP Top 10** : A03:2021 – Injection
- **CWE associée** : CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **Emplacement** : `app/app.py`, fonction `search_tickets()`, lignes 155-160.
- **Cause technique** :
  Le paramètre utilisateur `q` issu de la chaîne de requête GET est directement inséré par formatage de chaîne Python (`f-string`) dans la requête SQL sans échappement ni paramétrage :
  ```python
  query = f"""
      SELECT t.id, t.title, t.description, t.status, t.priority, t.user_id, t.created_at
      FROM tickets t
      WHERE t.title ILIKE '%{q}%' OR t.description ILIKE '%{q}%'
      ORDER BY t.created_at DESC;
  """
  ```
- **Impact** :
  Un utilisateur authentifié peut injecter des clauses SQL arbitraires (par exemple via l'opérateur `UNION`), lui permettant d'extraire la totalité des tables de la base de données, y compris les informations d'authentification (`users` : noms d'utilisateur, rôles et empreintes de mots de passe).
- **Preuve de concept (PoC)** :
  1. Se connecter avec le compte `alice` (ou n'importe quel compte client).
  2. Effectuer une recherche avec la charge utile SQL suivante dans la barre de recherche (ou via URL) :
     ```text
     ' UNION SELECT id, username, password_hash, role, 'HIGH', id, created_at FROM users --
     ```
  3. L'application affiche l'intégralité de la table des utilisateurs avec leurs hashs de mots de passe directement dans les lignes du tableau de tickets.
  - Commande de test :
    ```bash
    curl -b cookies.txt -s "http://localhost:5000/tickets/search?q=%27+UNION+SELECT+id%2C+username%2C+password_hash%2C+role%2C+%27HIGH%27%2C+id%2C+created_at+FROM+users+--"
    ```
- **Correctif prévu (branche `fixed`)** :
  Remplacer la concaténation de chaînes par une requête paramétrée avec placeholders sécurisés (`%s`) gérés par le pilote psycopg2 :
  ```python
  pattern = f"%{q}%"
  cur.execute(
      """
      SELECT t.id, t.title, t.description, t.status, t.priority, t.user_id, t.created_at
      FROM tickets t
      WHERE t.title ILIKE %s OR t.description ILIKE %s
      ORDER BY t.created_at DESC;
      """,
      (pattern, pattern)
  )
  ```

---

## 2. Contrôle d'accès défaillant (IDOR)

- **Catégorie OWASP Top 10** : A01:2021 – Broken Access Control
- **CWE associée** : CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Emplacement** : `app/app.py`, fonction `ticket_detail()`, lignes 187-204.
- **Cause technique** :
  La route `GET /tickets/<int:ticket_id>` extrait un ticket directement par son identifiant numérique sans vérifier que l'utilisateur connecté est le propriétaire du ticket (`ticket.user_id == session['user_id']`) ou dispose du rôle privilégié (`session['role'] == 'agent'`).
- **Impact** :
  Violation de la confidentialité : n'importe quel utilisateur connecté (ex. Alice) peut consulter les demandes privées et confidentielles déposées par d'autres utilisateurs (ex. Bob ou Charlie) en modifiant simplement le paramètre numérique dans l'URL.
- **Preuve de concept (PoC)** :
  1. Se connecter avec l'utilisateur `alice` (identifiant interne 1).
  2. Les tickets appartenant à `bob` portent par exemple les identifiants #5, #6, #7 (le ticket #7 s'intitule *"Données confidentielles : fuite supposée..."*).
  3. Alice navigue directement vers `http://localhost:5000/tickets/7`.
  4. La page s'affiche sans erreur et dévoile le contenu confidentiel du ticket de Bob et ses échanges.
  - Commande de test :
    ```bash
    curl -b cookies_alice.txt -s "http://localhost:5000/tickets/7" | grep -i "fuite"
    ```
- **Correctif prévu (branche `fixed`)** :
  Ajouter une vérification systématique de l'autorisation d'accès avant le rendu de la ressource :
  ```python
  if session.get("role") != "agent" and ticket["user_id"] != session.get("user_id"):
      abort(403)
  ```

---

## 3. Cross-Site Scripting stocké (XSS Stocké)

- **Catégorie OWASP Top 10** : A03:2021 – Injection
- **CWE associée** : CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **Emplacement** : `app/templates/ticket_detail.html`, ligne 63 (et route `add_comment` dans `app/app.py`).
- **Cause technique** :
  Dans le template Jinja2, le contenu du commentaire est affiché avec le filtre `| safe`, ce qui désactive le mécanisme natif d'auto-échappement contextuel du moteur de template :
  ```html
  <div class="comment-body">
      {{ c.content | safe }}
  </div>
  ```
- **Impact** :
  Exécution de scripts JavaScript malveillants dans le navigateur de toute personne consultant le ticket (notamment les agents de support technique ou administrateurs), pouvant conduire au vol de cookies de session, détournement de session ou redirections frauduleuses.
- **Preuve de concept (PoC)** :
  1. Se connecter avec `alice`.
  2. Ouvrir le ticket #1 (`/tickets/1`).
  3. Publier le commentaire suivant :
     ```html
     <script>alert('XSS-Stored-HelpDesk')</script>
     ```
  4. À chaque rechargement ou consultation par un agent de support (`agent_smith`), la boîte de dialogue JavaScript s'exécute immédiatement.
  - Commande de test :
    ```bash
    curl -b cookies_alice.txt -d "content=<script>alert('XSS-Stored-HelpDesk')</script>" -X POST "http://localhost:5000/tickets/1/comment"
    ```
- **Correctif prévu (branche `fixed`)** :
  Retirer le filtre `| safe` du template pour laisser Jinja2 neutraliser et encoder automatiquement les caractères HTML sensibles (`<`, `>`, `&`, `"`, `'`) :
  ```html
  <div class="comment-body">
      {{ c.content }}
  </div>
  ```

---

## 4. Secret fictif codé en dur (Hardcoded Secret)

- **Catégorie OWASP Top 10** : A07:2021 – Identification and Authentication Failures
- **CWE associée** : CWE-798 (Use of Hard-coded Credentials)
- **Emplacement** : `app/config.py`, lignes 19-20.
- **Cause technique** :
  Des jetons d'authentification fictifs (`HELPDESK_SLACK_WEBHOOK_KEY` et `HELPDESK_INTERNAL_API_SECRET`) sont déclarés directement sous forme de constantes statiques dans le code versionné, au lieu d'être gérés de manière externe par des variables d'environnement injectées lors de l'exécution.
- **Impact** :
  Exposition des identifiants dans le dépôt Git accessible aux collaborateurs ou aux outils tiers. Tout commit contenant un secret en clair est intercepté par les outils d'audit statique et de détection de fuite de secrets (Gitleaks, TruffleHog, Semgrep).
- **Preuve de concept (PoC)** :
  Lancer un outil de scan de secrets dans le dossier du projet :
  ```bash
  gitleaks detect --source app/ --verbose
  ```
  Le scanner détecte la constante et lève une anomalie bloquante.
- **Correctif prévu (branche `fixed`)** :
  1. Révoquer ou régénérer le jeton exposé.
  2. Supprimer la constante statique du fichier `app/config.py`.
  3. Lire la valeur exclusivement via variable d'environnement :
     ```python
     HELPDESK_SLACK_WEBHOOK_KEY = os.getenv("HELPDESK_SLACK_WEBHOOK_KEY")
     ```

---

## 5. Composant obsolète avec vulnérabilité connue (CVE)

- **Catégorie OWASP Top 10** : A06:2021 – Vulnerable and Outdated Components
- **CWE associée** : CWE-1395 (Dependency on Vulnerable Third-Party Component)
- **Emplacement** : `app/requirements.txt`, ligne 2.
- **Cause technique** :
  L'application épingle explicitement la dépendance `Werkzeug==2.2.2`. Cette version est affectée par la vulnérabilité publique **CVE-2023-25577** (déni de service via requêtes multipart comportant un nombre excessif de parties).
- **Impact** :
  Un attaquant distant peut provoquer une surconsommation CPU ou mémoire menant à un déni de service de l'application Flask. De plus, les scanners de vulnérabilités logicielle (Trivy, pip-audit, Safety) identifient cette vulnérabilité et font échouer le pipeline CI/CD en fonction de la politique de blocage.
- **Preuve de concept (PoC)** :
  Analyser les dépendances du projet avec Trivy :
  ```bash
  trivy fs app/requirements.txt
  ```
  Trivy remonte une alerte pour `Werkzeug` avec la référence CVE-2023-25577.
- **Correctif prévu (branche `fixed`)** :
  Mettre à jour le fichier `app/requirements.txt` vers une version récente exempte de vulnérabilités connues :
  ```text
  Werkzeug>=3.0.3
  Flask>=3.0.3
  ```
