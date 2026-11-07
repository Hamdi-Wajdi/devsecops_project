DEVSECOPS / ING-5-SSIR CAHIER DES CHARGES

Malek Ferchichi · TEK-UP University 

### PROJET DEVSECOPS

# Cahier des charges du projet

Concevoir une application présentant une réelle surface d’attaque et la sécuriser tout au long de son cycle de vie, du code source à la surveillance en production.

ÉQUIPE RENDU ÉVALUATION

2 étudiants Dépôt, rapport et soutenance Note de groupe modulée individuellement

## 1. Objet et périmètre

Objectif Livrer une application fonctionnelle, puis mettre en œuvre une démarche DevSecOps complète : analyse du code, sécurisation des conteneurs, pipeline bloquant, déploiement orchestré, tests dynamiques et détection d’incident.

Le projet couvre le cycle « écrire → construire → tester → livrer → déployer → observer ». À chaque étape, l’équipe fournit une preuve vérifiable.

- Une application conteneurisée et durcie.

- Un pipeline CI/CD doté de contrôles de sécurité réellement bloquants.

- Une gestion appropriée des secrets et un déploiement sur Kubernetes local.

- Des tests de sécurité dynamiques sur l’application de l’équipe.

- Au moins une attaque de test visible dans les journaux et un plan de réponse.

- Un rapport retraçant les failles avant et après correction.

## 2. Organisation de l’équipe

- Les équipes comptent 2 étudiants et sont déclarées au lancement du projet.

- Chaque équipe choisit un thème distinct, réservé après validation.

- La sécurité relève de toute l’équipe ; les rôles peuvent tourner.

- Chaque membre remet une fiche de contribution individuelle appuyée par des commits ou d’autres preuves.

## 3. Choix de l’application

L’application peut être créée par l’équipe ou adaptée à partir d’une base existante. Elle doit comprendre un backend, une base de données, une authentification avec au moins deux rôles et des données sensibles fictives.

THÈME APPLICATION SURFACE DE SÉCURITÉ

MediTrack Rendez-vous et dossiers patients Accès par rôle, objets, données sensibles

EduGrade Portail de notes Notes d’autrui, rôles, injection

ShopCart Mini-boutique Panier, prix, injection

DocVault Partage de documents Accès aux fichiers, secrets, dépôts

PayLite Portefeuille de paiements Montants, authentification, secrets

HelpDesk Système de tickets Rôles, injection, script stocké

JobBoard Portail de recrutement CV, dépôts, contrôle d’accès

FleetBook Réservation de véhicules Réservations, configuration, secrets

IoT Board Tableau de bord IoT Clés API, authentification, commandes

Thème libre À proposer et faire valider Respect des critères de validité

# 4. Exigences techniques

Toutes les exigences sont obligatoires, sauf mention « Bonus ». La démonstration prime sur le choix exact des outils.

### 4.1 Application et conteneur

- Backend, base de données, authentification à rôles et données sensibles fictives.

- Image Docker construite en plusieurs étapes, fondée sur une image de base minimale et exécutée par un

utilisateur non privilégié.

- Aucun secret ni répertoire .git dans l’image.

Vérification L’image se construit, l’application fonctionne et les contrôles ne révèlent ni secret embarqué ni exécution avec les droits root.

### 4.2 Failles initiales et modèle de menace

- Au moins quatre vulnérabilités relevant d’au moins trois catégories différentes.

- Exemples : injection, défaut de contrôle d’accès, mauvaise configuration, dépendance vulnérable ou secret de

test exposé.

- Modèle de menace STRIDE ou équivalent, avec rapprochement des failles et des catégories OWASP Top 10.

- Pour chaque faille avant correction : emplacement, cause, impact et preuve.

Vérification Chaque faille est démontrée uniquement sur l’application du groupe, puis corrigée et testée à nouveau.


### 4.3 Pipeline CI/CD et sécurité bloquante

- Étapes conseillées : build → tests → SAST → recherche de secrets → analyse des dépendances → construction

de l’image → analyse de l’image → déploiement → DAST.

- SAST : Semgrep, SonarQube ou équivalent ; dépendances et image : Trivy ou équivalent ; secrets : Gitleaks ou

équivalent, sans afficher leur valeur.

- Le pipeline échoue selon une politique de blocage écrite et justifiée.

Vérification Un secret fictif ajouté au dépôt ou une vulnérabilité critique relevant de la politique fait échouer le pipeline, preuve à l’appui.

### 4.4 Gestion des secrets

- Aucun secret réel dans le dépôt : utiliser exclusivement des valeurs fictives.

- Injecter les secrets nécessaires à l’exécution au moyen de variables protégées ou d’un mécanisme équivalent.

- Sur un secret fictif volontairement exposé, montrer l’ordre des opérations : révoquer ou remplacer d’abord,

nettoyer ensuite.

Vérification Le scanner ne détecte plus le secret de test et la procédure de rotation est documentée.

### 4.5 Déploiement Kubernetes et durcissement

- Déployer sur un cluster local : Minikube, kind ou Kubernetes intégré à Docker Desktop.

- Définir un securityContext restrictif et exécuter l’application sans droits root.

- Ne pas écrire les secrets en clair dans les manifestes versionnés.

- Configurer une NetworkPolicy de refus par défaut, puis n’autoriser que les communications nécessaires.

- Bonus : contrôle d’admission avec Kyverno, OPA Gatekeeper ou équivalent.

Vérification L’application reste fonctionnelle après le durcissement et la segmentation réseau.

### 4.6 Tests de sécurité dynamiques (DAST)

- Scanner uniquement une instance de test appartenant à l’équipe.

- Exécuter le DAST après le déploiement, sur une application accessible.

- Confirmer dynamiquement au moins deux vulnérabilités, les corriger puis relancer les tests.

Vérification Les deux failles sont constatées avant correction et ne sont plus confirmées après correction.

### 4.7 Observabilité et réponse à incident

- Produire des journaux exploitables, sans secrets ni données sensibles.

- Faire apparaître au moins une tentative d’attaque fictive dans la télémétrie.

- Présenter un plan de réponse : détecter → contenir → éradiquer → rétablir → tirer les enseignements.

Vérification L’événement fictif est visible dans les journaux et l’équipe sait expliquer la réponse.

### 4.8 Socle obligatoire et bonus

Socle obligatoire : application vulnérable, conteneur sécurisé, pipeline bloquant, gestion des secrets, Kubernetes durci, DAST sur deux failles, une détection à l’exécution et un plan de réponse.

Bonus : Kyverno ou OPA, tableaux de bord avancés, SIEM, plusieurs détections, modèle de menace approfondi et plus de deux failles confirmées en DAST.

### 4.9 Architecture de référence

Le rapport doit présenter une architecture lisible comprenant au minimum le dépôt, la CI/CD, les contrôles de sécurité, le registre d’images, Kubernetes, l’application, la base de données et l’observabilité.

BLOC CONTENU

Source Développeur → dépôt GitLab

Pipeline Build, tests, SAST, secrets, dépendances, analyse d’image

Image Registre d’images de conteneurs

Déploiement Kubernetes : frontend, backend, base de données

Observation Surveillance et journaux

Lecture : le développeur pousse le code ; le pipeline effectue les contrôles, construit l’image et l’envoie au registre ; Kubernetes déploie l’application ; les journaux et les métriques permettent d’observer son fonctionnement.

# 5. Outils conseillés

BESOIN OUTIL CONSEILLÉ ALTERNATIVE

CI/CD GitLab CI Jenkins, GitHub Actions

SAST Semgrep SonarQube, autre outil SAST

Dépendances et image Trivy Grype, Docker Scout

Secrets Gitleaks TruffleHog, detect-secrets

DAST OWASP ZAP Nuclei, Burp Suite Community

Orchestration Minikube ou kind Kubernetes Docker Desktop

Admission — bonus Kyverno OPA Gatekeeper

Observabilité Prometheus, Grafana, Loki ELK, OpenTelemetry

# 6. Jalons de progression

Les jalons permettent de vérifier régulièrement l’avancement du projet en classe.

JALON RÉSULTAT ATTENDU

1 — Thème Équipe, thème validé, architecture initiale

2 — Application Application fonctionnelle et dépôt Git

3 — Conteneur Dockerfile et Docker Compose fonctionnels

4 — CI/CD Build, tests et premier contrôle de sécurité

5 — Sécurité SAST, secrets, dépendances et analyse d’image

6 — Kubernetes Déploiement, securityContext et NetworkPolicy

7 — DAST et journaux Deux tests dynamiques et une détection

Final Rapport, dépôt, présentation et démonstration

# 7. Livrables

LIVRABLE FORMAT CONTENU ATTENDU

Dépôt de code URL Code, Dockerfile, Compose, pipeline, manifestes, README

Architecture Dans le rapport Schéma final lisible et commenté

Rapport de sécurité PDF, 6 à 10 pages Failles, preuves, corrections, limites, références

Pipeline Dans le dépôt Contrôles et politique de blocage documentée

Déploiement Dans le dépôt Kubernetes, sécurité, réseau, secrets

Soutenance Slides et démo Démonstration en direct structurée

Contribution 1 page/personne Travail réalisé, commits, difficulté résolue

# 8. Démonstration finale obligatoire

La soutenance présente le fonctionnement réel du projet et ne se limite pas aux captures d’écran.

1. Montrer l’application fonctionnelle.

2. Montrer les conteneurs et le déploiement Kubernetes.

3. Introduire un secret fictif ou une vulnérabilité de test préparée pour la démonstration.

4. Pousser le changement et montrer l’échec du pipeline.

5. Corriger le problème, relancer le pipeline et montrer sa réussite.

6. Présenter les principaux contrôles de sécurité.

7. Rejouer un test de sécurité sur le seul environnement du groupe.

8. Montrer l’événement correspondant dans les journaux ou la supervision.

Durée conseillée 8 à 10 minutes de démonstration technique, en plus de la présentation.

## 9. Règles et contraintes

Périmètre impératif Tous les scans et tests offensifs visent uniquement l’application et l’environnement de test du groupe. Aucun test ne doit cibler un système tiers ou non autorisé.

- Utiliser exclusivement des secrets fictifs.

- Ne jamais afficher de valeur sensible dans les journaux, le rapport ou la soutenance.

- Expliquer les limites du pipeline : un résultat réussi ne garantit pas une sécurité totale.

- Présenter les scores des outils avec leur contexte et leurs limites.

- Déclarer tout usage d’IA et vérifier les contenus produits.

- Fournir un travail original, citer les sources et éviter le plagiat.

## 10. Critères d’acceptation

Le projet est accepté si les conditions suivantes sont satisfaites :

- L’application fonctionne et est déployée sur Kubernetes.

- Le conteneur est durci et s’exécute sans droits root.

- Le pipeline bloque réellement un cas défini par la politique.

- Aucun secret fictif exposé ne subsiste dans le dépôt après correction.

- Au moins deux failles sont confirmées dynamiquement puis corrigées.

- La segmentation réseau préserve le fonctionnement de l’application.

- Une attaque fictive est visible dans la télémétrie.

- Le rapport présente les failles, correctifs, preuves et limites.


# Annexe A — Réservation de thème

À remettre au lancement. Les détails techniques peuvent évoluer après validation.

CHAMP À COMPLÉTER

Nom de l’équipe

Membres (2)

Thème — premier choix

Thème — deuxième choix

Application en une phrase

Backend, base, rôles et données fictives ? Oui / Non

# Annexe B — Fiche de contribution individuelle

Une fiche par étudiant, à remettre avec le livrable final.

CHAMP À COMPLÉTER

Nom

Rôle(s) principal(aux)

Travail réalisé

Commits et preuves

Difficulté rencontrée et résolue

Autoévaluation (/20)