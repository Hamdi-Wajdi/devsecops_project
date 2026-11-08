from werkzeug.security import generate_password_hash

def seed_database(conn):
    """Peuple la base de données avec des utilisateurs, tickets et commentaires fictifs."""
    cur = conn.cursor()

    # 1. Insertion des utilisateurs (3 clients 'user', 2 techniciens 'agent')
    users = [
        ("alice", generate_password_hash("Alice2026!"), "user", "Alice Martin"),
        ("bob", generate_password_hash("Bob2026!"), "user", "Bob Dupont"),
        ("charlie", generate_password_hash("Charlie2026!"), "user", "Charlie Lambert"),
        ("agent_smith", generate_password_hash("AgentSmith2026!"), "agent", "Agent Smith"),
        ("agent_clara", generate_password_hash("AgentClara2026!"), "agent", "Clara Rossi"),
    ]

    user_ids = {}
    for username, password_hash, role, full_name in users:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, role, full_name)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
            """,
            (username, password_hash, role, full_name)
        )
        user_ids[username] = cur.fetchone()["id"]

    # 2. Insertion de 10 tickets de support fictifs
    tickets = [
        (
            "Accès VPN impossible depuis le télétravail",
            "Message d'erreur TLS handshake failed lors de la connexion au serveur VPN d'entreprise.",
            "OPEN",
            "HIGH",
            user_ids["alice"]
        ),
        (
            "Demande d'accès au dépôt Git privé devsecops",
            "Bonjour, j'ai besoin des droits de lecture sur le dépôt GitLab interne pour le projet.",
            "RESOLVED",
            "MEDIUM",
            user_ids["alice"]
        ),
        (
            "Écran secondaire clignote en HDMI",
            "Depuis la mise à jour système, le deuxième moniteur s'éteint toutes les 5 minutes.",
            "IN_PROGRESS",
            "LOW",
            user_ids["alice"]
        ),
        (
            "Renouvellement du mot de passe SAP expiré",
            "Mon compte applicatif est bloqué après expiration des 90 jours réglementaires.",
            "CLOSED",
            "HIGH",
            user_ids["alice"]
        ),
        (
            "Demande d'installation de Docker Desktop",
            "Besoin de Docker pour tester les conteneurs locaux sur mon poste Windows.",
            "OPEN",
            "MEDIUM",
            user_ids["bob"]
        ),
        (
            "Imprimante réseau 2ème étage inaccessible",
            "Erreur d'impression Spooler Windows introuvable sur l'imprimante RH.",
            "IN_PROGRESS",
            "LOW",
            user_ids["bob"]
        ),
        (
            "Données confidentielles : fuite supposée sur le partage réseau",
            "Vérification demandée sur le répertoire RH public suite à une anomalie d'ACL.",
            "OPEN",
            "HIGH",
            user_ids["bob"]
        ),
        (
            "Problème de synchronisation messagerie Outlook",
            "Les e-mails de la boîte partagée commerciale ne se mettent plus à jour automatiquement.",
            "RESOLVED",
            "MEDIUM",
            user_ids["charlie"]
        ),
        (
            "Demande d'attribution de nouveau badge d'accès",
            "Badge physique égaré hier soir dans les transports, demande de révocation et remplacement.",
            "CLOSED",
            "HIGH",
            user_ids["charlie"]
        ),
        (
            "Lenteur anormale de la station de travail",
            "Utilisation CPU à 100% permanente même sans application lourde lancée.",
            "OPEN",
            "LOW",
            user_ids["charlie"]
        ),
    ]

    ticket_ids = []
    for title, desc, status, prio, uid in tickets:
        cur.execute(
            """
            INSERT INTO tickets (title, description, status, priority, user_id)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (title, desc, status, prio, uid)
        )
        ticket_ids.append(cur.fetchone()["id"])

    # 3. Insertion de quelques commentaires initiaux
    comments = [
        (ticket_ids[0], user_ids["agent_smith"], "Bonjour Alice, pouvez-vous tester en régénérant votre certificat client ?"),
        (ticket_ids[0], user_ids["alice"], "J'ai essayé, mais l'erreur persiste sur le port 1194."),
        (ticket_ids[1], user_ids["agent_clara"], "Droits ajoutés avec succès sur le groupe GitLab."),
        (ticket_ids[4], user_ids["agent_smith"], "Ticket pris en charge. Le paquet d'installation a été déployé sur votre poste."),
        (ticket_ids[6], user_ids["bob"], "Ticket confidentiel : merci de ne pas partager les détails en dehors de l'équipe sécurité."),
    ]

    for tid, aid, content in comments:
        cur.execute(
            """
            INSERT INTO comments (ticket_id, author_id, content)
            VALUES (%s, %s, %s);
            """,
            (tid, aid, content)
        )

    conn.commit()
    cur.close()
    print(f"[INFO] Initialisation terminée avec succès : {len(users)} utilisateurs, {len(tickets)} tickets et {len(comments)} commentaires créés.")
