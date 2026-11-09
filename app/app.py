import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash

from config import Config
from db import get_db_connection, init_db

app = Flask(__name__)
app.config.from_object(Config)

# ---------------------------------------------------------
# Décorateurs de contrôle d'accès
# ---------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def agent_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Veuillez vous connecter pour accéder à cette page.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "agent":
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------------------------------
# Routes d'authentification
# ---------------------------------------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("tickets"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s;", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            flash(f"Bienvenue, {user['full_name']} ({user['role']}) !", "success")
            return redirect(url_for("tickets"))
        else:
            flash("Identifiants invalides. Veuillez réessayer.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for("login"))

# ---------------------------------------------------------
# Gestion des tickets
# ---------------------------------------------------------
@app.route("/tickets")
@login_required
def tickets():
    conn = get_db_connection()
    cur = conn.cursor()

    # Règle métier normale :
    # Un utilisateur voit ses propres tickets. Un agent voit tous les tickets.
    if session["role"] == "agent":
        cur.execute("""
            SELECT t.*, u.username AS author_username, u.full_name AS author_full_name
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC;
        """)
    else:
        cur.execute("""
            SELECT t.*, u.username AS author_username, u.full_name AS author_full_name
            FROM tickets t
            JOIN users u ON t.user_id = u.id
            WHERE t.user_id = %s
            ORDER BY t.created_at DESC;
        """, (session["user_id"],))

    ticket_list = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("tickets.html", tickets=ticket_list, search_query="")

@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def new_ticket():
    if session["role"] != "user":
        flash("Seuls les utilisateurs standards peuvent ouvrir de nouveaux tickets.", "info")
        return redirect(url_for("tickets"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "MEDIUM")

        if not title or not description:
            flash("Le titre et la description sont obligatoires.", "warning")
            return render_template("new_ticket.html")

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO tickets (title, description, priority, user_id)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
        """, (title, description, priority, session["user_id"]))
        ticket_id = cur.fetchone()["id"]
        conn.commit()
        cur.close()
        conn.close()

        flash("Ticket créé avec succès.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return render_template("new_ticket.html")

# =============================================================================
# FAILLE 1 (VOLONTAIRE) : Injection SQL dans la recherche de tickets
# Catégorie : OWASP A03:2021 - Injection / CWE-89
# Cause : Concaténation directe du paramètre q dans la requête SQL brute.
# =============================================================================
@app.route("/tickets/search")
@login_required
def search_tickets():
    q = request.args.get("q", "")
    conn = get_db_connection()
    cur = conn.cursor()

    # CORRECTION : Requête paramétrée sécurisée (%s) pour neutraliser l'injection SQL (CWE-89)
    search_pattern = f"%{q}%"
    query = """
        SELECT t.id, t.title, t.description, t.status, t.priority, t.user_id, t.created_at
        FROM tickets t
        WHERE t.title ILIKE %s OR t.description ILIKE %s
        ORDER BY t.created_at DESC;
    """
    try:
        cur.execute(query, (search_pattern, search_pattern))
        ticket_list = cur.fetchall()
    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        flash(f"Erreur SQL lors de l'exécution de la recherche : {e}", "danger")
        return render_template("tickets.html", tickets=[], search_query=q)

    cur.close()
    conn.close()
    return render_template("tickets.html", tickets=ticket_list, search_query=q)

# =============================================================================
# FAILLE 2 (VOLONTAIRE) : IDOR (Insecure Direct Object Reference)
# Catégorie : OWASP A01:2021 - Broken Access Control / CWE-639
# Cause : Aucun contrôle d'autorisation vérifiant que le ticket appartient à
# l'utilisateur connecté s'il s'agit d'un simple 'user'.
# =============================================================================
@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT t.*, u.username AS author_username, u.full_name AS author_full_name
        FROM tickets t
        JOIN users u ON t.user_id = u.id
        WHERE t.id = %s;
    """, (ticket_id,))
    ticket = cur.fetchone()

    if not ticket:
        cur.close()
        conn.close()
        abort(404)

    # CORRECTION : Contrôle d'accès strict (CWE-639 / Broken Access Control)
    # Seul l'auteur du ticket ou un agent de support technique peut consulter le ticket
    if session.get("role") != "agent" and ticket["user_id"] != session.get("user_id"):
        cur.close()
        conn.close()
        abort(403)

    # Récupération des commentaires
    cur.execute("""
        SELECT c.*, u.username AS author_username, u.full_name AS author_full_name, u.role AS author_role
        FROM comments c
        JOIN users u ON c.author_id = u.id
        WHERE c.ticket_id = %s
        ORDER BY c.created_at ASC;
    """, (ticket_id,))
    comments = cur.fetchall()

    cur.close()
    conn.close()
    return render_template("ticket_detail.html", ticket=ticket, comments=comments)

@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@agent_required
def update_status(ticket_id):
    new_status = request.form.get("status")
    if new_status not in ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"]:
        flash("Statut invalide.", "warning")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE tickets SET status = %s WHERE id = %s;", (new_status, ticket_id))
    conn.commit()
    cur.close()
    conn.close()

    flash(f"Statut du ticket mis à jour : {new_status}", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))

# =============================================================================
# FAILLE 3 (VOLONTAIRE) : Enregistrement de commentaires permettant un XSS stocké
# Catégorie : OWASP A03:2021 - Injection / CWE-79
# Cause : Le commentaire est enregistré sans assainissement et sera affiché
# avec le filtre | safe dans le template ticket_detail.html.
# =============================================================================
@app.route("/tickets/<int:ticket_id>/comment", methods=["POST"])
@login_required
def add_comment(ticket_id):
    content = request.form.get("content", "").strip()
    if not content:
        flash("Le commentaire ne peut pas être vide.", "warning")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO comments (ticket_id, author_id, content)
        VALUES (%s, %s, %s);
    """, (ticket_id, session["user_id"], content))
    conn.commit()
    cur.close()
    conn.close()

    flash("Commentaire ajouté.", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))

@app.errorhandler(403)
def forbidden(e):
    return render_template("base.html", error_code=403, error_message="Accès refusé (403 Forbidden)."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error_code=404, error_message="Ressource introuvable (404 Not Found)."), 404

if __name__ == "__main__":
    init_db()
    # Écoute sur 0.0.0.0 pour être accessible depuis le conteneur Docker
    # nosemgrep: python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host - 0.0.0.0 est nécessaire dans un conteneur ; l'exposition est limitée par Kubernetes et la NetworkPolicy.
    app.run(host="0.0.0.0", port=5000, debug=False)
