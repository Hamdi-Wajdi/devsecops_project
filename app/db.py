import time
import psycopg2
from psycopg2.extras import RealDictCursor
from config import Config

def get_db_connection():
    """Établit et retourne une connexion à la base de données PostgreSQL."""
    return psycopg2.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        cursor_factory=RealDictCursor
    )

def wait_for_db(max_retries=15, delay=2):
    """Attend que la base de données PostgreSQL soit prête à recevoir des connexions."""
    print("[INFO] Attente de la disponibilité de PostgreSQL...")
    for attempt in range(1, max_retries + 1):
        try:
            conn = get_db_connection()
            conn.close()
            print("[INFO] Connexion PostgreSQL réussie.")
            return True
        except psycopg2.OperationalError as e:
            print(f"[ATTENTE] Tentative {attempt}/{max_retries} : base non prête ({e}). Nouvelle tentative dans {delay}s...")
            time.sleep(delay)
    raise RuntimeError("Impossible de se connecter à PostgreSQL après plusieurs tentatives.")

def init_db():
    """Initialise le schéma de la base de données et peuple les données fictives initiales."""
    wait_for_db()
    conn = get_db_connection()
    cur = conn.cursor()

    # Création des tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'agent')),
            full_name VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            description TEXT NOT NULL,
            status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED')),
            priority VARCHAR(20) DEFAULT 'MEDIUM' CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH')),
            user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS comments (
            id SERIAL PRIMARY KEY,
            ticket_id INT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
            author_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    # Vérification si la base est déjà peuplée
    cur.execute("SELECT COUNT(*) AS count FROM users;")
    row = cur.fetchone()
    if row["count"] == 0:
        print("[INFO] Base vide détectée. Lancement du peuplement initial (seed)...")
        from seed_data import seed_database
        seed_database(conn)
    else:
        print("[INFO] Données déjà présentes en base. Pas de re-seed nécessaire.")

    cur.close()
    conn.close()
