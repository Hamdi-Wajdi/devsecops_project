import os

class Config:
    """Configuration de base de l'application HelpDesk."""
    SECRET_KEY = os.getenv("SECRET_KEY", "fictif_dev_session_secret_key_98765")
    
    # Paramètres de connexion PostgreSQL
    DB_HOST = os.getenv("DB_HOST", "db")
    DB_PORT = int(os.getenv("DB_PORT", "5432"))
    DB_NAME = os.getenv("DB_NAME", "helpdesk")
    DB_USER = os.getenv("DB_USER", "helpdesk_user")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "fictif_postgres_password_123")

    # =========================================================================
    # FAILLE 4 (VOLONTAIRE) : Secret fictif en dur dans le code source
    # Catégorie : OWASP A07:2021 - Identification and Authentication Failures / CWE-798
    # Ce jeton fictif doit être détecté par Gitleaks / TruffleHog lors du scan CI/CD.
    # =========================================================================
    HELPDESK_SLACK_WEBHOOK_KEY = "xoxb-fake-helpdesk-agent-notification-token-987654321"
    HELPDESK_INTERNAL_API_SECRET = "sec_live_fictif_helpdesk_key_abcdef1234567890"
