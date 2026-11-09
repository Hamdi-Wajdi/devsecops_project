import os

class Config:
    """Configuration de base de l'application HelpDesk."""
    SECRET_KEY = os.environ.get("SECRET_KEY")
    
    # Paramètres de connexion PostgreSQL
    DB_HOST = os.environ.get("DB_HOST", "db")
    DB_PORT = int(os.environ.get("DB_PORT", "5432"))
    DB_NAME = os.environ.get("DB_NAME", "helpdesk")
    DB_USER = os.environ.get("DB_USER", "helpdesk_user")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")

    # =========================================================================
    # FAILLE 4 (CORRIGÉE) : Récupération des secrets via variables d'environnement
    # Catégorie : OWASP A07:2021 - Identification and Authentication Failures / CWE-798
    # Les secrets ne sont plus codés en dur mais lus depuis les variables d'environnement.
    # =========================================================================
    HELPDESK_SLACK_WEBHOOK_KEY = os.environ.get("HELPDESK_SLACK_WEBHOOK_KEY")
    HELPDESK_INTERNAL_API_SECRET = os.environ.get("HELPDESK_INTERNAL_API_SECRET")
