FROM python:3.10-slim

WORKDIR /app

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Création d'un utilisateur non-root (droits uniquement sur /app)
RUN useradd -u 10001 -m -s /bin/bash appuser

# Copie du code applicatif
COPY --chown=appuser:appuser . .

# Droits stricts uniquement sur /app
RUN chown -R appuser:appuser /app

USER appuser

# L'application écoute sur le port 5000 (> 1024, compatible non-root)
EXPOSE 5000

# Lancement de l'application Flask
CMD ["python", "app.py"]
