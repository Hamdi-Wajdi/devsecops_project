FROM python:3.10-slim

WORKDIR /app

# Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code applicatif
COPY . .

EXPOSE 5000

# Lancement de l'application Flask
CMD ["python", "app.py"]
