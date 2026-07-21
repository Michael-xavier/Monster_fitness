# ─── Monster Fitness — Dockerfile ───────────────────────────────────────────
# Segurança: imagem slim, usuário não-root, sem ferramentas desnecessárias.

FROM python:3.12-slim

# Metadados
LABEL maintainer="Monster Fitness Dev Team"
LABEL version="1.0"

# Variáveis de ambiente seguras
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    FLASK_DEBUG=false

WORKDIR /app

# Instalar dependências do sistema (mínimas — princípio do menor privilégio)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalar dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY app.py .
COPY templates/ templates/
COPY static/ static/

# Criar usuário não-root (princípio do menor privilégio)
RUN useradd -m -u 1001 -s /bin/sh mfapp && \
    mkdir -p /var/log/monsterfitness && \
    chown -R mfapp:mfapp /app /var/log/monsterfitness

USER mfapp

EXPOSE 5000

# Gunicorn: 3 workers, timeout 60s, sem access log no stdout (Nginx já loga)
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "3", \
     "--worker-class", "sync", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "warning", \
     "app:app"]
