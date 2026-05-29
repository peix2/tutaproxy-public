FROM python:3.11-slim

WORKDIR /app

# Zależności systemowe wymagane przez cryptography i lz4
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tuta/ ./tuta/
COPY run_proxy.py .

RUN mkdir -p /data

EXPOSE 1143 1025 5232 5233 5234

# Wewnątrz kontenera bind na 0.0.0.0 jest konieczny — port mapping Dockera
# (host 127.0.0.1:PORT → kontener PORT) nie dosięgnie 127.0.0.1 wewnątrz
# kontenera. Izolację daje docker-compose mapując porty na hosta 127.0.0.1.
ENV TUTA_IMAP_HOST=0.0.0.0 \
    TUTA_IMAP_PORT=1143 \
    TUTA_SMTP_HOST=0.0.0.0 \
    TUTA_SMTP_PORT=1025 \
    TUTA_CALDAV_HOST=0.0.0.0 \
    TUTA_CALDAV_PORT=5232 \
    TUTA_CARDDAV_HOST=0.0.0.0 \
    TUTA_CARDDAV_PORT=5233 \
    TUTA_WEBDAV_HOST=0.0.0.0 \
    TUTA_WEBDAV_PORT=5234 \
    TUTA_CACHE_PATH=/data/tuta_cache.db \
    LOG_LEVEL=INFO \
    TUTA_SYS_VERSION=150 \
    TUTA_TUTANOTA_VERSION=108 \
    TUTA_STORAGE_VERSION=14 \
    TUTA_CLIENT_VERSION=346.260428.0

CMD ["python", "run_proxy.py"]
