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

EXPOSE 1143 1025 5232 5233

ENV TUTA_IMAP_HOST=0.0.0.0 \
    TUTA_IMAP_PORT=1143 \
    TUTA_SMTP_HOST=0.0.0.0 \
    TUTA_SMTP_PORT=1025 \
    TUTA_CALDAV_HOST=0.0.0.0 \
    TUTA_CALDAV_PORT=5232 \
    TUTA_CARDDAV_HOST=0.0.0.0 \
    TUTA_CARDDAV_PORT=5233 \
    TUTA_CACHE_PATH=/data/tuta_cache.db \
    LOG_LEVEL=INFO \
    TUTA_SYS_VERSION=150 \
    TUTA_TUTANOTA_VERSION=108 \
    TUTA_STORAGE_VERSION=14 \
    TUTA_CLIENT_VERSION=346.260428.0

CMD ["python", "run_proxy.py"]
