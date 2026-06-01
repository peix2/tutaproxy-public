"""
Uruchamia tuta-proxy IMAP server na localhost:1143.

Użycie:
    python run_imap.py

Konfiguracja przez zmienne środowiskowe lub plik .env (opcjonalne):
    TUTA_IMAP_HOST   — domyślnie 127.0.0.1
    TUTA_IMAP_PORT   — domyślnie 1143
    TUTA_CACHE_PATH  — ścieżka do SQLite cache flag, domyślnie tuta_cache.db
    LOG_LEVEL        — domyślnie INFO (DEBUG dla szczegółów)
    LOG_FILE         — jeśli ustawiony, logi tylko do pliku
"""

import asyncio
import logging
import logging.handlers
import os
import sys

sys.path.insert(0, ".")


def _load_dotenv(path: str = ".env") -> None:
    """Wczytuje zmienne z pliku .env (jeśli istnieje). Nie nadpisuje istniejących zmiennych."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except FileNotFoundError:
        pass


_load_dotenv()

LOG_LEVEL        = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE         = os.environ.get("LOG_FILE", "")
LOG_ROTATE_BYTES = int(os.environ.get("LOG_ROTATE_BYTES", str(50 * 1024 * 1024)))
LOG_ROTATE_COUNT = int(os.environ.get("LOG_ROTATE_COUNT", "5"))

# Jeśli LOG_FILE ustawiony — tylko plik (stderr przekierowany do tego samego
# pliku przez shell powoduje podwójne wpisy).
if LOG_FILE:
    log_handlers: list[logging.Handler] = [
        logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=LOG_ROTATE_BYTES, backupCount=LOG_ROTATE_COUNT, encoding="utf-8"
        )
    ]
else:
    log_handlers = [logging.StreamHandler(sys.stderr)]

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=log_handlers,
)

from tuta.imap_server import IMAPServer


async def main():
    host = os.environ.get("TUTA_IMAP_HOST", "127.0.0.1")
    port = int(os.environ.get("TUTA_IMAP_PORT", "1143"))
    cache_path = os.environ.get("TUTA_CACHE_PATH", "tuta_cache.db")

    server = IMAPServer(host=host, port=port, cache_path=cache_path)
    print(f"tuta-proxy IMAP server starting on {host}:{port}")
    print("Zatrzymaj: Ctrl+C")

    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nZatrzymuję serwer...")
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
