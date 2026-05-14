"""
Uruchamia tuta-proxy SMTP server na localhost:1025.

Użycie:
    python run_smtp.py

Konfiguracja przez zmienne środowiskowe lub plik .env (opcjonalne):
    TUTA_SMTP_HOST  — domyślnie 127.0.0.1
    TUTA_SMTP_PORT  — domyślnie 1025
    LOG_LEVEL       — domyślnie INFO (DEBUG dla szczegółów)
    LOG_FILE        — jeśli ustawiony, logi tylko do pliku
"""

import asyncio
import logging
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

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FILE = os.environ.get("LOG_FILE", "")

if LOG_FILE:
    log_handlers: list[logging.Handler] = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
else:
    log_handlers = [logging.StreamHandler(sys.stderr)]

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=log_handlers,
)

from tuta.smtp_server import SMTPServer


async def main():
    host = os.environ.get("TUTA_SMTP_HOST", "127.0.0.1")
    port = int(os.environ.get("TUTA_SMTP_PORT", "1025"))

    server = SMTPServer(host=host, port=port)
    print(f"tuta-proxy SMTP server starting on {host}:{port}")
    print("Zatrzymaj: Ctrl+C")

    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nZatrzymuję serwer...")
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
