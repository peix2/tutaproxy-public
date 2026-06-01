"""
run_caldav.py
Uruchamia serwer CalDAV dla konta Tuta.

Zmienne środowiskowe (z .env):
  TUTA_CALDAV_HOST  — adres nasłuchu (default: 127.0.0.1)
  TUTA_CALDAV_PORT  — port (default: 5232)
  LOG_LEVEL         — poziom logów (default: INFO)
  LOG_FILE          — plik logów (jeśli ustawiony, tylko plik, nie stderr)

Użycie:
  PYTHONPATH=.venv/lib/python3.10/site-packages /usr/bin/python3 run_caldav.py

Konfiguracja Thunderbirda (Lightning):
  Plik → Nowy → Kalendarz → Sieć → CalDAV
  Adres: http://localhost:5232/
  Użytkownik: twój@tuta.com
"""

import asyncio
import logging
import logging.handlers
import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Konfiguracja logowania
log_level        = os.environ.get("LOG_LEVEL", "INFO").upper()
log_file         = os.environ.get("LOG_FILE", "")
log_rotate_bytes = int(os.environ.get("LOG_ROTATE_BYTES", str(50 * 1024 * 1024)))
log_rotate_count = int(os.environ.get("LOG_ROTATE_COUNT", "5"))

handlers = []
if log_file:
    handlers.append(
        logging.handlers.RotatingFileHandler(
            log_file, maxBytes=log_rotate_bytes, backupCount=log_rotate_count, encoding="utf-8"
        )
    )
else:
    handlers.append(logging.StreamHandler(sys.stderr))

logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=handlers,
)

from tuta.caldav_server import CalDAVServer

HOST = os.environ.get("TUTA_CALDAV_HOST", "127.0.0.1")
PORT = int(os.environ.get("TUTA_CALDAV_PORT", "5232"))


async def main() -> None:
    server = CalDAVServer(host=HOST, port=PORT)
    await server.start()
    print(f"CalDAV server: http://{HOST}:{PORT}/", flush=True)
    print("Zatrzymaj: Ctrl+C", flush=True)
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    asyncio.run(main())
