"""
run_carddav.py
Uruchamia serwer CardDAV dla konta Tuta.

Zmienne środowiskowe (z .env):
  TUTA_CARDDAV_HOST  — adres nasłuchu (default: 127.0.0.1)
  TUTA_CARDDAV_PORT  — port (default: 5233)
  LOG_LEVEL          — poziom logów (default: INFO)
  LOG_FILE           — plik logów (jeśli ustawiony, tylko plik, nie stderr)

Użycie:
  PYTHONPATH=.venv/lib/python3.11/site-packages .venv/bin/python run_carddav.py

Konfiguracja Thunderbirda (TbSync):
  CardDAV server: http://localhost:5233/
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

from tuta.carddav_server import CardDAVServer

HOST = os.environ.get("TUTA_CARDDAV_HOST", "127.0.0.1")
PORT = int(os.environ.get("TUTA_CARDDAV_PORT", "5233"))


async def main() -> None:
    server = CardDAVServer(host=HOST, port=PORT)
    await server.start()
    print(f"CardDAV server: http://{HOST}:{PORT}/", flush=True)
    print("Zatrzymaj: Ctrl+C", flush=True)
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


if __name__ == "__main__":
    asyncio.run(main())
