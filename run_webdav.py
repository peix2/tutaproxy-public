"""
run_webdav.py
Uruchamia serwer WebDAV dla Tuta Drive.

Zmienne środowiskowe (z .env):
  TUTA_WEBDAV_HOST  — adres nasłuchu (default: 127.0.0.1)
  TUTA_WEBDAV_PORT  — port (default: 5234)
  LOG_LEVEL         — poziom logów (default: INFO)
  LOG_FILE          — plik logów (jeśli ustawiony, tylko plik, nie stderr)

Użycie:
  PYTHONPATH=.venv/lib/python3.11/site-packages .venv/bin/python run_webdav.py

Montowanie na Linuxie:
  sudo mount -t davfs http://localhost:5234/ /mnt/tuta-drive
  # lub przez /etc/fstab:
  # http://localhost:5234/ /mnt/tuta-drive davfs noauto,user 0 0

  # rclone (rekomendowany — nie wymaga root):
  rclone config  # dodaj WebDAV remote z URL http://localhost:5234/

  # GNOME Files (Nautilus):
  #   Ctrl+L → dav://localhost:5234/
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

from tuta.webdav_server import WebDAVServer

HOST = os.environ.get("TUTA_WEBDAV_HOST", "127.0.0.1")
PORT = int(os.environ.get("TUTA_WEBDAV_PORT", "5234"))


async def main() -> None:
    server = WebDAVServer(host=HOST, port=PORT)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
