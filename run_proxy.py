"""
run_proxy.py
Uruchamia IMAP i SMTP proxy jednocześnie w jednej pętli asyncio.

Zmienne środowiskowe:
    TUTA_IMAP_HOST   — domyślnie 0.0.0.0
    TUTA_IMAP_PORT   — domyślnie 1143
    TUTA_SMTP_HOST   — domyślnie 0.0.0.0
    TUTA_SMTP_PORT   — domyślnie 1025
    TUTA_CACHE_PATH  — domyślnie /data/tuta_cache.db
    LOG_LEVEL        — domyślnie INFO
    LOG_FILE         — jeśli ustawiony, logi tylko do pliku
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, ".")


def _load_dotenv(path: str = ".env") -> None:
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

from tuta.imap_server import IMAPServer
from tuta.smtp_server import SMTPServer


async def main() -> None:
    imap_host = os.environ.get("TUTA_IMAP_HOST", "0.0.0.0")
    imap_port = int(os.environ.get("TUTA_IMAP_PORT", "1143"))
    smtp_host = os.environ.get("TUTA_SMTP_HOST", "0.0.0.0")
    smtp_port = int(os.environ.get("TUTA_SMTP_PORT", "1025"))
    cache_path = os.environ.get("TUTA_CACHE_PATH", "/data/tuta_cache.db")

    imap = IMAPServer(host=imap_host, port=imap_port, cache_path=cache_path)
    smtp = SMTPServer(host=smtp_host, port=smtp_port)

    print(f"tuta-proxy IMAP  {imap_host}:{imap_port}")
    print(f"tuta-proxy SMTP  {smtp_host}:{smtp_port}")
    print(f"cache: {cache_path}")
    print("Zatrzymaj: Ctrl+C")

    try:
        await asyncio.gather(imap.start(), smtp.start())
    except asyncio.CancelledError:
        pass
    finally:
        await asyncio.gather(imap.stop(), smtp.stop(), return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nZatrzymano.")
