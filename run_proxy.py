"""
run_proxy.py
Uruchamia IMAP i SMTP proxy jednocześnie w jednej pętli asyncio.

Zmienne środowiskowe:
    TUTA_IMAP_HOST      — domyślnie 127.0.0.1 (Docker nadpisuje na 0.0.0.0)
    TUTA_IMAP_PORT      — domyślnie 1143
    TUTA_SMTP_HOST      — domyślnie 127.0.0.1
    TUTA_SMTP_PORT      — domyślnie 1025
    TUTA_CALDAV_HOST    — domyślnie 127.0.0.1
    TUTA_CALDAV_PORT    — domyślnie 5232
    TUTA_CARDDAV_HOST   — domyślnie 127.0.0.1
    TUTA_CARDDAV_PORT   — domyślnie 5233
    TUTA_WEBDAV_HOST    — domyślnie 127.0.0.1
    TUTA_WEBDAV_PORT    — domyślnie 5234
    TUTA_CACHE_PATH     — domyślnie /data/tuta_cache.db
    LOG_LEVEL           — domyślnie INFO
    LOG_FILE            — jeśli ustawiony, logi tylko do pliku
"""

import asyncio
import logging
import os
import signal
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
from tuta.caldav_server import CalDAVServer
from tuta.carddav_server import CardDAVServer
from tuta.webdav_server import WebDAVServer


async def main() -> None:
    # Defaulty 127.0.0.1 — bez TLS-a między klientem a proxy hasło Tuty
    # i całe konto byłyby narażone przy bind na 0.0.0.0. Docker nadpisuje
    # przez ENV w Dockerfile (gdzie 0.0.0.0 jest konieczne dla port mappingu).
    imap_host    = os.environ.get("TUTA_IMAP_HOST",    "127.0.0.1")
    imap_port    = int(os.environ.get("TUTA_IMAP_PORT",    "1143"))
    smtp_host    = os.environ.get("TUTA_SMTP_HOST",    "127.0.0.1")
    smtp_port    = int(os.environ.get("TUTA_SMTP_PORT",    "1025"))
    caldav_host  = os.environ.get("TUTA_CALDAV_HOST",  "127.0.0.1")
    caldav_port  = int(os.environ.get("TUTA_CALDAV_PORT",  "5232"))
    carddav_host = os.environ.get("TUTA_CARDDAV_HOST", "127.0.0.1")
    carddav_port = int(os.environ.get("TUTA_CARDDAV_PORT", "5233"))
    webdav_host  = os.environ.get("TUTA_WEBDAV_HOST",  "127.0.0.1")
    webdav_port  = int(os.environ.get("TUTA_WEBDAV_PORT",  "5234"))
    cache_path   = os.environ.get("TUTA_CACHE_PATH",   "/data/tuta_cache.db")

    imap    = IMAPServer(host=imap_host, port=imap_port, cache_path=cache_path)
    smtp    = SMTPServer(host=smtp_host, port=smtp_port)
    caldav  = CalDAVServer(host=caldav_host, port=caldav_port)
    carddav = CardDAVServer(host=carddav_host, port=carddav_port)
    webdav  = WebDAVServer(host=webdav_host, port=webdav_port)

    print(f"tuta-proxy IMAP    {imap_host}:{imap_port}")
    print(f"tuta-proxy SMTP    {smtp_host}:{smtp_port}")
    print(f"tuta-proxy CalDAV  {caldav_host}:{caldav_port}")
    print(f"tuta-proxy CardDAV {carddav_host}:{carddav_port}")
    print(f"tuta-proxy WebDAV  {webdav_host}:{webdav_port}  (Tuta Drive)")
    print(f"cache: {cache_path}")
    print("Zatrzymaj: Ctrl+C (lub SIGTERM)")

    # SIGTERM (docker stop) i SIGINT (Ctrl+C) anulują główny gather.
    # Bez SIGTERM handlera docker stop tylko zabija proces po 10s timeout —
    # graceful logout sesji w Tucie się nigdy nie wykona i sesje akumulują
    # się w UI Tuty.
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop(sig_name: str) -> None:
        if not stop_event.is_set():
            print(f"\n{sig_name} — graceful shutdown...", flush=True)
            stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _request_stop, sig.name)
        except NotImplementedError:
            # Windows nie wspiera add_signal_handler — fallback do KeyboardInterrupt
            pass

    servers = [imap, smtp, caldav, carddav, webdav]
    serve_task = asyncio.gather(*(s.start() for s in servers), return_exceptions=True)
    stop_task = asyncio.create_task(stop_event.wait())

    try:
        done, pending = await asyncio.wait(
            {serve_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        # Anuluj główne serve_task; każdy serv.start() w nim się rozpiąć (CancelledError)
        # lub zakończy bo .stop() zamknie listener.
        for t in (serve_task, stop_task):
            if not t.done():
                t.cancel()
        # Graceful shutdown z timeoutem — DELETE /sys/session per użytkownik
        # może trwać; ale nie chcemy wisieć w nieskończoność.
        try:
            await asyncio.wait_for(
                asyncio.gather(*(s.stop() for s in servers), return_exceptions=True),
                timeout=15,
            )
        except asyncio.TimeoutError:
            print("Graceful shutdown timeout (15s) — wymuszam zamknięcie.", flush=True)
        # Spokojnie odczekaj na anulowane taski
        for t in (serve_task, stop_task):
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        print("Zatrzymano.", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Fallback gdy add_signal_handler niedostępne (np. Windows)
        print("\nZatrzymano (KeyboardInterrupt).")
