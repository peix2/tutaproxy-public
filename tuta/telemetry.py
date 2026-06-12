"""
Klient telemetrii tutaproxy.

Przy starcie proxy (raz na 24h):
  1. Loguje dokładnie co jest wysyłane — pełna transparentność.
  2. Wysyła ping do serwera zliczającego (UUID instalacji + wersja).
  3. Sprawdza GitHub Releases czy dostępna jest nowsza wersja.

Wyłącz: TUTAPROXY_TELEMETRY=false w .env lub docker-compose.yml
"""

import asyncio
import json
import logging
import os
import ssl
import time
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

_PING_URL    = "https://176.121.81.52:442/ping"
_GITHUB_API  = "https://api.github.com/repos/peix2/tutaproxy-public/releases/latest"
_CERTS_DIR   = Path(__file__).parent / "certs"
_PING_INTERVAL = 86400  # 24h


def _id_file() -> Path:
    # Przechowuj w tym samym katalogu co cache bazy — trwały między restartami kontenera
    cache = os.environ.get("TUTA_CACHE_PATH", "")
    if cache:
        return Path(cache).parent / ".tutaproxy-id"
    return Path(".tutaproxy-id")


def _current_version() -> str:
    from tuta.version import __version__
    return __version__


def _load_install_id() -> tuple[str, float, str]:
    """Zwraca (uuid, last_ping_ts, last_pinged_version). Tworzy plik przy pierwszym wywołaniu."""
    if _id_file().exists():
        try:
            data = json.loads(_id_file().read_text())
            return data["id"], float(data.get("last_ping", 0)), data.get("last_version", "")
        except Exception:
            pass
    new_id = str(uuid.uuid4())
    _id_file().write_text(json.dumps({"id": new_id, "last_ping": 0, "last_version": ""}))
    return new_id, 0.0, ""


def _save_last_ping(install_id: str, version: str) -> None:
    try:
        _id_file().write_text(json.dumps({
            "id": install_id,
            "last_ping": time.time(),
            "last_version": version,
        }))
    except Exception:
        pass


def _is_newer(latest: str, current: str) -> bool:
    """Zwraca True jeśli latest > current (format X.Y.Z)."""
    try:
        return (
            tuple(int(x) for x in latest.split("."))
            > tuple(int(x) for x in current.split("."))
        )
    except ValueError:
        return False


def _server_pin_context() -> ssl.SSLContext | None:
    """Buduje SSLContext pinujący serwer telemetrii do prywatnego CA.

    Bez certyfikatu klienta: projekt jest open-source (AGPL), więc dołączenie
    klucza klienta nie dałoby realnego uwierzytelnienia — każdy ma dostęp do repo.
    Pinning serwera (cafile=ca.crt) zapewnia poufność kanału i pewność, że klient
    łączy się z właściwym serwerem (cert ma IP w SAN). None jeśli ca.crt nie istnieje.
    """
    ca = _CERTS_DIR / "ca.crt"
    if not ca.exists():
        return None
    return ssl.create_default_context(cafile=str(ca))


async def _do_ping(install_id: str, version: str) -> None:
    ctx = _server_pin_context()
    if ctx is None:
        logger.debug("Telemetria — brak ca.crt w %s, ping pominięty.", _CERTS_DIR)
        return
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                _PING_URL,
                json={"id": install_id, "version": version},
                ssl=ctx,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    _save_last_ping(install_id, version)
    except Exception as e:
        logger.debug("Telemetria — błąd pinga: %s", e)


async def _check_version(current: str) -> None:
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                _GITHUB_API,
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    latest = data.get("tag_name", "").lstrip("v")
                    if latest and _is_newer(latest, current):
                        logger.warning(
                            "[AKTUALIZACJA] Dostępna nowsza wersja tutaproxy: %s "
                            "(zainstalowana: %s). "
                            "https://github.com/peix2/tutaproxy-public/releases",
                            latest, current,
                        )
    except Exception as e:
        logger.debug("Telemetria — błąd sprawdzania wersji: %s", e)


async def startup() -> None:
    """Wywołaj raz przy starcie proxy. Loguje status i uruchamia ping+wersję w tle."""
    enabled = os.environ.get("TUTAPROXY_TELEMETRY", "true").lower() not in ("false", "0", "no")
    version = _current_version()

    if not enabled:
        logger.info(
            "[TELEMETRIA] Wyłączona (TUTAPROXY_TELEMETRY=false). "
            "Sprawdzanie wersji pominięte."
        )
        return

    install_id, last_ping, last_version = _load_install_id()

    logger.info(
        "[TELEMETRIA] Sprawdzanie wersji i liczenie instalacji: WŁĄCZONE\n"
        "             Wysyłane do %s:\n"
        "               %s\n"
        "             To wszystko — więcej danych nie jest zbieranych ani przesyłanych.\n"
        "             Wyłącz: TUTAPROXY_TELEMETRY=false w .env lub docker-compose.yml",
        _PING_URL,
        json.dumps({"id": install_id, "version": version}),
    )

    asyncio.create_task(_check_version(version))
    # Pinguj jeśli minęło 24h LUB wersja się zmieniła (np. po aktualizacji)
    if (time.time() - last_ping) >= _PING_INTERVAL or last_version != version:
        asyncio.create_task(_do_ping(install_id, version))
