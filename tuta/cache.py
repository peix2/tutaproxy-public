"""
tuta/cache.py
SQLite cache dla persystencji lokalnych flag IMAP.

Tabela:
  local_flags — \Flagged i \Answered per elementId (Tuta nie ma tych stanów w API)

Celowo NIE cachujemy treści wiadomości — Tuta przechowuje je zaszyfrowane,
przechowywanie plaintext na dysku niszczyłoby model bezpieczeństwa E2E.
"""

import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS local_flags (
    element_id TEXT PRIMARY KEY,
    flagged    INTEGER NOT NULL DEFAULT 0,
    answered   INTEGER NOT NULL DEFAULT 0
);
"""


class TutaCache:
    """
    Thread-safe SQLite cache (check_same_thread=False).
    Jeden obiekt współdzielony między połączeniami IMAP.
    """

    def __init__(self, db_path: str | Path = "tuta_cache.db") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.debug(f"Cache: {self._path}")

    def get_local_flags(self, element_id: str) -> tuple[bool, bool]:
        """Zwraca (flagged, answered) dla danego elementId."""
        row = self._conn.execute(
            "SELECT flagged, answered FROM local_flags WHERE element_id = ?",
            (element_id,),
        ).fetchone()
        return (bool(row[0]), bool(row[1])) if row else (False, False)

    def set_local_flags(self, element_id: str, flagged: bool, answered: bool) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO local_flags (element_id, flagged, answered)"
            " VALUES (?, ?, ?)",
            (element_id, int(flagged), int(answered)),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
