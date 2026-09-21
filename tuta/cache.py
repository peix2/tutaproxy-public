"""
tuta/cache.py
SQLite cache dla persystencji lokalnego stanu IMAP.

Tabele:
  local_flags     — \\Flagged i \\Answered per elementId (Tuta nie ma tych stanów w API)
  mail_uid        — trwałe UID-y IMAP per (folder, mail): nadawane w kolejności
                    PIERWSZEGO zaobserwowania maila w folderze
  folder_uidstate — UIDVALIDITY i licznik uidnext per folder

Celowo NIE cachujemy treści wiadomości — Tuta przechowuje je zaszyfrowane,
przechowywanie plaintext na dysku niszczyłoby model bezpieczeństwa E2E.

Rejestr UID rozwiązuje wymóg RFC 3501: UID musi rosnąć monotonicznie w kolejności
pojawiania się maila w folderze. Timestamp z GeneratedId tego nie gwarantuje —
mail „wpadający" do folderu z opóźnieniem, ale z wcześniejszym receivedDate,
dostawał niższy UID i stawał się niewidoczny dla klienta synchronizującego
przyrostowo (UID FETCH <uidnext>:*).
"""

import sqlite3
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS local_flags (
    element_id TEXT PRIMARY KEY,
    flagged    INTEGER NOT NULL DEFAULT 0,
    answered   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mail_uid (
    folder_id  TEXT NOT NULL,
    element_id TEXT NOT NULL,
    uid        INTEGER NOT NULL,
    PRIMARY KEY (folder_id, element_id)
);
CREATE INDEX IF NOT EXISTS idx_mail_uid_folder ON mail_uid(folder_id);

CREATE TABLE IF NOT EXISTS folder_uidstate (
    folder_id   TEXT PRIMARY KEY,
    uidvalidity INTEGER NOT NULL,
    uidnext     INTEGER NOT NULL DEFAULT 1
);
"""


class TutaCache:
    """
    Thread-safe SQLite cache (check_same_thread=False).
    Jeden obiekt współdzielony między połączeniami IMAP — dzięki temu rejestr UID
    jest spójny między połączeniami puli. Metody UID są synchroniczne (bez await),
    więc w pętli asyncio wykonują się atomowo (read-modify-write uidnext bez wyścigu).
    """

    def __init__(self, db_path: str | Path = "tuta_cache.db") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        logger.debug(f"Cache: {self._path}")

    # ---------------------------------------------------------------- flagi

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

    # ------------------------------------------------------------- rejestr UID

    def _ensure_uidstate(self, folder_id: str) -> None:
        """Tworzy wiersz stanu folderu przy pierwszym dostępie. UIDVALIDITY = bieżący
        epoch: świeży build → nowa wartość ≠ stare md5-owe → Thunderbird raz
        resynchronizuje folder. Wipe cache → nowe UIDVALIDITY → też resync (poprawne)."""
        self._conn.execute(
            "INSERT OR IGNORE INTO folder_uidstate (folder_id, uidvalidity, uidnext)"
            " VALUES (?, ?, 1)",
            (folder_id, int(time.time())),
        )
        self._conn.commit()

    def get_uidvalidity(self, folder_id: str) -> int:
        """Stała wartość UIDVALIDITY folderu (generowana raz przy pierwszym dostępie)."""
        self._ensure_uidstate(folder_id)
        row = self._conn.execute(
            "SELECT uidvalidity FROM folder_uidstate WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()
        return int(row[0])

    def get_uidnext(self, folder_id: str) -> int:
        """Następny UID do nadania w folderze (== max nadany + 1, min. 1)."""
        self._ensure_uidstate(folder_id)
        row = self._conn.execute(
            "SELECT uidnext FROM folder_uidstate WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()
        return int(row[0])

    def get_uid(self, folder_id: str, element_id: str) -> int | None:
        """Zwraca nadany UID lub None (bez nadawania nowego)."""
        row = self._conn.execute(
            "SELECT uid FROM mail_uid WHERE folder_id = ? AND element_id = ?",
            (folder_id, element_id),
        ).fetchone()
        return int(row[0]) if row else None

    def uid_for(self, folder_id: str, element_id: str) -> int:
        """Zwraca trwały UID maila w folderze; nadaje nowy (uidnext++) jeśli brak.
        Używane przy wstawianiu pojedynczego maila (IDLE / move-into-folder)."""
        existing = self.get_uid(folder_id, element_id)
        if existing is not None:
            return existing
        uid = self.get_uidnext(folder_id)
        self._conn.execute(
            "INSERT OR IGNORE INTO mail_uid (folder_id, element_id, uid) VALUES (?, ?, ?)",
            (folder_id, element_id, uid),
        )
        self._conn.execute(
            "UPDATE folder_uidstate SET uidnext = ? WHERE folder_id = ?",
            (uid + 1, folder_id),
        )
        self._conn.commit()
        return uid

    def assign_uids(self, folder_id: str, ordered_element_ids: list[str]) -> dict[str, int]:
        """Nadaje trwałe, monotonicznie rosnące UID-y mailom folderu.
        Istniejące zwraca bez zmian; nowe — w podanej kolejności (przy pierwszej
        synchronizacji: receivedDate rosnąco) — dostają kolejne wartości uidnext.
        Zwraca mapę element_id → uid dla WSZYSTKICH żądanych ID.

        Wywoływane przy SELECT/STATUS: jednorazowy nadmiarowy odczyt całego rejestru
        folderu do pamięci (indeks po folder_id), potem numeracja bez dodatkowych zapytań.
        """
        self._ensure_uidstate(folder_id)
        rows = self._conn.execute(
            "SELECT element_id, uid FROM mail_uid WHERE folder_id = ?",
            (folder_id,),
        ).fetchall()
        existing = {r[0]: int(r[1]) for r in rows}
        uidnext = self._conn.execute(
            "SELECT uidnext FROM folder_uidstate WHERE folder_id = ?",
            (folder_id,),
        ).fetchone()[0]

        result: dict[str, int] = {}
        to_insert: list[tuple[str, str, int]] = []
        for eid in ordered_element_ids:
            if eid in existing:
                result[eid] = existing[eid]
            else:
                result[eid] = uidnext
                existing[eid] = uidnext          # chroni przed duplikatem w wejściu
                to_insert.append((folder_id, eid, uidnext))
                uidnext += 1

        if to_insert:
            self._conn.executemany(
                "INSERT OR IGNORE INTO mail_uid (folder_id, element_id, uid) VALUES (?, ?, ?)",
                to_insert,
            )
            self._conn.execute(
                "UPDATE folder_uidstate SET uidnext = ? WHERE folder_id = ?",
                (uidnext, folder_id),
            )
            self._conn.commit()
        return result

    def close(self) -> None:
        self._conn.close()
