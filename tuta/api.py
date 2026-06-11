"""
tuta/api.py
Klient REST API serwisu Tuta (app.tuta.com).

Protokół ustalony na podstawie analizy ruchu HTTP (mitmproxy, maj 2026):
  - Nagłówek v: 150 (sys), 108 (tutanota)
  - Nagłówki cp: 5, cv: 346.260428.0
  - Ciała JSON używają NUMERYCZNYCH kluczy zamiast nazw pól
  - Salt zwracany w zwykłym base64 (nie url-safe)

Mapowanie pól (ustalono empirycznie + kod TypeScript Tuty):
  saltservice request:  418=kdfVersion("0"), 419=mailAddress
  saltservice response: 421=kdfVersion, 422=salt(base64), 2133=kdfType(0=bcrypt,1=argon2)
  sessionservice req:   1212=authType("0"), 1213=mailAddress,
                        1214=verifier, 1215=clientIdentifier,
                        1216=null, 1217=null, 1218=[], 1417=null
  sessionservice resp:  1220=type, 1221=accessToken, 1222=[],
                        1223=[userId]
  user:                 96=memberships, 91=symEncGKey (user.userGroup)
  membership:           1030=groupType, 29=group(listId)
  mailboxgrouproot:     699=mailbox(elementId)
  mailbox:              443=folders aggregate [{1461:listId,1462:[elementId]}]
  mailfolder:           431=_id, 432=mails(listId), 434=name(enc), 436=folderType
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

import aiohttp

from .crypto import (
    compute_verifier,
    derive_session_key,
    UserKeys,
    aes128_decrypt,
    aes_encrypt_tuta,
    aes_decrypt_tuta,
    compress_lz4,
    b64url_decode,
    b64url_encode,
    decrypt_user_group_key,
    pq_encapsulate_bucket_key,
    pq_decapsulate_bucket_key,
    reconstruct_kyber_sk,
    rsa_oaep_encrypt_tuta,
    TUTA_AES128_KEY_LEN,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stałe
# ---------------------------------------------------------------------------

TUTA_BASE_URL = "https://app.tuta.com"

# Wersje modeli — nadpisywalne przez zmienne środowiskowe.
# Gdy Tuta zbumpuje wersję, ustaw TUTA_SYS_VERSION / TUTA_TUTANOTA_VERSION / TUTA_CLIENT_VERSION
# bez zmiany kodu. Proxy wykryje niezgodność wersji i zaloguje ostrzeżenie.
SYS_MODEL_VERSION     = os.environ.get("TUTA_SYS_VERSION",      "150")
TUTANOTA_MODEL_VERSION = os.environ.get("TUTA_TUTANOTA_VERSION", "108")
STORAGE_MODEL_VERSION  = os.environ.get("TUTA_STORAGE_VERSION",  "14")
CLIENT_VERSION         = os.environ.get("TUTA_CLIENT_VERSION",   "346.260428.0")
DRIVE_MODEL_VERSION    = os.environ.get("TUTA_DRIVE_VERSION",    "4")

# Nagłówki dla endpointów sys
TUTA_HEADERS = {
    "v": SYS_MODEL_VERSION,
    "cp": "5",
    "cv": CLIENT_VERSION,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Nagłówki dla endpointów tutanota
TUTANOTA_HEADERS = {
    "v": TUTANOTA_MODEL_VERSION,
    "cp": "5",
    "cv": CLIENT_VERSION,
    "Content-Type": "application/json",
    "Accept": "application/json",
}

# Nagłówki dla endpointów drive (GroupType.File = "7", ArchiveDataType.DriveFile = "4")
DRIVE_HEADERS = {
    "v": DRIVE_MODEL_VERSION,
    "cp": "5",
    "cv": CLIENT_VERSION,
    "Content-Type": "application/json",
    "Accept": "application/json",
}
FILE_GROUP_TYPE = "7"
ARCHIVE_DATA_TYPE_DRIVE = "4"
BLOB_CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB — maksymalny rozmiar pojedynczego bloba (limit serwera Tuta)

# ---------------------------------------------------------------------------
# Typy danych
# ---------------------------------------------------------------------------

@dataclass
class Session:
    access_token: str
    user_id: str                   # elementId użytkownika
    user_group_key: bytes          # odszyfrowany klucz grupy (w RAM)
    user_keys: Optional[UserKeys] = None
    mail_group_id: Optional[str] = None          # elementId grupy mail (wypełniane przez get_folders)
    mail_group_key_version: str = "0"            # wersja klucza grupy mail (pole 2246 w GroupMembership)
    user_email: str = ""                         # adres email zalogowanego użytkownika
    # Klucze asymetryczne do deszyfrowania TutaCrypt PQ (pole 1310)
    priv_ecc: Optional[bytes] = None             # X25519 klucz prywatny (32B)
    pub_ecc: Optional[bytes] = None              # X25519 klucz publiczny (32B)
    pub_kyber_tuta: Optional[bytes] = None       # Kyber klucz publiczny w formacie Tuty (1572B)
    kyber_sk: Optional[bytes] = None             # Pełny klucz prywatny Kyber1024 (3168B)
    user_key_version: str = "0"                  # Wersja klucza grupy użytkownika (pole 2271)
    user_group_id: str = ""                      # elementId grupy użytkownika (potrzebne dla Secure External)


@dataclass
class MailFolder:
    id: str
    mail_list_id: str              # listId z entries (pole 1459)
    name_encrypted: str            # surowy base64 z API (pole 435, zaszyfrowane przez folder_session_key)
    folder_type: str               # 1=INBOX,2=SENT,3=TRASH,4=ARCHIVE,5=SPAM,6=DRAFT,0=własny
    owner_enc_session_key: str = ""  # pole 434 — _ownerEncSessionKey (szyfruje pole 435)
    folder_list_id: str = ""       # listId samego folderu (fid[0] z pola 431) — potrzebne dla MoveMailService
    owner_key_version: str = "0"   # pole 1399 — wersja klucza grupy szyfrującego session key
    permissions: str = ""          # pole 432 — _permissions (wymagane przy PUT)
    kdf_nonce: Optional[str] = None  # pole 1847 — _kdfNonce
    parent_folder_raw: Optional[list] = None  # pole 439 — parentFolder (ZeroOrOne), [] lub [[listId, elemId]]
    _name: Optional[str] = None


@dataclass
class RawMail:
    """Surowe dane maila z API — przed deszyfrowaniem."""
    id: str
    list_id: str
    raw: dict                      # pełny obiekt z API


# ---------------------------------------------------------------------------
# Klient
# ---------------------------------------------------------------------------

class TutaClient:
    """
    Asynchroniczny klient API Tuty.

    Użycie:
        async with TutaClient() as client:
            session = await client.login("user@tutamail.com", "hasło")
            folders = await client.get_folders(session)
    """

    def __init__(self, base_url: str = TUTA_BASE_URL):
        self.base_url = base_url
        self._http: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            import ssl, certifi
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        except ImportError:
            connector = None
        self._http = aiohttp.ClientSession(headers=TUTA_HEADERS, timeout=timeout, connector=connector)
        return self

    async def __aexit__(self, *_):
        if self._http:
            await self._http.close()

    # -----------------------------------------------------------------------
    # HTTP helpers
    # -----------------------------------------------------------------------

    def _url(self, app: str, service: str, *ids: str) -> str:
        path = f"/rest/{app}/{service}"
        for i in ids:
            path += f"/{i}"
        return self.base_url + path

    @staticmethod
    def _check_version_mismatch(status: int, body: str) -> None:
        """Loguje ostrzeżenie przy HTTP 412 — Tuta zwraca to dla niezgodności wersji modelu."""
        if status == 412:
            logger.warning(
                "Możliwa niezgodność wersji API Tuty (HTTP %d). "
                "Aktualne wersje: sys=%s tutanota=%s storage=%s client=%s. "
                "Ustaw TUTA_SYS_VERSION / TUTA_TUTANOTA_VERSION / TUTA_CLIENT_VERSION "
                "lub zaktualizuj proxy.",
                status, SYS_MODEL_VERSION, TUTANOTA_MODEL_VERSION,
                STORAGE_MODEL_VERSION, CLIENT_VERSION,
            )

    async def _get(self, url: str, token: str = "", params: dict = None) -> Any:
        """GET dla endpointów sys (v=150)."""
        headers = {"accessToken": token} if token else {}
        async with self._http.get(url, headers=headers, params=params) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            body = await r.text()
            self._check_version_mismatch(r.status, body)
            raise _api_error(r.status, body)

    async def _get_tutanota(self, url: str, token: str, params: dict = None) -> Any:
        """GET dla endpointów tutanota (v=108)."""
        headers = {
            "accessToken": token,
            **TUTANOTA_HEADERS,
        }
        async with self._http.get(url, headers=headers, params=params) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            body = await r.text()
            self._check_version_mismatch(r.status, body)
            raise _api_error(r.status, body)

    async def _post(self, url: str, body: dict, token: str = "") -> Any:
        headers = {"accessToken": token} if token else {}
        async with self._http.post(url, json=body, headers=headers) as r:
            if r.status in (200, 201):
                return await r.json(content_type=None)
            text = await r.text()
            self._check_version_mismatch(r.status, text)
            raise _api_error(r.status, text)

    async def _delete(self, url: str, token: str) -> None:
        async with self._http.delete(
            url, headers={"accessToken": token}
        ) as r:
            if r.status not in (200, 204):
                body = await r.text()
                self._check_version_mismatch(r.status, body)
                raise _api_error(r.status, body)

    # -----------------------------------------------------------------------
    # Login
    # -----------------------------------------------------------------------

    async def login(self, email: str, password: str) -> Session:
        """
        Loguje użytkownika. Przepływ:
          1. GET saltservice  → salt + kdfType
          2. Oblicz verifier lokalnie (argon2id)
          3. POST sessionservice → accessToken + userId
          4. GET user → zaszyfrowane klucze
          5. Odszyfruj klucze lokalnie
        """
        logger.info(f"Login: {email}")

        # Krok 1 — salt
        salt_url = self._url("sys", "saltservice")
        params = {"_body": f'{{"418":"0","419":"{email}"}}'}
        salt_resp = await self._get(salt_url, params=params)

        # Pole 2133 = kdfType: "0"=bcrypt, "1"=argon2id
        # Pole 421  = kdfVersion (zawsze "0", nie mylić z kdfType)
        kdf_version = int(salt_resp.get("2133", salt_resp.get("421", "0")))
        salt_b64 = salt_resp.get("422", "")
        salt = base64.b64decode(salt_b64)
        logger.debug(f"kdfVersion={kdf_version}, salt={salt_b64[:8]}...")

        # Krok 2 — verifier
        verifier = compute_verifier(password, salt, kdf_version)
        logger.debug(f"verifier={verifier[:8]}...")

        # Krok 3 — sesja
        session_url = self._url("sys", "sessionservice")
        session_body = {
            "1212": "0",           # authType = password
            "1213": email,
            "1214": verifier,      # base64url
            "1215": "tuta-proxy",  # clientIdentifier
            "1216": None,
            "1217": None,
            "1218": [],
            "1417": None,
        }
        session_resp = await self._post(session_url, session_body)

        access_token = session_resp.get("1221", "")
        user_id_list = session_resp.get("1223", [""])
        user_id = user_id_list[-1] if user_id_list else ""
        logger.info(f"Sesja OK, userId={user_id}")

        # Krok 4 & 5 — klucze użytkownika
        user_group_key = await self._load_user_keys(
            access_token, user_id, password, salt, kdf_version
        )

        session = Session(
            access_token=access_token,
            user_id=user_id,
            user_group_key=user_group_key,
            user_email=email,
        )

        # Krok 6 — klucze asymetryczne do TutaCrypt PQ decapsulation
        await self._load_pq_keys(session)

        return session

    async def _load_user_keys(
        self,
        token: str,
        user_id: str,
        password: str,
        salt: bytes,
        kdf_version: int,
    ) -> bytes:
        """Pobiera dane użytkownika i odszyfrowuje klucz grupy."""
        user_url = self._url("sys", "user", user_id)
        try:
            user_data = await self._get(user_url, token=token)
        except TutaAPIError as e:
            logger.warning(f"Nie udało się pobrać danych użytkownika: {e}")
            return b"\x00" * 32

        # symEncGKey jest w user.userGroup (pole 95[0]['27']), nie w polu 91
        # Pole 91 to stary format, pole 95 to GroupMembership z aktualnym kluczem
        user_group_list = user_data.get("95", [])
        if isinstance(user_group_list, list) and user_group_list:
            user_group = user_group_list[0]
        else:
            user_group = user_group_list
        enc_group_key_b64 = user_group.get("27", "") if isinstance(user_group, dict) else ""

        # Fallback do starego pola 91
        if not enc_group_key_b64:
            enc_group_key_b64 = user_data.get("91", "")

        logger.debug(f"symEncGKey: {enc_group_key_b64[:20]}...")

        if not enc_group_key_b64:
            logger.warning("Nie znaleziono symEncGKey — klucze będą niedostępne")
            return b"\x00" * 32

        try:
            enc_group_key = base64.b64decode(enc_group_key_b64)
            logger.debug(f"symEncGKey bytes: {enc_group_key.hex()[:32]}... len={len(enc_group_key)}")
            return decrypt_user_group_key(password, salt, kdf_version, enc_group_key)
        except Exception as e:
            logger.error(f"Błąd deszyfrowania klucza grupy: {e}")
            return b"\x00" * 32

    async def _load_pq_keys(self, session: Session) -> None:
        """
        Ładuje i odszyfrowuje klucze asymetryczne ECC + Kyber z grupy użytkownika.
        Klucze są potrzebne do TutaCrypt PQ decapsulation (pole 1310 w mailu).
        Ustawia session.priv_ecc, pub_ecc, pub_kyber_tuta, kyber_sk.
        """
        from .crypto import reconstruct_kyber_sk

        try:
            user_data = await self._get(
                self._url("sys", "user", session.user_id),
                token=session.access_token
            )
            user_group_list = user_data.get("95", [])
            ug = user_group_list[0] if isinstance(user_group_list, list) and user_group_list else {}
            g_ref = ug.get("29", [""])
            user_group_id = g_ref[-1] if isinstance(g_ref, list) else g_ref

            group_data = await self._get(
                self._url("sys", "group", user_group_id),
                token=session.access_token
            )
            current_keys = group_data.get("13", {})
            if isinstance(current_keys, list):
                current_keys = current_keys[0] if current_keys else {}

            pub_ecc_raw    = base64.b64decode(current_keys.get("2144", "") or "")
            enc_priv_ecc   = base64.b64decode(current_keys.get("2145", "") or "")
            pub_kyber_tuta = base64.b64decode(current_keys.get("2146", "") or "")
            enc_priv_kyber = base64.b64decode(current_keys.get("2147", "") or "")

            if not enc_priv_ecc or not enc_priv_kyber:
                logger.warning("Brak kluczy asymetrycznych w grupie — TutaCrypt PQ niedostępny")
                return

            priv_ecc       = aes_decrypt_tuta(session.user_group_key, enc_priv_ecc)
            priv_kyber_raw = aes_decrypt_tuta(session.user_group_key, enc_priv_kyber)
            kyber_sk       = reconstruct_kyber_sk(priv_kyber_raw, pub_kyber_tuta)

            session.priv_ecc        = priv_ecc
            session.pub_ecc         = pub_ecc_raw
            session.pub_kyber_tuta  = pub_kyber_tuta
            session.kyber_sk        = kyber_sk
            session.user_key_version = str(group_data.get("2271", "0") or "0")
            session.user_group_id   = user_group_id
            logger.info("Klucze PQ załadowane: priv_ecc=%dB kyber_sk=%dB kv=%s",
                        len(priv_ecc), len(kyber_sk), session.user_key_version)
        except Exception as e:
            logger.warning("Nie udało się załadować kluczy PQ: %s", e)

    async def logout(self, session: Session) -> None:
        url = self._url("sys", "session", session.access_token)
        try:
            await self._delete(url, session.access_token)
        except TutaAPIError:
            pass
        logger.info("Wylogowano")

    # -----------------------------------------------------------------------
    # Foldery
    # -----------------------------------------------------------------------

    async def get_folders(self, session: Session) -> list[MailFolder]:
        """Pobiera listę folderów skrzynki."""
        # Krok 1: znajdz mail group id z memberships (pole 96, groupType=5)
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token
        )
        mail_group_id = None
        mail_group_key_version = "0"
        for m in user_data.get("96", []):
            if m.get("1030") == "5":  # mail group
                g = m.get("29", [""])
                mail_group_id = g[-1] if isinstance(g, list) else g
                mail_group_key_version = str(m.get("2246", "0") or "0")
                break
        if not mail_group_id:
            raise TutaAPIError(0, "Nie znaleziono grupy mailbox")
        session.mail_group_id = mail_group_id
        session.mail_group_key_version = mail_group_key_version
        logger.debug(f"mail_group_id={mail_group_id}, mail_group_key_version={mail_group_key_version}")

        # Krok 2: mailboxgrouproot (wymaga v=108)
        root_data = await self._get_tutanota(
            self._url("tutanota", "mailboxgrouproot", mail_group_id),
            token=session.access_token
        )
        # Pole 699 = mailbox elementId
        mb_ref = root_data.get("699", "")
        mailbox_id = mb_ref[-1] if isinstance(mb_ref, list) else mb_ref

        # Krok 3: mailbox
        mailbox_data = await self._get_tutanota(
            self._url("tutanota", "mailbox", mailbox_id),
            token=session.access_token
        )
        # Pole 443 = folders aggregate [{1461:listId, 1462:[elementId]}]
        folders_agg = mailbox_data.get("443", [])
        if not folders_agg:
            raise TutaAPIError(0, "Nie znaleziono referencji do folderów")
        fl = folders_agg[0].get("442", [""])
        folders_list_id = fl[-1] if isinstance(fl, list) else fl

        # Krok 4: lista folderów (nowy endpoint: mailset zamiast mailfolder)
        raw_folders = await self._get_tutanota(
            self._url("tutanota", "mailset", folders_list_id),
            token=session.access_token,
            params={"start": "AAAAAAAAAAAA", "count": "100", "reverse": "false"}
        )

        result = []
        for rf in (raw_folders if isinstance(raw_folders, list) else []):
            fid = rf.get("431", ["", ""])  # _id = [listId, elementId]
            # 434 = _ownerEncSessionKey (szyfruje pole 435)
            # 435 = name (zaszyfrowane przez klucz z pola 434)
            # 1459 = entries (LIST_ASSOCIATION do MailSetEntry)
            entries_ref = rf.get("1459", "")
            # LIST_ASSOCIATION w API może być stringiem lub listą z jednym ID
            if isinstance(entries_ref, list):
                entries_ref = entries_ref[-1] if entries_ref else ""
            result.append(MailFolder(
                id=fid[1] if isinstance(fid, list) and len(fid) > 1 else fid,
                folder_list_id=fid[0] if isinstance(fid, list) and len(fid) > 0 else "",
                mail_list_id=entries_ref,
                name_encrypted=rf.get("435", ""),
                folder_type=rf.get("436", "0"),
                owner_enc_session_key=rf.get("434", ""),
                owner_key_version=str(rf.get("1399", "0") or "0"),
                permissions=rf.get("432", ""),
                kdf_nonce=rf.get("1847"),
                parent_folder_raw=rf.get("439", []),
            ))

        logger.info(f"Pobrano {len(result)} folderów")
        return result

    async def get_mail_bags(self, session: Session) -> list[str]:
        """
        Zwraca listę list ID maili ze wszystkich MailBagów w mailboxie.
        Mailbox ma currentMailBag (1464) i archivedMailBags (1463) — skanujemy oba.
        """
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token
        )
        mail_group_id = None
        for m in user_data.get("96", []):
            if m.get("1030") == "5":
                g = m.get("29", [""])
                mail_group_id = g[-1] if isinstance(g, list) else g
                break
        if not mail_group_id:
            return []

        root_data = await self._get_tutanota(
            self._url("tutanota", "mailboxgrouproot", mail_group_id),
            token=session.access_token
        )
        mb_ref = root_data.get("699", "")
        mailbox_id = mb_ref[-1] if isinstance(mb_ref, list) else mb_ref

        mailbox_data = await self._get_tutanota(
            self._url("tutanota", "mailbox", mailbox_id),
            token=session.access_token
        )

        def _extract_bag_list_id(bag: dict) -> str | None:
            if not isinstance(bag, dict):
                return None
            mails_ref = bag.get("1462", "")
            if isinstance(mails_ref, list) and mails_ref:
                return mails_ref[-1]
            if isinstance(mails_ref, str) and mails_ref:
                return mails_ref
            return None

        mail_list_ids = []

        # currentMailBag (1464) — ZeroOrOne, może być dict lub lista z jednym elementem
        current = mailbox_data.get("1464")
        if current:
            bags = current if isinstance(current, list) else [current]
            for bag in bags:
                lid = _extract_bag_list_id(bag)
                if lid:
                    mail_list_ids.append(lid)

        # archivedMailBags (1463) — lista starszych bagów
        for bag in (mailbox_data.get("1463") or []):
            lid = _extract_bag_list_id(bag)
            if lid and lid not in mail_list_ids:
                mail_list_ids.append(lid)

        logger.debug(f"get_mail_bags: {len(mail_list_ids)} bags found")
        return mail_list_ids

    async def get_mails_in_folder(
        self,
        session: Session,
        entries_list_id: str,
    ) -> list[dict]:
        """
        Pobiera maile z folderu przez MailSetEntry (typ 1450).
        entries_list_id = MailSet.entries (pole 1459) — lista MailSetEntry.
        MailSetEntry[1456] = [bagListId, mailElementId] — bezpośredni link do maila.

        Podejście:
          1. Pobierz wszystkie MailSetEntry z entries_list_id (z paginacją).
          2. Zgrupuj mailElemId po bagListId.
          3. Dla każdego baga: pobierz cały zakres maili i przefiltruj do żądanych ID.
        """
        if not entries_list_id:
            logger.warning("get_mails_in_folder: brak entries_list_id (pole 1459 folderu)")
            return []

        logger.debug(f"get_mails_in_folder: entries_list_id={entries_list_id!r}")

        # Krok 1: zbierz wszystkie referencje do maili z MailSetEntry
        # start=None → _mailset_entry_max_id() = '__________8' (FF*8 w base64url)
        bag_to_elem_ids: dict[str, set] = {}
        start: str | None = None
        entry_count = 0
        for _ in range(100):  # max 100 stron × 200 = 20 000 wpisów
            entries = await self._get_mailset_entries(session, entries_list_id,
                                                      start=start, count=200)
            if not entries:
                break
            for entry in entries:
                # 1456 = mail (LIST_ELEMENT_ASSOCIATION_GENERATED) → [[bagListId, mailElemId]]
                mail_ref_raw = entry.get("1456", [])
                mail_ref = None
                if isinstance(mail_ref_raw, list) and mail_ref_raw:
                    first = mail_ref_raw[0]
                    if isinstance(first, list) and len(first) >= 2:
                        mail_ref = first          # format [[listId, elemId]]
                    elif isinstance(first, str) and len(mail_ref_raw) >= 2:
                        mail_ref = mail_ref_raw   # format [listId, elemId]
                if mail_ref:
                    bag_to_elem_ids.setdefault(mail_ref[0], set()).add(mail_ref[1])
                    entry_count += 1
                else:
                    logger.warning("get_mails_in_folder: nieznany format 1456=%r (entry._id=%r)",
                                   mail_ref_raw, entry.get("1452"))
            if len(entries) < 200:
                break
            # _id (1452) = IdTuple [listId, elemId] — używamy elemId jako kursora
            last_id = entries[-1].get("1452", ["", ""])
            start = last_id[1] if isinstance(last_id, list) and len(last_id) > 1 else None

        logger.debug(f"get_mails_in_folder: {entry_count} entries, {len(bag_to_elem_ids)} bags")

        # Krok 2: pobierz maile z każdego baga, filtruj do żądanych elementIds
        result: list[dict] = []
        for bag_list_id, elem_ids in bag_to_elem_ids.items():
            bag_start = "zzzzzzzzzzzz"
            for _ in range(100):
                batch = await self.get_mail_list(session, bag_list_id, count=200, start_id=bag_start)
                if not batch:
                    break
                for mail in batch:
                    mid = mail.get("99", ["", ""])
                    eid = mid[1] if isinstance(mid, list) and len(mid) > 1 else str(mid)
                    if eid in elem_ids:
                        result.append(mail)
                if len(batch) < 200:
                    break
                last_id = batch[-1].get("99", ["", ""])
                bag_start = last_id[1] if isinstance(last_id, list) and len(last_id) > 1 else str(last_id)

        logger.info(f"get_mails_in_folder: entries_list={entries_list_id[:12]} → {len(result)} mails")
        return result

    @staticmethod
    def _mailset_entry_max_id() -> str:
        """
        Odpowiednik constructMailSetEntryId(far_future, GENERATED_MAX_ID) z Tuty.
        MailSetEntry._id = base64url(uint32_timestamp_shifted || uint32_mail_prefix)
        Maksymalne: wszystkie bajty = 0xFF → base64url(FF*8) = '__________8'
        """
        import struct as _struct
        buf = _struct.pack(">Q", 0xFFFFFFFFFFFFFFFF)  # 8 bajtów 0xFF
        return base64.urlsafe_b64encode(buf).rstrip(b"=").decode()

    async def _get_mailset_entries(
        self,
        session: Session,
        entries_list_id: str,
        start: str | None = None,
        count: int = 200,
    ) -> list[dict]:
        """Pobiera stronę MailSetEntry z podanej listy (CustomId, reverse=true)."""
        if start is None:
            start = self._mailset_entry_max_id()
        url = self._url("tutanota", "mailsetentry", entries_list_id)
        logger.debug(f"_get_mailset_entries: GET {url}?start={start[:12]}&count={count}&reverse=true")
        result = await self._get_tutanota(
            url,
            token=session.access_token,
            params={"start": start, "count": str(count), "reverse": "true"},
        )
        logger.debug(f"_get_mailset_entries: odpowiedź type={type(result).__name__} len={len(result) if result else 0} sample={str(result)[:200]}")
        return result if isinstance(result, list) else []



    async def get_mail_list(
        self,
        session: Session,
        list_id: str,
        count: int = 50,
        start_id: str = "zzzzzzzzzzzz",
    ) -> list[dict]:
        """Pobiera listę maili z podanej listy (MailBag)."""
        url = self._url("tutanota", "mail", list_id)
        params = {
            "start": start_id,
            "count": str(count),
            "reverse": "true",
        }
        result = await self._get_tutanota(url, token=session.access_token, params=params)
        return result if isinstance(result, list) else []

    async def get_mail_details(self, session: Session, mail: dict) -> dict:
        """
        Pobiera MailDetailsBlob dla maila przez blob storage.
        
        Przepływ (ustalony przez mitmproxy, maj 2026):
          1. POST /storage/blobaccesstokenservice (v=14) → blobAccessToken + serwery
          2. GET https://wNN.api.tuta.com/rest/tutanota/maildetailsblob/{archiveId}
                 ?ids={elementId}&blobAccessToken=...&accessToken=...&v=108
        
        Pole 117 w mailu = [[archiveId, elementId]] (mailDetails IdTuple).
        """
        import secrets

        # Pole 1308 = [[archiveId, elementId]] dla MailDetailsBlob
        # (nie 117 które jest starym formatem)
        mail_details_ref = mail.get("1308", [])
        if not mail_details_ref:
            # Fallback do pola 117
            mail_details_ref = mail.get("117", [])
        if not mail_details_ref:
            raise TutaAPIError(0, "Brak pola 1308/117 (mailDetails) w mailu")
        archive_id = mail_details_ref[0][0]
        element_id = mail_details_ref[0][1]
        logger.debug(f"get_mail_details: archiveId={archive_id!r}, elementId={element_id!r}")

        # Krok 1: pobierz blob access token
        # Format wzorowany na requestach przeglądarki (mitmproxy, maj 2026)
        import secrets as _secrets
        random_id = _secrets.token_urlsafe(4)[:6]  # ~6 znakowy CustomId
        token_body = {
            "78": "0",
            "80": [],     # write = null (jako pusta lista)
            "180": None,  # archiveDataType = null
            "181": [{     # read = lista z jednym BlobReadData
                "176": random_id,  # _id (CustomId)
                "177": archive_id, # archiveId
                "178": None,       # instanceListId = null
                "179": []          # instanceIds = pusta (element_id idzie w URL params)
            }]
        }
        headers = {
            "accessToken": session.access_token,
            "v": STORAGE_MODEL_VERSION,
            "cp": "5",
            "cv": CLIENT_VERSION,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        async with self._http.post(
            self.base_url + "/rest/storage/blobaccesstokenservice",
            json=token_body,
            headers=headers
        ) as r:
            if r.status not in (200, 201):
                raise _api_error(r.status, await r.text())
            token_resp = await r.json(content_type=None)

        # Parsuj odpowiedź: 161=[{158:tokenId, 159:blobAccessToken, 160:[{155:serverId,156:url}]}]
        access_info = token_resp.get("161", [{}])[0]
        blob_token = access_info.get("159", "")
        servers = access_info.get("160", [])
        if not servers:
            raise TutaAPIError(0, "Brak serwerów blob w odpowiedzi")
        server_url = servers[0].get("156", "")

        # Krok 2: pobierz MailDetailsBlob z serwera blob
        # WAŻNE: v=108 musi być w nagłówkach, nie w query params
        params = {
            "ids": element_id,
            "blobAccessToken": blob_token,
            "accessToken": session.access_token,
        }
        blob_headers = {
            "Accept": "application/json",
            "v": TUTANOTA_MODEL_VERSION,
        }
        async with self._http.get(
            f"{server_url}/rest/tutanota/maildetailsblob/{archive_id}",
            headers=blob_headers,
            params=params
        ) as r:
            if r.status != 200:
                raise _api_error(r.status, await r.text())
            # Odpowiedź to JSON array
            data = await r.json(content_type=None)

        # Zwróć pierwszy element (MailDetailsBlob)
        return data[0] if isinstance(data, list) and data else data

    async def get_mail_group_key(self, session: Session) -> bytes:
        """
        Pobiera i odszyfrowuje klucz grupy mail.
        Klucz jest w polu 27 membership z groupType=5.
        Ustawia też session.mail_group_id i session.mail_group_key_version.
        """
        from .crypto import decrypt_mail_group_key
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token
        )
        for m in user_data.get("96", []):
            if m.get("1030") == "5":  # mail group
                enc_mgk = base64.b64decode(m.get("27", ""))
                # Ustaw mail_group_id i key_version jeśli jeszcze nie ustawione
                if not session.mail_group_id:
                    g = m.get("29", "")
                    session.mail_group_id = g[-1] if isinstance(g, list) else g
                session.mail_group_key_version = str(m.get("2246", "0") or "0")
                return decrypt_mail_group_key(session.user_group_key, enc_mgk)
        raise TutaAPIError(0, "Nie znaleziono mail group key")

    async def get_mail_details_draft(self, session: Session, list_id: str, elem_id: str) -> dict:
        """Pobiera MailDetailsDraft (pole 1309 w Mail) — treść niesłanego draftu."""
        url = self._url("tutanota", "maildetailsdraft", list_id, elem_id)
        return await self._get_tutanota(url, token=session.access_token)

    async def decrypt_mail_content(self, session: Session, mail: dict, mail_group_key: bytes) -> str:
        """
        Pobiera i odszyfrowuje treść maila. Zwraca HTML.

        Ścieżki:
          Draft (pole 1309 → MailDetailsDraft): GET maildetailsdraft → 1297[0] → 1288[0] → 1276
          Wysłany (pole 1308 → MailDetailsBlob): blob storage    → 1305[0] → 1288[0] → 1276
        """
        from .crypto import decrypt_mail_session_key, decrypt_mail_body, uncompress_lz4

        enc_sk_b64 = mail.get("102") or ""
        if enc_sk_b64:
            mail_key = decrypt_mail_session_key(mail_group_key, base64.b64decode(enc_sk_b64))
        else:
            # TutaCrypt PQ path — Tuta→Tuta E2E: pole 1310 = internalRecipientKeyData
            field_1310 = mail.get("1310") or []
            if not field_1310 or not session.priv_ecc or not session.kyber_sk:
                raise TutaAPIError(0, f"Brak klucza sesji (pole 102 null, brak PQ keys lub pola 1310) dla maila {mail.get('99', '?')}")
            entry = field_1310[0] if isinstance(field_1310, list) else field_1310
            pq_msg = base64.b64decode(entry.get("2045", ""))
            bucket_key = pq_decapsulate_bucket_key(
                session.priv_ecc, session.pub_ecc, session.pub_kyber_tuta, session.kyber_sk, pq_msg
            )
            mail_id = mail.get("99", ["", ""])
            mail_elem_id = mail_id[1] if isinstance(mail_id, list) and len(mail_id) > 1 else str(mail_id)
            mail_key = None
            for e in (entry.get("2048") or []):
                if e.get("2041") == mail_elem_id:
                    mail_key = aes_decrypt_tuta(bucket_key, base64.b64decode(e["2042"]))
                    break
            if mail_key is None:
                raise TutaAPIError(0, f"Brak pasującego elementId {mail_elem_id!r} w 1310[0]['2048']")

        draft_ref = mail.get("1309")
        logger.debug(f"decrypt_mail_content: mail_id={mail.get('99')} 1308={mail.get('1308')!r} 1309={draft_ref!r}")
        if draft_ref:
            # Draft — MailDetailsDraft, zwykły list element (nie blob)
            # Tuta zwraca LIST_ELEMENT_ASSOCIATION jako [[listId, elemId]] w JSON
            list_id = elem_id = ""
            if isinstance(draft_ref, list) and draft_ref:
                inner = draft_ref[0]
                if isinstance(inner, list) and len(inner) >= 2:
                    list_id, elem_id = inner[0], inner[1]
                elif isinstance(inner, str) and len(draft_ref) >= 2:
                    list_id, elem_id = draft_ref[0], draft_ref[1]
            logger.debug(f"decrypt_mail_content: draft path list_id={list_id!r} elem_id={elem_id!r}")
            entity = await self.get_mail_details_draft(session, list_id, elem_id)
            # MailDetailsDraft[1297] = details (MailDetails aggregation, One → [{}])
            md_list = entity.get("1297", [])
            md = md_list[0] if isinstance(md_list, list) and md_list else (md_list or {})
        else:
            # Wysłany/odebrany — MailDetailsBlob (blob storage)
            details = await self.get_mail_details(session, mail)
            # MailDetailsBlob[1305] = details (MailDetails aggregation, One → [{}])
            md_list = details.get("1305", [])
            md = md_list[0] if isinstance(md_list, list) and md_list else (md_list or {})

        # Body aggregation: MailDetails[1288] = Body (One → [{}])
        body_list = md.get("1288", [])
        body = body_list[0] if isinstance(body_list, list) and body_list else (body_list or {})

        compressed_b64 = body.get("1276", "")
        text_b64 = body.get("1275", "")

        if compressed_b64:
            enc_body = base64.b64decode(compressed_b64)
            compressed = decrypt_mail_body(mail_key, enc_body)
            return uncompress_lz4(compressed).decode("utf-8", errors="replace")
        elif text_b64:
            enc_body = base64.b64decode(text_b64)
            return decrypt_mail_body(mail_key, enc_body).decode("utf-8", errors="replace")
        else:
            return ""

    async def get_file(self, session: Session, list_id: str, element_id: str) -> dict:
        """Pobiera obiekt TutanotaFile (pole 15=_id, 18=_ownerEncSessionKey, 21=name, 23=mimeType, 1225=blobs)."""
        url = self._url("tutanota", "file", list_id, element_id)
        return await self._get_tutanota(url, token=session.access_token)

    async def _get_blob_token(
        self,
        session: Session,
        archive_id: str,
        instance_list_id: str,
        instance_id: str,
    ) -> dict:
        """
        Pobiera blob access token dla archiwum załącznika.
        Próbuje trzech podejść (kolejność: od najbardziej do najmniej specyficznego):
          1. instance-level  (archiveDataType="1", Attachments)
          2. instance-level  (archiveDataType="2", MailDetails — dla starych kont)
          3. archive-level   (archiveDataType=null — wymaga własności archiwum)
        Pierwsze podejście które zwróci 200 wygrywa.
        """
        import json as _json
        import secrets as _secrets

        token_headers = {
            "accessToken": session.access_token,
            "v": STORAGE_MODEL_VERSION,
            "Content-Type": "application/json",
        }

        def _make_instance_body(arch_data_type: str) -> dict:
            rnd_read = _secrets.token_urlsafe(4)[:6]
            rnd_inst = _secrets.token_urlsafe(4)[:6]
            return {
                "78": "0",
                "80": [],
                "180": arch_data_type,
                "181": [{
                    "176": rnd_read,
                    "177": archive_id,
                    "178": instance_list_id,
                    "179": [{"173": rnd_inst, "174": instance_id}],
                }],
            }

        def _make_archive_body() -> dict:
            rnd = _secrets.token_urlsafe(4)[:6]
            return {
                "78": "0",
                "80": [],
                "180": None,
                "181": [{
                    "176": rnd,
                    "177": archive_id,
                    "178": None,
                    "179": [],
                }],
            }

        attempts = [
            ("instance archiveDataType=1", _make_instance_body("1")),
            ("instance archiveDataType=2", _make_instance_body("2")),
            ("archive-level",              _make_archive_body()),
        ]

        last_status = 0
        last_body = ""
        for label, body in attempts:
            logger.debug(f"_get_blob_token [{label}]: archiveId={archive_id}")
            async with self._http.post(
                self.base_url + "/rest/storage/blobaccesstokenservice",
                data=_json.dumps(body, separators=(",", ":")).encode("utf-8"),
                headers=token_headers,
            ) as r:
                resp_text = await r.text()
                last_status = r.status
                last_body = resp_text
                if r.status in (200, 201):
                    logger.debug(f"_get_blob_token [{label}]: OK")
                    return _json.loads(resp_text)
                logger.warning(f"_get_blob_token [{label}]: {r.status} body={resp_text!r}")

        raise _api_error(last_status, last_body)

    async def get_file_data(self, session: Session, file_obj: dict) -> list[bytes]:
        """
        Pobiera zaszyfrowane dane pliku z blob storage.
        Każdy blob w file_obj["1225"] jest osobnym, zaszyfrowanym chunkiem AesCbcThenHmac.
        Zwraca listę chunków — każdy wymaga osobnego odszyfrowania.
        """
        import json as _json
        import secrets as _secrets
        import struct

        blobs = file_obj.get("1225", [])
        if not blobs:
            return []

        archive_id = blobs[0].get("1884", "")
        file_id = file_obj.get("15", ["", ""])
        owner_group = file_obj.get("580", "")
        logger.debug(f"get_file_data: {len(blobs)} blobs, archiveId={archive_id}, file_id={file_id!r}, ownerGroup={owner_group!r}")

        file_list_id = file_id[0] if isinstance(file_id, list) and len(file_id) > 0 else ""
        file_elem_id = file_id[1] if isinstance(file_id, list) and len(file_id) > 1 else ""

        token_resp = await self._get_blob_token(session, archive_id, file_list_id, file_elem_id)

        access_info = token_resp.get("161", [{}])[0]

        blob_token = access_info.get("159", "")
        servers = access_info.get("160", [])
        if not servers:
            raise TutaAPIError(0, "Brak serwerów blob dla pliku")
        server_url = servers[0].get("156", "")

        # Pobierz każdy blob — każdy jest osobno zaszyfrowanym chunkiem
        result_chunks: list[bytes] = []
        for blob in blobs:
            blob_archive_id = blob.get("1884", "")
            blob_id = blob.get("1906", "")

            entry_id = _secrets.token_urlsafe(4)[:6]
            blob_get_in = {
                "51": "0",
                "52": blob_archive_id,
                "110": None,
                "193": [{"145": entry_id, "146": blob_id}],
            }
            params = {
                "blobAccessToken": blob_token,
                "accessToken": session.access_token,
            }
            logger.debug(
                f"get_file_data blob GET: server={server_url} archiveId={blob_archive_id} blobId={blob_id}"
            )
            # GET z ciałem JSON — aiohttp obsługuje to przez request()
            # v=14 musi być w headerach (jak w blobaccesstokenservice), nie w params
            async with self._http.request(
                "GET",
                f"{server_url}/rest/storage/blobservice",
                headers={"Content-Type": "application/json", "v": STORAGE_MODEL_VERSION},
                params=params,
                data=_json.dumps(blob_get_in).encode("utf-8"),
            ) as r:
                if r.status != 200:
                    body = await r.text()
                    logger.warning(f"blobservice GET 400: server={server_url} body={body!r}")
                    raise _api_error(r.status, body)
                raw = await r.read()

            # Format odpowiedzi: [count:4B][blobId:9B][hash:6B][size:4B][data:size B]...
            if len(raw) < 4:
                continue
            count = struct.unpack(">i", raw[:4])[0]
            offset = 4
            for _ in range(count):
                if offset + 19 > len(raw):
                    break
                chunk_size = struct.unpack(">i", raw[offset + 15: offset + 19])[0]
                chunk = raw[offset + 19: offset + 19 + chunk_size]
                result_chunks.append(chunk)
                offset += 19 + chunk_size

        # Zwróć listę osobno zaszyfrowanych chunków
        return result_chunks

    async def load_attachments(
        self,
        session: Session,
        mail_raw: dict,
        mail_group_key: bytes,
    ) -> list[dict]:
        """
        Pobiera i odszyfrowuje wszystkie załączniki maila.
        Zwraca listę słowników: {name, mime_type, cid, data}.
        mail_raw["115"] = [[listId, elementId], ...] — referencje do File.

        Ścieżki deszyfrowania klucza pliku:
          1. Pole 18 (_ownerEncSessionKey): AES(mail_group_key, file_sk) — maile non-E2E
          2. Pole 1310 → 2048: bucket_key → AES(bucket_key, file_sk) — maile E2E (TutaCrypt)
             Serwer kasuje pole 18 dla plików w mailach E2E; klucz pliku jest w tablicy
             instanceSessionKeys (2048) tego samego BucketKey co klucz maila.
        """
        from .crypto import decrypt_mail_session_key, aes_decrypt_tuta, pq_decapsulate_bucket_key
        from .message_builder import _decrypt_str

        file_refs = mail_raw.get("115", [])
        if not file_refs:
            return []

        # Lazy-compute bucket_key + mapa instanceId→encSessionKey z pola 1310.
        # Potrzebne tylko gdy pole 18 jest null (maile E2E).
        _pq_data: "tuple[bytes, dict] | None | bool" = False  # False = nie sprawdzane

        def _get_pq_sk_map() -> "tuple[bytes, dict] | None":
            """Zwraca (bucket_key, {elem_id: enc_sk_b64}) lub None jeśli niedostępne."""
            nonlocal _pq_data
            if _pq_data is False:
                field_1310 = mail_raw.get("1310") or []
                if field_1310 and session.priv_ecc and session.kyber_sk:
                    entry = field_1310[0] if isinstance(field_1310, list) else field_1310
                    pq_msg = base64.b64decode(entry.get("2045", ""))
                    bk = pq_decapsulate_bucket_key(
                        session.priv_ecc, session.pub_ecc,
                        session.pub_kyber_tuta, session.kyber_sk, pq_msg,
                    )
                    sk_map = {
                        e.get("2041"): e.get("2042", "")
                        for e in (entry.get("2048") or [])
                    }
                    _pq_data = (bk, sk_map)
                else:
                    _pq_data = None
            return _pq_data  # type: ignore[return-value]

        attachments = []
        for file_ref in file_refs:
            if not isinstance(file_ref, list) or len(file_ref) < 2:
                continue
            list_id, element_id = file_ref[0], file_ref[1]
            try:
                file_obj = await self.get_file(session, list_id, element_id)
            except Exception as e:
                logger.warning(f"Nie udało się pobrać pliku {element_id}: {e}")
                continue

            try:
                enc_sk_b64 = file_obj.get("18") or ""
                if enc_sk_b64:
                    # Ścieżka 1: ownerEncSessionKey — maile non-E2E
                    file_key = decrypt_mail_session_key(
                        mail_group_key, base64.b64decode(enc_sk_b64)
                    )
                else:
                    # Ścieżka 2: BucketKey (1310 → 2048) — maile E2E
                    pq = _get_pq_sk_map()
                    if pq is None:
                        raise ValueError(
                            "Pole 18 null i brak PQ keys/pola 1310 — nie można odszyfrować"
                        )
                    bucket_key, sk_map = pq
                    enc_file_sk_b64 = sk_map.get(element_id, "")
                    if not enc_file_sk_b64:
                        raise ValueError(
                            f"Brak klucza pliku {element_id!r} w 1310[0]['2048']"
                        )
                    file_key = aes_decrypt_tuta(
                        bucket_key, base64.b64decode(enc_file_sk_b64)
                    )
            except Exception as e:
                logger.warning(f"Nie udało się odszyfrować klucza pliku {element_id}: {e}")
                continue

            name = _decrypt_str(file_key, file_obj.get("21", "")) or "attachment"
            mime_type = _decrypt_str(file_key, file_obj.get("23", "")) or "application/octet-stream"
            cid_enc = file_obj.get("924", "")
            cid = _decrypt_str(file_key, cid_enc) if cid_enc else ""

            try:
                enc_chunks = await self.get_file_data(session, file_obj)
                # Każdy chunk jest osobno zaszyfrowany — deszyfrujemy każdy z osobna
                data = b"".join(aes_decrypt_tuta(file_key, chunk) for chunk in enc_chunks)
            except Exception as e:
                logger.warning(f"Nie udało się pobrać/odszyfrować danych pliku {element_id}: {e}")
                data = b""

            logger.debug(f"Załącznik: {name!r} ({mime_type}) {len(data)} B")
            attachments.append({"name": name, "mime_type": mime_type, "cid": cid, "data": data})

        return attachments

    async def get_single_mail(self, session: Session, list_id: str, element_id: str) -> dict:
        """Pobiera pojedynczy mail po listId + elementId."""
        url = self._url("tutanota", "mail", list_id, element_id)
        return await self._get_tutanota(url, token=session.access_token)

    async def iter_event_stream(self, session: Session):
        """
        Async generator — podłącza się do WebSocket Tuty i zwraca entity update eventy.
        Każdy event to dict: {application, type_id, operation, list_id, element_id}.
        operation: "0"=CREATE, "1"=UPDATE, "2"=DELETE

        Kończy się gdy WebSocket zostanie zamknięty lub generator zostanie anulowany.
        """
        import json as _json

        ws_url = (
            TUTA_BASE_URL.replace("https://", "wss://")
            + f"/event?modelVersions={SYS_MODEL_VERSION}.{TUTANOTA_MODEL_VERSION}"
            f"&clientVersion={CLIENT_VERSION}"
            f"&userId={session.user_id}"
            f"&accessToken={session.access_token}"
        )
        logger.debug(f"WS connect: ...userId={session.user_id}")

        timeout = aiohttp.ClientTimeout(total=None, sock_connect=30)
        async with aiohttp.ClientSession(timeout=timeout) as ws_session:
            try:
                async with ws_session.ws_connect(ws_url, heartbeat=55) as ws:
                    logger.info("Tuta WebSocket connected")
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            sep = msg.data.find(";")
                            if sep == -1:
                                continue
                            if msg.data[:sep] != "entityUpdate":
                                continue
                            try:
                                data = _json.loads(msg.data[sep + 1:])
                            except Exception:
                                continue
                            for upd in data.get("1487", []):
                                yield {
                                    "application": upd.get("464", ""),
                                    "type_id": str(upd.get("2556", "")),
                                    "operation": str(upd.get("624", "")),
                                    "list_id": upd.get("466", ""),
                                    "element_id": upd.get("467", ""),
                                }
                        elif msg.type in (
                            aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.CLOSING,
                            aiohttp.WSMsgType.ERROR,
                        ):
                            logger.info(f"Tuta WebSocket closed: {msg.type}")
                            break
            except aiohttp.ClientError as e:
                logger.warning(f"Tuta WebSocket error: {e}")

    async def get_mail_body(self, session: Session, body_id: str) -> dict:
        """Pobiera treść maila (stary format - dla kompatybilności)."""
        url = self._url("tutanota", "mailbody", body_id)
        return await self._get_tutanota(url, token=session.access_token)

    async def mark_mails_unread(
        self,
        session: Session,
        mail_ids: list[tuple[str, str]],
        unread: bool,
    ) -> None:
        """
        Oznacza maile jako przeczytane / nieprzeczytane.
        POST /rest/tutanota/unreadmailstateservice (v=108)
        mail_ids: lista (listId, elementId) z pola 99 maila.
        """
        body = {
            "1475": "0",
            # Tuta koduje Boolean jako "1"/"0" (string), nie jako JSON true/false
            "1477": "1" if unread else "0",
            "1476": [[lid, eid] for lid, eid in mail_ids],
        }
        headers = {
            "accessToken": session.access_token,
            **TUTANOTA_HEADERS,
        }
        async with self._http.post(
            self.base_url + "/rest/tutanota/unreadmailstateservice",
            json=body,
            headers=headers,
        ) as r:
            if r.status not in (200, 201, 204):
                text = await r.text()
                raise _api_error(r.status, text)
        logger.debug(f"mark_mails_unread: {len(mail_ids)} mails, unread={unread}")

    async def create_folder(
        self,
        session: Session,
        name: str,
        mail_group_key: bytes,
        parent_folder: Optional["MailFolder"] = None,
    ) -> tuple[str, str]:
        """
        Tworzy nowy folder użytkownika.
        Zwraca (folder_list_id, folder_id) nowego folderu.
        POST /rest/tutanota/mailfolderservice (v=108)
        """
        from .crypto import aes_encrypt_tuta
        sk = os.urandom(32)
        owner_enc_sk = aes_encrypt_tuta(mail_group_key, sk, add_padding=False)
        name_enc = aes_encrypt_tuta(sk, name.encode("utf-8"))
        # ownerKeyVersion = wersja klucza grupy mail użytego do szyfrowania owner_enc_sk
        key_version = session.mail_group_key_version
        # ZeroOrOne association in Tuta: empty array for null, [[listId, elemId]] for present value
        parent_ref = [[parent_folder.folder_list_id, parent_folder.id]] if parent_folder else []
        body: dict = {
            "451": "0",
            "453": base64.b64encode(name_enc).decode(),
            "454": base64.b64encode(owner_enc_sk).decode(),
            "1268": session.mail_group_id,
            "1414": key_version,
            "452": parent_ref,
        }
        url = self.base_url + "/rest/tutanota/mailfolderservice"
        logger.debug(f"create_folder POST {url}")
        logger.debug(f"create_folder body: {body}")
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"create_folder headers: { {k:v for k,v in headers.items() if k != 'accessToken'} }")
        async with self._http.post(url, json=body, headers=headers) as r:
            text = await r.text()
            logger.debug(f"create_folder response {r.status}, headers={dict(r.headers)}: '{text[:500]}'")
            if r.status not in (200, 201, 204):
                raise _api_error(r.status, text)
            resp = json.loads(text) if text else {}
        # Odpowiedź: {"456":"0","457":[["listId","elementId"]]} — One association wrapped in array
        new_id = resp.get("457", [[]])[0]
        logger.info(f"create_folder: '{name}' → {new_id}")
        return (new_id[0], new_id[1]) if isinstance(new_id, list) and len(new_id) == 2 else ("", "")

    async def rename_folder(
        self,
        session: Session,
        folder: "MailFolder",
        new_bare_name: str,
        mail_group_key: bytes,
        new_parent: Optional["MailFolder"] = None,
        move_to_root: bool = False,
    ) -> None:
        """
        Zmienia nazwę i/lub przenosi folder.

        Tuta wymaga dwóch osobnych requestów:
          1. PUT /mailset/{id}             — tylko zmiana nazwy (parentFolder = STARY!)
          2. PUT /mailfolderservice         — tylko zmiana rodzica (UpdateMailFolderData)
        """
        from .crypto import aes_encrypt_tuta, aes_decrypt_tuta
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}

        # ── 1. Zmiana nazwy: PUT mailset, parentFolder = stary (nie zmieniamy!) ──
        enc_sk = base64.b64decode(folder.owner_enc_session_key)
        folder_sk = aes_decrypt_tuta(mail_group_key, enc_sk)
        name_enc = aes_encrypt_tuta(folder_sk, new_bare_name.encode("utf-8"))
        original_parent_ref = folder.parent_folder_raw if folder.parent_folder_raw is not None else []
        body: dict = {
            "431": [folder.folder_list_id, folder.id],
            "432": folder.permissions,
            "433": "0",
            "434": folder.owner_enc_session_key,
            "435": base64.b64encode(name_enc).decode(),
            "436": folder.folder_type,
            "439": original_parent_ref,         # stary rodzic — serwer nie pozwala zmieniać go tutaj
            "589": session.mail_group_id,
            "1399": folder.owner_key_version,
            "1459": [folder.mail_list_id],       # LIST_ASSOCIATION One → [listId]
            "1479": None,
            "1847": folder.kdf_nonce,
        }
        logger.debug(f"rename_folder PUT mailset body: {body}")
        async with self._http.put(
            self.base_url + f"/rest/tutanota/mailset/{folder.folder_list_id}/{folder.id}",
            json=body, headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"rename_folder PUT mailset {r.status}: {text[:200]}")
                raise _api_error(r.status, text)
        logger.info(f"rename_folder name: '{folder.id}' → '{new_bare_name}'")

        # ── 2. Zmiana rodzica: PUT mailfolderservice (UpdateMailFolderData, typ 1311) ──
        parent_changed = new_parent is not None or move_to_root
        if parent_changed:
            if new_parent is not None:
                new_parent_ref = [[new_parent.folder_list_id, new_parent.id]]
            else:
                new_parent_ref = []  # przenieś na root
            update_body: dict = {
                "1312": "0",                                      # _format
                "1313": [[folder.folder_list_id, folder.id]],    # folder (One → [[...]])
                "1314": new_parent_ref,                           # newParent (ZeroOrOne → [] lub [[...]])
            }
            logger.debug(f"rename_folder PUT mailfolderservice body: {update_body}")
            async with self._http.put(
                self.base_url + "/rest/tutanota/mailfolderservice",
                json=update_body, headers=headers,
            ) as r:
                text = await r.text()
                if r.status not in (200, 201, 204):
                    logger.warning(f"rename_folder PUT mailfolderservice {r.status}: {text[:200]}")
                    raise _api_error(r.status, text)
            logger.info(f"rename_folder parent: '{folder.id}' → parent={new_parent.id if new_parent else None}")

    async def delete_folder(
        self,
        session: Session,
        folder: "MailFolder",
    ) -> None:
        """
        Usuwa folder użytkownika (tylko CUSTOM type=0).
        DELETE /rest/tutanota/mailfolderservice (v=108)
        """
        body: dict = {
            "459": "0",
            "460": [[folder.folder_list_id, folder.id]],
        }
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        async with self._http.delete(
            self.base_url + "/rest/tutanota/mailfolderservice",
            json=body, headers=headers,
        ) as r:
            if r.status not in (200, 201, 204):
                text = await r.text()
                raise _api_error(r.status, text)
        logger.info(f"delete_folder: '{folder.id}' deleted")

    async def delete_mails(
        self,
        session: Session,
        mail_ids: list[tuple[str, str]],
        folder_id: Optional[tuple[str, str]] = None,
    ) -> None:
        """
        Trwale usuwa maile (DELETE /rest/tutanota/mailservice).
        Używane gdy mail jest już w Koszu i chcemy go usunąć na stałe.
        folder_id: opcjonalny (listId, elementId) folderu źródłowego jako filtr.
        """
        body: dict = {
            "420": "0",
            "421": [[lid, eid] for lid, eid in mail_ids],
            "724": list(folder_id) if folder_id else None,
        }
        headers = {
            "accessToken": session.access_token,
            **TUTANOTA_HEADERS,
        }
        logger.debug(f"delete_mails: body={body}")
        async with self._http.delete(
            self.base_url + "/rest/tutanota/mailservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.debug(f"delete_mails: {r.status} response={text!r}")
                raise _api_error(r.status, text)
        logger.debug(f"delete_mails: {len(mail_ids)} mails deleted")

    async def simple_move_mails(
        self,
        session: Session,
        mail_ids: list[tuple[str, str]],
        destination_set_type: str,
    ) -> None:
        """
        Przenosi maile do folderu systemowego przez SimpleMoveMailService.
        destination_set_type: folder_type string — "3"=Trash, "4"=Archive, "5"=Spam.
        POST /rest/tutanota/simplemovemailservice (v=108)
        """
        body = {
            "1470": "0",
            "1472": destination_set_type,
            "1471": [[lid, eid] for lid, eid in mail_ids],
            "1713": None,
        }
        headers = {
            "accessToken": session.access_token,
            **TUTANOTA_HEADERS,
        }
        logger.debug(f"simple_move_mails: body={body}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/simplemovemailservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.debug(f"simple_move_mails: {r.status} response={text!r}")
                raise _api_error(r.status, text)
        logger.debug(f"simple_move_mails: {len(mail_ids)} mails → type {destination_set_type}")

    async def move_mails_to_folder(
        self,
        session: Session,
        mail_ids: list[tuple[str, str]],
        target_folder_list_id: str,
        target_folder_id: str,
    ) -> None:
        """
        Przenosi maile do wskazanego folderu.
        POST /rest/tutanota/movemailservice (v=108)
        mail_ids: lista (listId, elementId) z pola 99 maila.
        targetFolder = [target_folder_list_id, target_folder_id] (pole 431 folderu).
        """
        body = {
            "446": "0",
            "1714": None,
            "447": [target_folder_list_id, target_folder_id],
            "448": [[lid, eid] for lid, eid in mail_ids],
            "1644": None,
        }
        headers = {
            "accessToken": session.access_token,
            **TUTANOTA_HEADERS,
        }
        logger.debug(f"move_mails_to_folder: body={body}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/movemailservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.debug(f"move_mails_to_folder: {r.status} response={text!r}")
                raise _api_error(r.status, text)
        logger.debug(f"move_mails_to_folder: {len(mail_ids)} mails → {target_folder_id}")

    async def create_draft(
        self,
        session: Session,
        subject: str,
        body_html: str,
        from_addr: str,
        from_name: str,
        to_recipients: list[tuple[str, str]],
        cc_recipients: list[tuple[str, str]],
        bcc_recipients: list[tuple[str, str]],
        mail_group_key: bytes,
        confidential: bool = False,
        attachments: "list[dict] | None" = None,
    ) -> tuple[str, str, bytes]:
        """
        Tworzy draft wiadomości przez DraftService.

        Zwraca (draft_list_id, draft_elem_id, session_key).
        session_key potrzebny przy send_draft (non-confidential).

        Wszystkie zaszyfrowane pola: AesCbcThenHmac z session_key.
        Ciało: LZ4 + encrypt (compressedBodyText, typ CompressedString).
        Non-confidential — klucz sesji trafia jawnie do SendDraftData.
        """
        # Nowy klucz sesji dla draftu
        sk = os.urandom(32)
        owner_enc_sk = aes_encrypt_tuta(mail_group_key, sk, add_padding=False)
        key_version = session.mail_group_key_version

        def enc(plaintext: str) -> str:
            return base64.b64encode(
                aes_encrypt_tuta(sk, plaintext.encode("utf-8"), add_padding=True)
            ).decode()

        def enc_bytes(data: bytes) -> str:
            return base64.b64encode(
                aes_encrypt_tuta(sk, data, add_padding=True)
            ).decode()

        def make_recipient(name: str, addr: str) -> dict:
            return {
                "483": _random_custom_id(),
                "484": enc(name),
                "485": addr,
            }

        body = {
            "509": "0",                                          # _format
            "510": None,                                         # previousMessageId
            "511": "0",                                          # conversationType = NEW
            "512": base64.b64encode(owner_enc_sk).decode(),      # ownerEncSessionKey
            "1427": key_version,                                 # ownerKeyVersion
            "515": [{                                            # draftData (One aggregation)
                "497": _random_custom_id(),                      # _id
                "498": enc(subject),                             # subject (enc String)
                "499": enc(""),                                  # bodyText (enc String, puste — deprecated)
                "500": from_addr,                                # senderMailAddress
                "501": enc(from_name),                           # senderName (enc String)
                "502": enc("1" if confidential else "0"),        # confidential (enc Boolean)
                "1116": enc("0"),                                # method = NONE (enc Number)
                "1194": enc_bytes(compress_lz4(body_html.encode("utf-8"))),  # compressedBodyText
                "503": [make_recipient(n, a) for n, a in to_recipients],
                "504": [make_recipient(n, a) for n, a in cc_recipients],
                "505": [make_recipient(n, a) for n, a in bcc_recipients],
                "506": attachments or [],  # addedAttachments
                "507": [],  # removedAttachments
                "819": [],  # replyTos
            }],
        }

        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"create_draft ownerKeyVersion={key_version} mail_group_id={session.mail_group_id}")
        logger.debug(f"create_draft full body: {json.dumps(body)}")
        logger.debug(f"create_draft POST to={[a for _,a in to_recipients]}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/draftservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"create_draft {r.status}: {text[:400]}")
                raise _api_error(r.status, text)
            resp = json.loads(text)

        # Odpowiedź: DraftCreateReturn (typ 516), pole 518 = draft (One LIST_ELEMENT) → [[listId, elemId]]
        draft_ref = resp.get("518", [[]])[0]
        draft_list_id = draft_ref[0] if len(draft_ref) > 0 else ""
        draft_elem_id = draft_ref[1] if len(draft_ref) > 1 else ""
        logger.info(f"create_draft: draft_list={draft_list_id} elem={draft_elem_id}")
        return draft_list_id, draft_elem_id, sk

    async def get_draft_file_ids(
        self,
        session: Session,
        draft_list_id: str,
        draft_elem_id: str,
    ) -> "list[tuple[str, str]]":
        """
        Pobiera identyfikatory plików (załączników) z maila-draftu.
        Serwer ustawia pole 115 (attachments) po przetworzeniu DraftAttachment.referenceTokens.
        Zwraca listę (listId, elementId) w kolejności jak w polu 506 draftu.
        """
        mail = await self.get_single_mail(session, draft_list_id, draft_elem_id)
        return [
            (ref[0], ref[1])
            for ref in mail.get("115", [])
            if isinstance(ref, list) and len(ref) >= 2
        ]

    # ------------------------------------------------------------------
    # Secure External — wysyłka do zewnętrznych odbiorców z hasłem
    # ------------------------------------------------------------------

    def _mail_address_to_custom_id(self, mail_address: str) -> str:
        """Konwertuje adres email na CustomId (base64url UTF-8 bajtów)."""
        return base64.urlsafe_b64encode(
            mail_address.strip().lower().encode()
        ).rstrip(b"=").decode()

    async def _get_external_user_refs_list_id(self, session: Session) -> str:
        """
        Zwraca listId ExternalUserReferences z GroupRoot użytkownika.

        Tuta używa dwustopniowego loadRoot:
          1. GET /rest/sys/rootinstance/{userGroupId}/A3N5cwBu → RootInstance.reference
          2. GET /rest/sys/grouproot/{reference}              → GroupRoot.externalUserReferences
        """
        if not session.user_group_id:
            raise TutaAPIError(0, "user_group_id niedostępny — PQ keys nie załadowane")

        # Krok 1: RootInstance (listId=userGroupId, elemId=GroupRoot.rootId)
        GROUP_ROOT_ROOT_ID = "A3N5cwBu"
        root_instance_url = self._url("sys", "rootinstance", session.user_group_id, GROUP_ROOT_ROOT_ID)
        logger.debug(f"GET RootInstance (GroupRoot): {root_instance_url}")
        root_instance = await self._get(root_instance_url, token=session.access_token)
        group_root_id = root_instance.get("236", "")  # reference

        # Krok 2: GroupRoot
        group_root_url = self._url("sys", "grouproot", group_root_id)
        logger.debug(f"GET GroupRoot: {group_root_url}")
        group_root = await self._get(group_root_url, token=session.access_token)
        logger.debug(f"GroupRoot raw 117={group_root.get('117')!r}")
        ext_refs = group_root.get("117", "")
        # LIST_ASSOCIATION może przyjść jako lista [listId] lub plain string
        if isinstance(ext_refs, list):
            ext_refs = ext_refs[0] if ext_refs else ""
        return ext_refs

    async def _get_or_create_external_user(
        self,
        session: Session,
        mail_address: str,
        password_key: bytes,
        verifier: bytes,
        mail_group_key: bytes,
    ) -> "tuple[bytes, bytes]":
        """
        Zwraca (externalUserGroupKey, externalMailGroupKey) dla odbiorcy zewnętrznego.
        Tworzy konto przez ExternalUserService jeśli odbiorca nie istnieje jeszcze w systemie.
        """
        cleaned = mail_address.strip().lower()
        ext_refs_list_id = await self._get_external_user_refs_list_id(session)
        mail_addr_custom_id = self._mail_address_to_custom_id(cleaned)

        url = self._url("sys", "externaluserreference", ext_refs_list_id, mail_addr_custom_id)
        logger.debug(f"GET ExternalUserReference: list={ext_refs_list_id} id={mail_addr_custom_id}")
        try:
            ext_ref = await self._get(url, token=session.access_token)
        except TutaAPIError as e:
            logger.debug(f"GET ExternalUserReference HTTP {e.status_code} — odbiorca nie istnieje")
            if e.status_code not in (404, 400):
                raise
            logger.debug(f"Secure External: odbiorca {cleaned} nie istnieje (HTTP {e.status_code}), tworzę konto")
            return await self._create_external_user(session, cleaned, password_key, verifier, mail_group_key)

        # Odbiorca istnieje — załaduj jego klucze
        # Pola 108/109 mogą być listą (ELEMENT_ASSOCIATION) — bierzemy ostatni element
        ext_user_id_raw = ext_ref.get("108", "")
        ext_user_id = ext_user_id_raw[-1] if isinstance(ext_user_id_raw, list) else ext_user_id_raw
        ext_user_group_id_raw = ext_ref.get("109", "")
        ext_user_group_id = ext_user_group_id_raw[-1] if isinstance(ext_user_group_id_raw, list) else ext_user_group_id_raw
        logger.debug(f"Secure External: odbiorca {cleaned} już istnieje (user={ext_user_id!r} group={ext_user_group_id!r}), ładuję klucze")
        return await self._load_existing_external_user_keys(session, ext_user_id, ext_user_group_id)

    async def _load_existing_external_user_keys(
        self,
        session: Session,
        ext_user_id: str,
        ext_user_group_id: str,
    ) -> "tuple[bytes, bytes]":
        """Ładuje klucze istniejącego zewnętrznego użytkownika."""
        # Załaduj dane użytkownika zewnętrznego
        user_data = await self._get(self._url("sys", "user", ext_user_id), token=session.access_token)

        # Znajdź grupę mail (groupType=5)
        memberships = user_data.get("96", [])
        ext_mail_group_id = None
        for m in memberships:
            if str(m.get("1030", "")) == "5":
                g_ref = m.get("29", [""])
                ext_mail_group_id = g_ref[-1] if isinstance(g_ref, list) else g_ref
                break
        if not ext_mail_group_id:
            raise TutaAPIError(0, f"Brak grupy mail dla zewnętrznego użytkownika {ext_user_id}")

        # Załaduj obie grupy
        ext_user_group = await self._get(self._url("sys", "group", ext_user_group_id), token=session.access_token)
        ext_mail_group = await self._get(self._url("sys", "group", ext_mail_group_id), token=session.access_token)

        # Odszyfruj ext_user_group_key używając naszego user_group_key
        enc_ext_user_key = base64.b64decode(ext_user_group.get("11", "") or "")
        ext_user_group_key = aes_decrypt_tuta(session.user_group_key, enc_ext_user_key)

        # Odszyfruj ext_mail_group_key używając ext_user_group_key
        enc_ext_mail_key = base64.b64decode(ext_mail_group.get("11", "") or "")
        ext_mail_group_key = aes_decrypt_tuta(ext_user_group_key, enc_ext_mail_key)

        return ext_user_group_key, ext_mail_group_key

    async def _create_external_user(
        self,
        session: Session,
        mail_address: str,
        password_key: bytes,
        verifier: bytes,
        mail_group_key: bytes,
    ) -> "tuple[bytes, bytes]":
        """
        Tworzy konto zewnętrznego użytkownika przez ExternalUserService (POST).
        Zwraca (externalUserGroupKey, externalMailGroupKey).
        """
        ext_user_group_key   = os.urandom(32)
        ext_mail_group_key   = os.urandom(32)
        ext_user_group_info_sk  = os.urandom(32)
        ext_mail_group_info_sk  = os.urandom(32)
        tutanota_props_sk    = os.urandom(32)
        mailbox_sk           = os.urandom(32)
        entropy              = os.urandom(32)

        def enc_key(enc_with: bytes, key: bytes) -> str:
            return base64.b64encode(aes_encrypt_tuta(enc_with, key, add_padding=False)).decode()

        user_group_data = {
            "139": _random_custom_id(),
            "141": mail_address,
            "142": enc_key(password_key, ext_user_group_key),        # externalPwEncUserGroupKey
            "143": enc_key(session.user_group_key, ext_user_group_key),  # internalUserEncUserGroupKey
            "1433": session.user_key_version,                         # internalUserGroupKeyVersion
        }

        body = {
            "146": "0",                                               # _format
            "1323": "1",                                              # kdfVersion = argon2id
            "1429": session.mail_group_key_version,                   # internalMailGroupKeyVersion
            "149": base64.b64encode(verifier).decode(),               # verifier = sha256(passwordKey)
            "412": base64.b64encode(                                  # externalUserEncEntropy (z paddingiem)
                aes_encrypt_tuta(ext_user_group_key, entropy, add_padding=True)
            ).decode(),
            "148": enc_key(ext_user_group_key, ext_mail_group_key),   # externalUserEncMailGroupKey
            "150": enc_key(ext_user_group_key, ext_user_group_info_sk),  # externalUserEncUserGroupInfoSessionKey
            "672": enc_key(ext_user_group_key, tutanota_props_sk),    # externalUserEncTutanotaPropertiesSessionKey
            "670": enc_key(ext_mail_group_key, ext_mail_group_info_sk),  # externalMailEncMailGroupInfoSessionKey
            "673": enc_key(ext_mail_group_key, mailbox_sk),           # externalMailEncMailBoxSessionKey
            "669": enc_key(mail_group_key, ext_user_group_info_sk),   # internalMailEncUserGroupInfoSessionKey
            "671": enc_key(mail_group_key, ext_mail_group_info_sk),   # internalMailEncMailGroupInfoSessionKey
            "151": [user_group_data],                                  # userGroupData (AGGREGATION → lista)
        }

        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"ExternalUserService POST dla {mail_address}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/externaluserservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"ExternalUserService {r.status}: {text[:400]}")
                raise _api_error(r.status, text)
        logger.info(f"Secure External: konto utworzone dla {mail_address}")
        return ext_user_group_key, ext_mail_group_key

    async def send_draft_secure_external(
        self,
        session: Session,
        draft_list_id: str,
        draft_elem_id: str,
        session_key: bytes,
        mail_group_key: bytes,
        recipients: "list[tuple[str, str]]",
        attachment_keys: "list[tuple[str, str, bytes]] | None" = None,
        sender_name: str = "",
    ) -> None:
        """
        Wysyła draft do odbiorców zewnętrznych z szyfrowaniem Secure External.

        recipients: lista (mail_address, password) — hasło przekazane przez X-Tuta-Password.
        Dla każdego odbiorcy: argon2id(password, salt) → klucz → szyfruje bucket_key.
        Odbiorca dostaje link do app.tuta.com, gdzie wpisuje hasło.
        """
        bucket_key = os.urandom(32)
        bucket_enc_session_key = aes_encrypt_tuta(bucket_key, session_key, add_padding=False)

        secure_ext_key_data = []
        for addr, password in recipients:
            salt = os.urandom(16)
            password_key = derive_session_key(password, salt, kdf_version=1)
            verifier = hashlib.sha256(password_key).digest()

            ext_user_group_key, ext_mail_group_key = await self._get_or_create_external_user(
                session, addr, password_key, verifier, mail_group_key
            )

            secure_ext_key_data.append({
                "533": _random_custom_id(),
                "534": addr,
                "536": base64.b64encode(verifier).decode(),
                "538": base64.b64encode(salt).decode(),
                "539": base64.b64encode(hashlib.sha256(salt).digest()).decode(),
                "540": base64.b64encode(
                    aes_encrypt_tuta(password_key, ext_user_group_key, add_padding=False)
                ).decode(),
                "599": base64.b64encode(
                    aes_encrypt_tuta(ext_mail_group_key, bucket_key, add_padding=False)
                ).decode(),
                "1324": "1",   # kdfVersion = argon2id
                "1417": "0",   # ownerKeyVersion
                "1445": "0",   # userGroupKeyVersion
            })

        att_key_data = [
            {
                "543": _random_custom_id(),
                "544": base64.b64encode(
                    aes_encrypt_tuta(bucket_key, file_sk, add_padding=False)
                ).decode(),
                "545": None,
                "546": [[flist_id, felem_id]],
            }
            for flist_id, felem_id, file_sk in (attachment_keys or [])
        ]

        body = {
            "548": "0",
            "549": "en",
            "550": None,
            "551": base64.b64encode(bucket_enc_session_key).decode(),
            "552": sender_name or None,   # senderNameUnencrypted — podstawiane jako $senderName$ w notyfikacji
            "675": "0",
            "1117": "0",
            "1444": None,
            "1809": None,
            "1822": "0",
            "553": [],
            "554": secure_ext_key_data,
            "555": att_key_data,
            "556": [[draft_list_id, draft_elem_id]],
            "1353": [],
            "1810": [],
        }

        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"send_draft_secure_external POST draft={draft_elem_id} recipients={[a for a,_ in recipients]}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/senddraftservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"send_draft_secure_external {r.status}: {text[:400]}")
                raise _api_error(r.status, text)
        logger.info(f"send_draft_secure_external: draft {draft_elem_id} sent → {len(recipients)} odbiorców")

    async def send_draft(
        self,
        session: Session,
        draft_list_id: str,
        draft_elem_id: str,
        session_key: bytes,
        attachment_keys: "list[tuple[str, str, bytes]] | None" = None,
    ) -> None:
        """
        Wysyła draft przez SendDraftService.

        Non-confidential: klucz sesji trafia jawnie do pola 550 (mailSessionKey).
        Brak szyfrowania E2E — działa dla odbiorców zewnętrznych i Tuty
        (bez gwarancji E2E dla adresów @tuta.com).
        """
        # AttachmentKeyData (type 542): non-E2E → plaintext fileSessionKey (pole 545)
        # pole 546 = file (LIST_ELEMENT_ASSOCIATION_GENERATED One) → [[listId, elemId]]
        att_key_data = [
            {
                "543": _random_custom_id(),
                "544": None,
                "545": base64.b64encode(file_sk).decode(),
                "546": [[flist_id, felem_id]],
            }
            for flist_id, felem_id, file_sk in (attachment_keys or [])
        ]

        body = {
            "548": "0",                                            # _format
            "549": "en",                                           # language
            "550": base64.b64encode(session_key).decode(),         # mailSessionKey (plaintext!)
            "551": None,                                           # bucketEncMailSessionKey
            "552": None,                                           # senderNameUnencrypted
            "675": "0",                                            # plaintext = false
            "1117": "0",                                           # calendarMethod = false
            "1444": None,                                          # sessionEncEncryptionAuthStatus
            "1809": None,                                          # sendAt
            "1822": "0",                                           # allowUndo = false
            "553": [],                                             # internalRecipientKeyData
            "554": [],                                             # secureExternalRecipientKeyData
            "555": att_key_data,                                   # attachmentKeyData
            "556": [[draft_list_id, draft_elem_id]],               # mail (One LIST_ELEMENT)
            "1353": [],                                            # symEncInternalRecipientKeyData
            "1810": [],                                            # parameters (ZeroOrOne → absent)
        }

        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"send_draft POST draft={draft_elem_id} attachments={len(att_key_data)}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/senddraftservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"send_draft {r.status}: {text[:400]}")
                raise _api_error(r.status, text)
        logger.info(f"send_draft: draft {draft_elem_id} sent OK")


    async def _get_blob_write_token(self, session: Session) -> "tuple[str, str]":
        """
        Pobiera write token dla blob storage (ArchiveDataType.Attachments = "1").
        Zwraca (blobAccessToken, server_url).
        """
        body = {
            "78": "0",
            "80": [{"74": _random_custom_id(), "75": session.mail_group_id}],
            "180": "1",   # ArchiveDataType.Attachments
            "181": [],
        }
        headers = {
            "accessToken": session.access_token,
            "v": STORAGE_MODEL_VERSION,
            "Content-Type": "application/json",
        }
        async with self._http.post(
            self.base_url + "/rest/storage/blobaccesstokenservice",
            json=body,
            headers=headers,
        ) as r:
            if r.status not in (200, 201):
                resp_text = await r.text()
                logger.warning(f"_get_blob_write_token {r.status}: {resp_text[:400]}")
                raise _api_error(r.status, resp_text)
            resp = await r.json(content_type=None)

        access_info = resp.get("161", {})
        if isinstance(access_info, list):
            access_info = access_info[0] if access_info else {}
        blob_token = access_info.get("159", "")
        servers = access_info.get("160", [])
        if not servers:
            raise TutaAPIError(0, "Brak serwerów blob dla uploadu")
        server_url = servers[0].get("156", "")
        return blob_token, server_url

    async def upload_attachment(
        self,
        session: Session,
        mail_group_key: bytes,
        data: bytes,
        filename: str,
        mime_type: str,
        cid: "str | None" = None,
    ) -> "tuple[dict, bytes]":
        """
        Szyfruje i uploaduje załącznik do Tuta blob storage.
        Zwraca (DraftAttachment dict, file_session_key).

        DraftAttachment idzie do create_draft (pole 506).
        file_session_key potrzebny do AttachmentKeyData w send_draft/_e2e.

        Flow:
          1. Generuj file_session_key (losowy AES-256)
          2. Zaszyfruj dane pliku (AesCbcThenHmac)
          3. Upload do blob storage → blobReferenceToken
          4. Zaszyfruj nazwę, MIME i opcjonalnie CID kluczem sesji pliku
          5. Zwróć DraftAttachment + file_session_key
        """
        import hashlib as _hl

        if not session.mail_group_id:
            raise TutaAPIError(0, "mail_group_id nie ustawione — wywołaj get_mail_group_key() przed upload_attachment()")

        file_sk = os.urandom(32)
        encrypted_data = aes_encrypt_tuta(file_sk, data, add_padding=True)
        blob_hash = base64.b64encode(_hl.sha256(encrypted_data).digest()[:6]).decode()

        blob_token, server_url = await self._get_blob_write_token(session)
        logger.debug(f"upload_attachment: blob_token={blob_token[:12]}... server={server_url}")

        # v=14 musi być w NAGŁÓWKACH (nie w query params) — serwer ignoruje query, sprawdza header
        # Session ma domyślnie v=150 (sys model) — jawny header nadpisuje
        params = {
            "blobAccessToken": blob_token,
            "blobHash": blob_hash,
            "accessToken": session.access_token,
        }
        async with self._http.post(
            f"{server_url}/rest/storage/blobservice",
            params=params,
            data=encrypted_data,
            headers={"Content-Type": "application/octet-stream", "v": STORAGE_MODEL_VERSION},
        ) as r:
            if r.status not in (200, 201):
                resp_text = await r.text()
                logger.warning(f"upload_attachment blob POST {r.status}: {resp_text[:400]}")
                raise _api_error(r.status, resp_text)
            blob_resp = await r.json(content_type=None)

        # pole 127 = blobReferenceToken (starszy format); 208 = lista wrapperów (nowszy)
        ref_token = blob_resp.get("127", "")
        if not ref_token:
            wrappers = blob_resp.get("208", [])
            ref_token = wrappers[0].get("1992", "") if wrappers else ""
        if not ref_token:
            raise TutaAPIError(0, "Brak blobReferenceToken w odpowiedzi blob storage")
        logger.debug(f"upload_attachment: {filename!r} {len(data)}B → refToken={ref_token[:16]}...")

        owner_enc_file_sk = aes_encrypt_tuta(mail_group_key, file_sk, add_padding=False)
        enc_filename  = aes_encrypt_tuta(file_sk, filename.encode("utf-8"), add_padding=True)
        enc_mime_type = aes_encrypt_tuta(file_sk, mime_type.encode("utf-8"), add_padding=True)

        new_file: dict = {
            "487": _random_custom_id(),
            "488": base64.b64encode(enc_filename).decode(),
            "489": base64.b64encode(enc_mime_type).decode(),
            "925": None,
            "1226": [{"1991": _random_custom_id(), "1992": ref_token}],
        }
        if cid:
            enc_cid = aes_encrypt_tuta(file_sk, cid.encode("utf-8"), add_padding=True)
            new_file["925"] = base64.b64encode(enc_cid).decode()

        draft_attachment: dict = {
            "492": _random_custom_id(),
            "493": base64.b64encode(owner_enc_file_sk).decode(),
            "1430": session.mail_group_key_version,
            "494": [new_file],
            "495": [],
        }
        return draft_attachment, file_sk

    async def get_recipient_public_key(self, email: str, token: str) -> "dict | None":
        """
        Sprawdza czy odbiorca jest użytkownikiem Tuty i zwraca jego klucze publiczne.
        Zwraca None jeśli odbiorca zewnętrzny (404 z PublicKeyService).

        Pola odpowiedzi PublicKeyGetOut:
          414=pubRsaKey, 415=pubKeyVersion, 2148=pubEccKey, 2149=pubKyberKey
        """
        url = self._url("sys", "publickeyservice")
        body = json.dumps({"410": "0", "411": email, "2244": None, "2468": "0"})
        params = {"_body": body}
        try:
            resp = await self._get(url, token=token, params=params)
        except TutaAPIError as e:
            if e.status_code == 404:
                return None
            raise

        return {
            "pubRsaKey": base64.b64decode(resp["414"]) if resp.get("414") else None,
            "pubEccKey": base64.b64decode(resp["2148"]) if resp.get("2148") else None,
            "pubKyberKey": base64.b64decode(resp["2149"]) if resp.get("2149") else None,
            "pubKeyVersion": resp.get("415", "0"),
        }

    async def get_sender_ecc_keypair(self, session: Session) -> "tuple[bytes, bytes, str]":
        """
        Ładuje parę kluczy X25519 nadawcy z jego grupy użytkownika.
        Zwraca (ecc_priv_bytes, ecc_pub_bytes, key_version).
        Używane w TutaCrypt do uwierzytelnienia nadawcy (auth shared secret).
        """
        user_data = await self._get(self._url("sys", "user", session.user_id), token=session.access_token)
        user_group_list = user_data.get("95", [])
        ug = user_group_list[0] if isinstance(user_group_list, list) and user_group_list else {}
        g_ref = ug.get("29", [""])
        user_group_id = g_ref[-1] if isinstance(g_ref, list) else g_ref

        group_data = await self._get(self._url("sys", "group", user_group_id), token=session.access_token)

        # currentKeys (pole 13) = KeyPair aggregate z kluczami ECC i Kyber
        current_keys = group_data.get("13", {})
        if isinstance(current_keys, list):
            current_keys = current_keys[0] if current_keys else {}

        pub_ecc = base64.b64decode(current_keys.get("2144", ""))
        enc_priv_ecc = base64.b64decode(current_keys.get("2145", ""))
        version = str(group_data.get("2271", "0"))

        priv_ecc = aes_decrypt_tuta(session.user_group_key, enc_priv_ecc)
        return priv_ecc, pub_ecc, version

    async def send_draft_e2e(
        self,
        session: Session,
        draft_list_id: str,
        draft_elem_id: str,
        session_key: bytes,
        recipients: "list[tuple[str, dict]]",
        sender_ecc_priv: bytes,
        sender_ecc_pub: bytes,
        sender_key_version: str,
        attachment_keys: "list[tuple[str, str, bytes]] | None" = None,
    ) -> None:
        """
        Wysyła draft z szyfrowaniem E2E (TutaCrypt lub RSA-OAEP).

        Dla każdego odbiorcy szyfruje bucket_key jego kluczem publicznym.
        Protokół:
          bucket_key → losowy 32-bajtowy klucz AES
          bucket_enc_session_key = aes_encrypt(bucket_key, session_key, no_padding)
          pub_enc_bucket_key = TutaCrypt lub RSA-OAEP(bucket_key)
          SendDraftData.internalRecipientKeyData = lista zaszyfrowanych kluczy

        InternalRecipientKeyData (id=527):
          528=_id, 529=mailAddress, 530=pubEncBucketKey (base64),
          531=recipientKeyVersion, 1352=protocolVersion, 1431=senderKeyVersion
        """
        bucket_key = os.urandom(32)
        bucket_enc_session_key = aes_encrypt_tuta(bucket_key, session_key, add_padding=False)

        internal_key_data = []
        all_tutacrypt = True
        for email, pub_key in recipients:
            pub_ecc = pub_key.get("pubEccKey")
            pub_kyber = pub_key.get("pubKyberKey")
            pub_rsa = pub_key.get("pubRsaKey")
            key_version = pub_key.get("pubKeyVersion", "0")

            if pub_ecc and pub_kyber:
                pub_enc_bucket_key = pq_encapsulate_bucket_key(
                    sender_ecc_priv, sender_ecc_pub,
                    pub_ecc, pub_kyber,
                    bucket_key,
                )
                proto_version = "2"  # CryptoProtocolVersion.TUTA_CRYPT
                sender_kv = sender_key_version
            elif pub_rsa:
                pub_enc_bucket_key = rsa_oaep_encrypt_tuta(pub_rsa, bucket_key)
                proto_version = "0"  # CryptoProtocolVersion.RSA
                sender_kv = None
                all_tutacrypt = False
            else:
                raise TutaAPIError(0, f"Brak obsługiwanego klucza publicznego dla {email}")

            internal_key_data.append({
                "528": _random_custom_id(),
                "529": email,
                "530": base64.b64encode(pub_enc_bucket_key).decode(),
                "531": key_version,
                "1352": proto_version,
                "1431": sender_kv,
            })

        # EncryptionAuthStatus.TUTACRYPT_SENDER = "4" zaszyfrowane kluczem sesji
        # Ustawiane tylko gdy wszyscy odbiorcy używają TutaCrypt (jak isTutaCryptMail w Tucie)
        session_enc_auth = None
        if all_tutacrypt:
            session_enc_auth = base64.b64encode(
                aes_encrypt_tuta(session_key, b"4", add_padding=True)
            ).decode()

        # AttachmentKeyData (type 542): E2E → klucz pliku szyfrowany bucket_key (pole 544)
        # pole 546 = file (LIST_ELEMENT_ASSOCIATION_GENERATED One) → [[listId, elemId]]
        att_key_data = [
            {
                "543": _random_custom_id(),
                "544": base64.b64encode(
                    aes_encrypt_tuta(bucket_key, file_sk, add_padding=False)
                ).decode(),
                "545": None,
                "546": [[flist_id, felem_id]],
            }
            for flist_id, felem_id, file_sk in (attachment_keys or [])
        ]

        body = {
            "548": "0",
            "549": "en",
            "550": None,
            "551": base64.b64encode(bucket_enc_session_key).decode(),
            "552": None,
            "675": "0",
            "1117": "0",
            "1444": session_enc_auth,
            "1809": None,
            "1822": "0",
            "553": internal_key_data,
            "554": [],
            "555": att_key_data,
            "556": [[draft_list_id, draft_elem_id]],
            "1353": [],
            "1810": [],
        }

        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug(f"send_draft_e2e POST draft={draft_elem_id} recipients={[e for e,_ in recipients]} attachments={len(att_key_data)}")
        async with self._http.post(
            self.base_url + "/rest/tutanota/senddraftservice",
            json=body,
            headers=headers,
        ) as r:
            text = await r.text()
            if r.status not in (200, 201, 204):
                logger.warning(f"send_draft_e2e {r.status}: {text[:400]}")
                raise _api_error(r.status, text)
        logger.info(f"send_draft_e2e: draft {draft_elem_id} sent E2E → {len(recipients)} odbiorców")


    # -----------------------------------------------------------------------
    # Kalendarz
    # -----------------------------------------------------------------------

    async def get_calendar_group_key(self, session: Session) -> tuple[str, bytes, str]:
        """
        Zwraca (calendar_group_id, calendar_group_key, cal_key_version).
        cal_key_version = wersja klucza z GroupMembership (pole 2246).
        """
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token,
        )
        for m in user_data.get("96", []):
            if m.get("1030") == "9":  # calendar group
                enc_key = base64.b64decode(m.get("27", ""))
                g = m.get("29", "")
                group_id = g[-1] if isinstance(g, list) else g
                key_version = str(m.get("2246", "0") or "0")
                cal_group_key = aes_decrypt_tuta(session.user_group_key, enc_key)
                logger.debug("calendar_group_id=%s key=%s... kv=%s",
                             group_id, cal_group_key.hex()[:16], key_version)
                return group_id, cal_group_key, key_version
        raise TutaAPIError(0, "Nie znaleziono grupy kalendarza (groupType=9)")

    async def get_calendar_events(self, session: Session) -> list["CalendarEvent"]:
        """
        Pobiera i odszyfrowuje wszystkie eventy kalendarza.
        CalendarGroupRoot → shortEvents (954) + longEvents (955) → CalendarEvent[].
        """
        cal_group_id, cal_group_key, _kv = await self.get_calendar_group_key(session)

        root = await self._get_tutanota(
            self._url("tutanota", "calendargrouproot", cal_group_id),
            token=session.access_token,
        )

        events: list[CalendarEvent] = []
        list_names = {"954": "shortEvents", "955": "longEvents"}
        # 954 = shortEvents listId, 955 = longEvents listId (LIST_ASSOCIATION)
        for field_id in ("954", "955"):
            list_id = root.get(field_id, "")
            if isinstance(list_id, list):
                list_id = list_id[-1] if list_id else ""
            if not list_id:
                logger.debug("get_calendar_events: brak list_id dla pola %s (%s)", field_id, list_names[field_id])
                continue

            raw_count = 0
            ok_count = 0
            # Pobierz wszystkie eventy z listy (paginacja po 200)
            start = "AAAAAAAAAAAA"
            for _ in range(50):  # max 10 000 eventów
                page = await self._get_tutanota(
                    self._url("tutanota", "calendarevent", list_id),
                    token=session.access_token,
                    params={"start": start, "count": "200", "reverse": "false"},
                )
                if not isinstance(page, list) or not page:
                    break
                raw_count += len(page)
                for raw in page:
                    ev = self._decrypt_calendar_event(raw, cal_group_key)
                    if ev:
                        ok_count += 1
                        events.append(ev)
                if len(page) < 200:
                    break
                # Następna strona — start = _id ostatniego elementu
                last_id = page[-1].get("935", "")
                if isinstance(last_id, list):
                    last_id = last_id[-1] if last_id else ""
                start = last_id or "AAAAAAAAAAAA"

            logger.debug("get_calendar_events: %s (field %s) → %d raw, %d odszyfrowanych",
                         list_names[field_id], field_id, raw_count, ok_count)

        logger.info("Pobrano %d eventów kalendarza", len(events))
        return events

    def _decrypt_calendar_event(
        self, raw: dict, cal_group_key: bytes
    ) -> Optional["CalendarEvent"]:
        """Odszyfrowuje pojedynczy CalendarEvent. Zwraca None przy błędzie."""
        try:
            enc_sk_b64 = raw.get("939", "")
            if not enc_sk_b64:
                return None
            session_key = aes_decrypt_tuta(
                cal_group_key, base64.b64decode(enc_sk_b64)
            )

            def dec_str(fid: str) -> str:
                val = raw.get(fid, "")
                if not val:
                    return ""
                return aes_decrypt_tuta(
                    session_key, base64.b64decode(val)
                ).decode("utf-8", errors="replace")

            def dec_date(fid: str) -> Optional[_datetime]:
                val = raw.get(fid, "")
                if not val:
                    return None
                # Tuta szyfruje datę jako string milli-sekund od epoki UTC
                ms_str = aes_decrypt_tuta(
                    session_key, base64.b64decode(val)
                ).decode("utf-8")
                return _datetime.utcfromtimestamp(int(ms_str) / 1000)

            start = dec_date("942")
            end   = dec_date("943")
            uid   = dec_str("988")

            # _id = [listId, elemId] — zachowaj do późniejszego usunięcia/aktualizacji
            ev_id_raw = raw.get("935", "")
            ev_list_id = ev_id_raw[0] if isinstance(ev_id_raw, list) and len(ev_id_raw) > 0 else ""
            ev_elem_id = ev_id_raw[1] if isinstance(ev_id_raw, list) and len(ev_id_raw) > 1 else ""

            # Fallback UID z pola _id eventu (935 = CustomId [listId, elemId])
            if not uid:
                uid = ev_elem_id or ""

            def _is_all_day(s: Optional[_datetime], e: Optional[_datetime]) -> bool:
                if not s or not e:
                    return False
                return (s.hour == 0 and s.minute == 0 and s.second == 0
                        and e.hour == 0 and e.minute == 0 and e.second == 0)

            seq_raw = raw.get("1089", "")
            sequence = 0
            if seq_raw:
                try:
                    seq_bytes = aes_decrypt_tuta(session_key, base64.b64decode(seq_raw))
                    sequence = int(seq_bytes.decode("utf-8"))
                except Exception:
                    pass

            rrule = self._decrypt_repeat_rule(raw.get("945"), session_key)
            try:
                recurrence_id = dec_date("1320")
            except Exception:
                recurrence_id = None

            return CalendarEvent(
                uid=uid,
                summary=dec_str("940"),
                start=start,
                end=end,
                location=dec_str("944"),
                description=dec_str("941"),
                all_day=_is_all_day(start, end),
                sequence=sequence,
                list_id=ev_list_id,
                elem_id=ev_elem_id,
                rrule=rrule,
                recurrence_id=recurrence_id,
            )
        except Exception as exc:
            ev_id = raw.get("935", "?")
            logger.warning("Błąd deszyfrowania eventu %s: %s", ev_id, exc)
            return None

    @staticmethod
    def _decrypt_repeat_rule(raw_field, session_key: bytes) -> Optional["RepeatRule"]:
        """
        Deszyfruje CalendarRepeatRule z pola 945 CalendarEvent.
        raw_field: [] gdy brak, [{...}] gdy present (ZeroOrOne aggregation).
        """
        if not raw_field or not isinstance(raw_field, list) or len(raw_field) == 0:
            return None
        rr = raw_field[0] if isinstance(raw_field[0], dict) else None
        if not rr:
            return None

        def d(fid: str, default: str = "") -> str:
            val = rr.get(fid, "")
            if not val:
                return default
            try:
                return aes_decrypt_tuta(session_key, base64.b64decode(val)).decode("utf-8")
            except Exception:
                return default

        frequency = d("928", "0")
        end_type  = d("929", "0")
        end_value = d("930") or None
        interval  = d("931", "1")
        time_zone = d("932", "UTC")

        # excludedDates: lista DateWrapper [{2074:_id, 2075:date_enc}]
        excluded_dates: list[int] = []
        for dw in (rr.get("1319") or []):
            if not isinstance(dw, dict):
                continue
            date_enc = dw.get("2075", "")
            if date_enc:
                try:
                    ms = int(aes_decrypt_tuta(session_key, base64.b64decode(date_enc)).decode())
                    excluded_dates.append(ms)
                except Exception:
                    pass

        # advancedRules: lista AdvancedRepeatRule [{1587:_id, 1588:ruleType_enc, 1589:interval_enc}]
        advanced: list[RepeatRuleAdvanced] = []
        for ar in (rr.get("1590") or []):
            if not isinstance(ar, dict):
                continue
            rt_enc = ar.get("1588", "")
            iv_enc = ar.get("1589", "")
            if rt_enc and iv_enc:
                try:
                    rule_type = aes_decrypt_tuta(session_key, base64.b64decode(rt_enc)).decode()
                    rule_iv   = aes_decrypt_tuta(session_key, base64.b64decode(iv_enc)).decode()
                    advanced.append(RepeatRuleAdvanced(rule_type=rule_type, interval=rule_iv))
                except Exception:
                    pass

        return RepeatRule(
            frequency=frequency,
            end_type=end_type,
            end_value=end_value,
            interval=interval,
            time_zone=time_zone,
            excluded_dates=excluded_dates,
            advanced_rules=advanced,
        )

    @staticmethod
    def _encode_repeat_rule(rr: "RepeatRule", session_key: bytes) -> list:
        """
        Koduje RepeatRule do formatu JSON dla pola 945 CalendarEvent.
        Zwraca [{}] (One element array) jak wymaga ZeroOrOne aggregation.
        """
        def e(text: str) -> str:
            return base64.b64encode(
                aes_encrypt_tuta(session_key, text.encode("utf-8"), add_padding=True)
            ).decode()

        # excludedDates: lista DateWrapper
        excluded = []
        for ms in (rr.excluded_dates or []):
            excl_id = base64.urlsafe_b64encode(os.urandom(4)).rstrip(b"=").decode()
            excluded.append({
                "2074": excl_id,
                "2075": e(str(ms)),
            })

        # advancedRules: lista AdvancedRepeatRule
        adv_rules = []
        for ar in (rr.advanced_rules or []):
            ar_id = base64.urlsafe_b64encode(os.urandom(4)).rstrip(b"=").decode()
            adv_rules.append({
                "1587": ar_id,
                "1588": e(ar.rule_type),
                "1589": e(ar.interval),
            })

        rr_id = base64.urlsafe_b64encode(os.urandom(4)).rstrip(b"=").decode()
        obj = {
            "927": rr_id,
            "928": e(rr.frequency),
            "929": e(rr.end_type),
            "930": e(rr.end_value) if rr.end_value else None,
            "931": e(rr.interval),
            "932": e(rr.time_zone or "UTC"),
            "1319": excluded,
            "1590": adv_rules,
        }
        return [obj]

    async def get_calendar_group_root_info(
        self, session: Session
    ) -> tuple[str, bytes, str, str, str]:
        """Zwraca (group_id, group_key, short_list_id, long_list_id, key_version)."""
        group_id, group_key, key_version = await self.get_calendar_group_key(session)
        root = await self._get_tutanota(
            self._url("tutanota", "calendargrouproot", group_id),
            token=session.access_token,
        )
        def _list_id(fid: str) -> str:
            v = root.get(fid, "")
            return (v[-1] if isinstance(v, list) and v else v) or ""
        return group_id, group_key, _list_id("954"), _list_id("955"), key_version

    async def create_calendar_event_api(
        self,
        session: Session,
        group_key: bytes,
        group_id: str,
        short_list_id: str,
        long_list_id: str,
        ev: "CalendarEvent",
        key_version: str = "0",
    ) -> tuple[str, str]:
        """
        Tworzy nowy event kalendarza w Tuta.
        Zwraca (listId, elemId) nowego eventu.

        Event trafia do shortEvents gdy czas trwania < 15 dni, inaczej do longEvents.
        Klucz sesji eventu jest szyfrowany group_key.
        """
        from datetime import timezone as _tz

        sk = os.urandom(32)
        owner_enc_sk = aes_encrypt_tuta(group_key, sk, add_padding=False)

        def enc(text: str) -> str:
            return base64.b64encode(
                aes_encrypt_tuta(sk, text.encode("utf-8"), add_padding=True)
            ).decode()

        def _to_ms(dt: Optional[_datetime]) -> int:
            if dt is None:
                return 0
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_tz.utc)
            return int(dt.timestamp() * 1000)

        start_ms = _to_ms(ev.start)
        end_ms   = _to_ms(ev.end)
        DAYS_15_MS = 15 * 24 * 60 * 60 * 1000
        # Tuta: isLongEvent = repeatRule != null || duration >= DAYS_SHIFTED_MS (~15 dni)
        # Recurring events MUST be in longEvents — shortEvents są przeszukiwane range-based po ID
        is_long  = (end_ms - start_ms) >= DAYS_15_MS or ev.rrule is not None
        list_id  = long_list_id if is_long else short_list_id

        # CustomId = base64url(str(start_ms + random_shift_±15 dni))
        elem_id  = _generate_event_elem_id(start_ms)

        uid = ev.uid or _random_custom_id()
        hashed_uid = base64.b64encode(hashlib.sha256(uid.encode()).digest()).decode()

        body = {
            "935": [list_id, elem_id],         # _id (CustomId)
            "936": None,                       # _permissions — null przy tworzeniu, serwer generuje
            "937": "0",                        # _format
            "938": group_id,                   # _ownerGroup (ZeroOrOne, FINAL)
            "939": base64.b64encode(owner_enc_sk).decode(),  # _ownerEncSessionKey
            "940": enc(ev.summary or ""),      # summary (Exactly1, encrypted)
            "941": enc(ev.description or ""),  # description (Exactly1, encrypted)
            "942": enc(str(start_ms)),         # startTime (Exactly1, encrypted)
            "943": enc(str(end_ms)),           # endTime (Exactly1, encrypted)
            "944": enc(ev.location or ""),     # location (Exactly1, encrypted)
            "945": self._encode_repeat_rule(ev.rrule, sk) if ev.rrule else [],  # repeatRule (ZeroOrOne)
            "946": [],                         # alarmInfos (LIST_ELEMENT_ASSOCIATION)
            "988": enc(uid),                   # uid (ZeroOrOne, encrypted)
            "1088": hashed_uid,                # hashedUid (ZeroOrOne, SHA-256 base64)
            "1089": enc(str(ev.sequence or 0)), # sequence (Exactly1, encrypted)
            "1090": enc("0"),                  # invitedConfidentially = false (jak Tuta web app)
            "1091": [],                        # attendees (aggregation, Any)
            "1092": [],                        # organizer (ZeroOrOne aggregation → [] gdy brak)
            "1320": None,                      # recurrenceId (ZeroOrOne)
            "1401": key_version,               # _ownerKeyVersion (widoczne w raw events)
            "1812": None,                      # sender (ZeroOrOne)
            "1813": enc("0"),                  # pendingInvitation (ZeroOrOne, encrypted bool)
            "1845": None,                      # _kdfNonce (widoczne w raw events)
        }
        url = self._url("tutanota", "calendarevent", list_id)
        # Tuta używa setupMultiple() nawet dla pojedynczych eventów → array + ?count=N
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        async with self._http.post(url, json=[body], headers=headers,
                                   params={"count": "1"}) as r:
            if r.status not in (200, 201):
                text = await r.text()
                logger.error("create_calendar_event_api: HTTP %d headers=%s — %s", r.status, dict(r.headers), text[:500])
                raise _api_error(r.status, text)
        logger.info("create_calendar_event_api: %s → [%s, %s]", uid[:16], list_id[:12], elem_id[:12])
        return list_id, elem_id

    async def delete_calendar_event_api(
        self,
        session: Session,
        list_id: str,
        elem_id: str,
    ) -> None:
        """Usuwa event kalendarza przez REST DELETE."""
        url = self._url("tutanota", "calendarevent", list_id, elem_id)
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        async with self._http.delete(url, headers=headers) as r:
            if r.status not in (200, 204):
                text = await r.text()
                raise _api_error(r.status, text)
        logger.info("delete_calendar_event_api: [%s, %s]", list_id[:12], elem_id[:12])

    # -----------------------------------------------------------------------
    # Kontakty
    # -----------------------------------------------------------------------

    async def get_contact_group_info(
        self, session: Session
    ) -> "tuple[str, bytes, str, str]":
        """
        Zwraca (list_id, contact_group_key, group_id, key_version).
        list_id = ID listy kontaktów w Tucie.
        """
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token,
        )
        contact_group_key: Optional[bytes] = None
        group_id = ""
        key_version = "0"
        memberships = user_data.get("96", [])
        logger.debug("get_contact_group_info: dostępne groupType: %s",
                     [m.get("1030") for m in memberships if isinstance(m, dict)])
        for m in memberships:
            if m.get("1030") == "6":  # Contact group (nie "11" = ContactList, to enterprise shared lists)
                enc_key = base64.b64decode(m.get("27", ""))
                g = m.get("29", "")
                group_id = g[-1] if isinstance(g, list) else g
                key_version = str(m.get("2246", "0") or "0")
                contact_group_key = aes_decrypt_tuta(session.user_group_key, enc_key)
                break
        if contact_group_key is None or not group_id:
            logger.error("get_contact_group_info: brak groupType=6, dostępne: %s",
                         [m.get("1030") for m in memberships if isinstance(m, dict)])
            raise TutaAPIError(0, "Nie znaleziono grupy kontaktów (groupType=6)")

        if not session.user_group_id:
            raise TutaAPIError(0, "user_group_id niedostępny")
        # loadRoot(ContactListTypeRef, user.userGroup.group):
        #   1. GET /rest/sys/rootinstance/{user_group_id}/CHR1dGFub3RhAACZ → reference
        #   2. GET /rest/tutanota/contactlist/{reference} → pole 160 = contacts list_id
        CONTACT_LIST_ROOT_ID = "CHR1dGFub3RhAACZ"
        ri_url = self._url("sys", "rootinstance", session.user_group_id, CONTACT_LIST_ROOT_ID)
        logger.debug("get_contact_group_info: rootinstance URL=%s", ri_url)
        root_instance = await self._get(ri_url, token=session.access_token)
        contact_list_elem_id = root_instance.get("236", "")
        if not contact_list_elem_id:
            raise TutaAPIError(0, "Brak reference w RootInstance ContactList")
        contact_list = await self._get_tutanota(
            self._url("tutanota", "contactlist", contact_list_elem_id),
            token=session.access_token,
        )
        list_id = contact_list.get("160", "")
        if isinstance(list_id, list):
            list_id = list_id[-1] if list_id else ""
        if not list_id:
            raise TutaAPIError(0, "Brak contacts list_id w ContactList")

        logger.debug("contact list_id=%s group_id=%s kv=%s", list_id[:12], group_id[:12], key_version)
        return list_id, contact_group_key, group_id, key_version

    async def get_contacts(self, session: Session) -> "list[Contact]":
        """Pobiera i odszyfrowuje wszystkie kontakty użytkownika."""
        list_id, contact_group_key, _gid, _kv = await self.get_contact_group_info(session)
        contacts: list[Contact] = []
        start = "AAAAAAAAAAAA"
        raw_total = 0
        for _ in range(200):  # max ~100 000 kontaktów (strony po 500)
            page = await self._get_tutanota(
                self._url("tutanota", "contact", list_id),
                token=session.access_token,
                params={"start": start, "count": "500", "reverse": "false"},
            )
            if not isinstance(page, list) or not page:
                break
            raw_total += len(page)
            for raw in page:
                c = self._decrypt_contact(raw, contact_group_key)
                if c:
                    contacts.append(c)
            if len(page) < 500:
                break
            last_raw_id = page[-1].get("66", "")
            if isinstance(last_raw_id, list):
                last_raw_id = last_raw_id[-1] if last_raw_id else ""
            start = last_raw_id or "AAAAAAAAAAAA"

        logger.info("Pobrano %d kontaktów (raw: %d)", len(contacts), raw_total)
        return contacts

    def _decrypt_contact(self, raw: dict, contact_group_key: bytes) -> "Optional[Contact]":
        """Odszyfrowuje pojedynczy Contact. Zwraca None przy błędzie."""
        try:
            enc_sk_b64 = raw.get("69", "")
            if not enc_sk_b64:
                return None
            sk = aes_decrypt_tuta(contact_group_key, base64.b64decode(enc_sk_b64))

            def d(fid: str) -> str:
                v = raw.get(fid, "")
                if not v:
                    return ""
                try:
                    return aes_decrypt_tuta(sk, base64.b64decode(v)).decode("utf-8")
                except Exception:
                    return ""

            def da(obj: dict, fid: str) -> str:
                v = obj.get(fid, "")
                if not v:
                    return ""
                try:
                    return aes_decrypt_tuta(sk, base64.b64decode(v)).decode("utf-8")
                except Exception:
                    return ""

            raw_id = raw.get("66", "")
            if isinstance(raw_id, list) and len(raw_id) == 2:
                c_list_id, elem_id = raw_id[0], raw_id[1]
            else:
                c_list_id, elem_id = "", str(raw_id)

            mail_addresses = [
                ContactMailAddress(
                    _id=m.get("45", ""),
                    type=da(m, "46") or "2",
                    custom_type=da(m, "48"),
                    address=da(m, "47"),
                )
                for m in (raw.get("80") or []) if isinstance(m, dict)
            ]
            phone_numbers = [
                ContactPhoneNumber(
                    _id=p.get("50", ""),
                    type=da(p, "51") or "4",
                    custom_type=da(p, "53"),
                    number=da(p, "52"),
                )
                for p in (raw.get("81") or []) if isinstance(p, dict)
            ]
            addresses = [
                ContactAddress(
                    _id=a.get("55", ""),
                    type=da(a, "56") or "2",
                    custom_type=da(a, "58"),
                    address=da(a, "57"),
                )
                for a in (raw.get("82") or []) if isinstance(a, dict)
            ]
            websites = [
                (da(w, "1363") or "2", da(w, "1365"))
                for w in (raw.get("1387") or [])
                if isinstance(w, dict) and da(w, "1365")
            ]
            social_ids = [
                (da(s, "61") or "4", da(s, "62"))
                for s in (raw.get("83") or [])
                if isinstance(s, dict) and da(s, "62")
            ]

            return Contact(
                list_id=c_list_id,
                elem_id=elem_id,
                first_name=d("72"),
                last_name=d("73"),
                middle_name=d("1380"),
                title=d("850"),
                name_suffix=d("1381"),
                nickname=d("849"),
                company=d("74"),
                department=d("1385"),
                role=d("75"),
                mail_addresses=mail_addresses,
                phone_numbers=phone_numbers,
                addresses=addresses,
                websites=websites,
                social_ids=social_ids,
                birthday_iso=d("1083"),
                comment=d("77"),
            )
        except Exception as exc:
            logger.warning("_decrypt_contact: błąd — %s", exc)
            return None

    def _enc_contact_body(
        self,
        contact: "Contact",
        sk: bytes,
        group_id: str,
        owner_enc_sk: bytes,
        key_version: str,
        existing_raw: Optional[dict] = None,
    ) -> dict:
        """Buduje zaszyfrowany JSON kontaktu dla POST/PUT."""
        def enc(text: str) -> str:
            return base64.b64encode(
                aes_encrypt_tuta(sk, (text or "").encode("utf-8"), add_padding=True)
            ).decode()

        def enc_or_null(text: str) -> Optional[str]:
            return enc(text) if text else None

        def enc_mail(m: "ContactMailAddress") -> dict:
            return {"45": m._id or _random_custom_id(), "46": enc(m.type),
                    "47": enc(m.address), "48": enc(m.custom_type)}

        def enc_phone(p: "ContactPhoneNumber") -> dict:
            return {"50": p._id or _random_custom_id(), "51": enc(p.type),
                    "52": enc(p.number), "53": enc(p.custom_type)}

        def enc_addr(a: "ContactAddress") -> dict:
            return {"55": a._id or _random_custom_id(), "56": enc(a.type),
                    "57": enc(a.address), "58": enc(a.custom_type)}

        def enc_website(w: tuple) -> dict:
            t, url = w
            return {"1362": _random_custom_id(), "1363": enc(t), "1364": enc(""), "1365": enc(url)}

        def enc_social(s: tuple) -> dict:
            t, sid = s
            return {"60": _random_custom_id(), "61": enc(t), "62": enc(sid), "63": enc("")}

        return {
            "66": [contact.list_id, contact.elem_id] if contact.list_id and contact.elem_id else None,
            "67": existing_raw.get("67") if existing_raw else None,  # _permissions
            "68": "0",
            "69": base64.b64encode(owner_enc_sk).decode(),
            "72": enc(contact.first_name),
            "73": enc(contact.last_name),
            "74": enc(contact.company),
            "75": enc(contact.role),
            "76": existing_raw.get("76") if existing_raw else None,  # oldBirthdayDate (deprecated, preserve on update)
            "77": enc(contact.comment),
            "79": None,  # presharedPassword
            "80": [enc_mail(m) for m in contact.mail_addresses],
            "81": [enc_phone(p) for p in contact.phone_numbers],
            "82": [enc_addr(a) for a in contact.addresses],
            "83": [enc_social(s) for s in contact.social_ids],
            "585": existing_raw.get("585") if existing_raw else group_id,  # _ownerGroup
            "849": enc_or_null(contact.nickname),
            "850": enc_or_null(contact.title),
            "851": [],   # oldBirthdayAggregate (ZeroOrOne AGGREGATION → [] when absent)
            # photo: LIST_ELEMENT_ASSOCIATION ZeroOrOne — Tuta wymaga [] gdy brak, nie null
            "852": (existing_raw.get("852") or []) if existing_raw else [],
            "1083": enc_or_null(contact.birthday_iso),
            "1380": enc_or_null(contact.middle_name),
            "1381": enc_or_null(contact.name_suffix),
            "1382": None, "1383": None, "1384": None,  # phonetic fields
            "1385": enc_or_null(contact.department),
            "1386": [],  # customDate
            "1387": [enc_website(w) for w in contact.websites],
            "1388": [],  # relationships
            "1389": [],  # messengerHandles
            "1390": [],  # pronouns
            # FINAL fields — przy update zachowujemy wartości z istniejącego rekordu
            "1394": existing_raw.get("1394", key_version) if existing_raw else key_version,  # _ownerKeyVersion
            "1837": existing_raw.get("1837") if existing_raw else None,  # _kdfNonce (FINAL)
        }

    async def create_contact_api(
        self,
        session: Session,
        contact: "Contact",
        list_id: str,
        contact_group_key: bytes,
        group_id: str,
        key_version: str = "0",
    ) -> "tuple[str, str]":
        """Tworzy nowy kontakt w Tucie. Zwraca (list_id, elem_id) nowego kontaktu."""
        sk = os.urandom(32)
        owner_enc_sk = aes_encrypt_tuta(contact_group_key, sk, add_padding=False)
        body = self._enc_contact_body(contact, sk, group_id, owner_enc_sk, key_version)

        # setupMultiple — Tuta wymaga tablicy + ?count=N (tak samo jak CalendarEvent)
        url = self._url("tutanota", "contact", list_id)
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        logger.debug("create_contact_api: body keys=%s", list(body.keys()))
        async with self._http.post(url, json=[body], headers=headers,
                                   params={"count": "1"}) as r:
            if r.status not in (200, 201):
                text = await r.text()
                resp_hdrs = dict(r.headers)
                logger.error("create_contact_api: HTTP %d hdrs=%s — %r", r.status, resp_hdrs, text[:800])
                raise _api_error(r.status, text)
            resp = await r.json()

        # setupMultiple zwraca listę PersistenceResourcePostReturn:
        # [{'1': '0', '2': generatedId, '3': permissionListId}, ...]
        if isinstance(resp, list) and resp:
            entry = resp[0]
            if isinstance(entry, dict):
                new_id = entry.get("2") or str(entry)
            elif isinstance(entry, list):
                new_id = entry[-1]
            else:
                new_id = str(entry)
        else:
            new_id = str(resp)
        logger.info("create_contact_api: → [%s, %s]", list_id[:12], new_id[:12])
        return list_id, new_id

    async def update_contact_api(
        self,
        session: Session,
        contact: "Contact",
        contact_group_key: bytes,
        key_version: str = "0",
    ) -> None:
        """Aktualizuje istniejący kontakt przez PUT."""
        if not contact.list_id or not contact.elem_id:
            raise TutaAPIError(0, "Kontakt bez list_id/elem_id — nie można zaktualizować")

        url = self._url("tutanota", "contact", contact.list_id, contact.elem_id)
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        raw = await self._get_tutanota(url, token=session.access_token)

        logger.debug("update_contact_api: raw keys=%s", sorted(raw.keys()))
        # Reużywamy istniejący klucz sesji zamiast generować nowy
        enc_sk_b64 = raw.get("69", "")
        if enc_sk_b64:
            sk = aes_decrypt_tuta(contact_group_key, base64.b64decode(enc_sk_b64))
            owner_enc_sk = base64.b64decode(enc_sk_b64)
        else:
            sk = os.urandom(32)
            owner_enc_sk = aes_encrypt_tuta(contact_group_key, sk, add_padding=False)
        body = self._enc_contact_body(
            contact, sk, raw.get("585", ""), owner_enc_sk, key_version, existing_raw=raw
        )

        logger.debug("update_contact_api: body keys=%s", list(body.keys()))
        async with self._http.put(url, json=body, headers=headers) as r:
            if r.status not in (200, 204):
                text = await r.text()
                resp_hdrs = dict(r.headers)
                logger.error("update_contact_api: HTTP %d hdrs=%s — %r", r.status, resp_hdrs, text[:800])
                raise _api_error(r.status, text)
        logger.info("update_contact_api: [%s, %s]", contact.list_id[:12], contact.elem_id[:12])

    async def delete_contact_api(
        self,
        session: Session,
        list_id: str,
        elem_id: str,
    ) -> None:
        """Usuwa kontakt przez REST DELETE."""
        url = self._url("tutanota", "contact", list_id, elem_id)
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        async with self._http.delete(url, headers=headers) as r:
            if r.status not in (200, 204):
                text = await r.text()
                raise _api_error(r.status, text)
        logger.info("delete_contact_api: [%s, %s]", list_id[:12], elem_id[:12])

    async def delete_contacts_bulk_api(
        self,
        session: Session,
        list_id: str,
        elem_ids: list[str],
    ) -> None:
        """Bulk-delete kontaktów przez eraseMultiple (DELETE ?ids=id1,id2,...).

        Odpowiednik eraseMultiple() z EntityRestClient.ts — jeden request HTTP
        zamiast jednego per kontakt.
        """
        if not elem_ids:
            return
        url = self._url("tutanota", "contact", list_id)
        headers = {"accessToken": session.access_token, **TUTANOTA_HEADERS}
        params = {"ids": ",".join(elem_ids)}
        async with self._http.delete(url, headers=headers, params=params) as r:
            if r.status not in (200, 204):
                text = await r.text()
                raise _api_error(r.status, text)
        logger.info(
            "delete_contacts_bulk_api: [%s] × %d ids",
            list_id[:12], len(elem_ids),
        )

    # =========================================================================
    # Drive (Tuta Drive) — GroupType.File = "7", API v4
    # =========================================================================

    async def _get_drive(self, url: str, token: str, params: dict = None) -> Any:
        """GET dla endpointów drive (v=4)."""
        headers = {"accessToken": token, **DRIVE_HEADERS}
        async with self._http.get(url, headers=headers, params=params) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            body = await r.text()
            self._check_version_mismatch(r.status, body)
            raise _api_error(r.status, body)

    async def _post_drive(self, url: str, body: dict, token: str) -> Any:
        """POST dla endpointów drive (v=4)."""
        headers = {"accessToken": token, **DRIVE_HEADERS}
        async with self._http.post(url, json=body, headers=headers) as r:
            if r.status in (200, 201):
                text = await r.text()
                return json.loads(text) if text.strip() else None
            text = await r.text()
            self._check_version_mismatch(r.status, text)
            raise _api_error(r.status, text)

    async def _put_drive(self, url: str, body: dict, token: str) -> None:
        """PUT dla endpointów drive (v=4)."""
        headers = {"accessToken": token, **DRIVE_HEADERS}
        async with self._http.put(url, json=body, headers=headers) as r:
            if r.status not in (200, 204):
                text = await r.text()
                self._check_version_mismatch(r.status, text)
                raise _api_error(r.status, text)

    async def _delete_drive(self, url: str, body: dict, token: str) -> Any:
        """DELETE z ciałem JSON dla endpointów drive (v=4)."""
        headers = {"accessToken": token, **DRIVE_HEADERS}
        async with self._http.request("DELETE", url, json=body, headers=headers) as r:
            if r.status not in (200, 204):
                text = await r.text()
                self._check_version_mismatch(r.status, text)
                raise _api_error(r.status, text)
            if r.status == 200:
                return await r.json(content_type=None)
            return None

    async def get_drive_group_key(
        self, session: Session
    ) -> "tuple[str, bytes, str]":
        """Zwraca (file_group_id, file_group_key, key_version) dla groupType='7' (File)."""
        user_data = await self._get(
            self._url("sys", "user", session.user_id),
            token=session.access_token,
        )
        memberships = user_data.get("96", [])
        for m in memberships:
            if not isinstance(m, dict):
                continue
            if str(m.get("1030", "")) == FILE_GROUP_TYPE:
                enc_key_b64 = m.get("27", "")
                if not enc_key_b64:
                    continue
                g = m.get("29", "")
                group_id = g[-1] if isinstance(g, list) else g
                key_version = str(m.get("2246", "0") or "0")
                group_key = aes_decrypt_tuta(session.user_group_key, base64.b64decode(enc_key_b64))
                logger.debug("drive group_id=%s kv=%s", group_id[:12], key_version)
                return group_id, group_key, key_version
        raise TutaAPIError(0, "Brak grupy Drive (groupType=7) — konto bez dostępu do Tuta Drive")

    async def get_drive_root(
        self, session: Session, group_id: str, group_key: bytes, key_version: str
    ) -> "tuple[list, list]":
        """
        Ładuje DriveGroupRoot i zwraca (root_id_tuple, trash_id_tuple).
        Jeśli DriveGroupRoot nie istnieje (404), inicjalizuje Drive.
        """
        url = self._url("drive", "drivegrouproot", group_id)
        try:
            raw = await self._get_drive(url, token=session.access_token)
        except TutaAPIError as e:
            if e.status_code == 404:
                raw = await self._init_drive_root(session, group_id, group_key, key_version)
            else:
                raise
        # root i trash są LIST_ELEMENT_ASSOCIATION_GENERATED One → [[listId, elemId]]
        root = raw.get("53", [[]])[0] if isinstance(raw.get("53"), list) else []
        trash = raw.get("54", [[]])[0] if isinstance(raw.get("54"), list) else []
        if not root or not trash:
            raise TutaAPIError(0, f"DriveGroupRoot bez root/trash: {raw!r}")
        return root, trash

    async def _init_drive_root(
        self, session: Session, group_id: str, group_key: bytes, key_version: str
    ) -> dict:
        """POST DriveService — tworzy root i trash foldery Drive dla grupy."""
        root_sk = os.urandom(32)
        trash_sk = os.urandom(32)
        enc_root_sk = aes_encrypt_tuta(group_key, root_sk, add_padding=False)
        enc_trash_sk = aes_encrypt_tuta(group_key, trash_sk, add_padding=False)
        body = {
            "62": "0",   # _format
            "64": base64.b64encode(enc_root_sk).decode(),    # ownerEncRootFolderSessionKey
            "65": base64.b64encode(enc_trash_sk).decode(),   # ownerEncTrashFolderSessionKey
            "113": key_version,                               # ownerKeyVersion
            "63": group_id,                                   # fileGroupId (ELEMENT_ASSOCIATION)
        }
        url = self._url("drive", "driveservice")
        await self._post_drive(url, body, session.access_token)
        return await self._get_drive(
            self._url("drive", "drivegrouproot", group_id),
            token=session.access_token,
        )

    def _decrypt_drive_folder(self, raw: dict, group_key: bytes) -> "Optional[DriveFolder]":
        """Odszyfrowuje DriveFolder z surowego JSON API."""
        try:
            id_raw = raw.get("2", ["", ""])
            id_tuple = list(id_raw) if isinstance(id_raw, list) else ["", ""]
            enc_sk_b64 = raw.get("6", "")
            if not enc_sk_b64:
                return None
            sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))
            name_enc = raw.get("9", "")
            name = aes_decrypt_tuta(sk, base64.b64decode(name_enc)).decode("utf-8") if name_enc else ""
            folder_type = str(raw.get("8", "0"))
            parent_raw = raw.get("12")
            parent = list(parent_raw[0]) if isinstance(parent_raw, list) and parent_raw else None
            files_list_id_raw = raw.get("38", "")
            if isinstance(files_list_id_raw, list) and files_list_id_raw:
                files_list_id = str(files_list_id_raw[0])
            elif isinstance(files_list_id_raw, str):
                files_list_id = files_list_id_raw
            else:
                files_list_id = ""
            created_ms = int(raw.get("10", 0) or 0)
            updated_ms = int(raw.get("11", 0) or 0)
            return DriveFolder(
                id_tuple=id_tuple,
                name=name,
                folder_type=folder_type,
                parent=parent,
                files_list_id=files_list_id,
                created_ms=created_ms,
                updated_ms=updated_ms,
                raw=raw,
            )
        except Exception as e:
            logger.warning("_decrypt_drive_folder error: %s raw=%r", e, raw)
            return None

    def _decrypt_drive_file(self, raw: dict, group_key: bytes) -> "Optional[DriveFile]":
        """Odszyfrowuje DriveFile z surowego JSON API."""
        try:
            id_raw = raw.get("16", ["", ""])
            id_tuple = list(id_raw) if isinstance(id_raw, list) else ["", ""]
            enc_sk_b64 = raw.get("20", "")
            if not enc_sk_b64:
                return None
            sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))
            name_enc = raw.get("22", "")
            name = aes_decrypt_tuta(sk, base64.b64decode(name_enc)).decode("utf-8") if name_enc else ""
            mime_enc = raw.get("24", "")
            mime = aes_decrypt_tuta(sk, base64.b64decode(mime_enc)).decode("utf-8") if mime_enc else "application/octet-stream"
            size = int(raw.get("23", 0) or 0)
            folder_raw = raw.get("27", [])
            folder = list(folder_raw[0]) if isinstance(folder_raw, list) and folder_raw else ["", ""]
            blobs = raw.get("28", [])
            created_ms = int(raw.get("25", 0) or 0)
            updated_ms = int(raw.get("26", 0) or 0)
            return DriveFile(
                id_tuple=id_tuple,
                name=name,
                size=size,
                mime_type=mime,
                folder=folder,
                blobs=blobs,
                created_ms=created_ms,
                updated_ms=updated_ms,
                raw=raw,
            )
        except Exception as e:
            logger.warning("_decrypt_drive_file error: %s raw=%r", e, raw)
            return None

    async def get_drive_folder(
        self, session: Session, group_key: bytes, folder_id: list
    ) -> "Optional[DriveFolder]":
        """Ładuje i odszyfrowuje pojedynczy DriveFolder po IdTuple."""
        list_id, elem_id = folder_id[0], folder_id[1]
        url = self._url("drive", "drivefolder", list_id, elem_id)
        raw = await self._get_drive(url, token=session.access_token)
        return self._decrypt_drive_folder(raw, group_key)

    async def list_drive_folder_contents(
        self, session: Session, group_key: bytes, folder_id: list
    ) -> "tuple[list[DriveFolder], list[DriveFile]]":
        """
        Zwraca (subfolders, files) dla podanego folderu Drive.

        Przepływ:
          1. Załaduj DriveFolder → pobierz files_list_id (pole 38)
          2. GET wszystkich DriveFileRef z tej listy
          3. Dla każdego ref: załaduj DriveFile (ref.file) lub DriveFolder (ref.folder)
        """
        folder = await self.get_drive_folder(session, group_key, folder_id)
        if not folder or not folder.files_list_id:
            logger.warning("list_drive_folder_contents: folder=%s brak/pusty files_list_id (folder=%r)", folder_id, folder)
            return [], []
        logger.debug("list_drive_folder_contents: folder=%s files_list_id=%r", folder_id, folder.files_list_id)

        # Pobierz wszystkie DriveFileRef z listy (paginacja jak kontakty)
        refs = []
        start = "AAAAAAAAAAAA"
        for _ in range(50):
            page = await self._get_drive(
                self._url("drive", "drivefileref", folder.files_list_id),
                token=session.access_token,
                params={"start": start, "count": "500", "reverse": "false"},
            )
            if not isinstance(page, list) or not page:
                break
            refs.extend(page)
            if len(page) < 500:
                break
            last = page[-1]
            last_id = last.get("32", "")
            start = last_id[-1] if isinstance(last_id, list) else (last_id or start)

        logger.debug("list_drive_folder_contents: %d refs, sample=%r", len(refs), refs[:2] if refs else [])

        # Wydziel ID plików i podfolderów
        file_ids: list[list] = []
        subfolder_ids: list[list] = []
        for ref in refs:
            file_raw = ref.get("36")
            folder_raw = ref.get("37")
            if isinstance(file_raw, list) and file_raw:
                fid = list(file_raw[0]) if isinstance(file_raw[0], list) else list(file_raw)
                if fid and fid[0]:
                    file_ids.append(fid)
            elif isinstance(folder_raw, list) and folder_raw:
                fid = list(folder_raw[0]) if isinstance(folder_raw[0], list) else list(folder_raw)
                if fid and fid[0]:
                    subfolder_ids.append(fid)

        logger.debug("list_drive_folder_contents: file_ids=%s subfolder_ids=%s", file_ids, subfolder_ids)

        # Załaduj pliki i podfoldery (równolegle)
        async def load_file(fid):
            url = self._url("drive", "drivefile", fid[0], fid[1])
            try:
                raw = await self._get_drive(url, token=session.access_token)
                return self._decrypt_drive_file(raw, group_key)
            except TutaAPIError as e:
                logger.warning("load_file %s: %s", fid, e)
                return None

        async def load_subfolder(fid):
            try:
                return await self.get_drive_folder(session, group_key, fid)
            except TutaAPIError as e:
                logger.warning("load_subfolder %s: %s", fid, e)
                return None

        import asyncio as _aio
        files_raw = await _aio.gather(*[load_file(fid) for fid in file_ids])
        folders_raw = await _aio.gather(*[load_subfolder(fid) for fid in subfolder_ids])

        files = [f for f in files_raw if f is not None]
        folders = [f for f in folders_raw if f is not None]
        return folders, files

    async def download_drive_file_data(
        self, session: Session, group_key: bytes, drive_file: "DriveFile"
    ) -> bytes:
        """
        Pobiera i odszyfrowuje dane pliku Drive z blob storage.
        Zwraca pełne odszyfrowane bajty pliku.
        """
        import json as _json
        import secrets as _secrets
        import struct

        blobs = drive_file.blobs
        if not blobs:
            return b""

        archive_id = blobs[0].get("1884", "")
        file_list_id = drive_file.id_tuple[0] if len(drive_file.id_tuple) > 0 else ""
        file_elem_id = drive_file.id_tuple[1] if len(drive_file.id_tuple) > 1 else ""

        # Token odczytu z ArchiveDataType.DriveFile = "4"
        rnd_read = _secrets.token_urlsafe(4)[:6]
        rnd_inst = _secrets.token_urlsafe(4)[:6]
        token_body = {
            "78": "0",
            "80": [],
            "180": ARCHIVE_DATA_TYPE_DRIVE,
            "181": [{
                "176": rnd_read,
                "177": archive_id,
                "178": file_list_id,
                "179": [{"173": rnd_inst, "174": file_elem_id}],
            }],
        }
        token_headers = {
            "accessToken": session.access_token,
            "v": STORAGE_MODEL_VERSION,
            "Content-Type": "application/json",
        }
        async with self._http.post(
            self.base_url + "/rest/storage/blobaccesstokenservice",
            data=_json.dumps(token_body, separators=(",", ":")).encode(),
            headers=token_headers,
        ) as r:
            if r.status not in (200, 201):
                text = await r.text()
                raise _api_error(r.status, f"Drive blob token: {text}")
            token_resp = await r.json(content_type=None)

        access_info = token_resp.get("161", [{}])[0]
        blob_token = access_info.get("159", "")
        servers = access_info.get("160", [])
        if not servers:
            raise TutaAPIError(0, "Brak serwerów blob dla Drive file")
        server_url = servers[0].get("156", "")

        # Odszyfruj klucz sesji pliku
        enc_sk_b64 = drive_file.raw.get("20", "")
        file_sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))

        # Pobierz i odszyfruj każdy blob
        from .crypto import aes_decrypt_tuta as _aes_dec
        result_chunks: list[bytes] = []
        for blob in blobs:
            blob_archive_id = blob.get("1884", "")
            blob_id = blob.get("1906", "")
            entry_id = _secrets.token_urlsafe(4)[:6]
            blob_get_in = {
                "51": "0",
                "52": blob_archive_id,
                "110": None,
                "193": [{"145": entry_id, "146": blob_id}],
            }
            params = {
                "blobAccessToken": blob_token,
                "accessToken": session.access_token,
            }
            async with self._http.request(
                "GET",
                f"{server_url}/rest/storage/blobservice",
                headers={"Content-Type": "application/json", "v": STORAGE_MODEL_VERSION},
                params=params,
                data=_json.dumps(blob_get_in).encode(),
            ) as r:
                if r.status != 200:
                    body = await r.text()
                    raise _api_error(r.status, f"Drive blob GET: {body}")
                raw_bytes = await r.read()

            # Format: [count:4B][blobId:9B][hash:6B][size:4B][data:N B] per blob
            if len(raw_bytes) < 4:
                continue
            count = struct.unpack(">i", raw_bytes[:4])[0]
            offset = 4
            for _ in range(count):
                if offset + 19 > len(raw_bytes):
                    break
                chunk_size = struct.unpack(">i", raw_bytes[offset + 15: offset + 19])[0]
                chunk = raw_bytes[offset + 19: offset + 19 + chunk_size]
                decrypted = _aes_dec(file_sk, chunk)
                result_chunks.append(decrypted)
                offset += 19 + chunk_size

        return b"".join(result_chunks)

    async def _get_drive_blob_write_token(
        self, session: Session, file_group_id: str
    ) -> "tuple[str, str]":
        """Pobiera write token dla Drive blob storage (ArchiveDataType.DriveFile = '4')."""
        import json as _json
        body = {
            "78": "0",
            "80": [{"74": _random_custom_id(), "75": file_group_id}],
            "180": ARCHIVE_DATA_TYPE_DRIVE,
            "181": [],
        }
        headers = {
            "accessToken": session.access_token,
            "v": STORAGE_MODEL_VERSION,
            "Content-Type": "application/json",
        }
        async with self._http.post(
            self.base_url + "/rest/storage/blobaccesstokenservice",
            data=_json.dumps(body, separators=(",", ":")).encode(),
            headers=headers,
        ) as r:
            if r.status not in (200, 201):
                text = await r.text()
                raise _api_error(r.status, f"Drive write token: {text}")
            resp = await r.json(content_type=None)

        access_info = resp.get("161", {})
        if isinstance(access_info, list):
            access_info = access_info[0] if access_info else {}
        blob_token = access_info.get("159", "")
        servers = access_info.get("160", [])
        if not servers:
            raise TutaAPIError(0, "Brak serwerów blob dla Drive upload")
        server_url = servers[0].get("156", "")
        return blob_token, server_url

    async def create_drive_folder_api(
        self,
        session: Session,
        group_key: bytes,
        key_version: str,
        name: str,
        parent_id: list,
    ) -> "DriveFolder":
        """POST DriveFolderService — tworzy nowy folder Drive."""
        sk = os.urandom(32)
        enc_sk = aes_encrypt_tuta(group_key, sk, add_padding=False)
        enc_name = aes_encrypt_tuta(sk, name.encode("utf-8"))
        body = {
            "85": "0",                                         # _format
            "86": base64.b64encode(enc_name).decode(),        # folderName (encrypted)
            "87": base64.b64encode(enc_sk).decode(),          # ownerEncSessionKey
            "114": key_version,                                # ownerKeyVersion
            "88": [list(parent_id)],                          # parent (LIST_ELEMENT_ASSOC One)
        }
        url = self._url("drive", "drivefolderservice")
        resp = await self._post_drive(url, body, session.access_token)
        # DriveFolderServicePostOut.folder (field 91) → [[listId, elemId]]
        folder_id_raw = resp.get("91", [[]])
        folder_id = list(folder_id_raw[0]) if isinstance(folder_id_raw, list) and folder_id_raw else []
        if not folder_id:
            raise TutaAPIError(0, f"DriveFolderService: brak folder ID w odpowiedzi {resp!r}")
        raw_folder = await self._get_drive(
            self._url("drive", "drivefolder", folder_id[0], folder_id[1]),
            token=session.access_token,
        )
        result = self._decrypt_drive_folder(raw_folder, group_key)
        if not result:
            raise TutaAPIError(0, "Nie można odszyfrować nowo utworzonego folderu")
        logger.info("create_drive_folder_api: '%s' in %s", name, parent_id)
        return result

    async def upload_drive_file_api(
        self,
        session: Session,
        group_id: str,
        group_key: bytes,
        key_version: str,
        name: str,
        mime: str,
        data: bytes,
        parent_id: list,
    ) -> "DriveFile":
        """
        Szyfruje i uploaduje plik do Tuta Drive.
        Flow:
          1. Generuj file_sk (AES-256)
          2. Zaszyfruj dane pliku (AesCbcThenHmac)
          3. Upload do blob storage (ArchiveDataType.DriveFile)
          4. POST DriveItemService z DriveUploadedFile agregat
          5. Załaduj i zwróć DriveFile
        """
        logger.info("upload_drive_file_api: start '%s' %dB → parent=%s", name, len(data), parent_id)
        file_sk = os.urandom(32)
        enc_file_sk = aes_encrypt_tuta(group_key, file_sk, add_padding=False)

        # Podziel dane na chunki BLOB_CHUNK_SIZE i zaszyfruj każdy osobno tym samym file_sk.
        # Tuta uploaduje każdy chunk oddzielnie i zbiera listę blobReferenceTokenów.
        raw_chunks = [data[i:i + BLOB_CHUNK_SIZE] for i in range(0, len(data), BLOB_CHUNK_SIZE)]
        if not raw_chunks:
            raw_chunks = [b""]  # pusty plik — jeden pusty chunk

        blob_token, server_url = await self._get_drive_blob_write_token(session, group_id)
        logger.info("upload_drive_file_api: blob token OK, server=%s, %d chunk(s)", server_url, len(raw_chunks))

        # Timeout per chunk: 10 min — wysyłka 10 MB może trwać długo na wolnym łączu.
        # Retry na błędy sieciowe (timeout, reset) — nie retryujemy 4xx (błąd serwera, nie sieć).
        blob_timeout = aiohttp.ClientTimeout(total=600)
        CHUNK_RETRIES = 3

        reference_tokens = []
        for idx, chunk in enumerate(raw_chunks):
            enc_chunk = aes_encrypt_tuta(file_sk, chunk)
            blob_hash = base64.b64encode(hashlib.sha256(enc_chunk).digest()[:6]).decode()

            blob_ref_token = None
            for attempt in range(CHUNK_RETRIES):
                try:
                    async with self._http.post(
                        f"{server_url}/rest/storage/blobservice",
                        data=enc_chunk,
                        headers={"Content-Type": "application/octet-stream", "v": STORAGE_MODEL_VERSION},
                        params={"blobAccessToken": blob_token, "blobHash": blob_hash, "accessToken": session.access_token},
                        timeout=blob_timeout,
                    ) as r:
                        if r.status not in (200, 201):
                            text = await r.text()
                            logger.error("upload_drive_file_api: chunk %d/%d attempt %d status %d: %s",
                                         idx + 1, len(raw_chunks), attempt + 1, r.status, text[:200])
                            raise _api_error(r.status, f"Drive blob upload chunk {idx + 1}: {text}")
                        blob_resp = await r.json(content_type=None)

                    blob_ref_token = blob_resp.get("127") or ""
                    if not blob_ref_token and isinstance(blob_resp.get("208"), list) and blob_resp["208"]:
                        blob_ref_token = blob_resp["208"][0].get("1992", "")
                    if not blob_ref_token:
                        raise TutaAPIError(0, f"Brak blobReferenceToken chunk {idx + 1}: {blob_resp!r}")
                    break  # sukces

                except TutaAPIError as e:
                    if e.status_code == 403 and attempt < CHUNK_RETRIES - 1:
                        # Token wygasł podczas długiego uploadu — pobierz nowy i ponów
                        logger.warning("upload_drive_file_api: chunk %d/%d token 403 — odświeżam blob token",
                                       idx + 1, len(raw_chunks))
                        blob_token, server_url = await self._get_drive_blob_write_token(session, group_id)
                    else:
                        raise
                except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                    # Błąd sieciowy — warto spróbować jeszcze raz
                    if attempt < CHUNK_RETRIES - 1:
                        wait = 2 ** attempt   # 1s, 2s
                        logger.warning("upload_drive_file_api: chunk %d/%d attempt %d network error: %s — retry in %ds",
                                       idx + 1, len(raw_chunks), attempt + 1, e, wait)
                        await asyncio.sleep(wait)
                    else:
                        raise TutaAPIError(0, f"Chunk {idx + 1} network error after {CHUNK_RETRIES} attempts: {e}") from e

            reference_tokens.append({"1991": _random_custom_id(), "1992": blob_ref_token})
            logger.info("upload_drive_file_api: chunk %d/%d uploaded, refToken=%s...",
                        idx + 1, len(raw_chunks), blob_ref_token[:12])

        # Zaszyfruj pola nazwy i MIME w DriveUploadedFile
        enc_filename = aes_encrypt_tuta(file_sk, name.encode("utf-8"))
        enc_mime = aes_encrypt_tuta(file_sk, (mime or "application/octet-stream").encode("utf-8"))

        uploaded_file = {
            "56": _random_custom_id(),                           # _id
            "57": base64.b64encode(enc_filename).decode(),       # fileName (encrypted)
            "58": base64.b64encode(enc_mime).decode(),           # mimeType (encrypted)
            "59": base64.b64encode(enc_file_sk).decode(),        # ownerEncSessionKey
            "112": key_version,                                   # ownerKeyVersion
            "60": reference_tokens,                              # blobReferenceTokens (jeden per chunk)
        }
        body = {
            "68": "0",              # _format
            "69": [list(parent_id)],  # parent (LIST_ELEMENT_ASSOC One)
            "70": [uploaded_file],  # uploadedFile (AGGREGATION One) → zawsze lista
        }
        url = self._url("drive", "driveitemservice")
        resp = await self._post_drive(url, body, session.access_token)
        # DriveItemPostOut.createdFile (field 73) → [[listId, elemId]]
        created_raw = resp.get("73", [[]])
        created_id = list(created_raw[0]) if isinstance(created_raw, list) and created_raw else []
        if not created_id:
            raise TutaAPIError(0, f"DriveItemService: brak createdFile w odpowiedzi {resp!r}")
        logger.info("upload_drive_file_api: createdFile=%s", created_id)
        raw_file = await self._get_drive(
            self._url("drive", "drivefile", created_id[0], created_id[1]),
            token=session.access_token,
        )
        result = self._decrypt_drive_file(raw_file, group_key)
        if not result:
            raise TutaAPIError(0, "Nie można odszyfrować nowo wgranego pliku")
        logger.info("upload_drive_file_api: OK '%s' (%d B) → %s", name, len(data), parent_id)
        return result

    async def rename_drive_item_api(
        self,
        session: Session,
        group_key: bytes,
        item_raw: dict,
        new_name: str,
        is_file: bool,
    ) -> None:
        """PUT DriveItemService — zmiana nazwy pliku lub folderu Drive."""
        # Odszyfruj klucz sesji elementu
        sk_field = "20" if is_file else "6"
        enc_sk_b64 = item_raw.get(sk_field, "")
        item_sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))

        # Zaszyfruj nową nazwę kluczem sesji elementu
        enc_new_name = aes_encrypt_tuta(item_sk, new_name.encode("utf-8"))
        id_field = "16" if is_file else "2"
        id_raw = item_raw.get(id_field, ["", ""])
        id_tuple = list(id_raw) if isinstance(id_raw, list) else ["", ""]

        body = {
            "75": "0",                                          # _format
            "76": base64.b64encode(enc_new_name).decode(),     # newName (encrypted)
            "77": [list(id_tuple)] if is_file else [],         # file (ZeroOrOne)
            "78": [] if is_file else [list(id_tuple)],         # folder (ZeroOrOne)
        }
        url = self._url("drive", "driveitemservice")
        await self._put_drive(url, body, session.access_token)
        logger.info("rename_drive_item_api: %s → '%s'", id_tuple, new_name)

    async def move_drive_items_api(
        self,
        session: Session,
        group_key: bytes,
        file_items: "list[DriveFile]",
        folder_items: "list[DriveFolder]",
        dest_folder_id: list,
        rename_map: "Optional[dict]" = None,
    ) -> None:
        """
        PUT DriveFolderService — przenosi pliki/foldery do innego folderu.
        Opcjonalnie zmienia nazwy (rename_map: {old_name: new_name}).
        """
        items = []
        for f in file_items:
            new_name = (rename_map or {}).get(f.name)
            if new_name:
                enc_sk_b64 = f.raw.get("20", "")
                item_sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))
                enc_new_name = aes_encrypt_tuta(item_sk, new_name.encode("utf-8"))
                enc_new_name_b64 = base64.b64encode(enc_new_name).decode()
            else:
                enc_new_name_b64 = None
            items.append({
                "93": _random_custom_id(),
                "94": enc_new_name_b64,
                "95": [list(f.id_tuple)],
                "96": [],
            })
        for fld in folder_items:
            new_name = (rename_map or {}).get(fld.name)
            if new_name:
                enc_sk_b64 = fld.raw.get("6", "")
                item_sk = aes_decrypt_tuta(group_key, base64.b64decode(enc_sk_b64))
                enc_new_name = aes_encrypt_tuta(item_sk, new_name.encode("utf-8"))
                enc_new_name_b64 = base64.b64encode(enc_new_name).decode()
            else:
                enc_new_name_b64 = None
            items.append({
                "93": _random_custom_id(),
                "94": enc_new_name_b64,
                "95": [],
                "96": [list(fld.id_tuple)],
            })
        body = {
            "98": "0",              # _format
            "99": items,            # items (AGGREGATION Any)
            "100": [list(dest_folder_id)],  # destination (LIST_ELEMENT_ASSOC One)
        }
        url = self._url("drive", "drivefolderservice")
        await self._put_drive(url, body, session.access_token)
        logger.info(
            "move_drive_items_api: %d files, %d folders → %s",
            len(file_items), len(folder_items), dest_folder_id,
        )

    async def delete_drive_items_api(
        self,
        session: Session,
        file_id_tuples: "list[list]",
        folder_id_tuples: "list[list]",
        permanent: bool = False,
    ) -> None:
        """
        Usuwa elementy Drive.
        permanent=False → przenieś do kosza (DriveFolderServiceDeleteIn)
        permanent=True  → usuń z kosza na stałe (DriveItemDeleteIn)
        """
        if permanent:
            body = {
                "80": "0",
                "81": [list(fid) for fid in file_id_tuples],
                "82": [list(fid) for fid in folder_id_tuples],
            }
            url = self._url("drive", "driveitemservice")
        else:
            body = {
                "102": "0",
                "105": "0",   # restore=false — Tuta Boolean serializuje jako "0"/"1"
                "103": [list(fid) for fid in file_id_tuples],
                "104": [list(fid) for fid in folder_id_tuples],
            }
            url = self._url("drive", "drivefolderservice")
        await self._delete_drive(url, body, session.access_token)
        logger.info(
            "delete_drive_items_api: %d files, %d folders (permanent=%s)",
            len(file_id_tuples), len(folder_id_tuples), permanent,
        )


def _random_custom_id() -> str:
    """Generuje losowy CustomId (base64url, 4 bajty = 6 znaków) — format jak w importerze Tuty."""
    return base64.urlsafe_b64encode(os.urandom(4)).rstrip(b"=").decode()


def _generate_event_elem_id(start_ms: int) -> str:
    """
    Generuje CustomId dla CalendarEvent na podstawie czasu startu.
    Odpowiednik generateEventElementId() z Tuty: base64url(str(start_ms + shift).encode())
    gdzie shift ∈ [-15 dni, +15 dni] — zapobiega ujawnieniu dokładnego czasu serwerowi.
    """
    import random as _rnd
    DAYS_SHIFTED_MS = 15 * 24 * 60 * 60 * 1000
    shift = _rnd.randint(-DAYS_SHIFTED_MS, DAYS_SHIFTED_MS)
    return base64.urlsafe_b64encode(str(start_ms + shift).encode()).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Kalendarz
# ---------------------------------------------------------------------------

from datetime import datetime as _datetime


@dataclass
class RepeatRuleAdvanced:
    # ByRule enum: "2"=BYDAY, "3"=BYMONTHDAY, "4"=BYYEARDAY, "5"=BYWEEKNO, "6"=BYMONTH, "7"=BYSETPOS, "8"=WKST
    rule_type: str
    interval: str  # np. "MO", "1", "-1FR"


@dataclass
class RepeatRule:
    # RepeatPeriod: "0"=DAILY, "1"=WEEKLY, "2"=MONTHLY, "3"=ANNUALLY
    frequency: str
    # EndType: "0"=Never, "1"=Count, "2"=UntilDate
    end_type: str
    # Dla Count: liczba powtórzeń jako string; dla UntilDate: ms timestamp ekskluzywny (start następnego dnia)
    end_value: Optional[str]
    interval: str           # "1" = co 1 okres
    time_zone: str          # np. "Europe/Warsaw"
    excluded_dates: list    # ms timestamps (z EXDATE)
    advanced_rules: list    # lista RepeatRuleAdvanced


@dataclass
class CalendarEvent:
    uid: str
    summary: str
    start: Optional[_datetime]
    end: Optional[_datetime]
    location: str
    description: str
    all_day: bool
    sequence: int = 0
    list_id: str = ""   # _id[0] — shortEvents lub longEvents list ID
    elem_id: str = ""   # _id[1] — CustomId elementu w liście
    rrule: Optional["RepeatRule"] = None
    # Ustawione gdy event jest wyjątkiem cyklu (modyfikacja pojedynczego powtórzenia).
    # Zawiera czas oryginalnego powtórzenia (UTC). Eksportowane jako RECURRENCE-ID w iCal.
    recurrence_id: Optional[_datetime] = None


# ---------------------------------------------------------------------------
# Kontakty
# ---------------------------------------------------------------------------

@dataclass
class ContactMailAddress:
    # type: "0"=PRIVATE, "1"=WORK, "2"=OTHER, "3"=CUSTOM
    type: str
    custom_type: str
    address: str
    _id: str = ""


@dataclass
class ContactPhoneNumber:
    # type: "0"=PRIVATE, "1"=WORK, "2"=MOBILE, "3"=FAX, "4"=OTHER, "5"=CUSTOM
    type: str
    custom_type: str
    number: str
    _id: str = ""


@dataclass
class ContactAddress:
    # type: "0"=PRIVATE, "1"=WORK, "2"=OTHER, "3"=CUSTOM
    type: str
    custom_type: str
    address: str     # może być wieloliniowy
    _id: str = ""


@dataclass
class Contact:
    list_id: str = ""
    elem_id: str = ""
    # imię/nazwisko
    first_name: str = ""
    last_name: str = ""
    middle_name: str = ""
    title: str = ""          # grzecznościowy (Dr, Pan, etc.)
    name_suffix: str = ""
    nickname: str = ""
    # zawodowe
    company: str = ""
    department: str = ""
    role: str = ""           # stanowisko (job title)
    # dane kontaktowe
    mail_addresses: list = field(default_factory=list)   # list[ContactMailAddress]
    phone_numbers: list = field(default_factory=list)    # list[ContactPhoneNumber]
    addresses: list = field(default_factory=list)        # list[ContactAddress]
    websites: list = field(default_factory=list)         # list[tuple[str, str]] (type, url)
    social_ids: list = field(default_factory=list)       # list[tuple[str, str]] (type, socialId)
    # pozostałe
    birthday_iso: str = ""
    comment: str = ""


@dataclass
class DriveFolder:
    id_tuple: list           # [listId, elemId]
    name: str
    folder_type: str         # "0"=Regular, "1"=Root, "2"=Trash
    parent: Optional[list]   # [listId, elemId] lub None
    files_list_id: str       # listId dla DriveFileRef (pole 38)
    created_ms: int
    updated_ms: int
    raw: dict = field(default_factory=dict)


@dataclass
class DriveFile:
    id_tuple: list           # [listId, elemId]
    name: str
    size: int
    mime_type: str
    folder: list             # [listId, elemId] folderu nadrzędnego
    blobs: list              # surowe agregaty Blob (1884=archiveId, 1906=blobId)
    created_ms: int
    updated_ms: int
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Błędy
# ---------------------------------------------------------------------------

class TutaAPIError(Exception):
    def __init__(self, status: int, message: str):
        self.status_code = status
        super().__init__(f"TutaAPI {status}: {message}")


class TutaAuthError(TutaAPIError):
    """401 z Tuty — wydzielona klasa żeby DAV-y mogły mapować na własne 401."""


def _api_error(status: int, body: str) -> TutaAPIError:
    """Factory — przy 401 zwraca TutaAuthError, w pozostałych przypadkach TutaAPIError."""
    if status == 401:
        return TutaAuthError(status, body)
    return TutaAPIError(status, body)
