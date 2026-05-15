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
    UserKeys,
    aes128_decrypt,
    aes_encrypt_tuta,
    aes_decrypt_tuta,
    compress_lz4,
    b64url_decode,
    b64url_encode,
    decrypt_user_group_key,
    pq_encapsulate_bucket_key,
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
        self._http = aiohttp.ClientSession(headers=TUTA_HEADERS, timeout=timeout)
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
        """Loguje ostrzeżenie jeśli błąd wygląda na niezgodność wersji modelu API."""
        is_mismatch = (
            status == 412
            or (status in (400, 500) and any(
                kw in body.lower() for kw in ("model", "version", "outdated", "incompatible")
            ))
        )
        if is_mismatch:
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
            raise TutaAPIError(r.status, body)

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
            raise TutaAPIError(r.status, body)

    async def _post(self, url: str, body: dict, token: str = "") -> Any:
        headers = {"accessToken": token} if token else {}
        async with self._http.post(url, json=body, headers=headers) as r:
            if r.status in (200, 201):
                return await r.json(content_type=None)
            text = await r.text()
            self._check_version_mismatch(r.status, text)
            raise TutaAPIError(r.status, text)

    async def _delete(self, url: str, token: str) -> None:
        async with self._http.delete(
            url, headers={"accessToken": token}
        ) as r:
            if r.status not in (200, 204):
                body = await r.text()
                self._check_version_mismatch(r.status, body)
                raise TutaAPIError(r.status, body)

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

        return Session(
            access_token=access_token,
            user_id=user_id,
            user_group_key=user_group_key,
            user_email=email,
        )

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
                raise TutaAPIError(r.status, await r.text())
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
                raise TutaAPIError(r.status, await r.text())
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

        enc_sk = base64.b64decode(mail.get("102") or "")
        mail_key = decrypt_mail_session_key(mail_group_key, enc_sk)

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

        raise TutaAPIError(last_status, last_body)

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
                    raise TutaAPIError(r.status, body)
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
        """
        from .crypto import decrypt_mail_session_key, aes_decrypt_tuta
        from .message_builder import _decrypt_str

        file_refs = mail_raw.get("115", [])
        if not file_refs:
            return []

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
                enc_sk = base64.b64decode(file_obj.get("18", ""))
                file_key = decrypt_mail_session_key(mail_group_key, enc_sk)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                    raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, text)
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
                raise TutaAPIError(r.status, resp_text)
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
                raise TutaAPIError(r.status, resp_text)
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
                raise TutaAPIError(r.status, text)
        logger.info(f"send_draft_e2e: draft {draft_elem_id} sent E2E → {len(recipients)} odbiorców")


def _random_custom_id() -> str:
    """Generuje losowy CustomId (base64url, 4 bajty = 6 znaków) — format jak w importerze Tuty."""
    return base64.urlsafe_b64encode(os.urandom(4)).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Błędy
# ---------------------------------------------------------------------------

class TutaAPIError(Exception):
    def __init__(self, status: int, message: str):
        self.status_code = status
        super().__init__(f"TutaAPI {status}: {message}")

class TutaAuthError(TutaAPIError):
    pass
