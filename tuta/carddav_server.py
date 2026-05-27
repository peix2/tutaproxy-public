"""
tuta/carddav_server.py
Serwer CardDAV (RFC 6352) dla konta Tuta.

Obsługiwane metody HTTP:
  OPTIONS          → DAV: 1, 2, 3, addressbook
  PROPFIND /       → właściwości addressbook + lista kontaktów (depth=0 lub 1)
  REPORT /         → addressbook-query, addressbook-multiget
  GET  /{uid}.vcf  → pojedynczy kontakt jako vCard 3.0
  GET  /           → wszystkie kontakty (vCard 3.0, multiblok)
  PUT  /{uid}.vcf  → utwórz lub zaktualizuj kontakt
  DELETE /{uid}.vcf → usuń kontakt
  HEAD /{uid}.vcf  → jak GET, bez body

URL-space:
  /                → addressbook home i kolekcja
  /{elem_id}.vcf   → pojedynczy kontakt (UID = elem_id)
  /.well-known/carddav → redirect do /

Auth: HTTP Basic (email + hasło Tuta), per-request.
Cache: kontakty trzymane w pamięci przez CACHE_TTL sekund.
"""

import asyncio
import base64
import hashlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

from .api import (
    TutaClient,
    TutaAPIError,
    TutaAuthError,
    Contact,
    ContactMailAddress,
    ContactPhoneNumber,
    ContactAddress,
)

# Czas oczekiwania na kolejne DELETE zanim wyślemy batch do Tuty (sekundy).
# CardBook wysyła ~6 równoległych DELETEów; 150 ms wystarczy by zebrać całą
# paczkę, ale nie spowalnia widocznie pojedynczego usunięcia.
DELETE_BATCH_WINDOW = 0.15

logger = logging.getLogger(__name__)

CACHE_TTL = 60  # sekundy

# ---------------------------------------------------------------------------
# vCard 3.0 — eksport i import
# ---------------------------------------------------------------------------

_ADDR_TYPE_TO_VCARD   = {"0": "home", "1": "work"}
_TEL_TYPE_TO_VCARD    = {"0": "home", "1": "work", "2": "cell", "3": "fax"}

_VCARD_ADDR_TO_TUTA   = {"home": "0", "work": "1"}
_VCARD_TEL_TO_TUTA    = {"home": "0", "work": "1", "cell": "2", "fax": "3"}


def _vc_escape(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace("\n", "\\n")
    s = s.replace(";", "\\;")
    s = s.replace(",", "\\,")
    return s


def _vc_unescape(s: str) -> str:
    s = s.replace("\\n", "\n").replace("\\N", "\n")
    s = s.replace("\\;", ";")
    s = s.replace("\\,", ",")
    s = s.replace("\\\\", "\\")
    return s


def _fold(line: str) -> str:
    """Zawija linię vCard co 75 znaków (RFC 6350 §3.2)."""
    if len(line) <= 75:
        return line
    parts = []
    while len(line) > 75:
        parts.append(line[:75])
        line = line[75:]
    parts.append(line)
    return "\r\n ".join(parts)


def contact_to_vcard(contact: Contact) -> str:
    """Serializuje Contact do vCard 3.0."""
    lines: list[str] = ["BEGIN:VCARD", "VERSION:3.0"]

    # FN (wymagane w vCard 3.0)
    fn_parts = []
    if contact.title:       fn_parts.append(_vc_escape(contact.title))
    if contact.first_name:  fn_parts.append(_vc_escape(contact.first_name))
    if contact.middle_name: fn_parts.append(_vc_escape(contact.middle_name))
    if contact.last_name:   fn_parts.append(_vc_escape(contact.last_name))
    fn = " ".join(fn_parts).strip()
    if contact.name_suffix:
        fn = (fn + ", " + _vc_escape(contact.name_suffix)).strip(", ")
    lines.append(_fold("FN:" + (fn or "Unknown")))

    # N (wymagane): lastName;firstName;middleName;honorificPrefix;honorificSuffix
    n = ";".join([
        _vc_escape(contact.last_name),
        _vc_escape(contact.first_name),
        _vc_escape(contact.middle_name),
        _vc_escape(contact.title),
        _vc_escape(contact.name_suffix),
    ])
    lines.append(_fold("N:" + n))

    if contact.nickname:
        lines.append(_fold("NICKNAME:" + _vc_escape(contact.nickname)))

    if contact.birthday_iso:
        bday = contact.birthday_iso
        # Tuta używa "--MM-DD" dla dat bez roku; vCard 3.0 nie ma tego formatu
        # → zastępujemy 1111 jako rok-placeholder (jak robi Tuta VCardExporter)
        if bday.startswith("--"):
            bday = "1111-" + bday[2:]
        lines.append("BDAY:" + bday)

    # EMAIL
    for ma in contact.mail_addresses:
        if not ma.address:
            continue
        t = _ADDR_TYPE_TO_VCARD.get(ma.type, "")
        prop = "EMAIL;TYPE=internet" + (("," + t) if t else "")
        lines.append(_fold(prop + ":" + _vc_escape(ma.address)))

    # TEL
    for ph in contact.phone_numbers:
        if not ph.number:
            continue
        t = _TEL_TYPE_TO_VCARD.get(ph.type, "")
        prop = "TEL" + ((";TYPE=" + t) if t else "")
        lines.append(_fold(prop + ":" + _vc_escape(ph.number)))

    # ADR: ;;street;city;state;zip;country
    # Tuta przechowuje adres jako wolny tekst (wieloliniowy) → wstawiamy w pole street
    for a in contact.addresses:
        if not a.address:
            continue
        t = _ADDR_TYPE_TO_VCARD.get(a.type, "")
        prop = "ADR" + ((";TYPE=" + t) if t else "")
        # Kodujemy nowe linie jako \n w polu street
        street = _vc_escape(a.address)
        lines.append(_fold(prop + ":;;" + street + ";;;;"))

    # ORG
    if contact.company:
        org = _vc_escape(contact.company)
        if contact.department:
            org += ";" + _vc_escape(contact.department)
        lines.append(_fold("ORG:" + org))

    # TITLE (stanowisko)
    if contact.role:
        lines.append(_fold("TITLE:" + _vc_escape(contact.role)))

    # NOTE
    if contact.comment:
        lines.append(_fold("NOTE:" + _vc_escape(contact.comment)))

    # URL (strony WWW)
    for _type, url in contact.websites:
        if url:
            lines.append(_fold("URL:" + url))

    # UID — identyfikator dla CardDAV (= elem_id kontaktu)
    if contact.elem_id:
        lines.append("UID:" + contact.elem_id)

    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


def parse_vcard(text: str) -> Optional[Contact]:
    """
    Parsuje pojedynczy blok vCard (3.0 lub 4.0) do Contact.
    Zwraca None jeśli tekst nie zawiera VCARD.
    """
    # Unfold: linie kontynuowane znakiem spacji/tabulatora po CRLF lub LF
    text = re.sub(r"\r?\n[ \t]", "", text)

    if "BEGIN:VCARD" not in text.upper():
        return None

    contact = Contact()
    uid = ""

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.upper() in ("BEGIN:VCARD", "END:VCARD",
                                         "VERSION:3.0", "VERSION:4.0", "VERSION:2.1"):
            continue

        colon = line.find(":")
        if colon < 0:
            continue

        prop_full = line[:colon]
        value = line[colon + 1:]

        # Rozdziel nazwę właściwości i parametry (np. TEL;TYPE=home)
        prop_parts = prop_full.upper().split(";")
        prop_name = prop_parts[0]
        params: dict[str, str] = {}
        for p in prop_parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v.lower()
            else:
                params[p] = ""
        type_param = params.get("TYPE", "")

        value = _vc_unescape(value)

        if prop_name == "N":
            # lastName;firstName;middleName;honorificPrefix;honorificSuffix
            parts = _n_split(value, 5)
            contact.last_name   = parts[0] if len(parts) > 0 else ""
            contact.first_name  = parts[1] if len(parts) > 1 else ""
            contact.middle_name = parts[2] if len(parts) > 2 else ""
            contact.title       = parts[3] if len(parts) > 3 else ""
            contact.name_suffix = parts[4] if len(parts) > 4 else ""

        elif prop_name == "FN":
            # Użyjemy N jako głównego źródła; FN jako fallback gdy N brak
            if not (contact.first_name or contact.last_name):
                contact.first_name = value

        elif prop_name == "NICKNAME":
            contact.nickname = value

        elif prop_name == "BDAY":
            bday = value
            if bday.startswith("1111-"):
                bday = "--" + bday[5:]
            contact.birthday_iso = bday

        elif prop_name in ("EMAIL", "X-EMAILADDRESS"):
            tuta_type = _VCARD_ADDR_TO_TUTA.get(type_param, "2")
            if value:
                contact.mail_addresses.append(
                    ContactMailAddress(type=tuta_type, custom_type="", address=value)
                )

        elif prop_name == "TEL":
            tuta_type = _VCARD_TEL_TO_TUTA.get(type_param, "4")
            if value:
                contact.phone_numbers.append(
                    ContactPhoneNumber(type=tuta_type, custom_type="", number=value)
                )

        elif prop_name == "ADR":
            tuta_type = _VCARD_ADDR_TO_TUTA.get(type_param, "2")
            # vCard ADR: PO-box;extended;street;city;state;postal;country
            adr_parts = _n_split(value, 7)
            # Sklej niepuste części
            addr = "\n".join(p.strip() for p in adr_parts if p.strip())
            if addr:
                contact.addresses.append(
                    ContactAddress(type=tuta_type, custom_type="", address=addr)
                )

        elif prop_name == "ORG":
            org_parts = value.split(";", 1)
            contact.company    = org_parts[0].strip()
            if len(org_parts) > 1:
                contact.department = org_parts[1].strip()

        elif prop_name == "TITLE":
            contact.role = value

        elif prop_name == "NOTE":
            contact.comment = value

        elif prop_name == "URL":
            if value:
                contact.websites.append(("2", value))

        elif prop_name == "UID":
            uid = value

    if uid:
        contact.elem_id = uid

    # Minimalny kontakt musi mieć jakieś imię lub firmę
    if not (contact.first_name or contact.last_name or contact.company):
        return None

    return contact


def _n_split(text: str, count: int) -> list[str]:
    """Dzieli tekst po ';' z uwzględnieniem escape'owania. Max count elementów."""
    parts: list[str] = []
    current = ""
    i = 0
    while i < len(text) and len(parts) < count - 1:
        if text[i] == "\\" and i + 1 < len(text):
            current += text[i:i+2]
            i += 2
        elif text[i] == ";":
            parts.append(current)
            current = ""
            i += 1
        else:
            current += text[i]
            i += 1
    parts.append(current + text[i:])
    return parts


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass
class HTTPResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes = b""

    def to_bytes(self) -> bytes:
        lines = [f"HTTP/1.1 {self.status} {self.reason}"]
        self.headers.setdefault("Content-Length", str(len(self.body)))
        self.headers.setdefault("Connection", "close")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")
        header_part = "\r\n".join(lines).encode("utf-8")
        return header_part + self.body


def _xml_resp(status: int, reason: str, xml: str, extra: Optional[dict] = None) -> HTTPResponse:
    body = xml.encode("utf-8")
    hdrs = {"Content-Type": "application/xml; charset=utf-8", "DAV": "1, 2, 3, addressbook"}
    if extra:
        hdrs.update(extra)
    return HTTPResponse(status, reason, hdrs, body)


def _text_resp(status: int, reason: str, text: str = "") -> HTTPResponse:
    body = text.encode("utf-8")
    return HTTPResponse(status, reason,
                        {"Content-Type": "text/plain; charset=utf-8",
                         "DAV": "1, 2, 3, addressbook"}, body)


def _vcard_resp(status: int, etag: str, body: bytes) -> HTTPResponse:
    return HTTPResponse(status, "OK", {
        "Content-Type": "text/vcard; charset=utf-8",
        "ETag": f'"{etag}"',
        "DAV": "1, 2, 3, addressbook",
    }, body)


# ---------------------------------------------------------------------------
# Cache kontaktów
# ---------------------------------------------------------------------------

@dataclass
class _CacheEntry:
    contacts: list[Contact]
    ts: float
    list_id: str
    group_key: bytes
    group_id: str
    key_version: str


@dataclass
class _DeleteBatch:
    """Grupuje równoległe DELETE requests jednego usera w jeden eraseMultiple call."""
    items: list[tuple[str, str]]   # (list_id, elem_id)
    event: asyncio.Event
    error: Optional[Exception] = None


# ---------------------------------------------------------------------------
# Serwer CardDAV
# ---------------------------------------------------------------------------

class CardDAVServer:
    """Async TCP serwer CardDAV dla Tuta."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5233):
        self.host = host
        self.port = port
        # (session, client) per email — client żyje przez całą sesję serwera
        self._sessions: dict[str, tuple] = {}
        self._login_locks: dict[str, asyncio.Lock] = {}
        self._cache: dict[str, _CacheEntry] = {}
        self._cache_lock = asyncio.Lock()
        # Bufor batch-delete: username → _DeleteBatch.
        # Każdy request DELETE rejestruje się w aktywnym batchu i czeka na event;
        # timer po DELETE_BATCH_WINDOW s wywołuje flush, który wysyła eraseMultiple
        # i ustawia event (wszystkie czekające DELETy wracają 204 naraz).
        self._delete_batch: dict[str, "_DeleteBatch"] = {}
        self._delete_locks: dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle_conn, self.host, self.port)
        logger.info("CardDAV server: http://%s:%d/", self.host, self.port)
        async with server:
            await server.serve_forever()

    async def _get_session(self, username: str, password: str):
        """Zwraca (session, client) — loguje raz, potem cachuje."""
        if username in self._sessions:
            return self._sessions[username]
        if username not in self._login_locks:
            self._login_locks[username] = asyncio.Lock()
        async with self._login_locks[username]:
            if username in self._sessions:
                return self._sessions[username]
            client = TutaClient()
            await client.__aenter__()
            try:
                session = await client.login(username, password)
            except Exception:
                await client.__aexit__(None, None, None)
                raise
            self._sessions[username] = (session, client)
            logger.info("CardDAV: zalogowano %s", username)
            return session, client

    # -----------------------------------------------------------------------
    # Connection handler
    # -----------------------------------------------------------------------

    async def _handle_conn(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        try:
            req = await self._read_request(reader)
            if req is None:
                writer.close()
                return
            logger.info("CardDAV %s %s [%s:%d]", req.method, req.path, peer[0], peer[1])
            resp = await self._dispatch(req)
            writer.write(resp.to_bytes())
            await writer.drain()
        except Exception as e:
            logger.exception("CardDAV conn error [%s]: %s", peer, e)
        finally:
            writer.close()

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> Optional[HTTPRequest]:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
        except asyncio.TimeoutError:
            return None
        if not request_line:
            return None
        parts = request_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 2:
            return None
        method, raw_path = parts[0].upper(), parts[1]
        path = unquote(raw_path.split("?")[0])

        headers: dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                break
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body = b""
        cl = int(headers.get("content-length", "0") or "0")
        if cl > 0:
            body = await asyncio.wait_for(reader.readexactly(cl), timeout=30)

        return HTTPRequest(method, path, headers, body)

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    async def _dispatch(self, req: HTTPRequest) -> HTTPResponse:
        path = req.path

        # .well-known/carddav → redirect do /
        if path.rstrip("/") in ("/.well-known/carddav", "/.well-known/caldav"):
            return HTTPResponse(301, "Moved Permanently", {"Location": "/"})

        if req.method == "OPTIONS":
            return HTTPResponse(200, "OK", {
                "DAV": "1, 2, 3, addressbook",
                "Allow": "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT",
                "Content-Length": "0",
            })

        # Auth
        auth = req.headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return HTTPResponse(401, "Unauthorized", {
                "WWW-Authenticate": 'Basic realm="Tuta CardDAV"',
                "DAV": "1, 2, 3, addressbook",
            })
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return _text_resp(400, "Bad Request", "Nieprawidłowy nagłówek Authorization")

        try:
            session, client = await self._get_session(username, password)
        except TutaAuthError:
            return HTTPResponse(401, "Unauthorized", {
                "WWW-Authenticate": 'Basic realm="Tuta CardDAV"',
                "DAV": "1, 2, 3, addressbook",
            })
        except TutaAPIError as e:
            return _text_resp(503, "Service Unavailable", str(e))

        # Routing
        if req.method == "PROPFIND":
            return await self._handle_propfind(req, session, client, path, username)
        if req.method == "REPORT":
            return await self._handle_report(req, session, client, path, username)
        if req.method in ("GET", "HEAD"):
            return await self._handle_get(req, session, client, path, username)
        if req.method == "PUT":
            return await self._handle_put(req, session, client, path, username)
        if req.method == "DELETE":
            return await self._handle_delete(req, session, client, path, username)

        return _text_resp(405, "Method Not Allowed")

    # -----------------------------------------------------------------------
    # Cache
    # -----------------------------------------------------------------------

    async def _get_cached(
        self, username: str, session, client: TutaClient
    ) -> "_CacheEntry":
        async with self._cache_lock:
            entry = self._cache.get(username)
            if entry and (time.monotonic() - entry.ts) < CACHE_TTL:
                return entry

        list_id, group_key, group_id, key_version = \
            await client.get_contact_group_info(session)
        contacts = await client.get_contacts(session)

        new_entry = _CacheEntry(
            contacts=contacts,
            ts=time.monotonic(),
            list_id=list_id,
            group_key=group_key,
            group_id=group_id,
            key_version=key_version,
        )
        async with self._cache_lock:
            self._cache[username] = new_entry
        return new_entry

    def _invalidate(self, username: str) -> None:
        self._cache.pop(username, None)

    # -----------------------------------------------------------------------
    # ETag helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _contact_etag(c: Contact) -> str:
        h = hashlib.sha256()
        h.update(c.elem_id.encode())
        h.update(c.first_name.encode())
        h.update(c.last_name.encode())
        h.update(c.company.encode())
        for ma in c.mail_addresses:
            h.update(ma.address.encode())
        for ph in c.phone_numbers:
            h.update(ph.number.encode())
        return h.hexdigest()[:16]

    @staticmethod
    def _collection_ctag(contacts: list[Contact]) -> str:
        h = hashlib.sha256()
        for c in contacts:
            h.update(c.elem_id.encode())
        return h.hexdigest()[:16]

    # -----------------------------------------------------------------------
    # PROPFIND
    # -----------------------------------------------------------------------

    async def _handle_propfind(
        self, req: HTTPRequest, session, client: TutaClient, path: str, username: str
    ) -> HTTPResponse:
        depth = req.headers.get("depth", "0")
        logger.debug("PROPFIND path=%r depth=%s body=%r", path, depth, req.body[:500] if req.body else b"")
        entry = await self._get_cached(username, session, client)
        contacts = entry.contacts

        if path == "/" or path == "":
            if depth == "0":
                return _xml_resp(207, "Multi-Status", self._propfind_collection_xml(contacts))
            else:  # depth=1 lub infinity
                return _xml_resp(207, "Multi-Status", self._propfind_depth1_xml(contacts))

        # PROPFIND na konkretnym kontakcie
        uid = _uid_from_path(path)
        contact = next((c for c in contacts if c.elem_id == uid), None)
        if not contact:
            return _text_resp(404, "Not Found")
        return _xml_resp(207, "Multi-Status", self._propfind_contact_xml(contact))

    def _propfind_collection_xml(self, contacts: list[Contact]) -> str:
        ctag = self._collection_ctag(contacts)
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"'
            ' xmlns:CS="http://calendarserver.org/ns/">\n'
            '  <D:response>\n'
            '    <D:href>/</D:href>\n'
            '    <D:propstat>\n'
            '      <D:prop>\n'
            '        <D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>\n'
            '        <D:displayname>Tuta Contacts</D:displayname>\n'
            f'        <CS:getctag>"{ctag}"</CS:getctag>\n'
            '        <D:current-user-principal><D:href>/</D:href></D:current-user-principal>\n'
            '        <C:addressbook-home-set><D:href>/</D:href></C:addressbook-home-set>\n'
            '        <D:supported-report-set>\n'
            '          <D:supported-report><D:report>'
            '<C:addressbook-query/></D:report></D:supported-report>\n'
            '          <D:supported-report><D:report>'
            '<C:addressbook-multiget/></D:report></D:supported-report>\n'
            '        </D:supported-report-set>\n'
            '        <D:current-user-privilege-set>\n'
            '          <D:privilege><D:read/></D:privilege>\n'
            '          <D:privilege><D:write/></D:privilege>\n'
            '          <D:privilege><D:write-properties/></D:privilege>\n'
            '          <D:privilege><D:write-content/></D:privilege>\n'
            '          <D:privilege><D:bind/></D:privilege>\n'
            '          <D:privilege><D:unbind/></D:privilege>\n'
            '        </D:current-user-privilege-set>\n'
            '      </D:prop>\n'
            '      <D:status>HTTP/1.1 200 OK</D:status>\n'
            '    </D:propstat>\n'
            '  </D:response>\n'
            '</D:multistatus>'
        )

    def _propfind_depth1_xml(self, contacts: list[Contact]) -> str:
        ctag = self._collection_ctag(contacts)
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"'
            ' xmlns:CS="http://calendarserver.org/ns/">',
            '  <D:response>',
            '    <D:href>/</D:href>',
            '    <D:propstat>',
            '      <D:prop>',
            '        <D:resourcetype><D:collection/><C:addressbook/></D:resourcetype>',
            '        <D:displayname>Tuta Contacts</D:displayname>',
            f'        <CS:getctag>"{ctag}"</CS:getctag>',
            '        <D:current-user-privilege-set>',
            '          <D:privilege><D:read/></D:privilege>',
            '          <D:privilege><D:write/></D:privilege>',
            '          <D:privilege><D:write-properties/></D:privilege>',
            '          <D:privilege><D:write-content/></D:privilege>',
            '          <D:privilege><D:bind/></D:privilege>',
            '          <D:privilege><D:unbind/></D:privilege>',
            '        </D:current-user-privilege-set>',
            '        <C:supported-address-data>',
            '          <C:address-data-type content-type="text/vcard" version="3.0"/>',
            '        </C:supported-address-data>',
            '      </D:prop>',
            '      <D:status>HTTP/1.1 200 OK</D:status>',
            '    </D:propstat>',
            '  </D:response>',
        ]
        for c in contacts:
            etag = self._contact_etag(c)
            href = f"/{c.elem_id}.vcf"
            lines += [
                '  <D:response>',
                f'    <D:href>{_xml_escape(href)}</D:href>',
                '    <D:propstat>',
                '      <D:prop>',
                '        <D:resourcetype/>',
                f'        <D:getetag>"{etag}"</D:getetag>',
                '        <D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>',
                '      </D:prop>',
                '      <D:status>HTTP/1.1 200 OK</D:status>',
                '    </D:propstat>',
                '  </D:response>',
            ]
        lines.append('</D:multistatus>')
        return "\n".join(lines)

    def _propfind_contact_xml(self, c: Contact) -> str:
        etag = self._contact_etag(c)
        href = f"/{c.elem_id}.vcf"
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">\n'
            '  <D:response>\n'
            f'    <D:href>{_xml_escape(href)}</D:href>\n'
            '    <D:propstat>\n'
            '      <D:prop>\n'
            '        <D:resourcetype/>\n'
            f'        <D:getetag>"{etag}"</D:getetag>\n'
            '        <D:getcontenttype>text/vcard; charset=utf-8</D:getcontenttype>\n'
            '      </D:prop>\n'
            '      <D:status>HTTP/1.1 200 OK</D:status>\n'
            '    </D:propstat>\n'
            '  </D:response>\n'
            '</D:multistatus>'
        )

    # -----------------------------------------------------------------------
    # REPORT
    # -----------------------------------------------------------------------

    async def _handle_report(
        self, req: HTTPRequest, session, client: TutaClient, path: str, username: str
    ) -> HTTPResponse:
        body_str = req.body.decode("utf-8", errors="replace")
        entry = await self._get_cached(username, session, client)
        contacts = entry.contacts

        if "addressbook-multiget" in body_str:
            return await self._report_multiget(body_str, contacts)
        if "addressbook-query" in body_str:
            return self._report_query(body_str, contacts)

        return _text_resp(400, "Bad Request", "Nieznany typ REPORT")

    async def _report_multiget(
        self, body_str: str, contacts: list[Contact]
    ) -> HTTPResponse:
        hrefs = re.findall(r"<[^>]*:?href[^>]*>([^<]+)</[^>]*:?href>", body_str, re.I)
        want_address_data = "address-data" in body_str.lower()

        contact_map = {c.elem_id: c for c in contacts}
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">',
        ]
        for href in hrefs:
            href = href.strip()
            uid = _uid_from_path(href)
            c = contact_map.get(uid)
            if not c:
                lines += [
                    '  <D:response>',
                    f'    <D:href>{_xml_escape(href)}</D:href>',
                    '    <D:status>HTTP/1.1 404 Not Found</D:status>',
                    '  </D:response>',
                ]
                continue
            etag = self._contact_etag(c)
            lines += ['  <D:response>', f'    <D:href>{_xml_escape(href)}</D:href>',
                      '    <D:propstat>', '      <D:prop>',
                      f'        <D:getetag>"{etag}"</D:getetag>']
            if want_address_data:
                vcard = contact_to_vcard(c)
                lines.append(f'        <C:address-data>{_xml_escape(vcard)}</C:address-data>')
            lines += ['      </D:prop>', '      <D:status>HTTP/1.1 200 OK</D:status>',
                      '    </D:propstat>', '  </D:response>']
        lines.append('</D:multistatus>')
        return _xml_resp(207, "Multi-Status", "\n".join(lines))

    def _report_query(self, body_str: str, contacts: list[Contact]) -> HTTPResponse:
        want_address_data = "address-data" in body_str.lower()
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">',
        ]
        for c in contacts:
            etag = self._contact_etag(c)
            href = f"/{c.elem_id}.vcf"
            lines += ['  <D:response>', f'    <D:href>{_xml_escape(href)}</D:href>',
                      '    <D:propstat>', '      <D:prop>',
                      f'        <D:getetag>"{etag}"</D:getetag>']
            if want_address_data:
                vcard = contact_to_vcard(c)
                lines.append(f'        <C:address-data>{_xml_escape(vcard)}</C:address-data>')
            lines += ['      </D:prop>', '      <D:status>HTTP/1.1 200 OK</D:status>',
                      '    </D:propstat>', '  </D:response>']
        lines.append('</D:multistatus>')
        return _xml_resp(207, "Multi-Status", "\n".join(lines))

    # -----------------------------------------------------------------------
    # GET / HEAD
    # -----------------------------------------------------------------------

    async def _handle_get(
        self, req: HTTPRequest, session, client: TutaClient, path: str, username: str
    ) -> HTTPResponse:
        entry = await self._get_cached(username, session, client)
        contacts = entry.contacts

        # GET / → cały addressbook jako vCard multiblock
        if path == "/" or path == "":
            body = "".join(contact_to_vcard(c) for c in contacts)
            resp = _vcard_resp(200, self._collection_ctag(contacts), body.encode("utf-8"))
            if req.method == "HEAD":
                resp.body = b""
            return resp

        uid = _uid_from_path(path)
        c = next((x for x in contacts if x.elem_id == uid), None)
        if not c:
            return _text_resp(404, "Not Found")

        etag = self._contact_etag(c)
        body = contact_to_vcard(c).encode("utf-8")
        resp = _vcard_resp(200, etag, body)
        if req.method == "HEAD":
            resp.body = b""
        return resp

    # -----------------------------------------------------------------------
    # PUT — utwórz lub zaktualizuj kontakt
    # -----------------------------------------------------------------------

    async def _handle_put(
        self, req: HTTPRequest, session, client: TutaClient, path: str, username: str
    ) -> HTTPResponse:
        if not req.body:
            return _text_resp(400, "Bad Request", "Puste body")

        try:
            vcard_text = req.body.decode("utf-8")
        except UnicodeDecodeError:
            vcard_text = req.body.decode("latin-1")

        contact = parse_vcard(vcard_text)
        if not contact:
            return _text_resp(400, "Bad Request", "Nieprawidłowy vCard")

        uid_from_path = _uid_from_path(path)
        entry = await self._get_cached(username, session, client)

        existing = next((c for c in entry.contacts if c.elem_id == uid_from_path), None)

        try:
            if existing:
                contact.list_id = existing.list_id
                contact.elem_id = existing.elem_id
                await client.update_contact_api(
                    session, contact, entry.group_key, entry.key_version
                )
                self._invalidate(username)
                etag = self._contact_etag(contact)
                return HTTPResponse(204, "No Content", {"ETag": f'"{etag}"'})
            else:
                if uid_from_path and uid_from_path != path.strip("/"):
                    contact.elem_id = uid_from_path
                list_id, new_id = await client.create_contact_api(
                    session, contact,
                    entry.list_id, entry.group_key, entry.group_id, entry.key_version
                )
                self._invalidate(username)
                etag = self._contact_etag(contact)
                return HTTPResponse(201, "Created", {
                    "Location": f"/{new_id}.vcf",
                    "ETag": f'"{etag}"',
                })
        except TutaAPIError as e:
            logger.error("CardDAV PUT error: %s", e)
            return _text_resp(500, "Internal Server Error", str(e))

    # -----------------------------------------------------------------------
    # DELETE — batched via eraseMultiple
    # -----------------------------------------------------------------------

    async def _handle_delete(
        self, req: HTTPRequest, session, client: TutaClient, path: str, username: str
    ) -> HTTPResponse:
        uid = _uid_from_path(path)
        if not uid:
            return _text_resp(400, "Bad Request", "Brak UID w ścieżce")

        entry = await self._get_cached(username, session, client)
        c = next((x for x in entry.contacts if x.elem_id == uid), None)
        if not c:
            return _text_resp(404, "Not Found")

        if username not in self._delete_locks:
            self._delete_locks[username] = asyncio.Lock()

        async with self._delete_locks[username]:
            is_first = username not in self._delete_batch
            if is_first:
                self._delete_batch[username] = _DeleteBatch(
                    items=[], event=asyncio.Event()
                )
            batch = self._delete_batch[username]
            batch.items.append((c.list_id, c.elem_id))

        if is_first:
            # Pierwszy DELETE w tej paczce uruchamia timer flush.
            loop = asyncio.get_event_loop()
            loop.call_later(
                DELETE_BATCH_WINDOW,
                lambda: asyncio.ensure_future(
                    self._flush_deletes(username, batch, session, client)
                ),
            )

        # Każdy DELETE czeka aż flush wyśle batch i ustawi event.
        await batch.event.wait()

        if batch.error:
            return _text_resp(500, "Internal Server Error", str(batch.error))

        self._invalidate(username)
        return HTTPResponse(204, "No Content", {})

    async def _flush_deletes(
        self,
        username: str,
        batch: "_DeleteBatch",
        session,
        client: TutaClient,
    ) -> None:
        """Wysyła zgromadzone DELETy jako jeden eraseMultiple i zwalnia czekające requesty."""
        # Usuń batch ze słownika — nowe DELETy po tym punkcie dostaną nowy batch.
        async with self._delete_locks[username]:
            if self._delete_batch.get(username) is batch:
                del self._delete_batch[username]

        from collections import defaultdict
        by_list: dict[str, list[str]] = defaultdict(list)
        for list_id, elem_id in batch.items:
            by_list[list_id].append(elem_id)

        for list_id, elem_ids in by_list.items():
            try:
                logger.info(
                    "CardDAV batch DELETE: %d kontaktów z listy %s",
                    len(elem_ids), list_id[:12],
                )
                await client.delete_contacts_bulk_api(session, list_id, elem_ids)
            except Exception as e:
                logger.error("CardDAV batch DELETE error: %s", e)
                batch.error = e
                break

        batch.event.set()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uid_from_path(path: str) -> str:
    """Wyciąga UID z ścieżki (np. '/abc123.vcf' → 'abc123')."""
    name = path.rstrip("/").rsplit("/", 1)[-1]
    if name.lower().endswith(".vcf"):
        name = name[:-4]
    return name


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;"))
