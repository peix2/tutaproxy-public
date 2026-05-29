"""
tuta/webdav_server.py
Serwer WebDAV dla Tuta Drive.

Obsługiwane metody HTTP:
  OPTIONS   → dostępne metody
  PROPFIND  → właściwości zasobu (depth=0) lub listowanie katalogu (depth=1)
  GET/HEAD  → pobieranie pliku
  PUT       → upload pliku
  DELETE    → usunięcie (przeniesienie do kosza)
  MKCOL     → tworzenie katalogu
  MOVE      → zmiana nazwy lub przeniesienie

URL-space:
  /           → root folder Drive
  /Folder/    → podfolder (trailing slash = katalog)
  /File.ext   → plik w root
  /Folder/Sub/ → zagnieżdżony podfolder
  /Folder/F.ext → plik w podfolderze

Auth: HTTP Basic (email + hasło Tuta), per-request.
Montowanie na Linuxie (davfs2):
  sudo mount -t davfs http://localhost:5234/ /mnt/tuta
lub przez rclone, GNOME Files (Ctrl+L → dav://localhost:5234/).
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from email.utils import formatdate
from typing import Optional
from urllib.parse import unquote, quote

from .api import (
    TutaClient,
    TutaAPIError,
    TutaAuthError,
    DriveFolder,
    DriveFile,
)

logger = logging.getLogger(__name__)

CACHE_TTL = 30       # sekundy ważności cache folderów
UPLOAD_PIN_TTL = 300  # sekundy trzymania uploadowanego pliku w cache niezależnie od API
MAX_UPLOAD = 512 * 1024 * 1024  # 512 MB


# ---------------------------------------------------------------------------
# HTTP request/response
# ---------------------------------------------------------------------------

@dataclass
class HTTPRequest:
    method: str
    path: str
    headers: dict
    body: bytes

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def depth(self) -> int:
        d = self.header("depth", "0")
        if d == "infinity":
            return 99
        try:
            return int(d)
        except ValueError:
            return 0


@dataclass
class HTTPResponse:
    status: int
    reason: str
    headers: dict
    body: bytes = b""

    def to_bytes(self) -> bytes:
        hdrs = dict(self.headers)
        hdrs.setdefault("Content-Length", str(len(self.body)))
        hdrs.setdefault("DAV", "1, 2")
        hdrs.setdefault("MS-Author-Via", "DAV")
        status_line = f"HTTP/1.1 {self.status} {self.reason}\r\n"
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        return (status_line + header_lines + "\r\n").encode() + self.body


def _xml_resp(status: int, reason: str, xml: str, extra: dict = None) -> HTTPResponse:
    body = xml.encode("utf-8")
    hdrs = {"Content-Type": "application/xml; charset=utf-8"}
    if extra:
        hdrs.update(extra)
    return HTTPResponse(status, reason, hdrs, body)


def _bytes_resp(
    status: int,
    reason: str,
    data: bytes,
    mime: str = "application/octet-stream",
    extra: dict = None,
) -> HTTPResponse:
    hdrs = {"Content-Type": mime, "Accept-Ranges": "bytes"}
    if extra:
        hdrs.update(extra)
    return HTTPResponse(status, reason, hdrs, data)


def _simple_resp(status: int, reason: str, text: str = "") -> HTTPResponse:
    return HTTPResponse(status, reason, {"Content-Type": "text/plain; charset=utf-8"}, text.encode())


# ---------------------------------------------------------------------------
# Pomocnicze formatowanie czasu
# ---------------------------------------------------------------------------

def _iso8601(ms: int) -> str:
    """Timestamp w milisekundach → ISO 8601 UTC."""
    import datetime
    dt = datetime.datetime.utcfromtimestamp(ms / 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rfc1123(ms: int) -> str:
    """Timestamp w milisekundach → RFC 1123 (HTTP Date)."""
    return formatdate(ms / 1000, usegmt=True)


def _now_ms() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# PROPFIND XML helpers
# ---------------------------------------------------------------------------

def _prop_for_folder(href: str, name: str, created_ms: int, updated_ms: int) -> str:
    return f"""<D:response>
<D:href>{_xml_esc(href)}</D:href>
<D:propstat>
<D:prop>
<D:resourcetype><D:collection/></D:resourcetype>
<D:displayname>{_xml_esc(name)}</D:displayname>
<D:creationdate>{_iso8601(created_ms)}</D:creationdate>
<D:getlastmodified>{_rfc1123(updated_ms)}</D:getlastmodified>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"""


def _prop_for_file(
    href: str, name: str, size: int, mime: str,
    created_ms: int, updated_ms: int, etag: str
) -> str:
    return f"""<D:response>
<D:href>{_xml_esc(href)}</D:href>
<D:propstat>
<D:prop>
<D:resourcetype/>
<D:displayname>{_xml_esc(name)}</D:displayname>
<D:getcontentlength>{size}</D:getcontentlength>
<D:getcontenttype>{_xml_esc(mime)}</D:getcontenttype>
<D:getetag>"{etag}"</D:getetag>
<D:creationdate>{_iso8601(created_ms)}</D:creationdate>
<D:getlastmodified>{_rfc1123(updated_ms)}</D:getlastmodified>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>"""


def _multistatus(responses: list[str]) -> str:
    inner = "\n".join(responses)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
{inner}
</D:multistatus>"""


def _xml_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _file_etag(f: DriveFile) -> str:
    h = hashlib.sha256(f"{f.id_tuple}{f.name}{f.size}{f.updated_ms}".encode()).hexdigest()[:16]
    return h


def _folder_etag(f: DriveFolder) -> str:
    h = hashlib.sha256(f"{f.id_tuple}{f.name}{f.updated_ms}".encode()).hexdigest()[:16]
    return h


# ---------------------------------------------------------------------------
# Cache folderów Drive per user
# ---------------------------------------------------------------------------

@dataclass
class _FolderCache:
    """Cache zawartości jednego folderu."""
    subfolders: list[DriveFolder]
    files: list[DriveFile]
    ts: float


@dataclass
class _DriveCache:
    """Cache całości Drive dla jednego użytkownika."""
    group_id: str
    group_key: bytes
    key_version: str
    root_id: list          # [listId, elemId]
    trash_id: list         # [listId, elemId]
    folders: dict = field(default_factory=dict)   # tuple(id) → _FolderCache
    # Pliki przypięte po uploadzie — widoczne przez UPLOAD_PIN_TTL niezależnie od API
    pinned: dict = field(default_factory=dict)    # folder_key → list[(DriveFile, expiry_ts)]
    ts: float = 0.0

    def folder_key(self, id_tuple: list) -> tuple:
        return tuple(id_tuple)

    def get_folder_cache(self, id_tuple: list) -> Optional[_FolderCache]:
        entry = self.folders.get(self.folder_key(id_tuple))
        if entry and (time.time() - entry.ts) < CACHE_TTL:
            return entry
        return None

    def set_folder_cache(self, id_tuple: list, subfolders, files) -> None:
        self.folders[self.folder_key(id_tuple)] = _FolderCache(
            subfolders=subfolders, files=files, ts=time.time()
        )

    def invalidate_folder(self, id_tuple: list) -> None:
        self.folders.pop(self.folder_key(id_tuple), None)

    def pin_file(self, folder_id: list, file: DriveFile) -> None:
        key = self.folder_key(folder_id)
        expiry = time.time() + UPLOAD_PIN_TTL
        pins = self.pinned.get(key, [])
        pins = [(f, e) for f, e in pins if str(f.id_tuple) != str(file.id_tuple) and e > time.time()]
        pins.append((file, expiry))
        self.pinned[key] = pins

    def get_pinned_files(self, folder_id: list) -> list:
        key = self.folder_key(folder_id)
        now = time.time()
        return [f for f, e in self.pinned.get(key, []) if e > now]


# ---------------------------------------------------------------------------
# Serwer WebDAV
# ---------------------------------------------------------------------------

class WebDAVServer:
    """Async TCP serwer WebDAV dla Tuta Drive."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5234):
        self.host = host
        self.port = port
        # email → (session, client, pw_hash) — pw_hash chroni przed auth bypass:
        # bez tego drugi request z tym samym emailem i innym hasłem dostawałby
        # zalogowaną sesję pierwszego (krytyczna luka przy bind != 127.0.0.1).
        self._sessions: dict[str, tuple] = {}
        self._login_locks: dict[str, asyncio.Lock] = {}
        self._drive_cache: dict[str, _DriveCache] = {}
        self._cache_lock = asyncio.Lock()
        # Blokady uploadu per (email, path) — zapobiega równoległym uploadom tego samego pliku
        self._upload_locks: dict[str, asyncio.Lock] = {}

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle_conn, self.host, self.port)
        logger.info("WebDAV (Tuta Drive): http://%s:%d/", self.host, self.port)
        async with server:
            await server.serve_forever()

    # -----------------------------------------------------------------------
    # Autentykacja i sesja
    # -----------------------------------------------------------------------

    async def _get_session(self, username: str, password: str):
        """Cache trafia tylko gdy sha256(password) się zgadza — bez tego auth bypass."""
        pw_hash = hashlib.sha256(password.encode("utf-8")).digest()
        cached = self._sessions.get(username)
        if cached and len(cached) >= 3 and hmac.compare_digest(cached[2], pw_hash):
            return cached[0], cached[1]
        if username not in self._login_locks:
            self._login_locks[username] = asyncio.Lock()
        async with self._login_locks[username]:
            cached = self._sessions.get(username)
            if cached and len(cached) >= 3 and hmac.compare_digest(cached[2], pw_hash):
                return cached[0], cached[1]
            client = TutaClient()
            await client.__aenter__()
            try:
                session = await client.login(username, password)
            except Exception:
                await client.__aexit__(None, None, None)
                raise
            old = self._sessions.get(username)
            if old:
                try:
                    await old[1].__aexit__(None, None, None)
                except Exception as exc:
                    logger.debug("WebDAV: błąd zamykania starego klienta dla %s: %s", username, exc)
            self._sessions[username] = (session, client, pw_hash)
            logger.info("WebDAV: zalogowano %s", username)
            return session, client

    async def _get_drive_cache(
        self, session, client: TutaClient
    ) -> _DriveCache:
        """Zwraca _DriveCache dla użytkownika — inicjalizuje jeśli brak."""
        email = session.user_email
        async with self._cache_lock:
            if email not in self._drive_cache:
                logger.info("WebDAV: inicjalizacja Drive cache dla %s", email)
                group_id, group_key, key_version = await client.get_drive_group_key(session)
                root_id, trash_id = await client.get_drive_root(
                    session, group_id, group_key, key_version
                )
                self._drive_cache[email] = _DriveCache(
                    group_id=group_id,
                    group_key=group_key,
                    key_version=key_version,
                    root_id=root_id,
                    trash_id=trash_id,
                    ts=time.time(),
                )
                logger.info("WebDAV: Drive gotowy — root=%s trash=%s", root_id, trash_id)
        return self._drive_cache[email]

    # -----------------------------------------------------------------------
    # Path resolution
    # -----------------------------------------------------------------------

    async def _resolve_path(
        self,
        session,
        client: TutaClient,
        dc: _DriveCache,
        path: str,
    ) -> "Optional[tuple]":
        """
        Przekształca URL path → (kind, obj) gdzie kind ∈ {'folder', 'file'}.
        Zwraca None jeśli zasób nie istnieje.

        Algorytm: chodzi po drzewie folderów od root.
        Trailing slash → oczekuje folderu.
        Brak trailing slash → może być plik lub folder (sprawdza oba).
        """
        # Normalizacja path
        path = path.rstrip("/") or "/"
        if path == "/":
            folder = await client.get_drive_folder(session, dc.group_key, dc.root_id)
            return ("folder", folder) if folder else None

        parts = [p for p in path.split("/") if p]
        current_id = dc.root_id
        for i, part in enumerate(parts):
            subfolders, files = await self._get_folder_contents(session, client, dc, current_id)
            is_last = (i == len(parts) - 1)
            # Szukaj folderu o tej nazwie
            matched_folder = next((f for f in subfolders if f.name == part), None)
            if matched_folder:
                if is_last:
                    return ("folder", matched_folder)
                current_id = matched_folder.id_tuple
                continue
            # Szukaj pliku o tej nazwie (tylko na ostatnim poziomie)
            if is_last:
                matched_file = next((f for f in files if f.name == part), None)
                if matched_file:
                    return ("file", matched_file)
            return None  # pośredni komponent nie jest folderem
        return None

    async def _get_folder_contents(
        self,
        session,
        client: TutaClient,
        dc: _DriveCache,
        folder_id: list,
    ) -> "tuple[list[DriveFolder], list[DriveFile]]":
        """Zwraca zawartość folderu (z cache lub świeże)."""
        cached = dc.get_folder_cache(folder_id)
        if cached:
            return cached.subfolders, cached.files
        subfolders, files = await client.list_drive_folder_contents(
            session, dc.group_key, folder_id
        )
        logger.debug("Drive listing %s: %d folders %d files: %s",
                     folder_id, len(subfolders), len(files), [f.name for f in files])
        # Domieszaj pliki przypięte po uploadzie — API może jeszcze ich nie zwracać
        # (eventual consistency), ale wiemy że istnieją bo sami je wgraliśmy.
        pinned = dc.get_pinned_files(folder_id)
        if pinned:
            known_ids = {str(f.id_tuple) for f in files}
            extra = [f for f in pinned if str(f.id_tuple) not in known_ids]
            if extra:
                logger.debug("Drive listing: domieszano %d pinned: %s", len(extra), [f.name for f in extra])
            files = list(files) + extra
        dc.set_folder_cache(folder_id, subfolders, files)
        return subfolders, files

    def _parent_path(self, path: str) -> "tuple[str, str]":
        """Zwraca (parent_path, name) z URL path. '/' → ('/', '')."""
        path = path.rstrip("/")
        if "/" not in path:
            return "/", path
        parent, name = path.rsplit("/", 1)
        return (parent or "/"), name

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
            logger.info("WebDAV %s %s [%s:%d]", req.method, req.path, peer[0], peer[1])
            resp = await self._dispatch(req)
            logger.info("WebDAV → %d %s", resp.status, resp.reason)
            writer.write(resp.to_bytes())
            await writer.drain()
        except Exception as e:
            logger.exception("WebDAV conn error [%s]: %s", peer, e)
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
            if cl > MAX_UPLOAD:
                raise ValueError(f"Upload za duży: {cl} > {MAX_UPLOAD}")
            body = await asyncio.wait_for(reader.readexactly(cl), timeout=120)

        return HTTPRequest(method, path, headers, body)

    async def _dispatch(self, req: HTTPRequest) -> HTTPResponse:
        # Parsuj Basic Auth
        auth = req.header("authorization")
        if not auth.lower().startswith("basic "):
            return HTTPResponse(401, "Unauthorized", {
                "WWW-Authenticate": 'Basic realm="Tuta Drive"',
            })
        try:
            creds = base64.b64decode(auth[6:]).decode("utf-8")
            username, password = creds.split(":", 1)
        except Exception:
            return _simple_resp(400, "Bad Request", "Nieprawidłowe dane logowania")

        try:
            session, client = await self._get_session(username, password)
        except TutaAuthError:
            # Reset sesji przy błędzie auth
            self._sessions.pop(username, None)
            return HTTPResponse(401, "Unauthorized", {
                "WWW-Authenticate": 'Basic realm="Tuta Drive"',
            })
        except TutaAPIError as e:
            if "groupType=7" in str(e) or "Drive" in str(e):
                return _simple_resp(503, "Service Unavailable", str(e))
            return _simple_resp(502, "Bad Gateway", str(e))

        try:
            dc = await self._get_drive_cache(session, client)
        except TutaAPIError as e:
            return _simple_resp(503, "Service Unavailable", f"Drive niedostępny: {e}")

        method = req.method
        if method == "OPTIONS":
            return self._handle_options()
        elif method == "PROPFIND":
            return await self._handle_propfind(session, client, dc, req)
        elif method in ("GET", "HEAD"):
            return await self._handle_get(session, client, dc, req, head_only=(method == "HEAD"))
        elif method == "PUT":
            return await self._handle_put(session, client, dc, req)
        elif method == "DELETE":
            return await self._handle_delete(session, client, dc, req)
        elif method == "MKCOL":
            return await self._handle_mkcol(session, client, dc, req)
        elif method == "MOVE":
            return await self._handle_move(session, client, dc, req)
        elif method == "COPY":
            return _simple_resp(501, "Not Implemented", "COPY nie jest obsługiwany")
        elif method == "LOCK":
            # Odpowiedź LOCK jest wymagana przez niektóre klienty (Windows WebDAV)
            return self._handle_lock(req)
        elif method == "UNLOCK":
            return _simple_resp(204, "No Content")
        else:
            return _simple_resp(405, "Method Not Allowed")

    # -----------------------------------------------------------------------
    # OPTIONS
    # -----------------------------------------------------------------------

    def _handle_options(self) -> HTTPResponse:
        return HTTPResponse(200, "OK", {
            "Allow": "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, PROPFIND, LOCK, UNLOCK",
            "DAV": "1, 2",
            "MS-Author-Via": "DAV",
        })

    # -----------------------------------------------------------------------
    # LOCK (stub — niektóre klienty Windows wymagają odpowiedzi)
    # -----------------------------------------------------------------------

    def _handle_lock(self, req: HTTPRequest) -> HTTPResponse:
        path = req.path.rstrip("/") or "/"
        lock_token = f"opaquelocktoken:{hashlib.sha256(path.encode()).hexdigest()[:32]}"
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<D:prop xmlns:D="DAV:">
<D:lockdiscovery>
<D:activelock>
<D:locktype><D:write/></D:locktype>
<D:lockscope><D:exclusive/></D:lockscope>
<D:depth>0</D:depth>
<D:timeout>Second-3600</D:timeout>
<D:locktoken><D:href>{lock_token}</D:href></D:locktoken>
<D:lockroot><D:href>{_xml_esc(path)}</D:href></D:lockroot>
</D:activelock>
</D:lockdiscovery>
</D:prop>"""
        return HTTPResponse(200, "OK", {
            "Content-Type": "application/xml; charset=utf-8",
            "Lock-Token": f"<{lock_token}>",
        }, xml.encode())

    # -----------------------------------------------------------------------
    # PROPFIND
    # -----------------------------------------------------------------------

    async def _handle_propfind(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest
    ) -> HTTPResponse:
        path = req.path.rstrip("/") or "/"
        depth = req.depth()

        resource = await self._resolve_path(session, client, dc, path)
        if resource is None:
            return _simple_resp(404, "Not Found")

        kind, obj = resource
        responses: list[str] = []
        href = _path_to_href(path, kind == "folder")

        if kind == "folder":
            folder: DriveFolder = obj
            responses.append(_prop_for_folder(href, folder.name if path != "/" else "Drive", folder.created_ms, folder.updated_ms))
            if depth >= 1:
                subfolders, files = await self._get_folder_contents(session, client, dc, folder.id_tuple)
                for sf in subfolders:
                    sub_href = href.rstrip("/") + "/" + quote(sf.name, safe="") + "/"
                    responses.append(_prop_for_folder(sub_href, sf.name, sf.created_ms, sf.updated_ms))
                for f in files:
                    file_href = href.rstrip("/") + "/" + quote(f.name, safe="")
                    responses.append(_prop_for_file(file_href, f.name, f.size, f.mime_type, f.created_ms, f.updated_ms, _file_etag(f)))
        else:
            f: DriveFile = obj
            responses.append(_prop_for_file(href, f.name, f.size, f.mime_type, f.created_ms, f.updated_ms, _file_etag(f)))

        return _xml_resp(207, "Multi-Status", _multistatus(responses))

    # -----------------------------------------------------------------------
    # GET / HEAD
    # -----------------------------------------------------------------------

    async def _handle_get(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest, head_only: bool
    ) -> HTTPResponse:
        path = req.path.rstrip("/") or "/"
        resource = await self._resolve_path(session, client, dc, path)
        if resource is None:
            return _simple_resp(404, "Not Found")

        kind, obj = resource
        if kind == "folder":
            # Zwróć prostą listę HTML dla przeglądarek
            folder: DriveFolder = obj
            subfolders, files = await self._get_folder_contents(session, client, dc, folder.id_tuple)
            html = _folder_html(path, folder, subfolders, files)
            body = html.encode("utf-8") if not head_only else b""
            return _bytes_resp(200, "OK", body, "text/html; charset=utf-8")

        f: DriveFile = obj
        etag = _file_etag(f)
        if req.header("if-none-match") in (f'"{etag}"', etag):
            return HTTPResponse(304, "Not Modified", {"ETag": f'"{etag}"'})

        if head_only:
            return HTTPResponse(200, "OK", {
                "Content-Type": f.mime_type or "application/octet-stream",
                "Content-Length": str(f.size),
                "ETag": f'"{etag}"',
                "Last-Modified": _rfc1123(f.updated_ms),
            })

        try:
            data = await client.download_drive_file_data(session, dc.group_key, f)
        except TutaAPIError as e:
            return _simple_resp(502, "Bad Gateway", f"Błąd pobierania: {e}")

        return _bytes_resp(200, "OK", data, f.mime_type or "application/octet-stream", {
            "ETag": f'"{etag}"',
            "Last-Modified": _rfc1123(f.updated_ms),
            "Content-Disposition": f'attachment; filename="{f.name}"',
        })

    # -----------------------------------------------------------------------
    # PUT (upload)
    # -----------------------------------------------------------------------

    async def _handle_put(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest
    ) -> HTTPResponse:
        path = req.path.rstrip("/")
        if not path:
            return _simple_resp(400, "Bad Request", "Nie można nadpisać root folderu")

        parent_path, filename = self._parent_path(path)
        if not filename:
            return _simple_resp(400, "Bad Request", "Brak nazwy pliku")

        # Znajdź parent folder
        parent = await self._resolve_path(session, client, dc, parent_path)
        if parent is None:
            return _simple_resp(409, "Conflict", "Folder nadrzędny nie istnieje")
        if parent[0] != "folder":
            return _simple_resp(409, "Conflict", "Ścieżka nadrzędna nie jest folderem")
        parent_folder: DriveFolder = parent[1]

        # Serializacja uploadu per plik — davfs2 może wysyłać równoległe PUTy jeśli pierwszy
        # nie odpowiada dość szybko (duże pliki = wielominutowy upload). Lock zapewnia że
        # drugi PUT czeka na pierwszy i używa jego wyniku zamiast uploadować od nowa.
        email = session.user_id if hasattr(session, "user_id") else str(id(session))
        lock_key = f"{email}:{path}"
        if lock_key not in self._upload_locks:
            self._upload_locks[lock_key] = asyncio.Lock()
        async with self._upload_locks[lock_key]:
            return await self._do_put(session, client, dc, req, path, filename, parent_folder)

    async def _do_put(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest,
        path: str, filename: str, parent_folder: "DriveFolder"
    ) -> HTTPResponse:
        # Sprawdź czy plik został już uploadowany przez poprzedni równoległy PUT
        # (jest w pinned cache) — jeśli tak, zwróć 201 bez ponownego uploadu.
        pinned = dc.get_pinned_files(parent_folder.id_tuple)
        already = next((f for f in pinned if f.name == filename), None)
        if already:
            logger.info("PUT %s: plik już w cache (równoległy upload) → 201", filename)
            return HTTPResponse(201, "Created", {"ETag": f'"{_file_etag(already)}"'})

        # Sprawdź czy plik już istnieje → usuń go przed uplodem (replace)
        existing = await self._resolve_path(session, client, dc, path)
        if existing and existing[0] == "file":
            old_file: DriveFile = existing[1]
            try:
                await client.delete_drive_items_api(
                    session, [old_file.id_tuple], [], permanent=False
                )
            except TutaAPIError as e:
                logger.warning("PUT: nie można usunąć starego pliku: %s", e)

        mime = req.header("content-type") or "application/octet-stream"
        # Obetnij parametry (np. "text/plain; charset=utf-8" → "text/plain")
        mime = mime.split(";")[0].strip() or "application/octet-stream"

        try:
            new_file = await client.upload_drive_file_api(
                session,
                dc.group_id,
                dc.group_key,
                dc.key_version,
                filename,
                mime,
                req.body,
                parent_folder.id_tuple,
            )
        except TutaAPIError as e:
            logger.error("PUT %s failed: %s", filename, e)
            return _simple_resp(502, "Bad Gateway", f"Upload error: {e}")

        # Przypnij plik na UPLOAD_PIN_TTL sekund — Tuta API może nie zwracać go
        # w listingu folderu przez wiele sekund/minut po uploadzie (eventual consistency).
        # pin_file gwarantuje widoczność przez 5 minut niezależnie od odpowiedzi API.
        dc.pin_file(parent_folder.id_tuple, new_file)
        # Zaktualizuj też bieżący cache jeśli jest ważny (dla natychmiastowego HEAD)
        cached = dc.get_folder_cache(parent_folder.id_tuple)
        if cached:
            if not any(f.id_tuple == new_file.id_tuple for f in cached.files):
                dc.set_folder_cache(parent_folder.id_tuple, cached.subfolders, list(cached.files) + [new_file])
        else:
            dc.invalidate_folder(parent_folder.id_tuple)
        etag = _file_etag(new_file)
        return HTTPResponse(201, "Created", {"ETag": f'"{etag}"'})

    # -----------------------------------------------------------------------
    # DELETE
    # -----------------------------------------------------------------------

    async def _handle_delete(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest
    ) -> HTTPResponse:
        path = req.path.rstrip("/") or "/"
        if path == "/":
            return _simple_resp(403, "Forbidden", "Nie można usunąć root folderu Drive")

        resource = await self._resolve_path(session, client, dc, path)
        if resource is None:
            return _simple_resp(404, "Not Found")

        kind, obj = resource
        parent_path, _ = self._parent_path(path)

        try:
            if kind == "file":
                f: DriveFile = obj
                await client.delete_drive_items_api(session, [f.id_tuple], [], permanent=False)
            else:
                folder: DriveFolder = obj
                await client.delete_drive_items_api(session, [], [folder.id_tuple], permanent=False)
        except TutaAPIError as e:
            return _simple_resp(502, "Bad Gateway", f"Delete error: {e}")

        # Unieważnij cache folderu nadrzędnego
        parent_res = await self._resolve_path(session, client, dc, parent_path)
        if parent_res and parent_res[0] == "folder":
            dc.invalidate_folder(parent_res[1].id_tuple)

        return _simple_resp(204, "No Content")

    # -----------------------------------------------------------------------
    # MKCOL (utwórz katalog)
    # -----------------------------------------------------------------------

    async def _handle_mkcol(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest
    ) -> HTTPResponse:
        path = req.path.rstrip("/")
        if not path:
            return _simple_resp(405, "Method Not Allowed", "Root już istnieje")
        if req.body:
            return _simple_resp(415, "Unsupported Media Type")

        parent_path, dirname = self._parent_path(path)
        if not dirname:
            return _simple_resp(400, "Bad Request")

        parent = await self._resolve_path(session, client, dc, parent_path)
        if parent is None:
            return _simple_resp(409, "Conflict", "Folder nadrzędny nie istnieje")
        if parent[0] != "folder":
            return _simple_resp(409, "Conflict", "Ścieżka nadrzędna nie jest folderem")
        parent_folder: DriveFolder = parent[1]

        # Sprawdź czy już istnieje
        existing = await self._resolve_path(session, client, dc, path)
        if existing:
            return _simple_resp(405, "Method Not Allowed", "Zasób już istnieje")

        try:
            await client.create_drive_folder_api(
                session, dc.group_key, dc.key_version, dirname, parent_folder.id_tuple
            )
        except TutaAPIError as e:
            return _simple_resp(502, "Bad Gateway", f"MKCOL error: {e}")

        dc.invalidate_folder(parent_folder.id_tuple)
        return _simple_resp(201, "Created")

    # -----------------------------------------------------------------------
    # MOVE (zmiana nazwy lub przeniesienie)
    # -----------------------------------------------------------------------

    async def _handle_move(
        self, session, client: TutaClient, dc: _DriveCache, req: HTTPRequest
    ) -> HTTPResponse:
        src_path = req.path.rstrip("/") or "/"
        dest_raw = req.header("destination")
        if not dest_raw:
            return _simple_resp(400, "Bad Request", "Brak nagłówka Destination")

        # Wyciągnij ścieżkę z pełnego URL (http://host/path → /path)
        dest_path = _extract_path(dest_raw).rstrip("/") or "/"
        if src_path == dest_path:
            return _simple_resp(204, "No Content")
        if dest_path == "/":
            return _simple_resp(403, "Forbidden", "Nie można przenieść do root")

        resource = await self._resolve_path(session, client, dc, src_path)
        if resource is None:
            return _simple_resp(404, "Not Found")
        kind, obj = resource

        src_parent_path, src_name = self._parent_path(src_path)
        dest_parent_path, dest_name = self._parent_path(dest_path)

        # Znajdź folder docelowy
        dest_parent = await self._resolve_path(session, client, dc, dest_parent_path)
        if dest_parent is None:
            return _simple_resp(409, "Conflict", "Docelowy folder nadrzędny nie istnieje")
        if dest_parent[0] != "folder":
            return _simple_resp(409, "Conflict", "Cel nie jest folderem")
        dest_parent_folder: DriveFolder = dest_parent[1]

        same_parent = (src_parent_path.rstrip("/") == dest_parent_path.rstrip("/"))
        rename = (dest_name != src_name)

        # Usuń ewentualny konflikt w celu
        overwrite = req.header("overwrite", "T").upper()
        if overwrite == "T":
            existing_dest = await self._resolve_path(session, client, dc, dest_path)
            if existing_dest:
                dest_kind, dest_obj = existing_dest
                try:
                    if dest_kind == "file":
                        await client.delete_drive_items_api(session, [dest_obj.id_tuple], [], permanent=False)
                    else:
                        await client.delete_drive_items_api(session, [], [dest_obj.id_tuple], permanent=False)
                except TutaAPIError as e:
                    logger.warning("MOVE: usunięcie celu nieudane: %s", e)

        try:
            if same_parent and rename:
                # Tylko zmiana nazwy w tym samym folderze → DriveItemService PUT
                await client.rename_drive_item_api(
                    session, dc.group_key, obj.raw, dest_name, is_file=(kind == "file")
                )
            elif not same_parent and not rename:
                # Tylko przeniesienie (bez zmiany nazwy) → DriveFolderService PUT
                if kind == "file":
                    await client.move_drive_items_api(session, dc.group_key, [obj], [], dest_parent_folder.id_tuple)
                else:
                    await client.move_drive_items_api(session, dc.group_key, [], [obj], dest_parent_folder.id_tuple)
            else:
                # Przeniesienie + zmiana nazwy → DriveFolderService PUT z encNewName
                rename_map = {obj.name: dest_name}
                if kind == "file":
                    await client.move_drive_items_api(
                        session, dc.group_key, [obj], [], dest_parent_folder.id_tuple, rename_map
                    )
                else:
                    await client.move_drive_items_api(
                        session, dc.group_key, [], [obj], dest_parent_folder.id_tuple, rename_map
                    )
        except TutaAPIError as e:
            return _simple_resp(502, "Bad Gateway", f"MOVE error: {e}")

        # Unieważnij cache obu folderów
        src_parent_res = await self._resolve_path(session, client, dc, src_parent_path)
        if src_parent_res and src_parent_res[0] == "folder":
            dc.invalidate_folder(src_parent_res[1].id_tuple)
        dc.invalidate_folder(dest_parent_folder.id_tuple)

        return _simple_resp(201, "Created")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _path_to_href(path: str, is_folder: bool) -> str:
    """Konwertuje ścieżkę na href WebDAV (URL-encoded, trailing slash dla folderów)."""
    parts = [p for p in path.split("/") if p]
    encoded = "/".join(quote(p, safe="") for p in parts)
    result = "/" + encoded
    if is_folder:
        result += "/"
    return result


def _extract_path(url: str) -> str:
    """Wyciąga ścieżkę z pełnego URL lub zwraca sam path."""
    url = unquote(url)
    if url.startswith("http://") or url.startswith("https://"):
        # http://host:port/path → /path
        idx = url.find("/", 8)
        return url[idx:] if idx >= 0 else "/"
    return url


def _folder_html(path: str, folder: DriveFolder, subfolders: list, files: list) -> str:
    """Prosta lista HTML dla przeglądarek (nie jest używana przez klientów WebDAV)."""
    title = folder.name if path != "/" else "Tuta Drive"
    items = []
    if path != "/":
        parent = path.rsplit("/", 1)[0] or "/"
        items.append(f'<li><a href="{parent}/">..</a></li>')
    for sf in subfolders:
        href = path.rstrip("/") + "/" + quote(sf.name, safe="") + "/"
        items.append(f'<li>📁 <a href="{href}">{_html_esc(sf.name)}/</a></li>')
    for f in files:
        href = path.rstrip("/") + "/" + quote(f.name, safe="")
        items.append(f'<li>📄 <a href="{href}">{_html_esc(f.name)}</a> ({f.size} B)</li>')
    body = "\n".join(items)
    return f"<html><head><title>{title}</title></head><body><h1>{title}</h1><ul>{body}</ul></body></html>"


def _html_esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
