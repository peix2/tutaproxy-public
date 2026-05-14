"""
tuta/imap_server.py
Minimalny serwer IMAP4rev1 (RFC 3501) na localhost:1143.

Obsługiwane komendy:
  CAPABILITY, NOOP, LOGOUT
  LOGIN (uwierzytelnia przez Tuta API)
  LIST, LSUB
  SELECT, EXAMINE
  FETCH (FLAGS, UID, RFC822.SIZE, BODY[], BODY[HEADER*], BODY[TEXT])
  STORE (\Seen read/unread przez API, \Deleted lokalnie do EXPUNGE)
  EXPUNGE (przenosi \Deleted do Trash przez MoveMailService)
  IDLE (push nowych wiadomości przez WebSocket, RFC 2177)
  UID FETCH, UID STORE, UID EXPUNGE
  APPEND (Drafts → create_draft przez API; Sent/inne → odrzuca, Tuta zapisuje samo)

Nie obsługujemy (M4+):
  COPY, SEARCH
"""

import asyncio
import base64
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from email import message_from_bytes as _email_from_bytes
from email.header import decode_header as _decode_header_raw, make_header as _make_header
from email.utils import getaddresses as _getaddresses

from .api import TutaClient, TutaAPIError, Session, MailFolder
from .cache import TutaCache
from .message_builder import build_rfc2822, get_mail_flags, tuta_id_to_uid

logger = logging.getLogger(__name__)


def _mask_sensitive(line: str) -> str:
    """Masks password in LOGIN command before debug logging."""
    parts = line.split(None, 3)
    if len(parts) >= 3 and parts[1].upper() == "LOGIN":
        return f"{parts[0]} LOGIN {parts[2]} ***"
    return line


# ---------------------------------------------------------------------------
# Mapowanie typów folderów Tuta → nazwy IMAP
# ---------------------------------------------------------------------------

def _rfc2822_header(value: str | None) -> str:
    """Dekoduje nagłówek RFC 2047."""
    if not value:
        return ""
    try:
        return str(_make_header(_decode_header_raw(value)))
    except Exception:
        return value or ""


def _rfc2822_addrs(header_val: str | None) -> list[tuple[str, str]]:
    """Parsuje nagłówek adresowy → [(name, address)]."""
    if not header_val:
        return []
    return [(n.strip(), a.strip()) for n, a in _getaddresses([header_val]) if a.strip()]


def _rfc2822_body_html(msg) -> str:
    """Wyciąga body wiadomości jako HTML (preferuje text/html, fallback text/plain)."""
    if msg.is_multipart():
        html_part = plain_part = None
        for part in msg.walk():
            ct = part.get_content_type()
            if "attachment" in str(part.get("Content-Disposition", "")):
                continue
            if ct == "text/html" and html_part is None:
                html_part = part
            elif ct == "text/plain" and plain_part is None:
                plain_part = part
        part = html_part or plain_part
        if part is None:
            return "<html><body></body></html>"
        charset = part.get_content_charset() or "utf-8"
        payload = part.get_payload(decode=True).decode(charset, errors="replace")
        if part.get_content_type() == "text/plain":
            payload = f"<html><body><pre>{payload}</pre></body></html>"
        return payload
    ct = msg.get_content_type()
    charset = msg.get_content_charset() or "utf-8"
    payload = msg.get_payload(decode=True)
    if payload is None:
        return "<html><body></body></html>"
    text = payload.decode(charset, errors="replace")
    if ct != "text/html":
        text = f"<html><body><pre>{text}</pre></body></html>"
    return text


FOLDER_TYPE_NAMES = {
    "1": "INBOX",
    "2": "Sent",
    "3": "Trash",
    "4": "Archive",
    "5": "Spam",
    "6": "Drafts",
}

FOLDER_TYPE_SPECIAL = {
    "1": r"\Inbox",
    "2": r"\Sent",
    "3": r"\Trash",
    "4": r"\Archive",
    "5": r"\Junk",
    "6": r"\Drafts",
}


# ---------------------------------------------------------------------------
# Struktury danych sesji
# ---------------------------------------------------------------------------

@dataclass
class MailboxState:
    """Stan wybranej skrzynki (po SELECT)."""
    folder: MailFolder
    # Mapowanie: seq_num (1-based) → raw mail dict
    messages: list[dict] = field(default_factory=list)
    # Odszyfrowany klucz grupy mail (wspólny dla wszystkich maili w skrzynce)
    mail_group_key: Optional[bytes] = None
    # UIDs z flagą \Deleted (czekają na EXPUNGE / CLOSE)
    deleted_uids: set = field(default_factory=set)

    @property
    def exists(self) -> int:
        return len(self.messages)

    def seq_to_mail(self, seq: int) -> Optional[dict]:
        if 1 <= seq <= len(self.messages):
            return self.messages[seq - 1]
        return None

    def uid_to_seq(self, uid: int) -> Optional[int]:
        for i, m in enumerate(self.messages):
            if tuta_id_to_uid(m.get("99", "")) == uid:
                return i + 1
        return None


# ---------------------------------------------------------------------------
# Obsługa jednego połączenia IMAP
# ---------------------------------------------------------------------------

class IMAPConnection:
    """
    Stan maszyny IMAP dla jednego połączenia TCP.
    Stany: NOT_AUTH → AUTH → SELECTED → LOGOUT
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        client: TutaClient,
        cache: TutaCache,
    ):
        self.reader = reader
        self.writer = writer
        self.client = client
        self.cache = cache

        self.state = "NOT_AUTH"
        self.session: Optional[Session] = None
        self.mailbox: Optional[MailboxState] = None
        self._folders: Optional[list[MailFolder]] = None
        self._mail_group_key: Optional[bytes] = None
        self._credentials: "tuple[str, str] | None" = None  # (email, password) — tylko do re-login na 401
        # Cache zbudowanych wiadomości RFC 2822 — kluczem jest element_id maila.
        # Unikamy przebudowy dla każdego partial fetch (BODY[]<offset.count>),
        # co gwarantuje też stałe granice MIME między żądaniami.
        self._msg_cache: dict[str, bytes] = {}

        peer = writer.get_extra_info("peername")
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "unknown"

    # -----------------------------------------------------------------------
    # Wysyłanie odpowiedzi
    # -----------------------------------------------------------------------

    def _send(self, line: str) -> None:
        data = (line + "\r\n").encode("utf-8")
        self.writer.write(data)

    def _ok(self, tag: str, text: str = "OK") -> None:
        self._send(f"{tag} OK {text}")

    def _no(self, tag: str, text: str) -> None:
        self._send(f"{tag} NO {text}")

    def _bad(self, tag: str, text: str = "BAD command") -> None:
        self._send(f"{tag} BAD {text}")

    def _untagged(self, line: str) -> None:
        self._send(f"* {line}")

    # -----------------------------------------------------------------------
    # Główna pętla połączenia
    # -----------------------------------------------------------------------

    async def handle(self) -> None:
        logger.info(f"[{self.peer}] Nowe połączenie")
        self._send("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE] tuta-proxy ready")

        try:
            while True:
                try:
                    line = await asyncio.wait_for(
                        self.reader.readline(), timeout=300
                    )
                except asyncio.TimeoutError:
                    self._send("* BYE Timeout")
                    break

                if not line:
                    break

                decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not decoded:
                    continue

                logger.debug(f"[{self.peer}] << {_mask_sensitive(decoded)}")
                await self._dispatch(decoded)

                if self.state == "LOGOUT":
                    break

                await self.writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.exception(f"[{self.peer}] Nieoczekiwany błąd: {e}")
        finally:
            try:
                self.writer.close()
            except Exception:
                pass
            logger.info(f"[{self.peer}] Połączenie zamknięte")

    async def _dispatch(self, line: str) -> None:
        """Parsuje linię IMAP i wywołuje odpowiedni handler."""
        # Linia: TAG COMMAND [args...]
        # Obsługa literałów (np. {42}) — APPEND ma własny handler który czyta literal
        parts = line.split(None, 2)
        if len(parts) < 2:
            self._send("* BAD Empty command")
            return

        tag, command = parts[0], parts[1].upper()
        args = parts[2] if len(parts) > 2 else ""

        handlers = {
            "CAPABILITY":   self._cmd_capability,
            "NOOP":         self._cmd_noop,
            "LOGOUT":       self._cmd_logout,
            "LOGIN":        self._cmd_login,
            "AUTHENTICATE": self._cmd_authenticate,
            "LIST":         self._cmd_list,
            "LSUB":         self._cmd_lsub,
            "SELECT":       self._cmd_select,
            "EXAMINE":      self._cmd_examine,
            "STATUS":       self._cmd_status,
            "FETCH":        self._cmd_fetch,
            "UID":          self._cmd_uid,
            "STORE":        self._cmd_store,
            "COPY":         self._cmd_copy,
            "EXPUNGE":      self._cmd_expunge,
            "IDLE":         self._cmd_idle,
            "CLOSE":        self._cmd_close,
            "UNSELECT":     self._cmd_close,
            "CHECK":        self._cmd_check,
            "SUBSCRIBE":    self._cmd_subscribe,
            "UNSUBSCRIBE":  self._cmd_subscribe,
            "SEARCH":       self._cmd_search,
            "APPEND":       self._cmd_append,
            "CREATE":       self._cmd_create,
            "DELETE":       self._cmd_delete,
            "RENAME":       self._cmd_rename,
        }

        handler = handlers.get(command)
        if handler is None:
            self._bad(tag, f"Unknown command: {command}")
            return

        try:
            await handler(tag, args)
        except TutaAPIError as e:
            if e.status_code == 401:
                if await self._try_relogin():
                    try:
                        await handler(tag, args)
                    except TutaAPIError as e2:
                        if e2.status_code == 401:
                            logger.warning(f"[{self.peer}] 401 po re-login — BYE")
                            self._send("* BYE Session expired, please reconnect")
                            self.state = "LOGOUT"
                        else:
                            self._no(tag, f"Tuta API error: {e2}")
                    except Exception as e2:
                        logger.exception(f"[{self.peer}] Błąd po re-login w {command}: {e2}")
                        self._no(tag, f"Internal error: {e2}")
                else:
                    logger.warning(f"[{self.peer}] Re-login failed — BYE")
                    self._send("* BYE Session expired, please reconnect")
                    self.state = "LOGOUT"
            else:
                self._no(tag, f"Tuta API error: {e}")
        except Exception as e:
            logger.exception(f"[{self.peer}] Błąd w {command}: {e}")
            self._no(tag, f"Internal error: {e}")

    # -----------------------------------------------------------------------
    # Komendy — stan niezależny
    # -----------------------------------------------------------------------

    async def _cmd_capability(self, tag: str, args: str) -> None:
        self._untagged("CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE")
        self._ok(tag, "CAPABILITY completed")

    async def _cmd_noop(self, tag: str, args: str) -> None:
        self._ok(tag, "NOOP completed")

    async def _cmd_logout(self, tag: str, args: str) -> None:
        self._untagged("BYE tuta-proxy logging out")
        self._ok(tag, "LOGOUT completed")
        self.state = "LOGOUT"

    # -----------------------------------------------------------------------
    # Komendy — NOT_AUTH
    # -----------------------------------------------------------------------

    async def _cmd_login(self, tag: str, args: str) -> None:
        # LOGIN "user" "pass"  lub  LOGIN user pass
        parts = _parse_args(args)
        if len(parts) < 2:
            self._bad(tag, "LOGIN requires username and password")
            return

        username, password = parts[0], parts[1]
        logger.info(f"[{self.peer}] LOGIN attempt: {username}")

        try:
            self.session = await self.client.login(username, password)
        except TutaAPIError as e:
            self._no(tag, f"[AUTHENTICATIONFAILED] Login failed: {e}")
            return

        self.state = "AUTH"
        logger.info(f"[{self.peer}] Logged in: {username}")
        self._ok(tag, "LOGIN completed")

    async def _cmd_authenticate(self, tag: str, args: str) -> None:
        mechanism = args.strip().upper()
        if mechanism != "PLAIN":
            self._no(tag, f"Unsupported auth mechanism: {mechanism}")
            return

        # Send empty challenge — client responds with base64(\x00user\x00pass)
        self._send("+ ")
        await self.writer.drain()

        try:
            line = await asyncio.wait_for(self.reader.readline(), timeout=30)
        except asyncio.TimeoutError:
            self._no(tag, "Timeout waiting for credentials")
            return

        try:
            auth_bytes = base64.b64decode(line.strip())
            parts = auth_bytes.split(b"\x00")
            # Format: authzid\x00authcid\x00pass  or  authcid\x00pass
            if len(parts) == 3:
                username, password = parts[1].decode(), parts[2].decode()
            elif len(parts) == 2:
                username, password = parts[0].decode(), parts[1].decode()
            else:
                self._no(tag, "[AUTHENTICATIONFAILED] Invalid PLAIN format")
                return
        except Exception:
            self._no(tag, "[AUTHENTICATIONFAILED] Invalid base64 encoding")
            return

        logger.info(f"[{self.peer}] AUTHENTICATE PLAIN attempt: {username}")

        try:
            self.session = await self.client.login(username, password)
        except TutaAPIError as e:
            self._no(tag, f"[AUTHENTICATIONFAILED] Login failed: {e}")
            return

        self.state = "AUTH"
        logger.info(f"[{self.peer}] Logged in via AUTHENTICATE PLAIN: {username}")
        self._ok(tag, "AUTHENTICATE completed")

    # -----------------------------------------------------------------------
    # Re-login po wygaśnięciu sesji
    # -----------------------------------------------------------------------

    async def _try_relogin(self) -> bool:
        """
        Próbuje odświeżyć sesję Tuta bez zrywania połączenia IMAP.
        Używane gdy API zwróci 401 w trakcie aktywnej sesji.
        Czyści _folders i _mail_group_key — będą pobrane ponownie przy następnym użyciu.
        """
        if not self._credentials:
            return False
        username, password = self._credentials
        try:
            logger.info(f"[{self.peer}] Session expired — re-login: {username}")
            self.session = await self.client.login(username, password)
            self._folders = None
            self._mail_group_key = None
            logger.info(f"[{self.peer}] Re-login OK")
            return True
        except Exception as e:
            logger.warning(f"[{self.peer}] Re-login failed: {e}")
            return False

    # -----------------------------------------------------------------------
    # Komendy — AUTH
    # -----------------------------------------------------------------------

    async def _require_auth(self, tag: str) -> bool:
        if self.state not in ("AUTH", "SELECTED"):
            self._no(tag, "Not authenticated")
            return False
        return True

    async def _get_folders(self) -> list[MailFolder]:
        if self._folders is None:
            self._folders = await self.client.get_folders(self.session)
        return self._folders

    def _decrypt_folder_own_name(self, folder: MailFolder, mail_group_key: Optional[bytes]) -> str:
        """Zwraca tylko własną nazwę folderu (bez ścieżki rodzica)."""
        system_name = FOLDER_TYPE_NAMES.get(folder.folder_type)
        if system_name:
            return system_name
        if mail_group_key and folder.owner_enc_session_key and folder.name_encrypted:
            try:
                import base64 as _b64
                from .crypto import decrypt_mail_session_key
                from .message_builder import _decrypt_str
                enc_sk = _b64.b64decode(folder.owner_enc_session_key)
                folder_key = decrypt_mail_session_key(mail_group_key, enc_sk)
                decrypted = _decrypt_str(folder_key, folder.name_encrypted)
                if decrypted:
                    return decrypted
            except Exception as e:
                logger.debug(f"Błąd deszyfrowania nazwy folderu {folder.id}: {e}")
        return f"Folder-{folder.id}"

    def _folder_imap_name(
        self,
        folder: MailFolder,
        mail_group_key: Optional[bytes] = None,
        folder_map: Optional[dict] = None,
        _depth: int = 0,
    ) -> str:
        """Zwraca pełną ścieżkę IMAP folderu (np. 'INBOX/podfolder/sub').
        folder_map: {folder_id: MailFolder} — potrzebny do rozwijania hierarchii."""
        own = self._decrypt_folder_own_name(folder, mail_group_key)
        if _depth > 10:
            return own
        if folder_map and folder.parent_folder_raw:
            parent_id = folder.parent_folder_raw[0][1] if folder.parent_folder_raw else None
            if parent_id and parent_id in folder_map:
                parent = folder_map[parent_id]
                parent_path = self._folder_imap_name(parent, mail_group_key, folder_map, _depth + 1)
                return f"{parent_path}/{own}"
        return own

    async def _cmd_list(self, tag: str, args: str) -> None:
        if not await self._require_auth(tag):
            return

        # LIST "" "*"  lub  LIST "" "INBOX"
        parts = _parse_args(args)
        ref = parts[0] if parts else ""
        pattern = parts[1] if len(parts) > 1 else "*"

        folders = await self._get_folders()
        mail_group_key = await self._get_mail_group_key()
        folder_map = {f.id: f for f in folders}
        # Zbuduj zbiór ID folderów mających dzieci
        parent_ids = set()
        for f in folders:
            if f.parent_folder_raw:
                pid = f.parent_folder_raw[0][1]
                parent_ids.add(pid)

        for folder in folders:
            name = self._folder_imap_name(folder, mail_group_key, folder_map)
            encoded = encode_mutf7(name)
            has_children = r"\HasChildren" if folder.id in parent_ids else r"\HasNoChildren"
            attrs = has_children
            special = FOLDER_TYPE_SPECIAL.get(folder.folder_type, "")
            if special:
                attrs += f" {special}"
            self._untagged(f'LIST ({attrs}) "/" {_quote(encoded)}')

        self._ok(tag, "LIST completed")

    async def _cmd_lsub(self, tag: str, args: str) -> None:
        # Zwracamy te same foldery co LIST (subskrypcja jest automatyczna)
        await self._cmd_list(tag, args)

    async def _cmd_select(self, tag: str, args: str, readonly: bool = False) -> None:
        if not await self._require_auth(tag):
            return

        mailbox_name = decode_mutf7(_unquote(args.strip()))
        folders = await self._get_folders()

        # Znajdź folder po nazwie IMAP
        mail_group_key = await self._get_mail_group_key()
        folder_map = {f.id: f for f in folders}
        target = None
        for f in folders:
            imap_name = self._folder_imap_name(f, mail_group_key, folder_map)
            logger.debug(f"[{self.peer}] SELECT try: '{mailbox_name}' vs '{imap_name}' (id={f.id}, type={f.folder_type})")
            if imap_name.upper() == mailbox_name.upper():
                target = f
                break

        if target is None:
            logger.warning(f"[{self.peer}] SELECT '{mailbox_name}' — folder not found in {len(folders)} folders")
            self._no(tag, f"[NONEXISTENT] Mailbox not found: {mailbox_name}")
            return

        # Pobierz maile z tego folderu przez MailSetEntry (pole 1459 = entries)
        logger.info(f"[{self.peer}] SELECT {mailbox_name} (id={target.id})")
        mails = await self.client.get_mails_in_folder(
            self.session, target.mail_list_id
        )
        # RFC 3501 §2.3.1.1: UIDs muszą być ściśle rosnące wraz z numerem seq.
        # CRC32 nie gwarantuje tego porządku — sortujemy explicite.
        mails.sort(key=lambda m: tuta_id_to_uid(m.get("99", "")))

        # Inject lokalnych flag z SQLite (persystencja \Flagged, \Answered między restartami)
        for _m in mails:
            _mid = _m.get("99", ["", ""])
            _eid = _mid[-1] if isinstance(_mid, list) else str(_mid)
            _flagged, _answered = self.cache.get_local_flags(_eid)
            if _flagged:
                _m["_flagged"] = True
            if _answered:
                _m["_answered"] = True

        # Klucz grupy mail — pobierz (lub użyj cache)
        mail_group_key = await self._get_mail_group_key()

        self.mailbox = MailboxState(
            folder=target,
            messages=mails,
            mail_group_key=mail_group_key,
        )
        self._msg_cache.clear()
        self.state = "SELECTED"

        # UIDNEXT musi być > wszystkich istniejących UID (RFC 3501 §2.3.1.1)
        if self.mailbox.messages:
            max_uid = max(tuta_id_to_uid(m.get("99", "")) for m in self.mailbox.messages)
            uid_next = (max_uid + 1) & 0xFFFFFFFF
        else:
            uid_next = 1

        # Odpowiedź SELECT (RFC 3501 §6.3.1)
        self._untagged(f"{self.mailbox.exists} EXISTS")
        self._untagged("0 RECENT")
        self._untagged(r"OK [UNSEEN 0] No unseen messages")
        self._untagged(f"OK [UIDVALIDITY {_uidvalidity(target.id)}] UIDs valid")
        self._untagged(f"OK [UIDNEXT {uid_next}] Predicted next UID")
        self._untagged(r"FLAGS (\Answered \Flagged \Deleted \Seen \Draft)")
        self._untagged(r"OK [PERMANENTFLAGS (\Answered \Flagged \Seen \Deleted \*)] Permanent flags")

        mode = "READ-ONLY" if readonly else "READ-WRITE"
        self._ok(tag, f"[{mode}] SELECT completed")

    async def _cmd_examine(self, tag: str, args: str) -> None:
        await self._cmd_select(tag, args, readonly=True)

    async def _cmd_status(self, tag: str, args: str) -> None:
        if not await self._require_auth(tag):
            return

        m = re.match(r'^(\S+|"[^"]*")\s+\(([^)]*)\)', args.strip())
        if not m:
            self._bad(tag, "STATUS: invalid syntax")
            return

        mailbox_name = decode_mutf7(_unquote(m.group(1)))
        requested = m.group(2).upper().split()

        folders = await self._get_folders()
        mail_group_key = await self._get_mail_group_key()
        folder_map = {f.id: f for f in folders}
        target = None
        for f in folders:
            if self._folder_imap_name(f, mail_group_key, folder_map).upper() == mailbox_name.upper():
                target = f
                break

        if target is None:
            self._no(tag, f"[NONEXISTENT] Mailbox not found: {mailbox_name}")
            return

        # Reuse cached messages if this is the currently selected mailbox
        if self.mailbox and self.mailbox.folder.id == target.id:
            mails = self.mailbox.messages
        else:
            mails = await self.client.get_mails_in_folder(
                self.session, target.mail_list_id
            )

        msg_count = len(mails)
        unseen = sum(1 for mail in mails if mail.get("109", "1") == "1")
        uid_validity = _uidvalidity(target.id)
        if mails:
            max_uid = max(tuta_id_to_uid(mail.get("99", "")) for mail in mails)
            uid_next = (max_uid + 1) & 0xFFFFFFFF
        else:
            uid_next = 1

        parts = []
        for item in requested:
            if item == "MESSAGES":
                parts.append(f"MESSAGES {msg_count}")
            elif item == "UNSEEN":
                parts.append(f"UNSEEN {unseen}")
            elif item == "RECENT":
                parts.append("RECENT 0")
            elif item == "UIDNEXT":
                parts.append(f"UIDNEXT {uid_next}")
            elif item == "UIDVALIDITY":
                parts.append(f"UIDVALIDITY {uid_validity}")

        imap_name = encode_mutf7(self._folder_imap_name(target, mail_group_key, folder_map))
        self._untagged(f"STATUS {_quote(imap_name)} ({' '.join(parts)})")
        self._ok(tag, "STATUS completed")

    # -----------------------------------------------------------------------
    # FETCH — pobieranie wiadomości
    # -----------------------------------------------------------------------

    def _require_selected(self, tag: str) -> bool:
        if self.state != "SELECTED":
            self._no(tag, "No mailbox selected")
            return False
        return True

    async def _cmd_fetch(self, tag: str, args: str, uid_mode: bool = False) -> None:
        if not self._require_selected(tag):
            return

        # Parsuj: "1:*" "(FLAGS UID ...)"  lub  "1" "FLAGS"
        m = re.match(r"^(\S+)\s+(.+)$", args.strip(), re.DOTALL)
        if not m:
            self._bad(tag, "FETCH: invalid syntax")
            return

        seq_set_str, items_str = m.group(1), m.group(2).strip()
        items_str = items_str.strip("()")
        items = _parse_fetch_items(items_str)

        # Dla UID FETCH: * = największy UID w skrzynce (nie liczba wiadomości!)
        if uid_mode:
            max_val = max(
                (tuta_id_to_uid(m.get("99", "")) for m in self.mailbox.messages),
                default=1,
            )
        else:
            max_val = self.mailbox.exists

        for seq in range(1, self.mailbox.exists + 1):
            mail_raw = self.mailbox.seq_to_mail(seq)
            if mail_raw is None:
                continue

            if uid_mode:
                uid = tuta_id_to_uid(mail_raw.get("99", ""))
                if not _in_seq_set(uid, seq_set_str, max_val):
                    continue
            else:
                if not _in_seq_set(seq, seq_set_str, max_val):
                    continue

            try:
                await self._fetch_one(tag, seq, mail_raw, items, uid_mode)
            except Exception as e:
                logger.warning(f"[{self.peer}] FETCH seq={seq} error: {e}")
                # Wyślij minimalną odpowiedź — Thunderbird musi znać każdy seq numer
                uid = tuta_id_to_uid(mail_raw.get("99", ""))
                flags = get_mail_flags(mail_raw)
                flags_str = " ".join(flags) if flags else ""
                self._send(f"* {seq} FETCH (UID {uid} FLAGS ({flags_str}))")

        self._ok(tag, "FETCH completed")

    async def _fetch_one(
        self,
        tag: str,
        seq: int,
        mail_raw: dict,
        items: list[str],
        uid_mode: bool,
    ) -> None:
        mail_id = mail_raw.get("99", ["", ""])
        element_id = mail_id[-1] if isinstance(mail_id, list) else str(mail_id)
        uid = tuta_id_to_uid(mail_raw.get("99", ""))
        logger.debug(f"[{self.peer}] FETCH seq={seq} uid={uid} element_id={element_id} items={items}")
        flags = get_mail_flags(mail_raw)
        flags_str = " ".join(flags) if flags else ""

        response_parts = []

        # Zawsze dołącz UID jeśli UID FETCH
        needs_uid = uid_mode or any(i.upper() == "UID" for i in items)

        for item in items:
            item_upper = item.upper()

            if item_upper == "UID":
                response_parts.append(f"UID {uid}")

            elif item_upper == "FLAGS":
                response_parts.append(f"FLAGS ({flags_str})")

            elif item_upper in ("RFC822.SIZE", "BODY.SIZE"):
                # Jeśli wiadomość jest w cache — prawdziwy rozmiar.
                # Jeśli nie — szacowanie na podstawie nagłówków (Thunderbird zaktualizuje
                # wartość po otrzymaniu literału {N} przy BODY[]).
                mail_id_raw = mail_raw.get("99", ["", ""])
                eid = mail_id_raw[-1] if isinstance(mail_id_raw, list) else str(mail_id_raw)
                if eid in self._msg_cache:
                    size = len(self._msg_cache[eid])
                else:
                    headers = self._get_quick_headers(mail_raw)
                    size = len(headers) + 8192
                response_parts.append(f"RFC822.SIZE {size}")

            elif item_upper in ("RFC822", "BODY[]", "BODY.PEEK[]") or re.match(
                r'^(?:RFC822|BODY(?:\.PEEK)?\[\])(<\d+\.\d+>)?$', item_upper
            ):
                rfc = await self._get_rfc822(mail_raw)
                # Obsługa partial fetch: BODY[]<offset.count>
                partial = re.search(r'<(\d+)\.(\d+)>', item_upper)
                if partial:
                    offset = int(partial.group(1))
                    count = int(partial.group(2))
                    body_data = rfc[offset:offset + count]
                    item_tag = f"BODY[]<{offset}>"
                else:
                    body_data = rfc
                    item_tag = "BODY[]"
                if needs_uid and not any("UID" in p for p in response_parts):
                    response_parts.insert(0, f"UID {uid}")
                response_parts.append(f"{item_tag} {{{len(body_data)}}}")
                self._send(f"* {seq} FETCH ({' '.join(response_parts)}")
                self.writer.write(body_data + b")\r\n")
                return

            elif item_upper.startswith("BODY[HEADER") or item_upper.startswith("BODY.PEEK[HEADER"):
                # Szybka ścieżka: nagłówki z mail_raw bez API call
                # Echo exact item name (np. BODY[HEADER.FIELDS (From To Subject)]) — wymagane przez RFC 3501
                item_name = item.upper().replace("BODY.PEEK[", "BODY[")
                headers = self._get_quick_headers(mail_raw)
                if needs_uid and not any("UID" in p for p in response_parts):
                    response_parts.insert(0, f"UID {uid}")
                response_parts.append(f"{item_name} {{{len(headers)}}}")
                self._send(f"* {seq} FETCH ({' '.join(response_parts)}")
                self.writer.write(headers + b")\r\n")
                return

            elif item_upper.startswith("BODY[TEXT") or item_upper.startswith("BODY.PEEK[TEXT"):
                text_part = await self._get_text_part(mail_raw)
                item_name = item.upper().replace("BODY.PEEK[", "BODY[")
                if needs_uid and not any("UID" in p for p in response_parts):
                    response_parts.insert(0, f"UID {uid}")
                response_parts.append(f"{item_name} {{{len(text_part)}}}")
                self._send(f"* {seq} FETCH ({' '.join(response_parts)}")
                self.writer.write(text_part + b")\r\n")
                return

            elif item_upper in ("ENVELOPE",):
                env = await self._get_envelope(mail_raw)
                response_parts.append(f"ENVELOPE {env}")

            elif item_upper in ("INTERNALDATE",):
                ts = int(mail_raw.get("107", 0) or 0)
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) if ts else datetime.now(tz=timezone.utc)
                response_parts.append(f'INTERNALDATE "{_imap_date(dt)}"')

        if needs_uid and not any("UID" in p for p in response_parts):
            response_parts.insert(0, f"UID {uid}")

        self._send(f"* {seq} FETCH ({' '.join(response_parts)})")

    def _decrypt_mail_key(self, mail_raw: dict) -> bytes:
        """Odszyfrowuje klucz sesji maila lokalnie (bez API call)."""
        import base64 as _b64
        from .crypto import decrypt_mail_session_key
        # "or" zamiast get default — pole może być w dict z wartością None (JSON null)
        enc_sk_b64 = mail_raw.get("102") or ""
        if not enc_sk_b64:
            mid = mail_raw.get("99", "?")
            raise ValueError(f"Brak _ownerEncSessionKey (pole 102) w mailu {mid}")
        enc_sk = _b64.b64decode(enc_sk_b64)
        return decrypt_mail_session_key(self.mailbox.mail_group_key, enc_sk)

    def _get_quick_headers(self, mail_raw: dict) -> bytes:
        """
        Buduje sekcję nagłówkową z danych w obiekcie mail — bez API call.
        Subject, sender, date są w mail_raw i wymagają tylko lokalnej kryptografii.
        Używane do szybkiego listowania wiadomości przez Thunderbirda.
        """
        import email.utils
        from .message_builder import _decrypt_str, _decode_address, _format_address

        mail_key = self._decrypt_mail_key(mail_raw)

        subject = _decrypt_str(mail_key, mail_raw.get("105", "")) or "(brak tematu)"

        ts = int(mail_raw.get("107", 0) or 0)
        dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) if ts else datetime.now(tz=timezone.utc)

        sender_name, sender_address = _decode_address(mail_raw.get("111", {}), mail_key)
        from_str = _format_address(sender_name, sender_address)

        # firstRecipient (pole 1306) — dostępne w mail_raw bez dodatkowego API call
        first_rec = mail_raw.get("1306", {})
        rec_name, rec_addr = _decode_address(first_rec, mail_key)
        to_str = _format_address(rec_name, rec_addr) if rec_addr else ""

        mail_id = mail_raw.get("99", ["", ""])
        element_id = mail_id[-1] if isinstance(mail_id, list) else str(mail_id)

        lines = [
            f"Date: {email.utils.format_datetime(dt)}",
            f"From: {from_str}",
            f"Subject: {subject}",
            f"Message-ID: <tuta-{element_id}@tuta.local>",
        ]
        if to_str:
            lines.append(f"To: {to_str}")
        lines.append("")  # pusta linia kończy nagłówki

        return "\r\n".join(lines).encode("utf-8")

    async def _get_rfc822(self, mail_raw: dict) -> bytes:
        """Pobiera i buduje pełną wiadomość RFC 2822 (wymaga API call).
        Wynik jest cache'owany per element_id — partial fetche muszą dostawać
        identyczne bajty żeby granice MIME były spójne między żądaniami."""
        mail_id = mail_raw.get("99", ["", ""])
        element_id = mail_id[-1] if isinstance(mail_id, list) else str(mail_id)
        if element_id in self._msg_cache:
            return self._msg_cache[element_id]
        mail_key = self._decrypt_mail_key(mail_raw)

        draft_ref = mail_raw.get("1309")
        logger.debug(f"_get_rfc822: element_id={element_id!r} 1308={mail_raw.get('1308')!r} 1309={draft_ref!r}")

        # Jeśli field 1309 jest nieobecne a jesteśmy w Drafts, ponów GET pojedynczego maila —
        # list endpoint czasem nie zwraca wszystkich pól (null vs missing).
        if not draft_ref and self.mailbox and self.mailbox.folder.folder_type == "6":
            mid = mail_raw.get("99", ["", ""])
            list_id_m = mid[0] if isinstance(mid, list) and len(mid) >= 2 else ""
            elem_id_m = mid[-1] if isinstance(mid, list) else str(mid)
            if list_id_m and elem_id_m:
                try:
                    fresh = await self.client.get_single_mail(self.session, list_id_m, elem_id_m)
                    draft_ref = fresh.get("1309")
                    if draft_ref:
                        mail_raw = fresh  # użyj pełnego obiektu
                        logger.debug(f"_get_rfc822: re-fetched draft, 1309={draft_ref!r}")
                except Exception as e:
                    logger.warning(f"_get_rfc822: re-fetch draft failed: {e}")

        # Tuta zwraca LIST_ELEMENT_ASSOCIATION jako [[listId, elemId]] (nie [listId, elemId])
        draft_list_id = draft_elem_id = None
        if draft_ref and isinstance(draft_ref, list) and draft_ref:
            inner = draft_ref[0]
            if isinstance(inner, list) and len(inner) >= 2:
                draft_list_id, draft_elem_id = inner[0], inner[1]
            elif isinstance(inner, str) and len(draft_ref) >= 2:
                draft_list_id, draft_elem_id = draft_ref[0], draft_ref[1]

        if draft_list_id and draft_elem_id:
            # Draft — MailDetailsDraft; normalizuj do formatu MailDetailsBlob dla build_rfc2822
            logger.debug(f"_get_rfc822: draft path list_id={draft_list_id!r} elem_id={draft_elem_id!r}")
            raw_draft = await self.client.get_mail_details_draft(self.session, draft_list_id, draft_elem_id)
            # build_rfc2822 oczekuje klucza "1305" (MailDetailsBlob); mapujemy 1297→1305
            details = {"1305": raw_draft.get("1297", [])}
        else:
            details = await self.client.get_mail_details(self.session, mail_raw)

        attachments = await self.client.load_attachments(
            self.session, mail_raw, self.mailbox.mail_group_key
        )
        result = build_rfc2822(mail_raw, details, mail_key, attachments)
        self._msg_cache[element_id] = result
        return result

    async def _get_rfc822_size(self, mail_raw: dict) -> int:
        rfc = await self._get_rfc822(mail_raw)
        return len(rfc)

    async def _get_headers(self, mail_raw: dict, item: str) -> bytes:
        """Zwraca sekcję nagłówkową wiadomości (do BODY[HEADER*])."""
        rfc = await self._get_rfc822(mail_raw)
        # Znajdź granicę nagłówek/ciało (pusta linia)
        sep = rfc.find(b"\r\n\r\n")
        if sep == -1:
            sep = rfc.find(b"\n\n")
            if sep == -1:
                return rfc
            return rfc[:sep + 2]
        return rfc[:sep + 4]

    async def _get_text_part(self, mail_raw: dict) -> bytes:
        """Zwraca samo ciało wiadomości (bez nagłówków)."""
        rfc = await self._get_rfc822(mail_raw)
        sep = rfc.find(b"\r\n\r\n")
        if sep == -1:
            return rfc
        return rfc[sep + 4:]

    async def _get_envelope(self, mail_raw: dict) -> str:
        """Buduje ENVELOPE string (RFC 3501 §7.4.2)."""
        import base64 as _b64
        from .crypto import decrypt_mail_session_key

        enc_sk = _b64.b64decode(mail_raw.get("102", ""))
        mail_key = decrypt_mail_session_key(self.mailbox.mail_group_key, enc_sk)

        from .message_builder import _decrypt_str, _decode_address, _format_address
        subject = _decrypt_str(mail_key, mail_raw.get("105", "")) or "NIL"
        ts = int(mail_raw.get("107", 0) or 0)
        dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc) if ts else datetime.now(tz=timezone.utc)
        date_str = _imap_date(dt)

        sender_agg = mail_raw.get("111", {})
        sname, saddr = _decode_address(sender_agg, mail_key)

        from_env = _imap_address(sname, saddr)
        return f'("{date_str}" "{subject}" ({from_env}) ({from_env}) ({from_env}) NIL NIL NIL NIL NIL)'

    # -----------------------------------------------------------------------
    # Trywialne komendy
    # -----------------------------------------------------------------------

    async def _cmd_check(self, tag: str, args: str) -> None:
        self._ok(tag, "CHECK completed")

    async def _cmd_subscribe(self, tag: str, args: str) -> None:
        # Tuta pokazuje wszystkie foldery — subskrypcje są bez znaczenia
        self._ok(tag, "completed")

    async def _cmd_search(self, tag: str, args: str, uid_mode: bool = False) -> None:
        """
        Minimalna implementacja SEARCH/UID SEARCH.

        Obsługuje najczęstszy wzorzec Thunderbirda po APPEND:
          UID SEARCH UNDELETED HEADER Message-ID <id>
        oraz prosty ALL/UNDELETED.

        Dla kryteriów których nie umiemy przetworzyć zwracamy pusty wynik —
        klient i tak ma APPENDUID i nie musi korzystać z SEARCH.
        """
        if not self._require_selected(tag):
            return

        criteria = args.strip().upper()
        result_uids: list[int] = []

        if criteria in ("ALL", "UNDELETED", "NOT DELETED"):
            # Zwróć wszystkie wiadomości które nie są \Deleted
            for mail_raw in (self.mailbox.messages if self.mailbox else []):
                uid = tuta_id_to_uid(mail_raw.get("99", ""))
                if uid not in self.mailbox.deleted_uids:
                    result_uids.append(uid)
        # Dla innych kryteriów (np. HEADER Message-ID) zwracamy pusty wynik —
        # klient ma już UID z APPENDUID.

        if uid_mode:
            self._untagged(f"SEARCH {' '.join(str(u) for u in result_uids)}")
        else:
            # Tryb seq: przelicz UID→seq
            seqs = []
            for uid in result_uids:
                seq = self.mailbox.uid_to_seq(uid) if self.mailbox else None
                if seq:
                    seqs.append(str(seq))
            self._untagged(f"SEARCH {' '.join(seqs)}")

        self._ok(tag, "SEARCH completed")

    async def _cmd_append(self, tag: str, args: str) -> None:
        """
        APPEND mailbox [(\flags)] ["datetime"] {N}

        Drafts: tworzy draft przez Tuta API (create_draft bez send).
        Pozostałe foldery (Sent itp.): odczytuje i odrzuca —
        Tuta zapisuje kopię wysłanej wiadomości automatycznie po senddraftservice.
        """
        m = re.search(r'\{(\d+)(\+?)\}\s*$', args)
        if not m:
            self._bad(tag, "APPEND: oczekiwano literału {N}")
            return

        literal_size = int(m.group(1))
        non_sync = bool(m.group(2))

        if not non_sync:
            self._send("+ Ready for literal data")
            await self.writer.drain()

        try:
            raw = await asyncio.wait_for(self.reader.readexactly(literal_size), timeout=60)
        except asyncio.TimeoutError:
            self._no(tag, "APPEND timeout")
            return
        except asyncio.IncompleteReadError:
            self._no(tag, "APPEND: połączenie zamknięte podczas czytania literału")
            return

        if not self.session:
            self._no(tag, "APPEND: nie zalogowany")
            return

        # Wyciągnij nazwę skrzynki (pierwszy token, bez cudzysłowów i MUTF-7)
        mailbox_raw = args[:m.start()].strip().split()[0].strip('"')
        mailbox_name = decode_mutf7(mailbox_raw)

        # Znajdź folder docelowy po nazwie IMAP
        folders = await self._get_folders()
        mail_group_key = await self._get_mail_group_key()
        folder_map = {f.id: f for f in folders}

        target_folder: Optional[MailFolder] = None
        for f in folders:
            imap_name = self._folder_imap_name(f, mail_group_key, folder_map)
            if imap_name.lower() == mailbox_name.lower():
                target_folder = f
                break

        if target_folder is None or target_folder.folder_type != "6":
            # Nie-Drafts lub nieznany folder — odrzuć dane (Sent zarządzany przez Tuta)
            logger.info(f"[{self.peer}] APPEND {mailbox_name!r} {literal_size}B — odrzucono")
            self._ok(tag, "APPEND completed")
            return

        # ── Drafts: utwórz draft przez Tuta API ──
        if mail_group_key is None:
            self._no(tag, "APPEND: brak klucza grupy mail")
            return

        msg = _email_from_bytes(raw)
        subject = _rfc2822_header(msg.get("Subject", ""))
        from_parsed = _rfc2822_addrs(_rfc2822_header(msg.get("From", "")))
        from_name, from_addr = from_parsed[0] if from_parsed else ("", self.session.user_email)
        if not from_addr:
            from_addr = self.session.user_email
        to_list  = _rfc2822_addrs(_rfc2822_header(msg.get("To", "")))
        cc_list  = _rfc2822_addrs(_rfc2822_header(msg.get("Cc", "")))
        bcc_list = _rfc2822_addrs(_rfc2822_header(msg.get("Bcc", "")))
        body_html = _rfc2822_body_html(msg)

        try:
            draft_list_id, draft_elem_id, _sk = await self.client.create_draft(
                session=self.session,
                subject=subject,
                body_html=body_html,
                from_addr=from_addr,
                from_name=from_name,
                to_recipients=to_list,
                cc_recipients=cc_list,
                bcc_recipients=bcc_list,
                mail_group_key=mail_group_key,
            )
        except Exception as e:
            logger.error(f"[{self.peer}] APPEND Drafts — create_draft failed: {e}")
            self._no(tag, f"APPEND failed: {e}")
            return

        uid = tuta_id_to_uid([draft_list_id, draft_elem_id])
        uv = _uidvalidity(target_folder.id)
        logger.info(f"[{self.peer}] APPEND Drafts → draft_elem={draft_elem_id} uid={uid}")

        # Pobierz świeżo utworzony draft i dodaj do mailbox jeśli Drafts jest aktualnie wybrane
        if self.mailbox and self.mailbox.folder.id == target_folder.id:
            try:
                new_mail = await self.client.get_single_mail(self.session, draft_list_id, draft_elem_id)
                self.mailbox.messages.append(new_mail)
                count = len(self.mailbox.messages)
                self._untagged(f"{count} EXISTS")
                logger.debug(f"[{self.peer}] APPEND: mailbox updated, EXISTS={count}")
            except Exception as e:
                logger.warning(f"[{self.peer}] APPEND: nie można pobrać nowego draftu: {e}")

        self._ok(tag, f"[APPENDUID {uv} {uid}] APPEND completed")

    # -----------------------------------------------------------------------
    # Zarządzanie folderami — CREATE / DELETE / RENAME
    # -----------------------------------------------------------------------

    async def _cmd_create(self, tag: str, args: str) -> None:
        full_name = decode_mutf7(_unquote(args.strip()))
        if not full_name:
            self._bad(tag, "CREATE: brak nazwy folderu")
            return

        mail_group_key = await self._get_mail_group_key()
        if mail_group_key is None:
            logger.warning(f"[{self.peer}] CREATE: nie można pobrać mail_group_key")
            self._no(tag, "CREATE: nie można pobrać klucza grupy mail")
            return

        # Upewnij się że mail_group_id jest uzupełnione (get_folders ustawia go w session).
        # Jeśli _folders jest w cache, mail_group_id może być jeszcze nieuzupełnione —
        # wyczyść cache aby wymusić ponowne pobranie.
        if not self.session.mail_group_id:
            self._folders = None
            await self._get_folders()

        if not self.session.mail_group_id:
            logger.error(f"[{self.peer}] CREATE: mail_group_id nadal None po get_folders")
            self._no(tag, "CREATE: brak mail_group_id")
            return

        # Parsuj "ParentFolder/NazwaFolderu" — hierarchia IMAP przez ukośnik
        folders = await self._get_folders()
        folder_map = {f.id: f for f in folders}
        parent_folder: Optional[MailFolder] = None
        folder_name = full_name
        if "/" in full_name:
            parent_imap_name, folder_name = full_name.rsplit("/", 1)
            parent_folder = next(
                (f for f in folders
                 if self._folder_imap_name(f, mail_group_key, folder_map).upper() == parent_imap_name.upper()),
                None,
            )
            if parent_folder is None:
                logger.warning(f"[{self.peer}] CREATE: folder nadrzędny '{parent_imap_name}' nie istnieje")
                self._no(tag, f"[TRYCREATE] CREATE: nie znaleziono folderu '{parent_imap_name}'")
                return

        logger.info(f"[{self.peer}] CREATE '{folder_name}' (parent={parent_folder.id if parent_folder else None})")
        try:
            await self.client.create_folder(self.session, folder_name, mail_group_key, parent_folder)
        except TutaAPIError as e:
            logger.warning(f"[{self.peer}] CREATE failed: {e}")
            self._no(tag, f"CREATE failed: {e}")
            return
        except Exception as e:
            logger.exception(f"[{self.peer}] CREATE unexpected error")
            self._no(tag, f"CREATE internal error: {e}")
            return

        self._folders = None  # unieważnij cache folderów
        self._ok(tag, "CREATE completed")

    async def _cmd_delete(self, tag: str, args: str) -> None:
        folder_name = decode_mutf7(_unquote(args.strip()))
        mail_group_key = await self._get_mail_group_key()
        if mail_group_key is None:
            logger.warning(f"[{self.peer}] DELETE: nie można pobrać mail_group_key")
            self._no(tag, "DELETE: nie można pobrać klucza grupy")
            return

        folders = await self._get_folders()
        folder_map = {f.id: f for f in folders}
        target = next(
            (f for f in folders
             if self._folder_imap_name(f, mail_group_key, folder_map).upper() == folder_name.upper()),
            None,
        )
        if target is None:
            self._no(tag, f"[NONEXISTENT] DELETE: folder '{folder_name}' nie istnieje")
            return
        if target.folder_type != "0":
            self._no(tag, "DELETE: nie można usunąć folderu systemowego")
            return

        logger.info(f"[{self.peer}] DELETE '{folder_name}' (id={target.id})")
        try:
            await self.client.delete_folder(self.session, target)
        except TutaAPIError as e:
            logger.warning(f"[{self.peer}] DELETE failed: {e}")
            self._no(tag, f"DELETE failed: {e}")
            return

        self._folders = None
        self._ok(tag, "DELETE completed")

    async def _cmd_rename(self, tag: str, args: str) -> None:
        # Format: RENAME "stara-nazwa" "nowa-nazwa"
        parts = _parse_args(args)
        if len(parts) < 2:
            self._bad(tag, "RENAME: nieprawidłowa składnia")
            return
        old_name = decode_mutf7(parts[0])
        new_name = decode_mutf7(parts[1])

        mail_group_key = await self._get_mail_group_key()
        if mail_group_key is None:
            logger.warning(f"[{self.peer}] RENAME: nie można pobrać mail_group_key")
            self._no(tag, "RENAME: nie można pobrać klucza grupy")
            return

        folders = await self._get_folders()
        folder_map = {f.id: f for f in folders}
        target = next(
            (f for f in folders
             if self._folder_imap_name(f, mail_group_key, folder_map).upper() == old_name.upper()),
            None,
        )
        if target is None:
            self._no(tag, f"[NONEXISTENT] RENAME: folder '{old_name}' nie istnieje")
            return
        if target.folder_type != "0":
            self._no(tag, "RENAME: nie można zmieniać nazwy folderów systemowych")
            return

        # Parsuj nową nazwę IMAP: "Parent/bare_name" lub "bare_name" (root)
        if "/" in new_name:
            new_parent_imap, new_bare_name = new_name.rsplit("/", 1)
            new_parent = next(
                (f for f in folders
                 if self._folder_imap_name(f, mail_group_key, folder_map).upper() == new_parent_imap.upper()),
                None,
            )
            if new_parent is None:
                logger.warning(f"[{self.peer}] RENAME: folder nadrzędny '{new_parent_imap}' nie istnieje")
                self._no(tag, f"[TRYCREATE] RENAME: parent '{new_parent_imap}' not found")
                return
            move_to_root = False
        else:
            new_parent = None
            new_bare_name = new_name
            move_to_root = True  # przenieś na root (usuń rodzica)

        logger.info(f"[{self.peer}] RENAME '{old_name}' → '{new_name}' (id={target.id}, new_parent={new_parent.id if new_parent else None})")
        try:
            await self.client.rename_folder(
                self.session, target, new_bare_name, mail_group_key,
                new_parent=new_parent, move_to_root=move_to_root,
            )
        except TutaAPIError as e:
            logger.warning(f"[{self.peer}] RENAME failed: {e}")
            self._no(tag, f"RENAME failed: {e}")
            return

        self._folders = None
        self._ok(tag, "RENAME completed")

    async def _get_mail_group_key(self) -> Optional[bytes]:
        """Zwraca klucz grupy mail — z mailbox, z cache albo pobiera przez API."""
        if self.mailbox and self.mailbox.mail_group_key:
            return self.mailbox.mail_group_key
        if self._mail_group_key:
            return self._mail_group_key
        try:
            self._mail_group_key = await self.client.get_mail_group_key(self.session)
            return self._mail_group_key
        except Exception as e:
            logger.warning(f"[{self.peer}] _get_mail_group_key: {e}")
            return None

    # -----------------------------------------------------------------------
    # STORE — zmiana flag
    # -----------------------------------------------------------------------

    async def _cmd_store(self, tag: str, args: str, uid_mode: bool = False) -> None:
        if not self._require_selected(tag):
            return

        # Parsuj: "1:* +FLAGS (\Seen)" / "1 -FLAGS.SILENT (\Deleted)"
        m = re.match(r'^(\S+)\s+([+-]?FLAGS(?:\.SILENT)?)\s+(.+)$', args.strip(), re.IGNORECASE)
        if not m:
            self._bad(tag, "STORE: invalid syntax")
            return

        seq_set_str = m.group(1)
        flag_op_raw = m.group(2).upper()
        flag_list_str = m.group(3).strip().strip("()")

        silent = ".SILENT" in flag_op_raw
        if flag_op_raw.startswith("+"):
            op = "add"
        elif flag_op_raw.startswith("-"):
            op = "remove"
        else:
            op = "set"

        # Normalizuj flagi do uppercase z backslashem
        flags_requested = {f.strip().upper() for f in flag_list_str.split()}

        if uid_mode:
            max_val = max(
                (tuta_id_to_uid(mr.get("99", "")) for mr in self.mailbox.messages),
                default=1,
            )
        else:
            max_val = self.mailbox.exists

        # Zbierz dopasowane maile i podziel według operacji
        mark_seen: list[tuple[str, str]] = []    # (listId, elemId) → oznacz przeczytanym
        mark_unseen: list[tuple[str, str]] = []  # (listId, elemId) → oznacz nieprzeczytanym
        delete_uids: list[int] = []
        undelete_uids: list[int] = []
        affected_seqs: list[int] = []
        affected_mails: list[dict] = []

        for seq in range(1, self.mailbox.exists + 1):
            mail_raw = self.mailbox.seq_to_mail(seq)
            if mail_raw is None:
                continue
            uid = tuta_id_to_uid(mail_raw.get("99", ""))
            check_val = uid if uid_mode else seq
            if not _in_seq_set(check_val, seq_set_str, max_val):
                continue

            affected_seqs.append(seq)
            affected_mails.append(mail_raw)
            mail_id = mail_raw.get("99", ["", ""])
            list_id = mail_id[0] if isinstance(mail_id, list) and len(mail_id) > 0 else ""
            elem_id = mail_id[1] if isinstance(mail_id, list) and len(mail_id) > 1 else str(mail_id)

            if r"\SEEN" in flags_requested:
                if op in ("add", "set"):
                    mark_seen.append((list_id, elem_id))
                elif op == "remove":
                    mark_unseen.append((list_id, elem_id))

            if r"\DELETED" in flags_requested:
                if op in ("add", "set"):
                    delete_uids.append(uid)
                elif op == "remove":
                    undelete_uids.append(uid)

            # \Flagged i \Answered — lokalne (Tuta API nie ma odpowiednika)
            if r"\FLAGGED" in flags_requested:
                mail_raw["_flagged"] = op in ("add", "set")
            elif op == "set":
                mail_raw["_flagged"] = False
            if r"\ANSWERED" in flags_requested:
                mail_raw["_answered"] = op in ("add", "set")
            elif op == "set":
                mail_raw["_answered"] = False
            if r"\FLAGGED" in flags_requested or r"\ANSWERED" in flags_requested or op == "set":
                self.cache.set_local_flags(
                    elem_id,
                    bool(mail_raw.get("_flagged")),
                    bool(mail_raw.get("_answered")),
                )

        # Wywołania API dla \Seen
        if mark_seen:
            try:
                await self.client.mark_mails_unread(self.session, mark_seen, unread=False)
                # Aktualizuj stan lokalny żeby FETCH FLAGS był spójny
                for lid, eid in mark_seen:
                    for mr in self.mailbox.messages:
                        mid = mr.get("99", ["", ""])
                        if (isinstance(mid, list) and len(mid) > 1 and mid[1] == eid):
                            mr["109"] = "0"  # unread=false
            except TutaAPIError as e:
                logger.warning(f"[{self.peer}] STORE mark_seen failed: {e}")

        if mark_unseen:
            try:
                await self.client.mark_mails_unread(self.session, mark_unseen, unread=True)
                for lid, eid in mark_unseen:
                    for mr in self.mailbox.messages:
                        mid = mr.get("99", ["", ""])
                        if (isinstance(mid, list) and len(mid) > 1 and mid[1] == eid):
                            mr["109"] = "1"  # unread=true
            except TutaAPIError as e:
                logger.warning(f"[{self.peer}] STORE mark_unseen failed: {e}")

        # \Deleted — lokalnie, fizyczne usunięcie przy EXPUNGE
        for uid in delete_uids:
            self.mailbox.deleted_uids.add(uid)
        for uid in undelete_uids:
            self.mailbox.deleted_uids.discard(uid)

        # Odpowiedzi FETCH z aktualnymi flagami (chyba że .SILENT)
        if not silent:
            for seq in affected_seqs:
                mail_raw = self.mailbox.seq_to_mail(seq)
                if mail_raw is None:
                    continue
                uid = tuta_id_to_uid(mail_raw.get("99", ""))
                flags = list(get_mail_flags(mail_raw))
                if uid in self.mailbox.deleted_uids and r"\Deleted" not in flags:
                    flags.append(r"\Deleted")
                self._send(f"* {seq} FETCH (FLAGS ({' '.join(flags)}))")

        self._ok(tag, "STORE completed")

    # -----------------------------------------------------------------------
    # COPY / UID COPY — przenoszenie maili do innego folderu
    # -----------------------------------------------------------------------

    async def _cmd_copy(self, tag: str, args: str, uid_mode: bool = False) -> None:
        """
        Implementuje IMAP COPY jako move (Tuta nie obsługuje kopiowania).
        Używane przez Thunderbird do przenoszenia maili do Trash.
        RFC 3501 §6.4.7: po pomyślnym COPY wysyłamy * N EXPUNGE.
        """
        if not self._require_selected(tag):
            return

        m = re.match(r'^(\S+)\s+"?([^"]*)"?\s*$', args.strip())
        if not m:
            self._bad(tag, "COPY: invalid syntax")
            return

        seq_set_str = m.group(1)
        folder_name = m.group(2).strip('"')

        mail_group_key = self.mailbox.mail_group_key if self.mailbox else None
        folders = await self._get_folders()
        folder_map = {f.id: f for f in folders}
        target = next(
            (f for f in folders
             if self._folder_imap_name(f, mail_group_key, folder_map).upper() == folder_name.upper()),
            None,
        )
        if target is None:
            self._no(tag, f"COPY: folder '{folder_name}' not found")
            return
        if not target.folder_list_id:
            self._no(tag, "COPY: target folder_list_id missing")
            return

        if uid_mode:
            max_val = max(
                (tuta_id_to_uid(mr.get("99", "")) for mr in self.mailbox.messages),
                default=1,
            )
        else:
            max_val = self.mailbox.exists

        to_copy: list[tuple[int, dict]] = []
        for seq in range(1, self.mailbox.exists + 1):
            mail_raw = self.mailbox.seq_to_mail(seq)
            if mail_raw is None:
                continue
            uid = tuta_id_to_uid(mail_raw.get("99", ""))
            check_val = uid if uid_mode else seq
            if _in_seq_set(check_val, seq_set_str, max_val):
                to_copy.append((seq, mail_raw))

        if not to_copy:
            self._ok(tag, "COPY completed")
            return

        mail_ids: list[tuple[str, str]] = []
        for _, mail_raw in to_copy:
            mid = mail_raw.get("99", ["", ""])
            lid = mid[0] if isinstance(mid, list) and len(mid) > 0 else ""
            eid = mid[1] if isinstance(mid, list) and len(mid) > 1 else str(mid)
            mail_ids.append((lid, eid))

        current_type = self.mailbox.folder.folder_type if self.mailbox else ""
        same_folder = (target.folder_type == current_type and target.id == self.mailbox.folder.id)

        try:
            if same_folder:
                # Kopia do siebie = trwałe usunięcie (mail już w Koszu → EXPUNGE)
                src_folder_id = (self.mailbox.folder.folder_list_id, self.mailbox.folder.id)
                await self.client.delete_mails(self.session, mail_ids, src_folder_id)
            elif target.folder_type != "0":
                # Folder systemowy (Trash=3, Archive=4, Spam=5) — SimpleMoveMailService
                await self.client.simple_move_mails(
                    self.session, mail_ids, target.folder_type
                )
            else:
                # Folder własny (CUSTOM) — MoveMailService z explicit ID
                await self.client.move_mails_to_folder(
                    self.session, mail_ids, target.folder_list_id, target.id
                )
        except TutaAPIError as e:
            logger.warning(f"[{self.peer}] COPY move failed: {e}")
            self._no(tag, f"COPY failed: {e}")
            return

        copy_obj_ids = {id(mr) for _, mr in to_copy}
        for seq, mail_raw in reversed(to_copy):
            mid = mail_raw.get("99", ["", ""])
            elem_id = mid[-1] if isinstance(mid, list) else str(mid)
            self._msg_cache.pop(elem_id, None)
            self._send(f"* {seq} EXPUNGE")

        self.mailbox.messages = [mr for mr in self.mailbox.messages if id(mr) not in copy_obj_ids]
        self.mailbox.deleted_uids -= {tuta_id_to_uid(mr.get("99", "")) for _, mr in to_copy}

        logger.info(f"[{self.peer}] COPY {len(to_copy)} mail(s) → '{folder_name}' (move)")
        self._ok(tag, "COPY completed")

    # -----------------------------------------------------------------------
    # IDLE — push nowych wiadomości przez WebSocket (RFC 2177)
    # -----------------------------------------------------------------------

    async def _cmd_idle(self, tag: str, args: str) -> None:
        if not self._require_selected(tag):
            return

        self._send("+ idling")
        await self.writer.drain()

        async def _wait_done():
            # Czekaj na "DONE" od klienta; ignoruj inne linie podczas IDLE
            while True:
                line = await self.reader.readline()
                if not line:
                    return
                if line.decode("utf-8", errors="replace").rstrip("\r\n").strip().upper() == "DONE":
                    return

        done_task = asyncio.create_task(_wait_done())
        watch_task = asyncio.create_task(self._idle_watch_events())

        try:
            await asyncio.wait([done_task, watch_task], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (done_task, watch_task):
                if not t.done():
                    t.cancel()
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

        self._ok(tag, "IDLE terminated")

    async def _idle_watch_events(self) -> None:
        """Obserwuje WebSocket Tuty podczas IDLE, wysyła IMAP notifications."""
        try:
            async for event in self.client.iter_event_stream(self.session):
                if event["application"] != "tutanota" or event["type_id"] != "97":
                    continue
                op = event["operation"]
                list_id = event["list_id"]
                element_id = event["element_id"]
                if op == "0":   # CREATE — nowa wiadomość
                    await self._idle_handle_new_mail(list_id, element_id)
                elif op == "1": # UPDATE — zmiana flag (np. przeczytana w innym kliencie)
                    await self._idle_handle_mail_update(list_id, element_id)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning(f"[{self.peer}] IDLE watcher: {e}")

    async def _idle_handle_new_mail(self, list_id: str, element_id: str) -> None:
        # Tuta może jeszcze przetwarzać mail w chwili wysłania WebSocket eventu
        # (pole 102 = _ownerEncSessionKey bywa tymczasowo null). Retry z wykładniczym backoff.
        mail_raw = None
        for attempt in range(4):
            if attempt > 0:
                await asyncio.sleep(2 ** (attempt - 1))  # 1, 2, 4 s
            try:
                mail_raw = await self.client.get_single_mail(self.session, list_id, element_id)
                if mail_raw.get("102") is not None:
                    break
                logger.debug(f"[{self.peer}] IDLE: pole 102 null dla {element_id}, attempt {attempt + 1}")
            except Exception as e:
                logger.warning(f"[{self.peer}] IDLE new mail fetch {element_id} attempt {attempt + 1}: {e}")
                mail_raw = None
        if not mail_raw or mail_raw.get("102") is None:
            logger.warning(f"[{self.peer}] IDLE: pominięto {element_id} — brak _ownerEncSessionKey po retries")
            return


        # mail["1465"] = [[mailset_list, mailset_id]] — sprawdź czy mail należy do zaznaczonego folderu
        folder_refs = mail_raw.get("1465", [])
        in_folder = any(
            isinstance(ref, list) and len(ref) >= 2 and ref[1] == self.mailbox.folder.id
            for ref in folder_refs
        )
        if not in_folder:
            return

        # Wstaw w kolejności UID
        uid = tuta_id_to_uid(mail_raw.get("99", ""))
        insert_pos = len(self.mailbox.messages)
        for i, m in enumerate(self.mailbox.messages):
            if tuta_id_to_uid(m.get("99", "")) > uid:
                insert_pos = i
                break
        self.mailbox.messages.insert(insert_pos, mail_raw)

        count = self.mailbox.exists
        self._send(f"* {count} EXISTS")
        self._send(f"* 0 RECENT")
        await self.writer.drain()
        logger.info(f"[{self.peer}] IDLE: new mail uid={uid}, folder={self.mailbox.folder.id}, EXISTS={count}")

    async def _idle_handle_mail_update(self, list_id: str, element_id: str) -> None:
        # Znajdź mail w bieżącej skrzynce (jeśli tam jest)
        local_idx = next(
            (i for i, m in enumerate(self.mailbox.messages)
             if (lambda mid: mid[1] if isinstance(mid, list) and len(mid) > 1 else str(mid))(m.get("99", "")) == element_id),
            None,
        )

        try:
            updated = await self.client.get_single_mail(self.session, list_id, element_id)
        except Exception as e:
            logger.warning(f"[{self.peer}] IDLE mail update fetch {element_id}: {e}")
            return

        # Sprawdź czy mail należy do bieżącego folderu (pole 1465)
        folder_refs = updated.get("1465", [])
        in_current = any(
            isinstance(ref, list) and len(ref) >= 2 and ref[1] == self.mailbox.folder.id
            for ref in folder_refs
        )

        if in_current and local_idx is None:
            # Mail pojawił się w tym folderze (przeniesiony z innego) → dodaj jak nowy
            uid = tuta_id_to_uid(updated.get("99", ""))
            insert_pos = len(self.mailbox.messages)
            for i, m in enumerate(self.mailbox.messages):
                if tuta_id_to_uid(m.get("99", "")) > uid:
                    insert_pos = i
                    break
            self.mailbox.messages.insert(insert_pos, updated)
            count = self.mailbox.exists
            self._send(f"* {count} EXISTS")
            self._send(f"* 0 RECENT")
            logger.info(f"[{self.peer}] IDLE: mail moved INTO folder uid={uid}, EXISTS={count}")
        elif not in_current and local_idx is not None:
            # Mail opuścił ten folder (przeniesiony gdzie indziej) → EXPUNGE
            seq = local_idx + 1
            uid = tuta_id_to_uid(self.mailbox.messages[local_idx].get("99", ""))
            mid = self.mailbox.messages[local_idx].get("99", ["", ""])
            elem_id = mid[-1] if isinstance(mid, list) else str(mid)
            self._msg_cache.pop(elem_id, None)
            self.mailbox.messages.pop(local_idx)
            self.mailbox.deleted_uids.discard(uid)
            self._send(f"* {seq} EXPUNGE")
            logger.info(f"[{self.peer}] IDLE: mail moved OUT of folder seq={seq} uid={uid}")
        elif in_current and local_idx is not None:
            # Mail nadal w tym folderze — aktualizuj flagi
            self.mailbox.messages[local_idx] = updated
            seq = local_idx + 1
            flags = list(get_mail_flags(updated))
            uid = tuta_id_to_uid(updated.get("99", ""))
            if uid in self.mailbox.deleted_uids:
                flags.append(r"\Deleted")
            self._send(f"* {seq} FETCH (FLAGS ({' '.join(flags)}))")
            logger.debug(f"[{self.peer}] IDLE: flag update seq={seq} flags={flags}")

        await self.writer.drain()

    # -----------------------------------------------------------------------
    # EXPUNGE — fizyczne usunięcie wiadomości z \Deleted
    # -----------------------------------------------------------------------

    async def _cmd_expunge(self, tag: str, args: str, silent: bool = False) -> None:
        """
        Przenosi wszystkie wiadomości z \Deleted do Trash (MoveMailService),
        wysyła * N EXPUNGE (chyba że silent=True) i usuwa je z mailbox.messages.
        RFC 3501 §6.4.3: numery seq w EXPUNGE idą malejąco.
        """
        if not self._require_selected(tag):
            return

        if not self.mailbox.deleted_uids:
            self._ok(tag, "EXPUNGE completed")
            return

        # Znajdź folder Trash (type=3)
        folders = await self._get_folders()
        trash = next((f for f in folders if f.folder_type == "3"), None)
        if trash is None:
            self._no(tag, "No Trash folder found")
            return
        if not trash.folder_list_id:
            self._no(tag, "Trash folder_list_id missing — cannot move")
            return

        # Zbierz maile do usunięcia (w kolejności rosnącej seq)
        to_expunge: list[tuple[int, dict]] = []
        for seq in range(1, self.mailbox.exists + 1):
            mail_raw = self.mailbox.seq_to_mail(seq)
            if mail_raw is None:
                continue
            uid = tuta_id_to_uid(mail_raw.get("99", ""))
            if uid in self.mailbox.deleted_uids:
                to_expunge.append((seq, mail_raw))

        if not to_expunge:
            self.mailbox.deleted_uids.clear()
            self._ok(tag, "EXPUNGE completed")
            return

        # Buduj listę (listId, elemId) dla API
        mail_ids: list[tuple[str, str]] = []
        for _, mail_raw in to_expunge:
            mid = mail_raw.get("99", ["", ""])
            lid = mid[0] if isinstance(mid, list) and len(mid) > 0 else ""
            eid = mid[1] if isinstance(mid, list) and len(mid) > 1 else str(mid)
            mail_ids.append((lid, eid))

        try:
            await self.client.move_mails_to_folder(
                self.session, mail_ids, trash.folder_list_id, trash.id
            )
        except TutaAPIError as e:
            logger.warning(f"[{self.peer}] EXPUNGE move to trash failed: {e}")
            self._no(tag, f"EXPUNGE failed: move to Trash error")
            return

        # RFC 3501 §7.4.1: EXPUNGE numery wysyłamy w odwrotnej kolejności
        expunge_obj_ids = {id(mr) for _, mr in to_expunge}
        for seq, mail_raw in reversed(to_expunge):
            if not silent:
                self._send(f"* {seq} EXPUNGE")
            mid = mail_raw.get("99", ["", ""])
            elem_id = mid[-1] if isinstance(mid, list) else str(mid)
            self._msg_cache.pop(elem_id, None)

        self.mailbox.messages = [mr for mr in self.mailbox.messages if id(mr) not in expunge_obj_ids]
        self.mailbox.deleted_uids.clear()

        self._ok(tag, "EXPUNGE completed")

    # -----------------------------------------------------------------------
    # CLOSE / UNSELECT
    # -----------------------------------------------------------------------

    async def _cmd_close(self, tag: str, args: str) -> None:
        if not self._require_selected(tag):
            return
        # RFC 3501 §6.4.2: CLOSE musi cicho wyczyścić \Deleted (bez EXPUNGE responses)
        if self.mailbox.deleted_uids:
            await self._cmd_expunge(tag, args, silent=True)
            if self.state != "SELECTED":
                # _cmd_expunge zwróciło NO — zostajemy w SELECTED
                return
        self.mailbox = None
        self.state = "AUTH"
        self._ok(tag, "CLOSE completed")

    # -----------------------------------------------------------------------
    # UID prefix
    # -----------------------------------------------------------------------

    async def _cmd_uid(self, tag: str, args: str) -> None:
        parts = args.split(None, 1)
        if not parts:
            self._bad(tag, "UID requires a command")
            return
        sub_cmd = parts[0].upper()
        sub_args = parts[1] if len(parts) > 1 else ""

        if sub_cmd == "FETCH":
            await self._cmd_fetch(tag, sub_args, uid_mode=True)
        elif sub_cmd == "STORE":
            await self._cmd_store(tag, sub_args, uid_mode=True)
        elif sub_cmd == "EXPUNGE":
            await self._cmd_expunge(tag, sub_args)
        elif sub_cmd == "COPY":
            await self._cmd_copy(tag, sub_args, uid_mode=True)
        elif sub_cmd == "SEARCH":
            await self._cmd_search(tag, sub_args, uid_mode=True)
        else:
            self._bad(tag, f"UID {sub_cmd} not supported")


# ---------------------------------------------------------------------------
# Serwer TCP
# ---------------------------------------------------------------------------

class IMAPServer:
    """
    Asynchroniczny serwer IMAP4rev1 na localhost:1143.

    Użycie:
        server = IMAPServer(host="127.0.0.1", port=1143)
        await server.start()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 1143, cache_path: str = "tuta_cache.db"):
        self.host = host
        self.port = port
        self.cache_path = cache_path
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        # Jeden TutaClient i cache współdzielone między połączeniami
        self._cache = TutaCache(self.cache_path)
        self._tuta = TutaClient()
        await self._tuta.__aenter__()

        self._server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port,
        )
        logger.info(f"IMAP server listening on {self.host}:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
        if self._tuta:
            await self._tuta.__aexit__(None, None, None)
        if hasattr(self, "_cache"):
            self._cache.close()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        conn = IMAPConnection(reader, writer, self._tuta, self._cache)
        await conn.handle()


# ---------------------------------------------------------------------------
# Helpers — parsowanie IMAP
# ---------------------------------------------------------------------------

def _parse_args(s: str) -> list[str]:
    """Parsuje IMAP args: "foo" "bar" lub foo bar → ['foo', 'bar']."""
    result = []
    s = s.strip()
    while s:
        if s.startswith('"'):
            end = s.index('"', 1)
            result.append(s[1:end])
            s = s[end + 1:].lstrip()
        else:
            parts = s.split(None, 1)
            result.append(parts[0])
            s = parts[1].lstrip() if len(parts) > 1 else ""
    return result


def _quote(s: str) -> str:
    if " " in s or any(c in s for c in '"\\()%*'):
        return f'"{s}"'
    return s


def _unquote(s: str) -> str:
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _parse_fetch_items(s: str) -> list[str]:
    """
    Parsuje listę itemów FETCH (może zawierać BODY[HEADER.FIELDS (...)]).
    Przykład: 'FLAGS UID BODY.PEEK[HEADER.FIELDS (From To Subject)]'
    """
    items = []
    i = 0
    s = s.strip()
    while i < len(s):
        if s[i] == ' ':
            i += 1
            continue
        # Zbierz token do spacji lub nawiasu [
        start = i
        while i < len(s) and s[i] not in (' ',):
            if s[i] == '[':
                # Czytaj do zamknięcia ]
                depth = 1
                i += 1
                while i < len(s) and depth > 0:
                    if s[i] == '[':
                        depth += 1
                    elif s[i] == ']':
                        depth -= 1
                    elif s[i] == '(':
                        # Pomiń zawartość nawiasów w BODY[HEADER.FIELDS (...)]
                        j = s.index(')', i) if ')' in s[i:] else len(s)
                        i = j
                    i += 1
            else:
                i += 1
        items.append(s[start:i].strip())
    return [item for item in items if item]


def _expand_seq_set(seq_set: str, max_seq: int, uid_mode: bool = False) -> list[int]:
    """
    Rozwiją sekwencję IMAP np. "1:*", "1,3,5", "2:4" → lista integerów.
    W uid_mode zwraca UIDs (ale i tak je przetwarzamy jako liczby).
    """
    result = []
    for part in seq_set.split(","):
        part = part.strip()
        if ":" in part:
            lo, hi = part.split(":", 1)
            lo_val = max_seq if lo == "*" else int(lo)
            hi_val = max_seq if hi == "*" else int(hi)
            result.extend(range(min(lo_val, hi_val), max(lo_val, hi_val) + 1))
        else:
            val = max_seq if part == "*" else int(part)
            result.append(val)
    return result


def _in_seq_set(val: int, seq_set: str, max_val: int) -> bool:
    """
    Sprawdza czy val należy do IMAP sequence set (np. "1:*", "1,3,5", "2:4").
    Działa zarówno dla seq numbers jak i UIDs — max_val to wartość dla *.
    Nie rozwijamy zakresu do listy (UIDs mogą być > 4 mld).
    """
    for part in seq_set.split(","):
        part = part.strip()
        if ":" in part:
            lo_str, hi_str = part.split(":", 1)
            lo = max_val if lo_str.strip() == "*" else int(lo_str.strip())
            hi = max_val if hi_str.strip() == "*" else int(hi_str.strip())
            if min(lo, hi) <= val <= max(lo, hi):
                return True
        else:
            v = max_val if part == "*" else int(part)
            if val == v:
                return True
    return False


def encode_mutf7(s: str) -> str:
    """
    Encodes a Unicode string to IMAP modified UTF-7 (RFC 3501 §5.1.3).
    ASCII printable chars (0x20–0x7E) except '&' pass through unchanged.
    Non-ASCII runs are encoded as &<modified-base64>-.
    Modified base64: standard base64 with '/' replaced by ',' and no '=' padding.
    """
    result = []
    buf: list[str] = []

    def _flush():
        if buf:
            b64 = base64.b64encode("".join(buf).encode("utf-16-be")).decode("ascii")
            b64 = b64.replace("/", ",").rstrip("=")
            result.append(f"&{b64}-")
            buf.clear()

    for c in s:
        if c == "&":
            _flush()
            result.append("&-")
        elif "\x20" <= c <= "\x7e":
            _flush()
            result.append(c)
        else:
            buf.append(c)
    _flush()
    return "".join(result)


def decode_mutf7(s: str) -> str:
    """
    Decodes an IMAP modified UTF-7 string (RFC 3501 §5.1.3) to Unicode.
    Also handles plain UTF-8 input transparently (no '&' → returned as-is).
    """
    if "&" not in s:
        return s
    result = []
    i = 0
    while i < len(s):
        if s[i] == "&":
            try:
                j = s.index("-", i + 1)
            except ValueError:
                result.append(s[i:])
                break
            b64 = s[i + 1 : j]
            if not b64:
                result.append("&")
            else:
                b64std = b64.replace(",", "/")
                padding = (4 - len(b64std) % 4) % 4
                decoded = base64.b64decode(b64std + "=" * padding).decode("utf-16-be")
                result.append(decoded)
            i = j + 1
        else:
            result.append(s[i])
            i += 1
    return "".join(result)


def _uidvalidity(folder_id: str) -> int:
    """Stabilna wartość UIDVALIDITY z ID folderu.
    v3: zmiana schematu UID z CRC32 na timestamp z GeneratedId (2026-05-12).
    Zmiana prefixu wymusza porzucenie lokalnego cache UID przez Thunderbirda.
    """
    import hashlib
    h = hashlib.md5(f"v3:{folder_id}".encode()).digest()
    return int.from_bytes(h[:4], "big")


def _imap_date(dt: datetime) -> str:
    """Formatuje datę jako IMAP INTERNALDATE: '01-Jan-2024 12:00:00 +0000'."""
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    return f"{dt.day:02d}-{months[dt.month-1]}-{dt.year} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def _imap_address(name: str, address: str) -> str:
    """Formatuje adres jako IMAP ENVELOPE address: '("Name" NIL "user" "domain")'."""
    parts = address.split("@", 1) if "@" in address else [address, ""]
    user = parts[0]
    domain = parts[1] if len(parts) > 1 else ""
    name_enc = f'"{name}"' if name else "NIL"
    return f'({name_enc} NIL "{user}" "{domain}")'


# ---------------------------------------------------------------------------
# Punkt wejścia (standalone)
# ---------------------------------------------------------------------------

async def _main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    server = IMAPServer()
    await server.start()


if __name__ == "__main__":
    asyncio.run(_main())
