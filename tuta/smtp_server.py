"""
tuta/smtp_server.py
Serwer SMTP (RFC 5321) na localhost:1025 — proxy do Tuta API.

Protokół wysyłki:
  1. POST /rest/tutanota/draftservice     → tworzy draft (non-confidential)
  2. POST /rest/tutanota/senddraftservice → wysyła draft

Non-confidential: klucz sesji draftu trafia jawnie do SendDraftData.
  - Odbiorcy zewnętrzni (@gmail.com itp.): Tuta wysyła jako zwykłe SMTP.
  - Odbiorcy Tuta (@tuta.com, @tutanota.com): mail dotrze, ale bez E2E.
    Szyfrowanie E2E (bucket key + asymetryczne) — M4.

Uwierzytelnienie: AUTH PLAIN lub AUTH LOGIN.
  Serwer zawsze odpowiada 235 na AUTH — błąd weryfikują Tuta przy DATA.
"""

import asyncio
import hashlib
import hmac
import html
import logging
import time
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import getaddresses

from aiosmtpd.smtp import SMTP as SMTPProtocol, AuthResult, LoginPassword

from .api import Session, TutaClient, TutaAPIError

logger = logging.getLogger(__name__)

# TTL cache sesji SMTP. Token Tuty żyje godzinami; krótki TTL ogranicza okno,
# w którym sesja siedzi w pamięci, i wymusza okresowy świeży login.
_SMTP_SESSION_TTL = 300  # 5 min


def _decode_header(value: str | None) -> str:
    """Dekoduje nagłówek RFC 2047 (=?charset?...?= enkodowanie)."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value or ""


def _extract_body_and_attachments(
    msg,
) -> "tuple[str, list[tuple[bytes, str, str, str | None]]]":
    """
    Parsuje wiadomość RFC 2822. Zwraca (body_html, attachments).
    attachments: lista (data, filename, mime_type, cid_or_None).
    Obsługuje multipart/mixed, multipart/related (inline z CID), multipart/alternative.
    """
    if not msg.is_multipart():
        ct = msg.get_content_type()
        charset = msg.get_content_charset() or "utf-8"
        payload = msg.get_payload(decode=True)
        if payload is None:
            return "<html><body></body></html>", []
        text = payload.decode(charset, errors="replace")
        if ct != "text/html":
            text = f"<html><body><pre>{html.escape(text)}</pre></body></html>"
        return text, []

    html_part = None
    plain_part = None
    attachments: list[tuple[bytes, str, str, "str | None"]] = []

    for part in msg.walk():
        ct = part.get_content_type()
        if ct.startswith("multipart/"):
            continue

        disp = str(part.get("Content-Disposition", ""))
        cid_raw = part.get("Content-Id", "") or part.get("Content-ID", "")
        cid = cid_raw.strip().strip("<>") if cid_raw else None

        is_attachment = "attachment" in disp

        if ct == "text/html" and not is_attachment and html_part is None:
            html_part = part
        elif ct == "text/plain" and not is_attachment and plain_part is None:
            plain_part = part
        else:
            # Treść binarna lub explicit attachment (w tym inline images z CID)
            filename = _decode_header(part.get_filename() or "") or f"attachment_{len(attachments) + 1}"
            data = part.get_payload(decode=True)
            if data is not None:
                attachments.append((data, filename, ct or "application/octet-stream", cid))

    chosen = html_part or plain_part
    if chosen is None:
        return "<html><body></body></html>", attachments

    charset = chosen.get_content_charset() or "utf-8"
    body = chosen.get_payload(decode=True).decode(charset, errors="replace")
    if chosen.get_content_type() == "text/plain":
        body = f"<html><body><pre>{html.escape(body)}</pre></body></html>"
    return body, attachments


def _parse_recipients(header_val: str | None) -> list[tuple[str, str]]:
    """Parsuje nagłówek adresowy, zwraca listę (name, address)."""
    if not header_val:
        return []
    return [(name.strip(), addr.strip()) for name, addr in getaddresses([header_val]) if addr.strip()]


class _TutaSMTPHandler:
    """Handler aiosmtpd — obsługuje kompletną wiadomość z DATA."""

    def __init__(self, client: TutaClient):
        self.client = client
        # Cache sesji: email → (session, sha256(pw), monotonic_ts). Bez tego każdy
        # mail = pełny login (argon2id m=32MB,t=4 + handshake do Tuty); kolejka N maili
        # = N× argon2 → procesor leży. Porównanie sha256(pw) w czasie stałym chroni
        # przed auth bypass (jak w DAV). Reużycie tylko w obrębie _SMTP_SESSION_TTL.
        self._sessions: dict[str, tuple[Session, bytes, float]] = {}
        # Blokada per-email — drugi równoległy mail tego usera czeka zamiast logować drugi raz.
        self._login_locks: dict[str, asyncio.Lock] = {}

    async def _get_session(self, email: str, password: str) -> Session:
        """Zalogowana sesja dla (email, password) z cache. Reużywa w obrębie TTL gdy
        sha256(hasła) się zgadza; inaczej świeży login. Porównanie stałoczasowe
        zapobiega auth bypass (cache nie zwróci sesji dla innego hasła)."""
        pw_hash = hashlib.sha256(password.encode("utf-8")).digest()
        cached = self._sessions.get(email)
        if cached and hmac.compare_digest(cached[1], pw_hash) \
                and (time.monotonic() - cached[2]) < _SMTP_SESSION_TTL:
            return cached[0]
        # Blokada per-email: drugi równoległy request czeka zamiast logować się drugi raz
        lock = self._login_locks.setdefault(email, asyncio.Lock())
        async with lock:
            # Ponowne sprawdzenie pod blokadą — inny coroutine mógł właśnie zalogować
            cached = self._sessions.get(email)
            if cached and hmac.compare_digest(cached[1], pw_hash) \
                    and (time.monotonic() - cached[2]) < _SMTP_SESSION_TTL:
                return cached[0]
            # Stara sesja (inne hasło lub wygasły TTL) — wyloguj przed podmianą,
            # żeby nie akumulować aktywnych sesji w UI Tuty.
            old = self._sessions.pop(email, None)
            if old:
                await self._logout_session(email, old[0])
            session = await self.client.login(email, password)
            self._sessions[email] = (session, pw_hash, time.monotonic())
            logger.info("SMTP: zalogowano %s (cache, TTL %ds)", email, _SMTP_SESSION_TTL)
            return session

    async def _logout_session(self, email: str, session: Session) -> None:
        """Best-effort DELETE /sys/session — błąd ignorowany (token mógł już wygasnąć)."""
        try:
            await self.client.logout(session)
        except Exception as exc:
            logger.debug("SMTP: logout %s zignorowany: %s", email, exc)

    async def _invalidate_session(self, email: str) -> None:
        """Usuwa sesję z cache (po 401/440 podczas wysyłki) + best-effort logout."""
        old = self._sessions.pop(email, None)
        if old:
            await self._logout_session(email, old[0])

    async def logout_all(self) -> None:
        """Graceful logout wszystkich sesji z cache — wołane przy shutdown serwera."""
        if not self._sessions:
            return
        logger.info("SMTP: graceful logout %d sesji", len(self._sessions))
        for email, (session, _, _) in list(self._sessions.items()):
            await self._logout_session(email, session)
        self._sessions.clear()

    async def handle_DATA(self, server, session, envelope) -> str:
        email_addr = getattr(session, "tuta_email", None)
        password = getattr(session, "tuta_password", None)

        if not email_addr or not password:
            logger.warning("SMTP DATA bez uwierzytelnienia")
            return "530 5.7.0 Authentication required"

        # Parsuj RFC 2822
        msg = message_from_bytes(envelope.content)
        subject = _decode_header(msg.get("Subject", ""))
        from_raw = _decode_header(msg.get("From", ""))
        from_parsed = _parse_recipients(from_raw)
        from_name, from_addr = from_parsed[0] if from_parsed else ("", email_addr)
        if not from_addr:
            from_addr = email_addr

        to_list = _parse_recipients(_decode_header(msg.get("To", "")))
        cc_list = _parse_recipients(_decode_header(msg.get("Cc", "")))
        bcc_list = _parse_recipients(_decode_header(msg.get("Bcc", "")))

        # Fallback: użyj odbiorców z SMTP envelope jeśli nagłówki puste
        if not to_list and not cc_list and not bcc_list:
            to_list = [("", addr) for addr in envelope.rcpt_tos]

        body_html, mime_attachments = _extract_body_and_attachments(msg)

        # Hasło dla Secure External — opcjonalny nagłówek X-Tuta-Password
        secure_password = _decode_header(msg.get("X-Tuta-Password", "")).strip() or None

        logger.info(
            f"SMTP send: from={from_addr} to={[a for _, a in to_list]} "
            f"cc={[a for _, a in cc_list]} subject={subject!r} "
            f"attachments={len(mime_attachments)} secure_external={secure_password is not None}"
        )

        parsed = {
            "subject": subject,
            "from_addr": from_addr,
            "from_name": from_name,
            "to_list": to_list,
            "cc_list": cc_list,
            "bcc_list": bcc_list,
            "body_html": body_html,
            "mime_attachments": mime_attachments,
            "secure_password": secure_password,
        }
        # Cache sesji: sesja reużywana między mailami w obrębie TTL. Przy 401/440
        # (sesja wygasła po stronie Tuty) invalidate + jeden retry ze świeżym loginem.
        for attempt in (1, 2):
            try:
                tuta_session = await self._get_session(email_addr, password)
                await self._send_message(tuta_session, parsed)
                return "250 2.0.0 OK: Message accepted"
            except TutaAPIError as e:
                if e.status_code in (401, 440) and attempt == 1:
                    logger.info("SMTP: %s podczas wysyłki dla %s — invalidate + retry",
                                e.status_code, email_addr)
                    await self._invalidate_session(email_addr)
                    continue
                logger.error(f"SMTP send failed: {e}")
                return f"554 5.0.0 Send failed: {e}"
            except Exception as e:
                logger.exception(f"SMTP unexpected error: {e}")
                return "451 4.0.0 Internal error"
        return "451 4.0.0 Internal error"

    async def _send_message(self, tuta_session: Session, p: dict) -> None:
        """Wysyłka draftu w już zalogowanej (cache) sesji: upload załączników →
        create_draft → send_draft (E2E / Secure External / non-confidential).
        Rzuca TutaAPIError do wołającego — retry/invalidate obsługuje handle_DATA."""
        subject = p["subject"]
        from_addr = p["from_addr"]
        from_name = p["from_name"]
        to_list = p["to_list"]
        cc_list = p["cc_list"]
        bcc_list = p["bcc_list"]
        body_html = p["body_html"]
        mime_attachments = p["mime_attachments"]
        secure_password = p["secure_password"]

        mail_group_key = await self.client.get_mail_group_key(tuta_session)

        all_addresses = [a for _, a in (to_list + cc_list + bcc_list)]

        # Secure External — gdy ustawiony X-Tuta-Password i wszyscy odbiorcy zewnętrzni
        if secure_password is not None:
            has_tuta_recipients = False
            for addr in all_addresses:
                pub_key = await self.client.get_recipient_public_key(addr, tuta_session.access_token)
                if pub_key is not None:
                    has_tuta_recipients = True
                    break

            if has_tuta_recipients:
                logger.warning(
                    "X-Tuta-Password ustawiony, ale wśród odbiorców są konta Tuta — "
                    "Secure External wymaga wyłącznie odbiorców zewnętrznych. Fallback: non-confidential."
                )
                secure_password = None
            else:
                logger.info(f"SMTP send: Secure External recipients={all_addresses}")

        # Sprawdź E2E (Tuta→Tuta) — tylko gdy nie Secure External
        recipient_keys: dict[str, dict] = {}
        is_e2e = False
        if secure_password is None:
            is_e2e = True
            for addr in all_addresses:
                pub_key = await self.client.get_recipient_public_key(addr, tuta_session.access_token)
                if pub_key is None:
                    is_e2e = False
                    break
                recipient_keys[addr] = pub_key
            logger.info(f"SMTP send: E2E={'tak' if is_e2e else 'nie'} recipients={all_addresses}")

        # confidential=True przy E2E lub Secure External (wymagane przez API)
        is_confidential = is_e2e or (secure_password is not None)

        # Upload załączników przed tworzeniem draftu
        draft_attachments: list[dict] = []
        file_session_keys: list[bytes] = []
        for att_data, att_filename, att_mime, att_cid in mime_attachments:
            draft_att, file_sk = await self.client.upload_attachment(
                tuta_session, mail_group_key, att_data, att_filename, att_mime, att_cid
            )
            draft_attachments.append(draft_att)
            file_session_keys.append(file_sk)
            logger.debug(f"SMTP: załącznik upload OK: {att_filename!r} {len(att_data)}B")

        draft_list_id, draft_elem_id, sk = await self.client.create_draft(
            session=tuta_session,
            subject=subject,
            body_html=body_html,
            from_addr=from_addr,
            from_name=from_name,
            to_recipients=to_list,
            cc_recipients=cc_list,
            bcc_recipients=bcc_list,
            mail_group_key=mail_group_key,
            confidential=is_confidential,
            attachments=draft_attachments,
        )

        # Pobierz ID plików przypisane przez serwer (pole 115 w Mail)
        attachment_keys: list[tuple[str, str, bytes]] = []
        if draft_attachments:
            file_ids = await self.client.get_draft_file_ids(
                tuta_session, draft_list_id, draft_elem_id
            )
            for i, file_sk in enumerate(file_session_keys):
                if i < len(file_ids):
                    attachment_keys.append((file_ids[i][0], file_ids[i][1], file_sk))

        if secure_password is not None:
            recipients_with_pw = [(addr, secure_password) for addr in all_addresses]
            await self.client.send_draft_secure_external(
                session=tuta_session,
                draft_list_id=draft_list_id,
                draft_elem_id=draft_elem_id,
                session_key=sk,
                mail_group_key=mail_group_key,
                recipients=recipients_with_pw,
                attachment_keys=attachment_keys,
                sender_name=from_name,
            )
        elif is_e2e:
            sender_priv, sender_pub, sender_ver = await self.client.get_sender_ecc_keypair(tuta_session)
            recipients_with_keys = [(a, recipient_keys[a]) for a in all_addresses]
            await self.client.send_draft_e2e(
                session=tuta_session,
                draft_list_id=draft_list_id,
                draft_elem_id=draft_elem_id,
                session_key=sk,
                recipients=recipients_with_keys,
                sender_ecc_priv=sender_priv,
                sender_ecc_pub=sender_pub,
                sender_key_version=sender_ver,
                attachment_keys=attachment_keys,
            )
        else:
            await self.client.send_draft(
                session=tuta_session,
                draft_list_id=draft_list_id,
                draft_elem_id=draft_elem_id,
                session_key=sk,
                attachment_keys=attachment_keys,
            )


def _make_authenticator():
    """Zwraca callable do uwierzytelniania AUTH PLAIN/LOGIN w aiosmtpd."""
    def authenticator(smtp_server, smtp_session, envelope, mechanism, auth_data):
        if isinstance(auth_data, LoginPassword):
            try:
                smtp_session.tuta_email = auth_data.login.decode("utf-8")
                smtp_session.tuta_password = auth_data.password.decode("utf-8")
            except Exception:
                return AuthResult(success=False, handled=False)
        # Zawsze akceptuj — Tuta odrzuci złe hasło przy send
        return AuthResult(success=True)
    return authenticator


class SMTPServer:
    """Asyncio SMTP server — bezpośrednio używa loop.create_server z protokołem aiosmtpd."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1025):
        self.host = host
        self.port = port
        self._client: TutaClient | None = None
        self._server: asyncio.AbstractServer | None = None
        self._handler: "_TutaSMTPHandler | None" = None

    async def start(self):
        self._client = TutaClient()
        await self._client.__aenter__()

        handler = _TutaSMTPHandler(self._client)
        self._handler = handler
        authenticator = _make_authenticator()

        def smtp_factory():
            return SMTPProtocol(
                handler,
                auth_required=True,
                auth_require_tls=False,
                authenticator=authenticator,
            )

        loop = asyncio.get_running_loop()
        self._server = await loop.create_server(smtp_factory, host=self.host, port=self.port)
        logger.info(f"SMTP server started on {self.host}:{self.port}")

        # Utrzymuj pętlę zdarzeń aktywną do Ctrl+C
        await self._server.serve_forever()

    async def stop(self):
        """Graceful shutdown — listener zamykany, cache sesji wylogowany, klient
        aiohttp domknięty. Handler trzyma cache sesji SMTP (TTL), więc logout_all
        zamyka aktywne sesje, żeby nie zostawały w UI Tuty."""
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception as exc:
                logger.debug("SMTP: wait_closed: %s", exc)
        if self._handler:
            await self._handler.logout_all()
        if self._client:
            await self._client.__aexit__(None, None, None)
        logger.info("SMTP: shutdown OK")
