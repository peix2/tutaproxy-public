"""
tuta/message_builder.py
Konwersja surowych danych Tuta (numeryczne klucze API) → RFC 2822.

Mapowanie pól (z type_models/tutanota.json, maj 2026):
  Mail:      105=subject(enc), 107=receivedDate, 111=sender(agg)
  MailAddress: 94=name(enc), 95=address
  MailDetails: 1286=recipients(agg)
  Recipients:  1279=to, 1280=cc, 1281=bcc (każdy lista MailAddress)
  MailDetails: 1284=sentDate, 1288=body(agg)
  Body:        1276=compressedText(enc), 1275=text(enc)
"""

import base64
import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import email.utils
import logging
import re
import zlib
from datetime import datetime, timezone
from typing import Optional

from .crypto import aes_decrypt_tuta, uncompress_lz4

logger = logging.getLogger(__name__)


def _decrypt_str(key: bytes, b64_value: str) -> str:
    """Odszyfrowuje zaszyfrowany string (base64, AesCbcThenHmac)."""
    if not b64_value:
        return ""
    try:
        raw = base64.b64decode(b64_value)
        return aes_decrypt_tuta(key, raw).decode("utf-8", errors="replace")
    except Exception as e:
        logger.debug(f"Błąd deszyfrowania stringa: {e}")
        return ""


def _decode_address(agg, mail_key: bytes) -> tuple[str, str]:
    """Zwraca (name, address) z agregatu MailAddress (dict lub lista z jednym elementem)."""
    if isinstance(agg, list):
        agg = agg[0] if agg else {}
    if not isinstance(agg, dict):
        return "", ""
    name = _decrypt_str(mail_key, agg.get("94", ""))
    address = agg.get("95", "")
    return name, address


def _format_address(name: str, address: str) -> str:
    if name and address:
        return f"{name} <{address}>"
    if address:
        return address
    return name  # pusty adres: zwróć name as-is (może zawierać już sformatowany adres)


# Tuta używa base64Ext (sortowalne leksykograficznie) dla GeneratedId.
# Alfabet: -0123456789A-Z_a-z → mapowanie 1:1 na standardowy base64.
_B64EXT = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
_B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_EXT_LOOKUP = {c: i for i, c in enumerate(_B64EXT)}


def tuta_id_to_uid(mail_id) -> int:
    """
    UID z timestamp wbudowanego w Tuta GeneratedId (base64Ext).
    Pierwsze 42 bity = ms timestamp (Unix epoch).
    Zwracamy timestamp w sekundach (uint32, rośnie monotonicznie z czasem).
    Fallback do CRC32 gdy ID nie wygląda jak base64Ext (np. customId).
    """
    id_str = mail_id[-1] if isinstance(mail_id, list) else str(mail_id)
    try:
        b64 = "".join(_B64STD[_EXT_LOOKUP[c]] for c in id_str)
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        if len(raw) < 6:
            raise ValueError("too short")
        n = 0
        for i in range(5):
            n = n * 256 + raw[i]
        # 42-bitowy timestamp ms: 40 bitów z pierwszych 5 bajtów + 2 najwyższe bity bajtu 6
        ts_ms = n * 4 + (raw[5] >> 6)
        ts_sec = (ts_ms // 1000) & 0xFFFFFFFF
        return ts_sec if ts_sec > 0 else zlib.crc32(id_str.encode()) & 0xFFFFFFFF
    except Exception:
        return zlib.crc32(id_str.encode()) & 0xFFFFFFFF


def html_to_text(html: str) -> str:
    """Minimalna konwersja HTML → plain text."""
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"<p[^>]*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = (text
            .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&nbsp;", " ").replace("&quot;", '"').replace("&#39;", "'"))
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def build_rfc2822(
    mail_raw: dict,
    mail_details_blob: dict,
    mail_key: bytes,
    attachments: list[dict] | None = None,
) -> bytes:
    """
    Buduje wiadomość RFC 2822 z surowych danych API.

    mail_raw          — obiekt Mail (pola numeryczne, z TutaClient.get_mail_list)
    mail_details_blob — MailDetailsBlob (z TutaClient.get_mail_details)
    mail_key          — odszyfrowany klucz sesji maila (32B)
    """
    # --- Temat ---
    subject = _decrypt_str(mail_key, mail_raw.get("105", "")) or "(brak tematu)"

    # --- Nadawca (pole 111 = agregat MailAddress) ---
    sender_agg = mail_raw.get("111", {})
    logger.debug("build_rfc2822: raw sender_agg (pole 111) = %r", sender_agg)
    sender_name, sender_address = _decode_address(sender_agg, mail_key)
    logger.debug("build_rfc2822: sender_name=%r sender_address=%r", sender_name, sender_address)

    # --- Odbiorcy (przez MailDetails → pole 1305[0] → 1286 → Recipients) ---
    mail_details_list = mail_details_blob.get("1305", [])
    mail_details = mail_details_list[0] if isinstance(mail_details_list, list) and mail_details_list else {}

    # --- Data: sentDate (1284) z MailDetails jako primary, receivedDate (107) jako fallback.
    # Lokalna strefa czasowa pochodzi z TZ (env/system) — respektuje TZ z docker-compose.
    sent_ts_str = mail_details.get("1284", "") or ""
    ts_ms = int(sent_ts_str or mail_raw.get("107", 0) or 0)
    mail_date = datetime.fromtimestamp(ts_ms / 1000).astimezone() if ts_ms else datetime.now().astimezone()

    recipients_agg = mail_details.get("1286", {})
    if isinstance(recipients_agg, list):
        recipients_agg = recipients_agg[0] if recipients_agg else {}

    to_addrs = [
        _format_address(*_decode_address(r, mail_key))
        for r in (recipients_agg.get("1279", []) or [])
    ]
    cc_addrs = [
        _format_address(*_decode_address(r, mail_key))
        for r in (recipients_agg.get("1280", []) or [])
    ]

    # --- Treść (pole 1288 → Body → 1276=compressedText, 1275=text) ---
    body_agg_list = mail_details.get("1288", [])
    body_agg = body_agg_list[0] if isinstance(body_agg_list, list) and body_agg_list else {}

    body_html = ""
    compressed_b64 = body_agg.get("1276", "")
    text_b64 = body_agg.get("1275", "")

    if compressed_b64:
        try:
            enc = base64.b64decode(compressed_b64)
            compressed = aes_decrypt_tuta(mail_key, enc)
            body_html = uncompress_lz4(compressed).decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Błąd deszyfrowania/dekompresji treści: {e}")
    elif text_b64:
        body_html = _decrypt_str(mail_key, text_b64)

    body_text = html_to_text(body_html) if body_html else ""

    # --- Message-ID (stabilny, z elementId maila) ---
    mail_id = mail_raw.get("99", ["", ""])
    element_id = mail_id[-1] if isinstance(mail_id, list) else str(mail_id)
    uid = tuta_id_to_uid(mail_id)
    message_id = f"<tuta-{element_id}@tuta.local>"

    # --- Buduj MIME ---
    # Część tekstowa (alternative lub prosta)
    if body_html and body_text:
        body_part = email.mime.multipart.MIMEMultipart("alternative")
        body_part.attach(email.mime.text.MIMEText(body_text, "plain", "utf-8"))
        body_part.attach(email.mime.text.MIMEText(body_html, "html", "utf-8"))
    elif body_html:
        body_part = email.mime.text.MIMEText(body_html, "html", "utf-8")
    else:
        body_part = email.mime.text.MIMEText(body_text or "", "plain", "utf-8")

    if attachments:
        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg.attach(body_part)
        for att in attachments:
            mime_main, _, mime_sub = att["mime_type"].partition("/")
            if not mime_sub:
                mime_main, mime_sub = "application", "octet-stream"
            # Typy message/* (poza rfc822) i multipart/* mają w email.generator
            # dedykowane handlery oczekujące zagnieżdżonych obiektów Message.
            # MIMEBase + base64 daje payload-string → flatten() crashuje z
            # "'str' object has no attribute 'policy'". Częste w bounce'ach DSN
            # (message/delivery-status). Demotujemy do octet-stream — surowe dane
            # bez zmian, a czytelna treść bounce'a i tak jest w body.
            if mime_main == "multipart" or (mime_main == "message" and mime_sub != "rfc822"):
                mime_main, mime_sub = "application", "octet-stream"
            part = email.mime.base.MIMEBase(mime_main, mime_sub)
            part.set_payload(att["data"])
            email.encoders.encode_base64(part)
            part.add_header(
                "Content-Disposition", "attachment",
                filename=att["name"],
            )
            if att.get("cid"):
                part.add_header("Content-ID", f"<{att['cid']}>")
            msg.attach(part)
    else:
        msg = body_part

    msg["Subject"] = subject
    msg["From"] = _format_address(sender_name, sender_address)
    if to_addrs:
        msg["To"] = ", ".join(to_addrs)
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)
    msg["Date"] = email.utils.format_datetime(mail_date)
    msg["Message-ID"] = message_id

    return msg.as_bytes()


def get_mail_flags(mail_raw: dict) -> list[str]:
    """Zwraca listę IMAP flag dla maila."""
    flags = []
    if mail_raw.get("109", "1") == "0":
        flags.append(r"\Seen")
    # Lokalne flagi (nie mają odpowiednika w Tuta API — gubione po restarcie)
    if mail_raw.get("_flagged"):
        flags.append(r"\Flagged")
    if mail_raw.get("_answered"):
        flags.append(r"\Answered")
    return flags
