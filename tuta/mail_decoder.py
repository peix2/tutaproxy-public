"""
tuta/mail_decoder.py
Deszyfrowanie i dekodowanie wiadomości e-mail z API Tuty.

Tuta szyfruje każdą wiadomość odrębnym kluczem symetrycznym (mail key).
Klucz ten jest:
  - Legacy: zaszyfrowany RSA-2048 kluczem publicznym odbiorcy
  - TutaCrypt: opakowywany przez hybrydowy KEM (X25519 + Kyber)

Po odszyfrowaniu klucza maila, nim deszyfrowane są:
  - Temat (_ownerEncSessionKey)  
  - Nadawca (imię)
  - Treść HTML (MailBody.compressedText lub .text)
  - Załączniki
"""

import email
import email.mime.text
import email.mime.multipart
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from .api import Session, TutaAPIError
from .crypto import (
    UserKeys,
    aes128_decrypt,
    aes256_decrypt,
    b64url_decode,
    b64url_encode,
    rsa_decrypt_key,
    CRYPTO_PROTO_VERSION_AES128,
    CRYPTO_PROTO_VERSION_AES256,
)

logger = logging.getLogger(__name__)


@dataclass
class DecodedMail:
    """Odszyfrowana wiadomość gotowa do serwowania przez IMAP."""
    uid: int
    subject: str
    sender_address: str
    sender_name: str
    to_addresses: list[str]
    date: datetime
    body_html: str
    body_text: str
    unread: bool
    # Surowe nagłówki + treść w formacie RFC 2822 (do IMAP FETCH)
    raw_rfc822: Optional[bytes] = None


class MailDecoder:
    """
    Deszyfruje wiadomości korzystając z kluczy załadowanych do sesji.
    """

    def __init__(self, user_keys: UserKeys):
        self.user_keys = user_keys

    def decrypt_mail_session_key(self, raw_mail: dict) -> bytes:
        """
        Odszyfrowuje klucz sesji maila (_ownerEncSessionKey lub ownerEncSessionKey).
        
        Klucz sesji maila jest zaszyfrowany:
          - Legacy: RSA kluczem grupy
          - TutaCrypt: przez ownerKeyVersion i powiązany klucz grupy

        Zwraca 16 lub 32 bajty (AES-128 lub AES-256 key).
        """
        # ownerEncSessionKey to base64url-zakodowany zaszyfrowany klucz
        enc_session_key_b64 = raw_mail.get("_ownerEncSessionKey") or \
                              raw_mail.get("ownerEncSessionKey", "")
        if not enc_session_key_b64:
            raise TutaAPIError(0, "Brak ownerEncSessionKey w danych maila")

        enc_session_key = b64url_decode(enc_session_key_b64)

        # Sprawdź który klucz grupy jest właścicielem
        owner_group = raw_mail.get("_ownerGroup", "")

        # Wersja klucza właściciela (0 = legacy RSA, >= 1 = TutaCrypt)
        owner_key_version = int(raw_mail.get("ownerKeyVersion", "0") or "0")

        if owner_key_version == 0 and self.user_keys.private_key_pem:
            # Legacy: deszyfrowanie RSA
            return rsa_decrypt_key(self.user_keys.private_key_pem, enc_session_key)
        elif self.user_keys.user_group_key:
            # Klucz sesji zaszyfrowany kluczem grupy (AES)
            # Sprawdź wersję AES z bajtu nagłówka
            version_byte = enc_session_key[0] if enc_session_key else 0
            if version_byte == CRYPTO_PROTO_VERSION_AES256:
                return aes256_decrypt(self.user_keys.user_group_key, enc_session_key)
            else:
                return aes128_decrypt(self.user_keys.user_group_key, enc_session_key)
        else:
            raise TutaAPIError(0, "Brak odpowiedniego klucza do odszyfrowania klucza maila")

    def decrypt_string(self, mail_key: bytes, encrypted_b64: str) -> str:
        """
        Odszyfrowuje zaszyfrowany string (temat, imię nadawcy itp.)
        
        Format danych to base64url → bajty → AES decrypt → UTF-8 string.
        """
        if not encrypted_b64:
            return ""
        try:
            encrypted = b64url_decode(encrypted_b64)
            version_byte = encrypted[0] if encrypted else 0
            if version_byte == CRYPTO_PROTO_VERSION_AES256 or len(mail_key) == 32:
                plaintext = aes256_decrypt(mail_key, encrypted)
            else:
                plaintext = aes128_decrypt(mail_key, encrypted)
            return plaintext.decode("utf-8")
        except Exception as e:
            logger.warning(f"Nie udało się odszyfrować stringa: {e}")
            return "[błąd deszyfrowania]"

    def decode_mail(self, raw_mail: dict, raw_body: Optional[dict] = None) -> DecodedMail:
        """
        Tworzy DecodedMail z surowych danych API + opcjonalnie ciała wiadomości.
        
        raw_mail — obiekt Mail z API
        raw_body — obiekt MailBody z API (może być None jeśli nie pobrano)
        """
        # 1. Odszyfruj klucz sesji maila
        try:
            mail_key = self.decrypt_mail_session_key(raw_mail)
        except Exception as e:
            logger.error(f"Błąd odszyfrowania klucza maila: {e}")
            mail_key = b"\x00" * 16  # fallback — treść będzie błędem

        # 2. Odczytaj i odszyfruj pola
        subject = self.decrypt_string(mail_key, raw_mail.get("subject", ""))
        sender_address = raw_mail.get("sender", {}).get("address", "")
        sender_name_enc = raw_mail.get("sender", {}).get("name", "")
        sender_name = self.decrypt_string(mail_key, sender_name_enc)

        # Data (Unix timestamp w ms)
        date_ms = int(raw_mail.get("receivedDate", "0") or "0")
        date = datetime.fromtimestamp(date_ms / 1000, tz=timezone.utc)

        unread = raw_mail.get("unread", "1") == "1"

        # 3. Adresy TO
        to_list = raw_mail.get("toRecipients", [])
        to_addresses = []
        for r in to_list:
            addr = r.get("address", "")
            name_enc = r.get("name", "")
            name = self.decrypt_string(mail_key, name_enc)
            to_addresses.append(f"{name} <{addr}>" if name else addr)

        # 4. Treść maila
        body_html = ""
        body_text = ""
        if raw_body:
            compressed_text_b64 = raw_body.get("compressedText", "")
            text_b64 = raw_body.get("text", "")

            if compressed_text_b64:
                # Odszyfruj a potem zdekompresuj (LZW/deflate)
                enc = b64url_decode(compressed_text_b64)
                version_byte = enc[0] if enc else 0
                if version_byte == CRYPTO_PROTO_VERSION_AES256 or len(mail_key) == 32:
                    compressed = aes256_decrypt(mail_key, enc)
                else:
                    compressed = aes128_decrypt(mail_key, enc)
                body_html = self._decompress(compressed)
            elif text_b64:
                body_html = self.decrypt_string(mail_key, text_b64)

            # Prosta konwersja HTML → text (do IMAP TEXT part)
            body_text = self._html_to_text(body_html)

        # 5. Buduj RFC 2822
        mail_id = raw_mail.get("_id", ["", ""])
        uid = self._id_to_uid(mail_id)
        decoded = DecodedMail(
            uid=uid,
            subject=subject,
            sender_address=sender_address,
            sender_name=sender_name,
            to_addresses=to_addresses,
            date=date,
            body_html=body_html,
            body_text=body_text,
            unread=unread,
        )
        decoded.raw_rfc822 = self._build_rfc822(decoded)
        return decoded

    def _build_rfc822(self, mail: DecodedMail) -> bytes:
        """Buduje surową wiadomość w formacie RFC 2822 do serwowania przez IMAP."""
        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = mail.subject
        msg["From"] = (
            f"{mail.sender_name} <{mail.sender_address}>"
            if mail.sender_name else mail.sender_address
        )
        msg["To"] = ", ".join(mail.to_addresses)
        msg["Date"] = email.utils.format_datetime(mail.date)
        msg["Message-ID"] = f"<tuta-proxy-{mail.uid}@local>"

        if mail.body_text:
            msg.attach(email.mime.text.MIMEText(mail.body_text, "plain", "utf-8"))
        if mail.body_html:
            msg.attach(email.mime.text.MIMEText(mail.body_html, "html", "utf-8"))

        return msg.as_bytes()

    def _decompress(self, data: bytes) -> str:
        """Dekompresuje dane (Tuta używa deflate/zlib dla dużych treści)."""
        import zlib
        try:
            return zlib.decompress(data, wbits=-15).decode("utf-8")
        except Exception:
            try:
                return zlib.decompress(data).decode("utf-8")
            except Exception as e:
                logger.warning(f"Dekompresja nie powiodła się: {e}")
                return data.decode("utf-8", errors="replace")

    def _html_to_text(self, html: str) -> str:
        """Prosta konwersja HTML → plain text."""
        import re
        # Usuń tagi HTML
        text = re.sub(r"<[^>]+>", "", html)
        # Zdekoduj encje HTML
        text = text.replace("&amp;", "&").replace("&lt;", "<") \
                   .replace("&gt;", ">").replace("&nbsp;", " ") \
                   .replace("&quot;", '"').replace("&#39;", "'")
        # Normalizuj whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def _id_to_uid(self, mail_id) -> int:
        """
        Konwertuje ID maila Tuty na numeryczny UID dla IMAP.
        
        IMAP wymaga numerycznych UID. Tuta używa base64url stringów.
        Dekodujemy ostatnie 4 bajty jako uint32.
        
        WAŻNE: UID muszą być stabilne (nie zmieniać się między sesjami) —
        dlatego używamy deterministycznej funkcji zamiast licznika.
        """
        if isinstance(mail_id, list):
            id_str = mail_id[-1]  # elementId
        else:
            id_str = str(mail_id)

        # Base64url → bajty → bierzemy ostatnie 4 bajty jako big-endian uint32
        try:
            raw = b64url_decode(id_str)
            if len(raw) >= 4:
                import struct
                return struct.unpack(">I", raw[-4:])[0]
        except Exception:
            pass

        # Fallback: hash stringa
        return hash(id_str) & 0x7FFFFFFF
