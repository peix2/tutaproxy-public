"""tests/test_crypto.py"""
import logging
import os, pytest
from tuta.crypto import (
    aes128_decrypt, aes128_encrypt, aes256_decrypt, aes256_encrypt,
    aes_encrypt_tuta, aes_decrypt_tuta,
    b64url_decode, b64url_encode,
    TUTA_AES128_KEY_LEN, TUTA_AES256_KEY_LEN,
)

class TestAES128:
    def test_roundtrip(self):
        key = os.urandom(TUTA_AES128_KEY_LEN)
        ct = aes128_encrypt(key, b"Hello, Tuta proxy!")
        assert aes128_decrypt(key, ct) == b"Hello, Tuta proxy!"

    def test_version_byte(self):
        key = os.urandom(TUTA_AES128_KEY_LEN)
        ct = aes128_encrypt(key, b"test")
        assert ct[0] == 0x01

    def test_wrong_key_raises(self):
        k1, k2 = os.urandom(16), os.urandom(16)
        ct = aes128_encrypt(k1, b"tajne")
        with pytest.raises(Exception):
            aes128_decrypt(k2, ct)

class TestAES256:
    def test_roundtrip(self):
        key = os.urandom(TUTA_AES256_KEY_LEN)
        ct = aes256_encrypt(key, b"TutaCrypt message")
        assert aes256_decrypt(key, ct) == b"TutaCrypt message"

    def test_version_byte(self):
        key = os.urandom(TUTA_AES256_KEY_LEN)
        assert aes256_encrypt(key, b"x")[0] == 0x02

class TestBase64Url:
    def test_roundtrip(self):
        for n in range(1, 20):
            data = bytes(range(n))
            assert b64url_decode(b64url_encode(data)) == data

    def test_no_special_chars(self):
        enc = b64url_encode(os.urandom(32))
        assert "+" not in enc and "/" not in enc and "=" not in enc

    def test_known(self):
        assert b64url_decode("SGVsbG8") == b"Hello"

class TestVerifier:
    """Testy compute_verifier — zweryfikowane empirycznie z przeglądarką (maj 2026)."""

    # Wartości zweryfikowane przez mitmproxy:
    #   salt z saltservice pole 422: "0oPKyV9Q3qMQJMNGP/PzOQ=="
    #   verifier z sessionservice pole 1214: "XOwOt9--eENoo0PSuFd4ToWWrI--7W0epXilZLnFu0k"
    SALT_B64 = "0oPKyV9Q3qMQJMNGP/PzOQ=="
    EXPECTED_VERIFIER = "XOwOt9--eENoo0PSuFd4ToWWrI--7W0epXilZLnFu0k"

    def test_argon2_verifier(self):
        """Verifier argon2id musi pasować do wartości z przeglądarki."""
        import base64
        from tuta.crypto import compute_verifier
        salt = base64.b64decode(self.SALT_B64)
        password = os.environ.get("TUTA_TEST_PASS")
        if not password:
            pytest.skip("Ustaw TUTA_TEST_PASS żeby uruchomić ten test")
        result = compute_verifier(password, salt, kdf_version=1)
        assert result == self.EXPECTED_VERIFIER

    def test_argon2_verifier_length(self):
        """Verifier musi mieć 43 znaki (32 bajty SHA256 w base64url bez paddingu)."""
        import base64
        from tuta.crypto import compute_verifier
        salt = base64.b64decode(self.SALT_B64)
        result = compute_verifier("dowolne_haslo", salt, kdf_version=1)
        assert len(result) == 43
        assert "+" not in result
        assert "/" not in result
        assert "=" not in result

    def test_unknown_kdf_raises(self):
        """Nieznany kdf_version musi rzucić ValueError."""
        import base64
        from tuta.crypto import compute_verifier
        salt = base64.b64decode(self.SALT_B64)
        with pytest.raises(ValueError):
            compute_verifier("haslo", salt, kdf_version=99)


class TestAesCbcThenHmac:
    """Testy AesCbcThenHmac (aes_encrypt_tuta/aes_decrypt_tuta) — format 0x01 z HMAC."""

    def test_roundtrip(self):
        """Klucz 32B, dane długie ~kilkanaście bajtów — pełen roundtrip."""
        key = os.urandom(32)
        plaintext = b"Tuta AesCbcThenHmac test"
        ct = aes_encrypt_tuta(key, plaintext)
        assert ct[0] == 0x01
        assert aes_decrypt_tuta(key, ct) == plaintext

    def test_hmac_mismatch_raises_in_strict_mode(self):
        """Strict mode (domyślny): flip bita w HMAC → ValueError."""
        key = os.urandom(32)
        ct = bytearray(aes_encrypt_tuta(key, b"Wiadomosc testowa"))
        ct[-1] ^= 0x01
        with pytest.raises(ValueError, match="HMAC mismatch"):
            aes_decrypt_tuta(key, bytes(ct))

    def test_hmac_mismatch_warns_with_skip_env(self, caplog, monkeypatch):
        """TUTA_SKIP_HMAC=1: flip bita w HMAC → WARNING w logu, deszyfracja kontynuuje."""
        monkeypatch.setenv("TUTA_SKIP_HMAC", "1")
        key = os.urandom(32)
        plaintext = b"Wiadomosc testowa"
        ct = bytearray(aes_encrypt_tuta(key, plaintext))
        ct[-1] ^= 0x01

        with caplog.at_level(logging.WARNING, logger="tuta.crypto"):
            result = aes_decrypt_tuta(key, bytes(ct))

        assert result == plaintext
        warnings = [r for r in caplog.records if "HMAC mismatch" in r.message]
        assert len(warnings) == 1
        assert "key_fp=" in warnings[0].message

    def test_hmac_ok_no_warning(self, caplog):
        """Brak mismatchu → brak WARNINGu (smoke test, że nie spamujemy)."""
        key = os.urandom(32)
        ct = aes_encrypt_tuta(key, b"czyste dane")
        with caplog.at_level(logging.WARNING, logger="tuta.crypto"):
            aes_decrypt_tuta(key, ct)
        warnings = [r for r in caplog.records if "HMAC mismatch" in r.message]
        assert len(warnings) == 0

    def test_too_short_raises(self):
        """Dane krótsze niż 49B (ver+IV+HMAC) → ValueError."""
        key = os.urandom(32)
        with pytest.raises(ValueError, match="za krótkie"):
            aes_decrypt_tuta(key, b"\x01" + b"\x00" * 30)

    def test_wrong_version_raises(self):
        """Version byte != 0x01 → ValueError."""
        key = os.urandom(32)
        bogus = b"\x02" + b"\x00" * 48
        with pytest.raises(ValueError, match="version byte"):
            aes_decrypt_tuta(key, bogus)


class TestMailUID:
    def _decoder(self):
        from tuta.mail_decoder import MailDecoder
        from tuta.crypto import UserKeys
        return MailDecoder(UserKeys(user_group_key=b"\x00"*16))

    def test_stable(self):
        d = self._decoder()
        assert d._id_to_uid("ABcDefGhIjKl") == d._id_to_uid("ABcDefGhIjKl")

    def test_positive(self):
        d = self._decoder()
        assert d._id_to_uid("SomeMailId") >= 0
