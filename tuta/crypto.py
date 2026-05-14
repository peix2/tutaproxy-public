"""
tuta/crypto.py
Warstwa kryptograficzna dla Tuta proxy.

Algorytm verifier (ustalony empirycznie + z dyskusji github.com/tutao/tutanota/discussions/2859):
  1. pw_hash    = SHA256(password.encode("utf-8"))          # 32 bajty
  2. bcrypt_out = bcrypt(pw_hash, bcrypt_salt, rounds=8)    # string "$2b$08$..."
  3. verifier   = base64url( SHA256(bcrypt_out.encode()) )  # 32 bajty → base64url

Gdzie bcrypt_salt to 16-bajtowy salt z Tuty zakodowany w formacie bcrypt base64:
  "$2b$08$" + bcrypt_b64_encode(salt)
"""

import base64
import hashlib
import hmac as _hmac
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

try:
    import argon2
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False

# ---------------------------------------------------------------------------
# Stałe
# ---------------------------------------------------------------------------

TUTA_AES128_KEY_LEN = 16
TUTA_AES256_KEY_LEN = 32
TUTA_IV_LEN = 16
CRYPTO_PROTO_VERSION_AES128 = 0x01
CRYPTO_PROTO_VERSION_AES256 = 0x02

# Staly IV uzywany w starym formacie Tuty (UnusedReservedUnauthenticated)
TUTA_FIXED_IV = bytes([0x88] * 16)

# Alfabet base64 używany przez bcrypt (różni się od standardowego)
# Mapowanie: standardowy base64 → bcrypt base64
_STANDARD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_BCRYPT_B64   = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_STD_TO_BCRYPT = str.maketrans(_STANDARD_B64, _BCRYPT_B64)
_BCRYPT_TO_STD = str.maketrans(_BCRYPT_B64, _STANDARD_B64)


# ---------------------------------------------------------------------------
# Typy danych
# ---------------------------------------------------------------------------

@dataclass
class UserKeys:
    user_group_key: bytes
    private_key_pem: Optional[bytes] = None
    x25519_private_key: Optional[bytes] = None
    kyber_private_key: Optional[bytes] = None


# ---------------------------------------------------------------------------
# bcrypt base64 (niestandardowy alfabet)
# ---------------------------------------------------------------------------

def _bcrypt_b64_encode(data: bytes) -> str:
    """
    Koduje bajty do bcrypt base64 (alfabet ./ zamiast +/).
    Używane do formatowania saltu dla bcrypt.
    """
    # Standardowe base64 bez paddingu
    std = base64.b64encode(data).decode().rstrip("=")
    # Zamień alfabet
    return std.translate(_STD_TO_BCRYPT)


def _make_bcrypt_salt(raw_salt: bytes) -> str:
    """
    Tworzy string saltu w formacie bcrypt z 16-bajtowego raw saltu Tuty.
    Format: "$2b$08$" + bcrypt_b64(salt)  (22 znaki base64 = 16 bajtów + padding)
    """
    encoded = _bcrypt_b64_encode(raw_salt)
    # bcrypt oczekuje dokładnie 22 znaków base64 dla 16-bajtowego saltu
    encoded = encoded[:22].ljust(22, ".")
    return f"$2b$08${encoded}"


# ---------------------------------------------------------------------------
# Verifier — autentykacja do serwera Tuty
# ---------------------------------------------------------------------------

def compute_verifier(password: str, salt: bytes, kdf_version: int) -> str:
    """
    Oblicza verifier do autentykacji (wysyłany do sessionservice).

    Algorytm (kdfVersion=0, bcrypt):
      1. pw_hash    = SHA256(password_utf8)
      2. bcrypt_str = bcrypt(pw_hash, "$2b$08$" + bcrypt_b64(salt), rounds=8)
      3. verifier   = base64url_nopad( SHA256(bcrypt_str_utf8) )

    Źródło: github.com/tutao/tutanota/discussions/2859
    """
    if kdf_version == 0:
        return _verifier_bcrypt(password, salt)
    elif kdf_version == 1:
        return _verifier_argon2(password, salt)
    else:
        raise ValueError(f"Nieznana wersja KDF: {kdf_version}")


def _verifier_bcrypt(password: str, salt: bytes) -> str:
    """Verifier przez bcrypt (kdfVersion=0)."""
    try:
        import bcrypt as _bcrypt
    except ImportError:
        try:
            # passlib jako alternatywa (zainstalowana przez mitmproxy)
            from passlib.hash import bcrypt as _passlib_bcrypt
            return _verifier_bcrypt_passlib(password, salt, _passlib_bcrypt)
        except ImportError:
            raise RuntimeError(
                "Brak biblioteki bcrypt. Zainstaluj: pip install bcrypt\n"
                "lub: pip install passlib[bcrypt]"
            )

    # Krok 1: SHA256 hasła
    pw_hash = hashlib.sha256(password.encode("utf-8")).digest()

    # Krok 2: bcrypt z niestandardowym saltem
    bcrypt_salt_str = _make_bcrypt_salt(salt)
    bcrypt_salt_bytes = bcrypt_salt_str.encode("utf-8")

    # bcrypt.hashpw oczekuje bytes password i bytes salt
    bcrypt_result = _bcrypt.hashpw(pw_hash, bcrypt_salt_bytes)
    # Wynik to np. b"$2b$08$<salt><hash>" — 60 bajtów

    # Krok 3: SHA256 wyniku bcrypt → base64url
    final_hash = hashlib.sha256(bcrypt_result).digest()
    return b64url_encode(final_hash)


def _verifier_bcrypt_passlib(password: str, salt: bytes, passlib_bcrypt) -> str:
    """Verifier przez passlib (fallback gdy nie ma bcrypt)."""
    pw_hash = hashlib.sha256(password.encode("utf-8")).digest()
    bcrypt_salt_str = _make_bcrypt_salt(salt)

    # passlib używa innego API
    result = passlib_bcrypt.using(rounds=8, salt=bcrypt_salt_str[7:]).hash(
        pw_hash.hex()  # passlib może wymagać stringa
    )
    final_hash = hashlib.sha256(result.encode("utf-8")).digest()
    return b64url_encode(final_hash)


def _verifier_argon2(password: str, salt: bytes) -> str:
    """Verifier przez argon2id (kdfVersion=1).

    Zweryfikowany algorytm (maj 2026):
      key      = argon2id(password_utf8, salt, t=4, m=32768, p=1, len=32)
      verifier = base64url(SHA256(key))
    """
    if not HAS_ARGON2:
        raise RuntimeError("Brak argon2-cffi: pip install argon2-cffi")
    import argon2.low_level as _argon2
    key = _argon2.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=4,
        memory_cost=32 * 1024,
        parallelism=1,
        hash_len=32,
        type=_argon2.Type.ID,
    )
    # WAŻNE: verifier = SHA256(key), nie samo key
    return b64url_encode(hashlib.sha256(key).digest())


# ---------------------------------------------------------------------------
# KDF — wyprowadzenie klucza szyfrowania z hasła
# ---------------------------------------------------------------------------

def derive_session_key(password: str, salt: bytes, kdf_version: int) -> bytes:
    """
    Wyprowadza klucz AES (16B) do odszyfrowania userGroupKey.

    To INNY output niż verifier — ten klucz nigdy nie opuszcza urządzenia.
    Algorytm bcrypt jest ten sam ale bierzemy surowe bajty zamiast SHA256.
    """
    if kdf_version == 0:
        return _session_key_bcrypt(password, salt)
    elif kdf_version == 1:
        return _session_key_argon2(password, salt)
    else:
        raise ValueError(f"Nieznana wersja KDF: {kdf_version}")


def _session_key_bcrypt(password: str, salt: bytes) -> bytes:
    """Klucz sesji przez bcrypt — pierwsze 16 bajtów raw hasha."""
    try:
        import bcrypt as _bcrypt
    except ImportError:
        raise RuntimeError("Brak biblioteki bcrypt: pip install bcrypt")

    pw_hash = hashlib.sha256(password.encode("utf-8")).digest()
    bcrypt_salt_str = _make_bcrypt_salt(salt)
    bcrypt_result = _bcrypt.hashpw(pw_hash, bcrypt_salt_str.encode())

    # Wynik bcrypt to string "$2b$08$<22 znaki salt><31 znakow hash>"
    # Hash zaczyna się od pozycji 29 (po "$2b$08$" + 22 znaki salt)
    hash_part = bcrypt_result[29:]  # 31 bajtów w bcrypt base64
    # Dekoduj bcrypt base64 → raw bytes → pierwsze 16 bajtów = klucz AES-128
    raw = _bcrypt_b64_decode(hash_part)
    return raw[:TUTA_AES128_KEY_LEN]


def _bcrypt_b64_decode(data: bytes) -> bytes:
    """Dekoduje bcrypt base64 do raw bytes."""
    s = data.decode("utf-8", errors="replace").rstrip("\x00")
    std = s.translate(_BCRYPT_TO_STD)
    # Dodaj padding
    pad = 4 - len(std) % 4
    if pad != 4:
        std += "=" * pad
    return base64.b64decode(std)


def _session_key_argon2(password: str, salt: bytes) -> bytes:
    """Klucz sesji przez argon2id — 32 bajty (AES-256)."""
    if not HAS_ARGON2:
        raise RuntimeError("Brak argon2-cffi")
    import argon2.low_level as _argon2
    return _argon2.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=4,
        memory_cost=32 * 1024,
        parallelism=1,
        hash_len=TUTA_AES256_KEY_LEN,
        type=_argon2.Type.ID,
    )


def decrypt_user_group_key(
    password: str, salt: bytes, kdf_version: int, encrypted_group_key: bytes
) -> bytes:
    """Odszyfrowuje symEncGKey z user.userGroup przy użyciu hasła.
    
    Dwa formaty:
    1. UnusedReservedUnauthenticated (32B, bez version byte, stały IV 0x88*16) — stare konta
    2. AesCbcThenHmac (81B, version byte 0x01, SHA512 derive) — nowe konta
    """
    session_key = derive_session_key(password, salt, kdf_version)
    
    if len(encrypted_group_key) % 2 == 0:
        # Stary format bez version byte - uzyj stalego IV
        return aes256_decrypt_fixed_iv(session_key, encrypted_group_key)
    
    version = encrypted_group_key[0]
    if version == 0x01:  # AesCbcThenHmac
        return aes_decrypt_tuta(session_key, encrypted_group_key)
    elif version == CRYPTO_PROTO_VERSION_AES256:  # 0x02
        return aes256_decrypt(session_key, encrypted_group_key)
    else:
        return aes128_decrypt(session_key[:TUTA_AES128_KEY_LEN], encrypted_group_key)


# ---------------------------------------------------------------------------
# AES-128-CBC
# ---------------------------------------------------------------------------

def aes128_decrypt(key: bytes, ciphertext: bytes, iv: Optional[bytes] = None) -> bytes:
    if len(key) != TUTA_AES128_KEY_LEN:
        raise ValueError(f"AES-128 wymaga klucza 16B, dostałem {len(key)}")
    if iv is None:
        if len(ciphertext) < 17:
            raise ValueError("Zbyt krótkie dane")
        iv = ciphertext[1:17]
        ciphertext = ciphertext[17:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes128_encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != TUTA_AES128_KEY_LEN:
        raise ValueError("AES-128 wymaga klucza 16B")
    iv = os.urandom(TUTA_IV_LEN)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return bytes([CRYPTO_PROTO_VERSION_AES128]) + iv + encryptor.update(padded) + encryptor.finalize()


# ---------------------------------------------------------------------------
# AES-256-CBC
# ---------------------------------------------------------------------------

def aes256_decrypt(key: bytes, ciphertext: bytes, iv: Optional[bytes] = None) -> bytes:
    if len(key) != TUTA_AES256_KEY_LEN:
        raise ValueError(f"AES-256 wymaga klucza 32B, dostałem {len(key)}")
    if iv is None:
        if len(ciphertext) < 17:
            raise ValueError("Zbyt krótkie dane")
        iv = ciphertext[1:17]
        ciphertext = ciphertext[17:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes256_encrypt(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != TUTA_AES256_KEY_LEN:
        raise ValueError("AES-256 wymaga klucza 32B")
    iv = os.urandom(TUTA_IV_LEN)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return bytes([CRYPTO_PROTO_VERSION_AES256]) + iv + encryptor.update(padded) + encryptor.finalize()


# ---------------------------------------------------------------------------
def aes256_decrypt_fixed_iv(key: bytes, ciphertext: bytes) -> bytes:
    """
    Odszyfrowuje kluczem AES-256 z stałym IV (format UnusedReservedUnauthenticated).
    Używane do odszyfrowywania symEncGKey z user.userGroup.
    Brak PKCS7 paddingu — długość plaintext = długość ciphertext.
    """
    if len(key) != TUTA_AES256_KEY_LEN:
        raise ValueError(f"AES-256 wymaga klucza 32B, dostałem {len(key)}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(TUTA_FIXED_IV))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes128_decrypt_fixed_iv(key: bytes, ciphertext: bytes) -> bytes:
    """
    Odszyfrowuje kluczem AES-128 z stałym IV (format UnusedReservedUnauthenticated).
    """
    if len(key) != TUTA_AES128_KEY_LEN:
        raise ValueError(f"AES-128 wymaga klucza 16B, dostałem {len(key)}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(TUTA_FIXED_IV))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# AesCbcThenHmac — główny format szyfrowania Tuty
# ---------------------------------------------------------------------------

def aes_decrypt_tuta(key: bytes, enc_data: bytes) -> bytes:
    """
    Odszyfrowuje dane w formacie AesCbcThenHmac (version byte 0x01).

    Format: [0x01][IV 16B][ciphertext][HMAC-SHA256 32B]
    deriveSubKeys: SHA512(key) → enc_key(32B) + hmac_key(32B)

    Używane do odszyfrowywania:
      - mail_group_key z membership['27'] (kluczem user_group_key)
      - mail_session_key z mail['102'] (kluczem mail_group_key)
      - treści maila z body['1276'] (kluczem mail_session_key)
    """
    if enc_data[0] != 0x01:
        raise ValueError(f"Oczekiwano version byte 0x01, dostałem {hex(enc_data[0])}")
    iv = enc_data[1:17]
    ciphertext = enc_data[17:-32]  # HMAC jest na końcu
    # HMAC ignorujemy — weryfikacja opcjonalna
    enc_key = hashlib.sha512(key).digest()[:32]
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    raw = cipher.decryptor().update(ciphertext) + b""
    # Usuń PKCS7 padding jeśli jest
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(raw) + unpadder.finalize()
    except Exception:
        return raw


def aes_encrypt_tuta(key: bytes, plaintext: bytes, add_padding: bool = True) -> bytes:
    """
    Szyfruje dane w formacie AesCbcThenHmac (version byte 0x01).
    Format: [0x01][IV 16B][ciphertext][HMAC-SHA256 32B]
    HMAC liczony nad: IV + ciphertext (bez version byte — legacy).
    add_padding=False dla szyfrowania kluczy (32B, już wyrównane do bloku AES).
    """
    derived = hashlib.sha512(key).digest()
    enc_key = derived[:32]
    hmac_key = derived[32:]

    iv = os.urandom(16)

    if add_padding:
        padder = padding.PKCS7(128).padder()
        padded_pt = padder.update(plaintext) + padder.finalize()
    else:
        padded_pt = plaintext

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded_pt) + enc.finalize()

    mac = _hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    return bytes([0x01]) + iv + ciphertext + mac


def decrypt_mail_group_key(user_group_key: bytes, enc_mail_group_key: bytes) -> bytes:
    """Odszyfrowuje klucz grupy mail (pole 27 w membership)."""
    return aes_decrypt_tuta(user_group_key, enc_mail_group_key)


def decrypt_mail_session_key(mail_group_key: bytes, enc_session_key: bytes) -> bytes:
    """Odszyfrowuje klucz sesji maila (pole 102 w mail)."""
    return aes_decrypt_tuta(mail_group_key, enc_session_key)


def decrypt_mail_body(mail_session_key: bytes, enc_body: bytes) -> bytes:
    """Odszyfrowuje zaszyfrowane body maila (pole 1276 w Body)."""
    return aes_decrypt_tuta(mail_session_key, enc_body)


# ---------------------------------------------------------------------------
# LZ4 decompress — format używany przez Tutę do kompresji treści maili
# ---------------------------------------------------------------------------

def compress_lz4(data: bytes) -> bytes:
    """
    Kompresuje dane do formatu LZ4 block (Tuta Compression.ts).
    Prosta implementacja — wszystkie dane jako ostatnia sekwencja literałów.
    Brak back-references = brak kompresji, ale format jest poprawny.
    """
    if not data:
        return b""
    result = bytearray()
    ll = len(data)
    if ll < 15:
        result.append(ll << 4)
    else:
        result.append(0xF0)  # token: ll=15 (max 4-bit), ml=0
        remaining = ll - 15
        while remaining >= 255:
            result.append(255)
            remaining -= 255
        result.append(remaining)
    result.extend(data)
    return bytes(result)


def uncompress_lz4(data: bytes) -> bytes:
    """
    Dekompresuje dane skompresowane algorytmem LZ4 (Tuta Compression.ts).
    Port z oficjalnej implementacji TypeScript Tuty.
    """
    i, j = 0, 0
    n = len(data)
    out = bytearray(max(n * 6, 1024))

    while i < n:
        token = data[i]; i += 1
        ll = token >> 4

        if ll > 0:
            l = ll + 240
            while l == 255:
                l = data[i]; i += 1
                ll += l
            end = i + ll
            while len(out) < j + ll:
                out.extend(bytearray(len(out)))
            while i < end:
                out[j] = data[i]; j += 1; i += 1
            if i == n:
                break

        offset = data[i] | (data[i + 1] << 8); i += 2
        if offset == 0 or offset > j:
            raise ValueError(f"LZ4: nieprawidłowy offset {offset} przy i={i} j={j}")

        ml = token & 0xf
        l = ml + 240
        while l == 255:
            l = data[i]; i += 1
            ml += l

        pos = j - offset
        end = j + ml + 4
        while len(out) < end:
            out.extend(bytearray(len(out)))
        while j < end:
            out[j] = out[pos]; j += 1; pos += 1

    return bytes(out[:j])


# RSA
# ---------------------------------------------------------------------------

def rsa_decrypt_key(rsa_private_key_der: bytes, encrypted_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    private_key = load_der_private_key(rsa_private_key_der, password=None)
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )


def rsa_oaep_encrypt_tuta(rsa_pub_raw: bytes, plaintext: bytes) -> bytes:
    """
    RSA-OAEP-SHA256 for legacy Tuta recipients (no PQ keys).

    rsa_pub_raw binary format: [2B big-endian modulus_len][modulus][2B exponent_len][exponent]
    This is the raw bytes behind pubRsaKey (base64) from PublicKeyService.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    offset = 0
    mod_len = int.from_bytes(rsa_pub_raw[offset:offset + 2], "big"); offset += 2
    modulus = int.from_bytes(rsa_pub_raw[offset:offset + mod_len], "big"); offset += mod_len
    exp_len = int.from_bytes(rsa_pub_raw[offset:offset + 2], "big"); offset += 2
    exponent = int.from_bytes(rsa_pub_raw[offset:offset + exp_len], "big")

    pub_key = RSAPublicNumbers(e=exponent, n=modulus).public_key(default_backend())
    return pub_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# X25519 — klucze i ECDH
# ---------------------------------------------------------------------------

def x25519_generate_keypair() -> tuple[bytes, bytes]:
    """Generuje efemeryczną parę kluczy X25519. Zwraca (priv_raw_32B, pub_raw_32B)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def x25519_dh(priv_bytes: bytes, pub_bytes: bytes) -> bytes:
    """X25519 ECDH. Zwraca 32-bajtowy shared secret."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = X25519PublicKey.from_public_bytes(pub_bytes)
    return priv.exchange(pub)


# ---------------------------------------------------------------------------
# PQ encoding — format Tuty (byteArraysToBytes)
# ---------------------------------------------------------------------------

def pq_encode_parts(parts: list[bytes]) -> bytes:
    """Koduje listę bajtów do formatu Tuty: każda część poprzedzona 2B big-endian długością."""
    buf = bytearray()
    for p in parts:
        buf += len(p).to_bytes(2, "big")
        buf += p
    return bytes(buf)


def pq_decode_parts(data: bytes, count: int) -> list[bytes]:
    """Odwrotność pq_encode_parts."""
    parts = []
    offset = 0
    for _ in range(count):
        length = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        parts.append(data[offset:offset + length])
        offset += length
    return parts


# ---------------------------------------------------------------------------
# HKDF-SHA256
# ---------------------------------------------------------------------------

def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 używany w TutaCrypt do wyprowadzenia KEK."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


# ---------------------------------------------------------------------------
# TutaCrypt encapsulation (PQFacade.encapsulateAndEncode)
# ---------------------------------------------------------------------------

# CryptoProtocolVersion.TUTA_CRYPT = "2" → bajt w soli HKDF
_TUTA_CRYPT_PROTO_BYTE = bytes([2])


def pq_encapsulate_bucket_key(
    sender_ecc_priv: bytes,
    sender_ecc_pub: bytes,
    recipient_ecc_pub: bytes,
    recipient_kyber_pub_tuta: bytes,
    bucket_key: bytes,
) -> bytes:
    """
    TutaCrypt encapsulation: szyfruje bucket_key dla odbiorcy z parą kluczy PQ.

    Protokół (PQFacade.ts + derivePQKEK):
      1. Efemeryczna para kluczy X25519
      2. ECDH: eph_shared = DH(eph_priv, recipient_ecc_pub)
      3. ECDH: auth_shared = DH(sender_ecc_priv, recipient_ecc_pub)
      4. Kyber-1024 encaps z kluczem publicznym odbiorcy
      5. HKDF-SHA256:
           salt = sender_ecc_pub || eph_pub || recipient_ecc_pub
                  || recipient_kyber_pub_tuta || kyber_ct || [2]
           ikm  = eph_shared || auth_shared || kyber_shared
           info = b"kek"
      6. kek_enc_bucket_key = aes_encrypt_tuta(kek, bucket_key, padding=True)
      7. PQMessage = pq_encode_parts([sender_ecc_pub, eph_pub, kyber_ct, kek_enc_bucket_key])
    """
    try:
        from kyber_py.kyber import Kyber1024
    except ModuleNotFoundError:
        raise RuntimeError("Brak kyber-py: pip install kyber-py")

    eph_priv, eph_pub = x25519_generate_keypair()
    ecc_eph_shared = x25519_dh(eph_priv, recipient_ecc_pub)
    ecc_auth_shared = x25519_dh(sender_ecc_priv, recipient_ecc_pub)

    # Klucz Kyber w formacie Tuty: pq_encode_parts([t(1536B), rho(32B)])
    # kyber-py oczekuje surowej postaci: t || rho (1568B)
    t, rho = pq_decode_parts(recipient_kyber_pub_tuta, 2)
    raw_kyber_pub = t + rho
    kyber_shared, kyber_ct = Kyber1024.encaps(raw_kyber_pub)

    context = (
        sender_ecc_pub + eph_pub + recipient_ecc_pub
        + recipient_kyber_pub_tuta + kyber_ct
        + _TUTA_CRYPT_PROTO_BYTE
    )
    ikm = ecc_eph_shared + ecc_auth_shared + kyber_shared
    kek = hkdf_sha256(salt=context, ikm=ikm, info=b"kek", length=32)

    kek_enc_bucket_key = aes_encrypt_tuta(kek, bucket_key, add_padding=True)
    return pq_encode_parts([sender_ecc_pub, eph_pub, kyber_ct, kek_enc_bucket_key])


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")
