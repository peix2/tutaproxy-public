"""
Testy trwałego rejestru UID (bug: mail wpadający do folderu z opóźnieniem, ale
z wcześniejszym receivedDate, dostawał niższy UID i był niewidoczny dla klienta).

Sprawdza REALNY kod imap_server (_insert_mail_raw, _uid_of, uid_to_seq) + cache.
Uruchomienie: python3 test_uid_registry.py   (albo: pytest test_uid_registry.py)

Jeśli zależności runtime (aiohttp/cryptography) nie są zainstalowane, moduły są
zaślepiane — testowana logika UID ich nie dotyka.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _install_stubs() -> None:
    """Minimalne zaślepki aiohttp/cryptography — tylko po to, by zaimportować
    imap_server tam, gdzie brak zależności runtime. Kod UID ich nie używa."""
    import types

    def mod(name):
        m = types.ModuleType(name)
        sys.modules[name] = m
        return m

    if "aiohttp" not in sys.modules:
        mod("aiohttp")
    if "cryptography" not in sys.modules:
        c = mod("cryptography")
        h = mod("cryptography.hazmat"); c.hazmat = h
        p = mod("cryptography.hazmat.primitives"); h.primitives = p
        for a in ("hashes", "padding"):
            setattr(p, a, object())
        asym = mod("cryptography.hazmat.primitives.asymmetric"); p.asymmetric = asym
        asym.padding = object()
        ciph = mod("cryptography.hazmat.primitives.ciphers"); p.ciphers = ciph
        for a in ("Cipher", "algorithms", "modes"):
            setattr(ciph, a, object())


try:
    from tuta.imap_server import IMAPConnection, MailboxState, _elem_id
    from tuta.api import MailFolder
    from tuta.cache import TutaCache
except Exception:
    _install_stubs()
    from tuta.imap_server import IMAPConnection, MailboxState, _elem_id
    from tuta.api import MailFolder
    from tuta.cache import TutaCache


INBOX_ID = "OYJRAH_-2B-9"


def _mailbox(cache):
    """Świeże połączenie (bez __init__) z pustą skrzynką INBOX i realnym cache."""
    inbox = MailFolder(
        id=INBOX_ID,
        mail_list_id="entries-list",
        name_encrypted="",
        folder_type="1",
    )
    conn = IMAPConnection.__new__(IMAPConnection)
    conn.cache = cache
    conn.mailbox = MailboxState(folder=inbox, messages=[], uid_map={})
    return conn


def _mail(elem, received_ms, folder_id=INBOX_ID):
    """Surowy mail: pole 99 = [bag, elem], 1465 = mailSet, 107 = receivedDate."""
    return {
        "99": ["bag1", elem],
        "1465": [["setlist", folder_id]],
        "107": str(received_ms),
    }


def _fresh_cache():
    path = tempfile.mktemp(suffix=".db")
    return TutaCache(path), path


def test_late_mail_with_earlier_date_gets_higher_uid():
    """Rdzeń buga: test (S) zaobserwowany pierwszy, potem reply (R) z WCZEŚNIEJSZĄ
    datą, ale zaobserwowany później → R musi dostać WYŻSZY UID i wylądować na końcu."""
    cache, path = _fresh_cache()
    try:
        conn = _mailbox(cache)
        mail_S = _mail("S", received_ms=1_000_000_000_000)   # test, późniejsza data
        mail_R = _mail("R", received_ms=900_000_000_000)     # reply, wcześniejsza data

        assert conn._insert_mail_raw(mail_S) is True
        assert conn._insert_mail_raw(mail_R) is True   # R wpada PO S

        uid_S = conn._uid_of(mail_S)
        uid_R = conn._uid_of(mail_R)
        assert uid_R > uid_S, f"reply musi mieć wyższy UID: uid_S={uid_S} uid_R={uid_R}"

        # R na końcu listy = najwyższy numer seq → klient go pobierze
        assert conn.mailbox.messages[-1] is mail_R
        assert conn.mailbox.uid_to_seq(uid_S) == 1
        assert conn.mailbox.uid_to_seq(uid_R) == 2
    finally:
        cache.close(); os.unlink(path)


def test_insert_dedup_and_reject_foreign_folder():
    cache, path = _fresh_cache()
    try:
        conn = _mailbox(cache)
        mail_S = _mail("S", 1_000_000_000_000)
        assert conn._insert_mail_raw(mail_S) is True
        # Ponowny event tego samego maila → brak duplikatu
        assert conn._insert_mail_raw(mail_S) is False
        assert len(conn.mailbox.messages) == 1
        # Mail należący do innego folderu (1465 nie wskazuje INBOX-u) → odrzucony
        mail_foreign = _mail("X", 1_100_000_000_000, folder_id="OTHER-FOLDER")
        assert conn._insert_mail_raw(mail_foreign) is False
        assert len(conn.mailbox.messages) == 1
    finally:
        cache.close(); os.unlink(path)


def test_uid_stable_across_reselect():
    """UID przetrwa ponowny SELECT (rejestr trwały): re-numeracja po receivedDate
    dla nowej skrzynki daje te same UID-y co wcześniej nadane przy insercie."""
    cache, path = _fresh_cache()
    try:
        conn = _mailbox(cache)
        conn._insert_mail_raw(_mail("S", 1_000_000_000_000))
        conn._insert_mail_raw(_mail("R", 900_000_000_000))
        uid_S = cache.get_uid(INBOX_ID, "S")
        uid_R = cache.get_uid(INBOX_ID, "R")

        # Symulacja re-SELECT: assign_uids na tych samych mailach nie zmienia UID-ów
        remap = cache.assign_uids(INBOX_ID, ["R", "S"])   # kolejność bez znaczenia
        assert remap["S"] == uid_S
        assert remap["R"] == uid_R
        # Nowa poczta po re-SELECT dostaje kolejny (wyższy) UID
        assert cache.uid_for(INBOX_ID, "T") > max(uid_S, uid_R)
    finally:
        cache.close(); os.unlink(path)


class _FakeWriter:
    def write(self, *a): pass
    async def drain(self): pass


class _FakeClient:
    """Minimalny klient: zwraca ustalone MailSetEntry i maile po elem_id."""
    def __init__(self, entries, mails):
        self._entries = entries
        self._mails = mails

    async def _get_mailset_entries(self, session, list_id, start=None, count=1000):
        return self._entries

    async def get_single_mail(self, session, list_id, elem):
        return self._mails[elem]


def test_reconcile_adds_missing_mail_bypassing_1465():
    """Rdzeń Części 2: mail jest w MailSetEntry folderu, ale brakuje go w żywej
    skrzynce, a jego pole 1465 wskazuje INNY folder (opóźnienie po stronie Tuty).
    Rekoncyliacja NOOP i tak go dołoży (MailSetEntry autorytatywne) z UID = najwyższy."""
    import asyncio
    cache, path = _fresh_cache()
    try:
        conn = _mailbox(cache)
        conn.peer = "test"
        conn.writer = _FakeWriter()
        conn.session = object()
        conn._untagged = lambda *a, **k: None

        # Istniejący mail S (uid 1) — normalny insert (1465 pasuje do INBOX-u)
        mail_S = _mail("S", 1_000_000_000_000); mail_S["102"] = "k"
        assert conn._insert_mail_raw(mail_S) is True
        assert conn._uid_of(mail_S) == 1

        # R jest w MailSetEntry INBOX-u, BRAK w skrzynce, 1465 wskazuje inny folder
        mail_R = _mail("R", 900_000_000_000, folder_id="INNY-FOLDER"); mail_R["102"] = "k"
        entries = [{"1456": [["bag1", "R"]], "1452": ["setlist", "cid"]}]
        conn.client = _FakeClient(entries, {"R": mail_R})

        asyncio.run(conn._reconcile_folder())

        assert any(_elem_id(m.get("99", "")) == "R" for m in conn.mailbox.messages), \
            "reconcile powinien dołożyć maila obecnego w MailSetEntry"
        assert conn._uid_of(mail_R) == 2, "dołożony mail dostaje najwyższy UID"
        assert conn.mailbox.messages[-1] is mail_R, "dołożony mail na końcu (najwyższy seq)"
    finally:
        cache.close(); os.unlink(path)


def test_reconcile_noop_when_in_sync():
    """Gdy skrzynka zgadza się z MailSetEntry — reconcile nic nie dodaje."""
    import asyncio
    cache, path = _fresh_cache()
    try:
        conn = _mailbox(cache)
        conn.peer = "test"; conn.writer = _FakeWriter(); conn.session = object()
        conn._untagged = lambda *a, **k: None
        mail_S = _mail("S", 1_000_000_000_000); mail_S["102"] = "k"
        conn._insert_mail_raw(mail_S)
        entries = [{"1456": [["bag1", "S"]], "1452": ["setlist", "cid"]}]
        conn.client = _FakeClient(entries, {"S": mail_S})
        asyncio.run(conn._reconcile_folder())
        assert len(conn.mailbox.messages) == 1
    finally:
        cache.close(); os.unlink(path)


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"  PASS {t.__name__}")
    print(f"OK — {len(tests)} testów rejestru UID przeszło")


if __name__ == "__main__":
    _run_all()
