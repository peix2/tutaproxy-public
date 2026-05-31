# Changelog

## v1.3.4 — 2026-06-01 — Telemetria: sprawdzanie wersji + liczenie instalacji

Opcjonalna telemetria (domyślnie włączona, wyłącz: `TUTAPROXY_TELEMETRY=false`).

- Przy starcie loguje dokładnie co jest wysyłane — pełna transparentność.
- Wysyła ping (UUID instalacji + wersja) do serwera zliczającego raz na 24h.
- Sprawdza GitHub Releases czy dostępna jest nowsza wersja (loguje WARNING jeśli tak).
- UUID generowany losowo, przechowywany w `/data/.tutaproxy-id` — nie jest powiązany
  z kontem Tuta ani żadnymi danymi użytkownika.

Pliki: `tuta/telemetry.py`, `run_proxy.py`, `docker/docker-compose.yml`.

## v1.3.3 — 2026-05-31 — Session lifecycle: 440 re-login + graceful shutdown

Trzy powiązane fixy dotyczące cyklu życia sesji Tuta.

### Bug — IMAP nie reagował na 440 SessionExpired (push mejli ginął)

Po dłuższym IDLE (godziny) Tuta zwracała `440 SessionExpiredError` przy próbie
pobrania nowego maila. Proxy obsługiwało re-login wyłącznie dla 401
(`NotAuthenticatedError`). Skutek: WebSocket event przychodził, `get_single_mail`
dostawało 3× 440 (exp backoff 1/2/4s), mail wpadał do `_pending_mail_ids`,
NOOP też retry'ował z wygasłą sesją → mail nigdy nie docierał do Thunderbirda.

Dodatkowo `_credentials` (tuple email+password potrzebny do `_try_relogin`)
**nigdy nie był ustawiany** w `_cmd_login`/`_cmd_authenticate` — cały istniejący
re-login na 401 był martwym kodem.

Fix:
- `_cmd_login` i `_cmd_authenticate` zapisują `self._credentials` po sukcesie.
- Command handler, `_idle_handle_new_mail` i NOOP pending retry traktują 440
  tak samo jak 401: invalidate session, `_try_relogin()`, ponów raz.

Pliki: `tuta/imap_server.py`.

### DAV — to samo dla CalDAV/CardDAV/WebDAV

DAV cache `_get_session` zwracał starą sesję dla cached emaila bez sprawdzenia
czy access token jeszcze żyje. Po 440 SessionExpired każdy kolejny request
też dostawał 440 aż klient zmienił hasło.

Fix: każdy serwer DAV dostał `_invalidate_session(email)` i wrapper
`_dispatch_with_relogin(req)` — przy 440 wywala sesję z cache i ponawia
cały request raz (świeży `_get_session` zaloguje nową). Handlery które łapały
TutaAPIError lokalnie teraz przepuszczają 440 do wrappera (`if status_code == 440: raise`).

Pliki: `tuta/caldav_server.py`, `tuta/carddav_server.py`, `tuta/webdav_server.py`.

### Graceful shutdown — naprawienie wycieku sesji w UI Tuty

`TutaClient.logout()` (DELETE `/sys/session/{accessToken}`) istniał ale **nigdzie
nie był wołany**. Skutki w UI Tuty: dziesiątki "active sessions" zostawianych
po każdym restarcie proxy, każdym restarcie Thunderbirda, każdym uruchomieniu
SMTP send. Token TTL Tuty to wiele godzin — sesje czyściły się dopiero same.

Dodatkowo:
- DAV serwery (caldav/carddav/webdav) nie miały w ogóle metody `stop()`.
- `run_proxy.py` w `finally` wołał tylko `imap.stop()` i `smtp.stop()` —
  pomijał wszystkie 3 DAV-y.
- Brak `SIGTERM` handlera — `docker stop` wysyła SIGTERM (nie SIGINT), więc
  `KeyboardInterrupt` w `run_proxy.py` nigdy się nie wyzwalał w kontenerze.
  Cały (ograniczony) cleanup był ignorowany.

Fix:
- IMAPServer trzyma `self._connections: set[IMAPConnection]`; nowa metoda
  `IMAPConnection.graceful_logout()` wysyła `* BYE` i `client.logout(session)`.
  `IMAPServer.stop()` woła ją równolegle dla wszystkich aktywnych.
- SMTP loguje świeżą sesję per-request → dodany `finally` z `client.logout`
  po każdym `handle_DATA`.
- CalDAV/CardDAV/WebDAV mają teraz `stop()` które zamyka listener, loguje
  wszystkie sesje z cache (`client.logout`) i zamyka klientów aiohttp.
- `run_proxy.py` rejestruje `SIGTERM`/`SIGINT` przez `loop.add_signal_handler`
  i woła `stop()` na wszystkich 5 serwerach z timeoutem 15s.

Pliki: `tuta/imap_server.py`, `tuta/smtp_server.py`, `tuta/caldav_server.py`,
`tuta/carddav_server.py`, `tuta/webdav_server.py`, `run_proxy.py`.

Test po wdrożeniu: w UI Tuty (Settings → Login → Active sessions) lista po
`docker stop tutaproxy` powinna być pusta (lub przynajmniej nie rosnąć po
każdym restarcie).

## v1.3.2 — 2026-05-29 — Security fixy po review

Trzy poprawki bezpieczeństwa znalezione w sesji review. Szczegóły i uzasadnienia
wyborów w README, sekcja "Poprawki bezpieczeństwa — 2026-05-29".

### Security — DAV auth bypass (krytyczne)

CalDAV/CardDAV/WebDAV `_get_session` cachowało sesję po samym emailu, bez
weryfikacji hasła. Drugi request z innym hasłem dla tego samego emaila
dostawał pełną sesję pierwszego.

Fix: cache trzyma `(session, client, sha256(password))`. Hit cache tylko gdy
`hmac.compare_digest(stored_hash, sha256(password))`. Mismatch → normalna
ścieżka logowania (Tuta odrzuca złe hasło). Stary klient zamykany przy zmianie hasła.

Pliki: `tuta/caldav_server.py`, `tuta/carddav_server.py`, `tuta/webdav_server.py`.

### Security — default bind 0.0.0.0 → 127.0.0.1

`run_proxy.py` miało `0.0.0.0` jako default mimo deklaracji w README "127.0.0.1
by default". Bez TLS-a hasło Tuty i całe konto eksponowane przy uruchomieniu
poza Dockerem. Docker nadpisuje przez ENV w Dockerfile — nie zmieniony.

Plik: `run_proxy.py` (5 defaultów + docstring).

**Regresja w Dockerfile (wykryta przy teście WebDAV mount)**: Dockerfile nie
ustawiał `TUTA_WEBDAV_HOST=0.0.0.0` ani `EXPOSE 5234` — WebDAV (M10) został
dodany po początkowej wersji obrazu i Dockerfile pominął te env vars. Wcześniej
maskowane przez default `0.0.0.0` w `run_proxy.py`; po fixie tego defaultu
WebDAV bindował na 127.0.0.1 wewnątrz kontenera, port mapping Dockera (host
127.0.0.1:5234 → kontener 5234) nie miał jak dojść. Mount `davfs` dostawał
"Połączenie zerwane przez drugą stronę".

Fix: dodano `TUTA_WEBDAV_HOST=0.0.0.0`, `TUTA_WEBDAV_PORT=5234` i `5234`
do `EXPOSE`. Wymaga przebudowy obrazu: `docker-compose up -d --build`.

Plik: `docker/Dockerfile`.

### Security — HMAC weryfikacja w aes_decrypt_tuta (warn-only)

`aes_decrypt_tuta` ignorował HMAC ("weryfikacja opcjonalna"). Tryb warn-only:
oczekiwany HMAC porównywany stałoczasowo, mismatch → `logger.warning(...)`
z fingerprintem klucza, ale deszyfrowanie kontynuowane.

Wybór warn-only zamiast strict: komentarz w kodzie sugerował że strict mógłby
łamać działanie na nietypowych danych Tuty. Po okresie obserwacji bez warningów
plan: tryb strict z ENV `TUTA_SKIP_HMAC=1` jako kill-switch (szczegóły w README).

Pliki: `tuta/crypto.py` (dodano `import logging`, `logger`, weryfikacja HMAC).

---

## v1.3.1 — 2026-05-29

### Fix
- **WebDAV DELETE zwracał 502**: pole `105` (`restore`) w ciele `DriveFolderServiceDeleteIn`
  wysyłane jako Python `False` (JSON `false`) zamiast stringa `"0"`.
  Tuta API serializuje Boolean jako `"0"`/`"1"` — raw boolean był odrzucany przez serwer.

---

## v1.3.0 — 2026-05-28 (WebDAV — Tuta Drive)

### WebDAV server (Tuta Drive)

- **`files_list_id` (pole 38) jako lista**: pole zwracane przez API jako `["listId"]`,
  nie string — fix: `isinstance(files_list_id_raw, list)` zamiast zakładania stringa.
  Bez tego fix każdy folder zwracał `[], []` (0 plików, 0 podfolderów).

- **Multi-chunk upload**: split na 10 MB chunki, szyfrowanie AES-256 per chunk,
  retry × 3, auto-refresh blob tokenu (403 → nowy token), timeout 10 min per chunk.

- **Deduplicacja równoległych PUT**: `asyncio.Lock` per ścieżka + pinned files cache (5 min TTL).

- **Eventual consistency**: pinned files domieszane do listingu folderu przez 5 min.

---

## v1.2.4 — 2026-05-28 (CalDAV blob DELETE — fixy)

### Dwa bugi w blob PUT DELETE

**Bug 1: orphan override po usunięciu cyklu**

Thunderbird usuwa eventy cykliczne przez blob PUT (GET / → PUT / z pominiętym UID).
`uid_map` był słownikiem `safe_uid → CalendarEvent`, więc przy jednym UID z masterem
i overridem (recurrence_id) słownik trzymał tylko jeden z nich. DELETE pętla usuwała
tylko jeden event — orphan override z `recurrence_id` zostawał w Tucie. Przy kolejnym
GET / proxy emitowało go jako RECURRENCE-ID bez mastera — Thunderbird odrzucał cały
kalendarz ("temporarily unavailable").

Fix: `uid_to_all: dict[str, list]` — mapuje UID → lista WSZYSTKICH eventów z tym UID.
DELETE pętla iteruje po liście i usuwa każdy z nich.

**Bug 2: "modification failed" przy usuwaniu ostatniego eventu**

Thunderbird wysyła PUT / z pustym VCALENDAR (zero VEVENT) przy usuwaniu ostatniego
eventu w kalendarzu. Kod zwracał `400 Bad Request` ("brak VEVENT") — Thunderbird
wyświetlał "modification failed".

Fix: pusty VCALENDAR traktowany jak normalny diff — `put_uids = set()`, wszystkie
snapshottowane eventy usuwane. Tylko brak BEGIN:VCALENDAR lub pusty body zwraca 400.

**Zmiany w `caldav_server.py`**:
- `_handle_put` blob mode: `uid_to_all` zamiast `uid_map` w DELETE pętli
- `_handle_put` blob mode: pusty VCALENDAR nie zwraca 400
- `events_to_ical`: orphan override emitowany jako regularny event zamiast pominięcia

---

## v1.2.3 — 2026-05-28 (RECURRENCE-ID dla wyjątków cyklu)

Gdy użytkownik modyfikuje jedno powtórzenie eventu cyklicznego w Tucie, Tuta tworzy
drugi `CalendarEvent` z tym samym `uid` i ustawionym polem `recurrenceId` (1320).
Proxy nie odczytywało tego pola — Thunderbird nie mógł połączyć wyjątku z cyklem.

**Zmiany w `api.py`**:
- `CalendarEvent` — nowe pole `recurrence_id: Optional[datetime]`
- `_decrypt_calendar_event` — odczytuje pole `1320` (`recurrenceId`, encrypted date)

**Zmiany w `caldav_server.py`**:
- `_event_to_vevent` — emituje `RECURRENCE-ID` z prawidłowym formatem
- `events_to_ical` — buduje `uid_to_tz` i `uid_to_override_ms`
- EXDATE w masterze filtrowany z dat które mają override (RFC 5545 §3.8.5.1)

**Naprawione bugi**:
1. EXDATE + RECURRENCE-ID konflikt — nie emitujemy EXDATE dla dat z override
2. Błąd timezone przy porównaniu ms — `replace(tzinfo=utc)` przed `timestamp()`

---

## v1.2.2 — 2026-05-28 (VTIMEZONE w iCal)

Eventy cykliczne z niezerową strefą czasową były eksportowane z `DTSTART;TZID=...`
bez bloku `VTIMEZONE` — RFC 5545 wymaga VTIMEZONE jeśli używane jest TZID.

Nowa funkcja `_vtimezone_block(tz_str)` w `caldav_server.py`:
- Skanuje bieżący rok godzinowo przez `zoneinfo.ZoneInfo`, wykrywa przejścia DST
- Emituje komponenty `DAYLIGHT` i `STANDARD` z konkretnymi datami
- Dla stref bez DST: jeden komponent `STANDARD` z `DTSTART:19700101T000000`

---

## v1.2.1 — 2026-05-27 (CardDAV batch DELETE)

CardBook wysyła DELETE requests równolegle (~6 na raz). Przy bulk delete >100 kontaktów
CardBook przerywał cykl i czekał na ręczną synchronizację.

**Rozwiązanie**: bufor batcha z timerem 150ms w `carddav_server.py` + `eraseMultiple` w Tucie.

- `delete_contacts_bulk_api()` — `DELETE ?ids=id1,id2,...` (jeden HTTP request)
- `_DeleteBatch` + timer — zbiera równoległe DELETE, wysyła jeden `eraseMultiple`

**Wynik**: bulk delete 856 kontaktów bez przerw; batche 1–5 kontaktów co ~300ms.

---

## v1.2.0 — 2026-05-27 (CardDAV — kontakty)

Zaimplementowano pełny serwer CardDAV (RFC 6352). Nowe pliki: `tuta/carddav_server.py`, `run_carddav.py`.

Kluczowe bugi naprawione:
1. `"852": null` vs `"852": []` — asocjacje ZeroOrOne muszą być `[]`, nie `null`
2. Pola FINAL przy UPDATE — `_kdfNonce` (1837) i `_ownerKeyVersion` (1394) z `existing_raw`
3. PersistenceResourcePostReturn — pole `"2"` = nowy elem_id (nie string ani lista)
4. CardBook "dostępna offline" — bez tej opcji CardBook działa read-only
5. `current-user-privilege-set` wymagany w PROPFIND depth=1 (nie tylko depth=0)
6. loadRoot — dwuetapowy przez RootInstance, nie bezpośredni URL

---

## v1.1.0 — 2026-05-27 (IMAP fixes + release)

### Persistent WebSocket watcher (IMAP IDLE)

Root cause: między sesjami IMAP IDLE był 2-3 sekundowy gap bez WebSocket.
Eventy CREATE w tym oknie były tracone.

Naprawka: background task `_bg_event_watcher` trzyma WebSocket alive przez całą sesję.
Eventy trafiają do `asyncio.Queue`; IDLE i NOOP drainują z kolejki.

### PQ decaps fix

`dict.get("2045", "")` zwracało `None` gdy klucz istnieje z wartością null
→ `base64.b64decode(None)` → TypeError.

Naprawka: `pq_msg_b64 = entry.get("2045") or ""`.

---

## v1.0.2 — 2026-05-14 (parametryzacja wersji API)

Wersje modeli odczytywane ze zmiennych środowiskowych:
- `TUTA_SYS_VERSION` (default: 150)
- `TUTA_TUTANOTA_VERSION` (default: 108)
- `TUTA_STORAGE_VERSION` (default: 14)
- `TUTA_CLIENT_VERSION` (default: 346.260428.0)

`_check_version_mismatch()` — na HTTP 412 lub błąd z "model"/"version" loguje WARNING
z aktualnymi wersjami i instrukcją co zrobić.

---

## v1.0.1 — 2026-05-14 (Docker + publikacja)

- `run_proxy.py` — IMAP + SMTP w jednej pętli asyncio
- `docker/Dockerfile` + `docker/docker-compose.yml`
- Publiczne repo: https://github.com/peix2/tutaproxy-public (AGPL v3)

---

## v1.0.0 — 2026-05-14 (attachments fix)

**Upload blob (v=14 w nagłówkach)**: POST do `blobservice` miał `v=14` w query params
zamiast w nagłówkach — serwer odrzucał ze statusem 400.

**AttachmentKeyData.file (pole 546) = `[[listId, elemId]]`**: `LIST_ELEMENT_ASSOCIATION_GENERATED One`
musi być podwójnie opakowane.

---

## v0.9 — 2026-05-12 (poprzedni checkpoint)

Wszystkie funkcje M2 działają w Thunderbirdzie, w tym zarządzanie folderami.

**Naprawione (2026-05-11)**:
- `v=14` musiało być w nagłówkach HTTP requesta do `blobservice GET`
- Cache `_get_rfc822()` per elementId — eliminuje wielokrotne pobieranie przy partial fetch
- Sort UID po CRC32 — Thunderbird wymagał UID rosnących

**Naprawione (2026-05-12)**:
- CREATE folder — `ZeroOrOne` = `[]` nie `null`
- Parsowanie odpowiedzi create_folder — `resp.get("457",[[]])[0]`
- Hierarchia folderów w LIST — rekurencyjne budowanie ścieżki
- RENAME — dwa osobne endpointy (PUT mailset + PUT mailfolderservice)
- `entries` (pole 1459) — `LIST_ASSOCIATION One` = `["listId"]` nie `"listId"`
- Thunderbird DELETE = RENAME do Trash

**Naprawione (2026-05-13) — Drafts**:
- `_random_custom_id()` — 4 bajty (6 znaków), nie 12
- IMAP APPEND — Drafts przez `create_draft`, Sent odrzucane
- Drafts — pole 1309 → MailDetailsDraft (nie blob), format `[[listId, elemId]]`
