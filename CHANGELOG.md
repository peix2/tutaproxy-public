# Changelog

## v1.3.14 — 2026-07-29 — IMAP: moving/selecting a folder changed on another connection

### Bug fix: move to a just-reparented folder failed ("folder not found")

**Symptom** (Thunderbird): a folder created as a subfolder of Inbox and then
moved up to the top level (reparent). Moving a mail from Inbox into that folder
did nothing — the mail "came back" to Inbox. Workaround: move the mail to a
different, older folder first, then into the target.

**Root cause**: the folder cache (`IMAPConnection._folders`) is per-connection
and only invalidated by a folder operation on the *same* connection (CREATE/
DELETE/RENAME) or a re-login. Thunderbird keeps a connection pool: the reparent
runs on one connection while the move (IMAP COPY + `\Deleted` + EXPUNGE) runs on
another — with a stale cache that still sees the folder under its old path
(`INBOX/name`). The IMAP-name lookup misses → `COPY: folder '…' not found` (NO).
Thunderbird had optimistically hidden the message, so after a resync it reappears
in Inbox.

The bug does *not* occur at the API level (the move itself works, including into
a folder created under Inbox and reparented to root) — only in the IMAP layer.
Reproduced with two IMAP connections (one RENAME, the other COPY): the stale
connection returned `NO folder not found`, the fresh one `OK`.

### Change (`tuta/imap_server.py`)

- New `_find_folder_by_name()` helper with refresh-on-miss (cache miss → refresh
  → retry): if a folder is not found by IMAP name, the cache is invalidated once
  and the lookup retried.
- Wired into COPY, SELECT and STATUS — also deduplicates the repeated lookup
  pattern.

## v1.3.13 — 2026-06-23 — IMAP FETCH: bounce with DSN report no longer crashes

### Bug fix: FETCH crashed on bounce messages

A bounce message (e.g. "mailbox full") carrying a `message/delivery-status`
attachment made `FETCH` fail with `'str' object has no attribute 'policy'`.
Thunderbird showed the mail header (fast path, no API call) but never received
the body.

Root cause: `build_rfc2822()` built every attachment as `MIMEBase` + base64.
For `message/*` (other than rfc822) and `multipart/*` types, `email.generator`
has dedicated handlers (`_handle_message_delivery_status`, `_handle_multipart`)
that iterate the payload expecting nested `Message` objects — a base64 string
has no `.policy` attribute, so `as_bytes()` raised and the whole FETCH failed.

### Changes

- `tuta/message_builder.py` — attachments of type `message/*` (other than
  rfc822) and `multipart/*` are demoted to `application/octet-stream`. Raw data
  is preserved; the human-readable bounce text is already in the body. A
  `message/rfc822` part is left untouched — Thunderbird re-parses it and shows
  the embedded original.

## v1.3.12 — 2026-06-16 — Permanent delete fix (folder field)

### Bug fix: permanent mail deletion failed with HTTP 400

`delete_mails` (DELETE /rest/tutanota/mailservice, DeleteMailData) sent the
`folder` field (724, a ZeroOrOne association) as `null` when no source folder
was given, which the server rejects with HTTP 400. Permanent deletion of mails
already in Trash/Spam therefore failed.

Fixed by sending an empty array `[]` when no folder is given and a wrapped
`[[listId, elementId]]` when one is — the same pattern already used for
`excludeMailSet` in `move_mails_to_folder`.

### Changes

- `tuta/api.py` — `delete_mails`: field 724 as `[]` / `[[listId, elementId]]`
  instead of `null`

## v1.3.11 — 2026-06-16 — From header fix + Date in local timezone

### Bug fix: malformed `From:` header

When opening a sent mail, the `From:` header could appear as
`Name <email@example.com> <>` — with a spurious trailing `<>`.

Root cause: `_format_address()` unconditionally wrapped the name in
`<address>` even when `address` was an empty string (which Tuta can return
for the sender field in Sent-folder mails). Fixed by only adding `<address>`
when the address is non-empty.

### Date header in local timezone

The `Date:` header was always formatted as UTC (`+0000`). Email clients
display dates in local time in the message list, but forwarded-message
blocks include the raw header — so the timezone offset was visible to users
as `+0000`.

The date is now formatted using the local timezone from the `TZ` environment
variable (already present in `docker-compose.yml` as `TZ: Pacific/Auckland`
or the equivalent for your location) or the system timezone when running
outside Docker.

As a side effect, `sentDate` (field 1284 from MailDetails) is now preferred
over `receivedDate` (field 107) as the `Date:` header timestamp — this
reflects when the sender dispatched the message rather than when the server
received it.

### Changes

- `tuta/message_builder.py` — `_format_address`: skip `<address>` wrapper
  when address is empty
- `tuta/message_builder.py` — `build_rfc2822`: use `sentDate` (1284) with
  `receivedDate` (107) fallback; format with local timezone via `.astimezone()`
- `tuta/imap_server.py` — `_get_quick_headers`: same local-timezone fix for
  the quick `Date:` header

## v1.3.10 — 2026-06-13 — Move to custom folders + labels (MailSetKind)

`movemailservice` returned **400 (empty body)** when moving a mail into a custom
folder (type 0). The fix turned out to be about the association-serialization
convention, not a new API shape:

- `447` (targetFolder, a One association) was sent flat as `[list, elem]` — it must
  be wrapped: `[[list, elem]]`.
- `1644` (excludeMailSet, ZeroOrOne) was sent as `null` — it must be `[]`.

Second finding: `folderType "8"` is a **label (MailSetKind.LABEL)**, not a custom
folder. In the unified model, folders and labels are both MailSets and arrive
together from `/mailset`. A label is applied via a separate service, not by moving.

### Changes (`tuta/api.py`)

- `move_mails_to_folder()`: corrected serialization (447 wrapped, 1644 = `[]`),
  plus grouping mails by mailbag listId and chunking by 50 (like the official
  client). Now works for both custom and system folders.
- `apply_labels()`: new method — add/remove labels via `ApplyLabelService`
  (entity 1504).
- `MailFolder`: `is_label` / `is_system` / `is_custom` properties + `FOLDER_*`
  constants for the full MailSetKind enum (0–10).

### IMAP (`tuta/imap_server.py`)

- Labels (type 8) are no longer exposed as IMAP folders, so a client can't try to
  "move" a mail into a label (which the server doesn't support). Moving into a
  custom folder now works thanks to the `api.py` fix.

## v1.3.9 — 2026-06-12 — SMTP: session cache (login reused across messages)

SMTP logged in a fresh session for **every** message (full argon2id m=32MB,t=4 +
handshake to Tuta) and logged out immediately. A queue of N messages = N× argon2 →
CPU pegged, an easy DoS and poor throughput on bursts.

### SMTP session cache (`tuta/smtp_server.py`)

The handler now keeps `dict[email] → (session, sha256(pw), monotonic_ts)`, modeled
on the DAV cache:

- Session reused across messages within a TTL (`_SMTP_SESSION_TTL = 300s`). The Tuta
  token lives for hours; a short TTL limits how long a session sits in memory and
  forces a periodic fresh login.
- Constant-time `hmac.compare_digest(sha256(pw))` — the cache never returns a session
  for a different password (auth-bypass guard).
- Per-email `asyncio.Lock` — concurrent messages from the same user wait instead of
  logging in twice; double-checked under the lock.
- An old session (different password / expired TTL) is logged out before replacement,
  so active sessions don't pile up in the Tuta UI.
- On `401`/`440` during send (session expired server-side): invalidate + one retry
  with a fresh login.
- Logout moved from per-message to TTL/shutdown: `SMTPServer.stop()` calls
  `logout_all()` (graceful logout of all cached sessions).

The send logic was extracted from `handle_DATA` into `_send_message()` (attachment
upload → create_draft → send_draft: E2E / Secure External / non-confidential).

## v1.3.8 — 2026-06-12 — Security: fail closed on key errors, telemetry without mTLS

Security review of the Tuta-facing communication. Three classes of fixes in
`tuta/api.py`, plus a change to the telemetry trust model.

### Fail closed — `_load_user_keys` (`tuta/api.py`)

Three error paths returned `b"\x00" * 32` instead of aborting login. An all-zero
dummy key would silently encrypt and decrypt data with a real (zero) key rather
than surfacing the failure — quiet and dangerous. All three now abort:

- User-data fetch fails → `logger.error` + `raise` (was a warning + dummy key).
- Missing `symEncGKey` → `TutaAPIError`.
- `userGroupKey` decryption error → `TutaAPIError(...) from e`.

Callers (`_cmd_login`/`_cmd_authenticate` in IMAP, `handle_DATA` in SMTP) already
handle these exceptions, so login now returns an error instead of admitting a
session backed by a dummy key.

### Logs no longer leak key material (`tuta/api.py`)

Removed/trimmed `logger.debug` calls that printed key fragments and full request
bodies: `symEncGKey` (hex bytes), `salt`, `verifier`, the full `create_draft`
body, and the calendar group key hex. Logs now show lengths only, never content.

### Salt request — JSON injection (`tuta/api.py`)

`login()` built the `_body` parameter with an f-string and an unescaped email; a
`"` in the address broke the request structure. Now built with `json.dumps`.

### Telemetry: server pinning instead of mTLS

The telemetry client certificate was committed to this public repo. In an
open-source (AGPL) project a shipped secret is public, so mTLS gave no real
client authentication. Removed `client.crt`/`client.key`; the client now pins
only the server via `ca.crt` (channel confidentiality + server identity, IP in
SAN), with abuse control handled by nginx rate limiting. The previously committed
client certificate is now inert — the server no longer verifies client
certificates.

Files: `tuta/api.py`, `tuta/telemetry.py`, `tuta/certs/`.

## v1.3.7 — 2026-06-11 — HMAC strict mode + stability fixes

### Security — HMAC verification now strict

`aes_decrypt_tuta` previously logged a warning on HMAC mismatch but continued
decrypting (warn-only mode, introduced in v1.3.2 to avoid regressions on unknown
legacy ciphertext formats). After 13 days of production use with zero HMAC
warnings, the mode has been switched to **strict**: a mismatch now raises
`ValueError` and aborts decryption.

If you ever hit a regression on unusual data, set `TUTA_SKIP_HMAC=1` as a
kill-switch — this restores the old warn-only behaviour.

File: `tuta/crypto.py`.

### Cleanup — removed dead bcrypt fallback code

`_verifier_bcrypt` contained a try/except that fell back to `passlib` when the
`bcrypt` package was not installed. The passlib path had a bug (it passed
`pw_hash.hex()` instead of the raw bytes, so the resulting verifier was always
wrong — login would always fail). Since `bcrypt` has been a hard requirement
since day one, the fallback was never reachable in a correct installation.

Removed `_verifier_bcrypt_passlib` and the surrounding try/except. A missing
`bcrypt` package now raises a clear `RuntimeError: bcrypt is required: pip install bcrypt`.

File: `tuta/crypto.py`.

### Fix — WebSocket reconnect exponential backoff

The persistent WebSocket event watcher in the IMAP server reconnected after a
fixed delay: 2 s on a clean close, 5 s on an exception. If the Tuta server
returned a persistent error (e.g. an API version mismatch), the watcher
hammered the server with reconnect attempts every few seconds.

Replaced with exponential backoff: 2 → 4 → 8 → … → 60 s (maximum). The delay
resets to 2 s after any successful stream of events.

File: `tuta/imap_server.py`.

### Fix — version mismatch detection based on HTTP status only

`_check_version_mismatch` logged a "possible API version mismatch" warning
whenever certain keywords (`"model"`, `"version"`, `"outdated"`, `"incompatible"`)
appeared in any error response body. This was both noisy (false positives on
unrelated errors) and fragile (false negatives when Tuta changes its error
messages).

Tuta's documented status for a model version conflict is **HTTP 412 Precondition
Failed**. The check now triggers only on 412.

File: `tuta/api.py`.

---

## v1.3.6 — 2026-06-01 — IMAP STORE performance + log rotation

### Performance — IMAP STORE O(N×M) → O(1)

After marking messages as read/unread via the Tuta API, the proxy updated local
state with a nested loop: for each `(listId, elemId)` pair in the operation, it
scanned the entire mailbox message list. On a folder with 10k messages and a STORE
of 100 entries, that was 1 million iterations.

Fix: build an `elem_id → mail_raw` dict once before the API call and replace both
inner loops with a single `dict.get()`.

File: `tuta/imap_server.py`.

### Ops — log rotation

All `run_*.py` scripts now use `RotatingFileHandler` instead of a plain
`FileHandler` when `LOG_FILE` is set. Defaults: 50 MB per file, 5 backup files.
Configurable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `LOG_ROTATE_BYTES` | `52428800` (50 MB) | Max log file size before rotation |
| `LOG_ROTATE_COUNT` | `5` | Number of rotated backup files to keep |

Files: `run_proxy.py`, `run_imap.py`, `run_smtp.py`, `run_caldav.py`, `run_carddav.py`, `run_webdav.py`.

---

## v1.3.5 — 2026-06-01 — Security fixes

### Security — Content-Length limit in CalDAV and CardDAV

`caldav_server.py` and `carddav_server.py` read request bodies up to whatever
size the `Content-Length` header claimed, with no upper bound. A malicious local
client could attempt to allocate e.g. 10 GB. The `Content-Length` header value was
also not validated — a non-numeric value caused an unhandled `ValueError`.

Fix: `MAX_BODY = 50 MB` constant; the header value is parsed in a `try/except`
block and requests exceeding the limit are rejected before reading the body.
(WebDAV already had a `MAX_UPLOAD = 512 MB` limit — same pattern.)

Files: `tuta/caldav_server.py`, `tuta/carddav_server.py`.

### Security — XSS in plain-text → HTML conversion

When converting a plain-text email body to HTML (wrapping it in `<pre>` tags),
the content was interpolated directly:
```python
text = f"<html><body><pre>{text}</pre></body></html>"
```
A plain-text message containing `</pre><script>alert(1)</script>` would be sent
to Tuta as raw HTML — Tuta's web UI would render the injected markup.

Fix: `html.escape()` applied to the text before interpolation. Affects both the
outgoing path (SMTP) and the incoming path (IMAP APPEND).

Files: `tuta/smtp_server.py`, `tuta/imap_server.py`.

---

## v1.3.4 — 2026-06-01 — Telemetry: version check + installation counting

Optional telemetry, enabled by default. Disable with `TUTAPROXY_TELEMETRY=false`.

- Logs exactly what is being sent on every startup — full transparency.
- Sends a ping (installation UUID + version string) to a counting server once every 24 hours, and immediately on version upgrade.
- Checks GitHub Releases for a newer version; logs a WARNING if one is available.
- UUID is randomly generated on first start, stored in `/data/.tutaproxy-id`. It is not linked to your Tuta account or any personal data.

See the [Telemetry](README.md#telemetry) section in README for full details and opt-out instructions.

Files: `tuta/telemetry.py`, `run_proxy.py`, `docker/docker-compose.yml`.

---

## v1.3.3 — 2026-05-31 — Session lifecycle: 440 re-login + graceful shutdown

Three related fixes for Tuta session lifecycle handling.

### Bug — IMAP did not handle 440 SessionExpired (push mail was silently lost)

After a long IDLE session (hours), Tuta returned `440 SessionExpiredError` when
the proxy tried to fetch a newly arrived message. The proxy only handled re-login
for 401 (`NotAuthenticatedError`). As a result: a WebSocket event arrived,
`get_single_mail` hit 440 three times (exponential backoff 1/2/4s), the mail fell
into `_pending_mail_ids`, and subsequent NOOP retries also failed with the expired
session — the message never reached Thunderbird.

Additionally, `_credentials` (the email + password tuple required by `_try_relogin`)
was **never set** in `_cmd_login` / `_cmd_authenticate`, making the existing 401
re-login path dead code.

Fix:
- `_cmd_login` and `_cmd_authenticate` now save `self._credentials` on success.
- The command handler, `_idle_handle_new_mail`, and NOOP pending retry all treat
  440 the same as 401: invalidate the session, call `_try_relogin()`, retry once.

File: `tuta/imap_server.py`.

### Same fix for CalDAV / CardDAV / WebDAV

The DAV session cache in `_get_session` returned a stale session for a cached
email without checking whether the access token was still valid. After a 440
SessionExpired, every subsequent request also got 440 until the client changed
its password.

Fix: each DAV server gained an `_invalidate_session(email)` method and a
`_dispatch_with_relogin(req)` wrapper — on 440 it evicts the session from cache
and retries the entire request once (a fresh `_get_session` will log in again).
Handlers that caught `TutaAPIError` locally now re-raise on 440
(`if status_code == 440: raise`) so the wrapper can handle it.

Files: `tuta/caldav_server.py`, `tuta/carddav_server.py`, `tuta/webdav_server.py`.

### Graceful shutdown — fix for session leak in Tuta's UI

`TutaClient.logout()` (DELETE `/sys/session/{accessToken}`) existed but was
**never called anywhere**. This left dozens of "active sessions" in Tuta's UI
after every proxy restart, every Thunderbird restart, and every SMTP send.
Tuta's token TTL is many hours — stale sessions only cleaned themselves up
eventually.

Additionally:
- DAV servers (caldav/carddav/webdav) had no `stop()` method at all.
- `run_proxy.py` only called `imap.stop()` and `smtp.stop()` in its `finally`
  block — all three DAV servers were skipped.
- There was no `SIGTERM` handler. `docker stop` sends SIGTERM (not SIGINT), so
  `KeyboardInterrupt` in `run_proxy.py` never fired inside the container and the
  cleanup code was always bypassed.

Fix:
- `IMAPServer` keeps `self._connections: set[IMAPConnection]`; new
  `IMAPConnection.graceful_logout()` sends `* BYE` and calls `client.logout(session)`.
  `IMAPServer.stop()` calls it in parallel for all active connections.
- SMTP creates a fresh session per send → added `finally: client.logout(session)`
  in every `handle_DATA`.
- CalDAV/CardDAV/WebDAV now have a `stop()` method that closes the listener, logs
  out all cached sessions, and closes the aiohttp clients.
- `run_proxy.py` registers `SIGTERM`/`SIGINT` via `loop.add_signal_handler` and
  calls `stop()` on all five servers with a 15-second timeout.

Files: `tuta/imap_server.py`, `tuta/smtp_server.py`, `tuta/caldav_server.py`,
`tuta/carddav_server.py`, `tuta/webdav_server.py`, `run_proxy.py`.

---

## v1.3.2 — 2026-05-29 — Security fixes

Three security fixes from a focused review session.

### Security — DAV auth bypass (critical)

CalDAV/CardDAV/WebDAV `_get_session` cached sessions keyed only by email address,
without verifying the password. A second request for the same email but with a
different password received the full session from the first request.

Fix: the cache now stores `(session, client, sha256(password))`. A cache hit
requires `hmac.compare_digest(stored_hash, sha256(password))`. On mismatch the
normal login path runs (Tuta rejects the wrong password). The old client is closed
when the password changes.

Files: `tuta/caldav_server.py`, `tuta/carddav_server.py`, `tuta/webdav_server.py`.

### Security — default bind address 0.0.0.0 → 127.0.0.1

`run_proxy.py` used `0.0.0.0` as its default bind address despite the README
stating "127.0.0.1 by default". Without TLS between client and proxy, this
exposed Tuta credentials and account data to the local network when run outside
Docker. Docker overrides this via ENV in the Dockerfile — unchanged.

File: `run_proxy.py` (five defaults + docstring).

**Dockerfile regression** (caught during WebDAV mount test): the Dockerfile was
missing `TUTA_WEBDAV_HOST=0.0.0.0` and `EXPOSE 5234`. WebDAV (added in v1.3.0)
was never added to the Dockerfile. Previously masked by the `0.0.0.0` default;
after fixing the default, WebDAV bound to `127.0.0.1` inside the container and
Docker's port mapping (`host 127.0.0.1:5234 → container:5234`) couldn't reach it.
`davfs` mount got "connection reset by peer".

Fix: added `TUTA_WEBDAV_HOST=0.0.0.0`, `TUTA_WEBDAV_PORT=5234`, and `5234` to
`EXPOSE`. Requires an image rebuild: `docker-compose up -d --build`.

File: `docker/Dockerfile`.

### Security — HMAC verification in aes_decrypt_tuta (warn-only)

`aes_decrypt_tuta` was silently ignoring the HMAC tag. Now in warn-only mode:
the expected HMAC is compared in constant time; a mismatch logs a `WARNING` with
a short key fingerprint, but decryption continues.

Warn-only rather than strict: a code comment suggested strict mode might break
decryption for some atypical Tuta data. After an observation period without
warnings, the plan is to switch to strict mode with `TUTA_SKIP_HMAC=1` as a
kill-switch (details in README).

Files: `tuta/crypto.py`.

---

## v1.3.1 — 2026-05-29

### Fix
- **WebDAV DELETE returned 502**: field `105` (`restore`) in the
  `DriveFolderServiceDeleteIn` body was sent as Python `False` (JSON `false`)
  instead of the string `"0"`. Tuta's API serializes booleans as `"0"`/`"1"` —
  a raw JSON boolean was rejected by the server.

---

## v1.3.0 — 2026-05-28 — WebDAV (Tuta Drive)

### WebDAV server for Tuta Drive

- **`files_list_id` (field 38) as a list**: the field is returned by the API as
  `["listId"]`, not a plain string. Fix: `isinstance(files_list_id_raw, list)`
  check. Without this, every folder listed `[], []` (no files, no subfolders).

- **Multi-chunk upload**: files are split into 10 MB chunks, each encrypted with
  AES-256, with 3 retries and automatic blob token refresh (403 → new token).
  Per-chunk timeout: 10 minutes.

- **Parallel PUT deduplication**: `asyncio.Lock` per path + pinned files cache
  with a 5-minute TTL.

- **Eventual consistency**: pinned files are merged into folder listings for
  5 minutes after upload.

---

## v1.2.4 — 2026-05-28 — CalDAV blob DELETE fixes

### Two bugs in blob PUT/DELETE

**Bug 1: orphan override after deleting a recurring event**

Thunderbird deletes recurring events via a blob PUT (GET all → PUT all minus the
deleted UID). `uid_map` was `safe_uid → CalendarEvent`, so when a UID had both a
master and an override (recurrence exception), the dict held only one of them. The
DELETE loop removed only one event — the orphaned override with `recurrenceId` was
left in Tuta. On the next GET, the proxy emitted it as a `RECURRENCE-ID` without
its master event, causing Thunderbird to reject the entire calendar as "temporarily
unavailable".

Fix: `uid_to_all: dict[str, list]` — maps a UID to the list of **all** events
sharing that UID. The DELETE loop iterates over the full list.

**Bug 2: "modification failed" when deleting the last event**

Thunderbird sends a PUT with an empty VCALENDAR (zero VEVENTs) when deleting the
last event in a calendar. The handler returned `400 Bad Request` ("no VEVENT") —
Thunderbird showed "modification failed".

Fix: an empty VCALENDAR is treated as a valid diff — `put_uids = set()`, all
snapshotted events are deleted. Only a missing `BEGIN:VCALENDAR` or an entirely
empty body returns 400.

---

## v1.2.3 — 2026-05-28 — RECURRENCE-ID for recurring event exceptions

When a user modifies a single occurrence of a recurring event in Tuta, Tuta creates
a second `CalendarEvent` with the same `uid` and a set `recurrenceId` field (1320).
The proxy was not reading this field — Thunderbird could not link the exception to
its parent series.

**`api.py`**: new `recurrence_id: Optional[datetime]` field on `CalendarEvent`;
`_decrypt_calendar_event` reads field `1320`.

**`caldav_server.py`**: `_event_to_vevent` emits `RECURRENCE-ID` in the correct
format; `events_to_ical` builds `uid_to_tz` and `uid_to_override_ms`; EXDATE
entries in the master are filtered out for dates that already have an override
(RFC 5545 §3.8.5.1).

Bugs fixed:
1. EXDATE + RECURRENCE-ID conflict — EXDATE is no longer emitted for dates that have an override.
2. Timezone error in millisecond comparison — `replace(tzinfo=utc)` added before `timestamp()`.

---

## v1.2.2 — 2026-05-28 — VTIMEZONE block in iCal output

Recurring events in a non-UTC timezone were exported with `DTSTART;TZID=...` but
without a `VTIMEZONE` component — RFC 5545 requires `VTIMEZONE` whenever `TZID` is
used.

New function `_vtimezone_block(tz_str)` in `caldav_server.py`:
- Scans the current year hour by hour using `zoneinfo.ZoneInfo` to detect DST transitions.
- Emits `DAYLIGHT` and `STANDARD` sub-components with concrete transition dates.
- For zones without DST: a single `STANDARD` component with `DTSTART:19700101T000000`.

---

## v1.2.1 — 2026-05-27 — CardDAV batch DELETE

CardBook sends DELETE requests in parallel (~6 at a time). On bulk delete of
100+ contacts, CardBook was interrupting the cycle and waiting for manual
re-sync.

Fix: a 150ms batch buffer in `carddav_server.py` + `eraseMultiple` in Tuta.

- `delete_contacts_bulk_api()` — `DELETE ?ids=id1,id2,...` (single HTTP request)
- `_DeleteBatch` + timer — collects parallel DELETEs and sends a single `eraseMultiple`

Result: bulk delete of 856 contacts without interruption; batches of 1–5 contacts
processed every ~300ms.

---

## v1.2.0 — 2026-05-27 — CardDAV (contacts)

Full CardDAV server (RFC 6352). New files: `tuta/carddav_server.py`, `run_carddav.py`.

Key bugs fixed during implementation:
1. `"852": null` vs `"852": []` — ZeroOrOne associations must be `[]`, not `null`
2. FINAL fields on UPDATE — `_kdfNonce` (1837) and `_ownerKeyVersion` (1394) must come from `existing_raw`
3. `PersistenceResourcePostReturn` — field `"2"` is the new elem_id (not a string or a list)
4. CardBook "available offline" option — without it, CardBook treats the address book as read-only
5. `current-user-privilege-set` required in `PROPFIND depth=1` (not just `depth=0`)
6. `loadRoot` — two-step lookup via `RootInstance`, not a direct URL

---

## v1.1.0 — 2026-05-27 — IMAP fixes

### Persistent WebSocket watcher (IMAP IDLE)

Root cause: there was a 2–3 second gap between IMAP IDLE sessions during which no
WebSocket was active. `CREATE` events arriving in that window were lost.

Fix: a background task `_bg_event_watcher` keeps the WebSocket alive for the
entire IMAP session. Events are pushed into an `asyncio.Queue`; IDLE and NOOP
drain from the queue.

### PQ decapsulation fix

`dict.get("2045", "")` returned `None` when the key existed with a null value
→ `base64.b64decode(None)` → `TypeError`.

Fix: `pq_msg_b64 = entry.get("2045") or ""`.

---

## v1.0.2 — 2026-05-14 — Parameterised API model versions

Model versions are now read from environment variables:
- `TUTA_SYS_VERSION` (default: 150)
- `TUTA_TUTANOTA_VERSION` (default: 108)
- `TUTA_STORAGE_VERSION` (default: 14)
- `TUTA_CLIENT_VERSION` (default: 346.260428.0)

`_check_version_mismatch()` — on HTTP 412 or an error message containing
"model"/"version", logs a WARNING with the current version values and instructions
on how to update.

---

## v1.0.1 — 2026-05-14 — Docker + initial release

- `run_proxy.py` — IMAP and SMTP in a single asyncio event loop
- `docker/Dockerfile` + `docker/docker-compose.yml`
- Public repository: https://github.com/peix2/tutaproxy-public (AGPL v3)

---

## v1.0.0 — 2026-05-14 — Attachment fixes

**Upload blob (`v=14` in headers)**: POST to `blobservice` was sending `v=14` as
a query parameter instead of in the HTTP headers — the server rejected it with 400.

**`AttachmentKeyData.file` (field 546) = `[[listId, elemId]]`**: a
`LIST_ELEMENT_ASSOCIATION_GENERATED One` field must be double-wrapped in a list.

---

## v0.9 — 2026-05-12 — Previous checkpoint

All M2 features working in Thunderbird, including folder management.

**Fixed 2026-05-11**:
- `v=14` must be in HTTP request headers for `blobservice GET`
- Per-elementId cache in `_get_rfc822()` — eliminates redundant fetches on partial FETCH
- UID sort by CRC32 — Thunderbird requires monotonically increasing UIDs

**Fixed 2026-05-12**:
- CREATE folder — `ZeroOrOne` = `[]` not `null`
- Parse create_folder response — `resp.get("457",[[]])[0]`
- Folder hierarchy in LIST — recursive path building
- RENAME — two separate endpoints (PUT mailset + PUT mailfolderservice)
- `entries` (field 1459) — `LIST_ASSOCIATION One` = `["listId"]` not `"listId"`
- Thunderbird DELETE = RENAME to Trash

**Fixed 2026-05-13 — Drafts**:
- `_random_custom_id()` — 4 bytes (6 characters), not 12
- IMAP APPEND — Drafts via `create_draft`; Sent folder rejected (Tuta saves sent mail automatically)
- Drafts — field 1309 → `MailDetailsDraft` (not blob), format `[[listId, elemId]]`
