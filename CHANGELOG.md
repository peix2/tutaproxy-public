# Changelog

All notable changes to tutaproxy will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/) — MAJOR.MINOR.PATCH.

---

## [1.3.1] — 2026-05-29

### Fixed
- **WebDAV DELETE returned 502 Bad Gateway** — the `restore` field (field `105`) in the
  `DriveFolderServiceDeleteIn` request body was sent as a JSON boolean `false` instead of
  the string `"0"`. Tuta's API serializes Boolean values as `"0"`/`"1"` strings and rejected
  the raw boolean with an error, causing every DELETE to fail.

---

## [1.3.0] — 2026-05-29

### Added
- **WebDAV server / Tuta Drive** — new WebDAV server on port `5234` exposes your Tuta Drive
  file storage to any WebDAV client. Mount it with davfs2, rclone, GNOME Files (Nautilus),
  macOS Finder, or Windows network drive. Supports browse, download, upload, rename, move,
  create folder, and delete.
  - Large files are automatically split into 10 MB chunks and uploaded sequentially.
  - Uploads are retried up to 3 times on network errors.
  - Blob access token is refreshed automatically if it expires mid-upload.
  - davfs2 duplicate PUT deduplication: if davfs2 sends a second PUT for the same file
    (it does this when the first takes a long time), the second request is a no-op.
  - Newly uploaded files are pinned in the local listing for 5 minutes to work around
    Tuta Drive's eventual consistency (new files may not appear in the API listing immediately).
- `run_webdav.py` — standalone entry point for the WebDAV server.
- `TUTA_WEBDAV_HOST` / `TUTA_WEBDAV_PORT` environment variables.

### Changed
- `run_proxy.py` now starts the WebDAV server alongside IMAP, SMTP, CalDAV, and CardDAV.
- Docker: port `5234` (WebDAV) is now exposed and mapped to `127.0.0.1:5234`.

---

## [1.2.4] — 2026-05-28

### Fixed
- **Deleting the last calendar event no longer fails with "modification failed"** — Thunderbird
  sends `PUT /` with an empty `VCALENDAR` (no `VEVENT` blocks) when deleting the last event.
  The proxy was rejecting this with `400 Bad Request`, which Thunderbird reported as
  "modification failed" and marked the calendar as "temporarily unavailable". Fixed by treating
  an empty `VCALENDAR` as a valid diff: all UIDs from the last snapshot are deleted.

- **Deleting a recurring event series now also removes override events** — when a recurring
  event has a modified occurrence (stored as a separate Tuta event with the same UID and
  `recurrenceId` set), deleting the series left the override orphaned in Tuta. On the next
  sync, the proxy emitted a `RECURRENCE-ID` without its required master event, causing
  Thunderbird to reject the entire calendar. Fixed by tracking all events per UID (`uid_to_all`)
  and deleting every one of them when the UID is absent from the blob PUT body.

- **Orphan override events no longer break CalDAV sync** — if a stale orphan override exists
  in Tuta (override without a matching master), it is now emitted as a regular event without
  `RECURRENCE-ID` rather than causing the calendar to be invalid.

---

## [1.2.3] — 2026-05-28

### Fixed
- **Modified recurring event occurrences now appear correctly in Thunderbird** — when a
  single occurrence of a recurring event is modified in Tuta (e.g. moved from 2 PM to 3 PM),
  it now shows up as expected in CalDAV clients instead of disappearing.

  Root cause 1 — EXDATE/RECURRENCE-ID conflict: Tuta internally stores both an `EXDATE` on
  the master event (marking the original occurrence as removed) and a separate override event
  with `recurrenceId` set. RFC 5545 §3.8.5.1 gives `EXDATE` precedence over `RECURRENCE-ID`,
  so Thunderbird deleted the occurrence and ignored the override. Fixed by omitting `EXDATE`
  entries that have a corresponding `RECURRENCE-ID` override.

  Root cause 2 — timezone mismatch in timestamp comparison: `datetime.utcfromtimestamp()`
  returns a naïve datetime that `datetime.timestamp()` then interprets as local time (e.g.
  UTC+12), producing a 12-hour offset that prevented the EXDATE filter from matching.
  Fixed by attaching UTC tzinfo before calling `timestamp()`.

- **`RECURRENCE-ID` uses the master event's timezone** — the override event inherits the
  master's `TZID` (e.g. `Pacific/Auckland`) so that `RECURRENCE-ID;TZID=Pacific/Auckland:`
  matches the original occurrence's `DTSTART` format, as required by RFC 5545 §3.8.4.4.

---

## [1.2.2] — 2026-05-28

### Fixed
- **VTIMEZONE block included in CalDAV iCal export** — recurring events with a non-UTC
  timezone (e.g. `Europe/Warsaw`) were exported with `DTSTART;TZID=...` but without the
  required `VTIMEZONE` component in the same `VCALENDAR`. RFC 5545 requires a `VTIMEZONE`
  block whenever a `TZID` is referenced. Fixed by generating `VTIMEZONE` blocks dynamically
  from the IANA timezone database (`zoneinfo`, stdlib) — one block per unique timezone used
  across all events, inserted between the `VCALENDAR` header and the `VEVENT` blocks.
  No new dependencies.

---

## [1.2.1] — 2026-05-27

### Fixed
- **Bulk contact delete no longer stalls** — deleting many contacts at once (e.g. select-all
  in CardBook) previously stopped after ~100 deletions and required a manual sync to continue.
  Root cause: each DELETE triggered a separate Tuta API call; CardBook's per-cycle operation
  limit was hit quickly. Fixed by batching concurrent DELETE requests: handlers arriving within
  150 ms of each other are collected and sent as a single `eraseMultiple` call
  (`DELETE /rest/tutanota/contact/{listId}?ids=id1,id2,...`), matching the endpoint used by
  Tuta's own clients. Bulk delete now runs continuously without pausing.

---

## [1.2.0] — 2026-05-27

### Added
- **CardDAV server** — CardDAV server on port `5233` exposes all Tuta contacts to standard
  contacts clients (CardBook for Thunderbird, Apple Contacts, etc.). Supports read, create,
  update, and delete. Contacts are exported and imported as vCard 3.0, including email
  addresses, phone numbers, postal addresses, websites, and birthday. Use your Tuta
  credentials to authenticate.
- `run_carddav.py` — standalone entry point for the CardDAV server.

### Fixed
- Proxy (`run_proxy.py`) now starts CardDAV alongside IMAP, SMTP, and CalDAV.

---

## [1.1.0] — 2026-05-27

### Added
- **CalDAV server** — CalDAV server on port `5232` exposes all Tuta calendars to standard
  calendar clients (Thunderbird via TbSync, Apple Calendar, etc.). Supports read, create,
  update, and delete. Events include full recurrence support (RRULE), timezone handling,
  and all standard iCalendar fields. Use your Tuta credentials to authenticate.

### Fixed
- **Secure External replies now appear in Thunderbird automatically** — previously a reply
  sent from Tuta's Secure External portal would only appear in Thunderbird after the user
  opened the mail in Tuta's web app first. Root cause: a 2–3 second WebSocket gap between
  consecutive IMAP IDLE sessions during which Tuta's CREATE event arrived and was silently
  dropped. Fixed by running a persistent background WebSocket watcher for the entire IMAP
  session that buffers events in a queue; IDLE and NOOP drain from that queue instead of
  opening a new WebSocket per session.
- **PQ decaps graceful failure** — Tuta briefly sets field `2045` (`pubEncBucketKey`) to
  `null` in JSON while processing new mail. Previously this caused a `TypeError: a bytes-like
  object is required, not 'NoneType'` crash. Now fails with a descriptive `ValueError` that
  the FETCH handler catches and recovers from; the subsequent UPDATE event delivers the mail
  with complete fields.

---

## [1.0.2] — 2026-05-26

### Added
- **Secure External** — send password-protected encrypted mail to non-Tuta recipients.
  Add the custom SMTP header `X-Tuta-Password: <password>` in your email client;
  the proxy encrypts the message using Tuta's Secure External flow (argon2id KDF +
  ExternalUserService + SecureExternalRecipientKeyData). The recipient receives a link
  and enters the password on `app.tuta.com` to read the message.
- `docs/thunderbird-secure-external.png` — screenshot showing how to add the
  `X-Tuta-Password` header in Thunderbird's compose window.

### Fixed
- Secure External: second (and subsequent) messages to the same external recipient
  previously triggered "invalid mac" in the Tuta portal. Root cause: an exception
  from `_load_existing_external_user_keys` was caught by the wrong `except` block,
  causing the proxy to silently create a new external account with fresh random keys
  on every send. The message was encrypted with the new keys, but the recipient's
  account still held the old ones.
- Secure External: notification emails showed the literal `$senderName$` instead of
  the sender's display name. Fixed by passing `senderNameUnencrypted` (field 552) in
  `SendDraftService`.

---

## [1.0.1] — 2026-05-14

### Added
- **TutaCrypt PQ decryption** — Tuta→Tuta messages using the new post-quantum key
  scheme (X25519 + ML-KEM/Kyber-1024 hybrid) are now fully decryptable. Previously
  these appeared with scrambled subject and content.
- **Import from external IMAP accounts** — copy or move messages (with attachments)
  from Gmail or any other IMAP account into Tuta via IMAP APPEND. Messages land in
  Inbox as properly encrypted Tuta mail.
- API version parametrization via environment variables (`TUTA_SYS_VERSION`,
  `TUTA_TUTANOTA_VERSION`, `TUTA_STORAGE_VERSION`, `TUTA_CLIENT_VERSION`).
  Update versions without touching the code when Tuta bumps their API.
- Version mismatch detection: HTTP 412 or model-related 400/500 errors now log a
  `WARNING` with the current version values and instructions.

---

## [1.0.0] — 2026-05-12

### Added
- Initial public release.
- IMAP4rev1 server on `127.0.0.1:1143`: read mail, folder management (create/rename/delete),
  COPY/MOVE, IDLE push, APPEND (drafts + import), EXPUNGE, read/unread flags.
- SMTP server on `127.0.0.1:1025`: send mail with attachments, E2E encryption for
  Tuta→Tuta messages (ECC + ML-KEM/Kyber), standard delivery for external recipients.
- Docker packaging (`docker/Dockerfile` + `docker/docker-compose.yml`).
- SQLite cache for folder list and local flags.
