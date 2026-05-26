# Changelog

All notable changes to tutaproxy will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/) — MAJOR.MINOR.PATCH.

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
