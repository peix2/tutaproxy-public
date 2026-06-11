# tuta-proxy

An unofficial local proxy that lets you access your [Tuta](https://tuta.com) account from any standard client — email, calendar, contacts, and file storage.

> **Disclaimer:** This project is not affiliated with, endorsed by, or connected to Tutao GmbH in any way. Use at your own risk. "Tuta" and "Tutanota" are trademarks of Tutao GmbH.

---

## Why

Tuta is a privacy-focused email service with strong end-to-end encryption. It only officially supports its own apps (web, desktop, Android, iOS). This proxy bridges the gap: it runs locally on your machine and translates standard protocols (IMAP, SMTP, CalDAV, CardDAV, WebDAV) to Tuta's native API — including full E2E encryption handling.

---

## Features

- **Read email** — full IMAP access to all your Tuta folders (Inbox, Sent, Drafts, Trash, Spam, Archive, and any custom folders)
- **Send email** — SMTP sending with attachment support
- **End-to-end encryption** — Tuta→Tuta emails are sent with full E2E encryption (ECC + ML-KEM/Kyber); emails to external addresses use standard delivery or Secure External (see below)
- **Secure External** — send password-protected encrypted mail to non-Tuta recipients; they receive a link and enter the password to read the message on Tuta's portal
- **Attachments** — download and upload, including inline images
- **Import from other accounts** — copy or move messages from Gmail or any other IMAP account into Tuta (with attachments); messages land in Inbox as properly encrypted Tuta mail
- **Folder management** — create, rename, delete folders; move messages between folders (IMAP COPY)
- **CalDAV (calendar sync)** — CalDAV server exposes your Tuta calendars to any CalDAV client (Thunderbird, Apple Calendar, etc.); supports reading, creating, updating, and deleting events; recurrence rules (RRULE) fully supported
- **CardDAV (contact sync)** — CardDAV server exposes your Tuta contacts to any CardDAV client (CardBook for Thunderbird, Apple Contacts, etc.); supports reading, creating, updating, and deleting contacts (vCard 3.0)
- **WebDAV / Tuta Drive** — WebDAV server on port `5234` exposes your Tuta Drive file storage; mount it with davfs2, rclone, Nautilus, or any WebDAV client; large files are chunked automatically
- **Push updates** — IMAP IDLE support so your client gets notified of new mail without polling
- **Flags** — read/unread, deleted (with EXPUNGE)
- **SQLite cache** — folder list and message IDs are cached locally to speed up reconnects
- **Docker-ready** — single container runs all five servers (IMAP, SMTP, CalDAV, CardDAV, WebDAV)

---

## Requirements

- Python 3.10+ **or** Docker
- A Tuta account (free or paid)

---

## Quick Start — Docker

```bash
git clone https://github.com/peix2/tutaproxy-public.git
cd tutaproxy-public/docker
docker-compose up -d --build
```

All five servers start automatically:
- IMAP on `127.0.0.1:1143`
- SMTP on `127.0.0.1:1025`
- CalDAV on `127.0.0.1:5232`
- CardDAV on `127.0.0.1:5233`
- WebDAV (Tuta Drive) on `127.0.0.1:5234`

Cache is stored in a Docker volume and survives container restarts.

---

## Quick Start — Python

```bash
git clone https://github.com/peix2/tutaproxy-public.git
cd tutaproxy-public
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start all servers (IMAP, SMTP, CalDAV, CardDAV, WebDAV):
python run_proxy.py

# Or start separately:
python run_imap.py
python run_smtp.py
python run_caldav.py
python run_carddav.py
python run_webdav.py
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `TUTA_IMAP_HOST` | `127.0.0.1` (Docker overrides to `0.0.0.0`) | IMAP bind address |
| `TUTA_IMAP_PORT` | `1143` | IMAP port |
| `TUTA_SMTP_HOST` | `127.0.0.1` (Docker overrides to `0.0.0.0`) | SMTP bind address |
| `TUTA_SMTP_PORT` | `1025` | SMTP port |
| `TUTA_CALDAV_HOST` | `127.0.0.1` (Docker overrides to `0.0.0.0`) | CalDAV bind address |
| `TUTA_CALDAV_PORT` | `5232` | CalDAV port |
| `TUTA_CARDDAV_HOST` | `127.0.0.1` (Docker overrides to `0.0.0.0`) | CardDAV bind address |
| `TUTA_CARDDAV_PORT` | `5233` | CardDAV port |
| `TUTA_WEBDAV_HOST` | `127.0.0.1` (Docker overrides to `0.0.0.0`) | WebDAV bind address |
| `TUTA_WEBDAV_PORT` | `5234` | WebDAV port |
| `TUTA_CACHE_PATH` | `tuta_cache.db` | SQLite cache file path |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_FILE` | *(stderr)* | Path to log file; if set, logs go to file instead of stderr |
| `LOG_ROTATE_BYTES` | `52428800` (50 MB) | Max log file size before rotation |
| `LOG_ROTATE_COUNT` | `5` | Number of rotated backup files to keep |
| `TUTA_SYS_VERSION` | `150` | Tuta sys model version (override after API update) |
| `TUTA_TUTANOTA_VERSION` | `108` | Tuta tutanota model version |
| `TUTA_STORAGE_VERSION` | `14` | Tuta storage model version |
| `TUTA_CLIENT_VERSION` | `346.260428.0` | Tuta client version string |

---

## Thunderbird Setup

1. **Add account** → "Set up account manually" (skip autoconfig)

2. **Incoming (IMAP)**
   - Server: `localhost`
   - Port: `1143`
   - Connection security: **None**
   - Authentication: **Normal password**

3. **Outgoing (SMTP)**
   - Server: `localhost`
   - Port: `1025`
   - Connection security: **None**
   - Authentication: **Normal password**

4. **Credentials** — use your full Tuta email address as the username and your Tuta password.

> The proxy runs entirely on localhost. Your credentials are used once to authenticate with Tuta's API per session and are never stored on disk.

---

## CalDAV Setup (calendar sync)

The proxy exposes a CalDAV server on port `5232`. Point your calendar client to:

```
http://localhost:5232/
```

Use your full Tuta email address as the username and your Tuta password.

### Thunderbird (via TbSync + Provider for CalDAV & CardDAV)

1. Install the [TbSync](https://addons.thunderbird.net/en-US/thunderbird/addon/tbsync/) and [Provider for CalDAV & CardDAV](https://addons.thunderbird.net/en-US/thunderbird/addon/dav-4-tbsync/) add-ons.
2. In TbSync → Account actions → Add new account → CalDAV & CardDAV.
3. Choose **Manual configuration**:
   - CalDAV server: `http://localhost:5232/`
   - Username: your Tuta email address
   - Password: your Tuta password
4. Synchronize — your Tuta calendars appear in Thunderbird.

### Apple Calendar

1. System Settings → Internet Accounts → Add Account → Other → CalDAV account.
2. Account type: **Manual**, server: `http://localhost:5232/`.
3. Username: your Tuta email, password: your Tuta password.

See [docs/caldav.md](docs/caldav.md) for more details.

---

## CardDAV Setup (contact sync)

The proxy exposes a CardDAV server on port `5233`. Point your contacts client to:

```
http://localhost:5233/
```

Use your full Tuta email address as the username and your Tuta password.

### CardBook (Thunderbird add-on)

[CardBook](https://addons.thunderbird.net/en-US/thunderbird/addon/cardbook/) is a separate Thunderbird add-on for CardDAV — it is not the same as Thunderbird's built-in address book.

1. Install the [CardBook](https://addons.thunderbird.net/en-US/thunderbird/addon/cardbook/) add-on.
2. In CardBook → Address Book → Add an address book → Remote → CardDAV.
3. URL: `http://localhost:5233/`, username: your Tuta email, password: your Tuta password.
4. **Important:** on the last step of the wizard, check **"Available offline"** (or similar wording). Without this option, CardBook treats the address book as read-only and will not send PUT or DELETE requests even though the server advertises write access.

### Apple Contacts

1. System Settings → Internet Accounts → Add Account → Other → CardDAV account.
2. Account type: **Manual**, server: `http://localhost:5233/`.
3. Username: your Tuta email, password: your Tuta password.

See [docs/carddav.md](docs/carddav.md) for more details.

---

## WebDAV Setup (Tuta Drive)

The proxy exposes a WebDAV server on port `5234` for Tuta Drive file storage.

See [docs/drive-webdav.md](docs/drive-webdav.md) for full setup instructions (davfs2, rclone, Nautilus, Windows, macOS).

### Quick start with rclone (no root required)

```bash
rclone config
# Type: WebDAV
# URL: http://localhost:5234/
# Vendor: Other
# User: your@tuta.com
# Password: your Tuta password

rclone ls tuta-drive:
rclone copy /local/path tuta-drive:
```

### Mount with davfs2 (Linux)

```bash
sudo mount -t davfs http://localhost:5234/ /mnt/tuta-drive
```

---

## Compatibility

| Client | IMAP | SMTP | Notes |
|---|---|---|---|
| Thunderbird | ✅ | ✅ | Tested |
| Apple Mail | ✅ | ✅ | Should work |
| Mutt/NeoMutt | ✅ | ✅ | Should work |
| Evolution | ✅ | ✅ | Should work |

Any client that supports IMAP4rev1 with AUTH=PLAIN and standard SMTP AUTH should work.

### What works

- Reading mail from all folders
- Sending mail (plain text, HTML, attachments)
- Sending encrypted mail to non-Tuta recipients (Secure External, password-protected)
- Folder create / rename / delete
- Moving messages between folders
- Importing messages from other IMAP accounts (with attachments) via IMAP APPEND
- Read/unread flags
- Delete + expunge
- IDLE (push notifications)
- Saving drafts (via IMAP APPEND)
- Calendar sync (CalDAV): read, create, update, delete events; full recurrence support
- Contact sync (CardDAV): read, create, update, delete contacts; vCard 3.0
- File storage (WebDAV / Tuta Drive): browse, download, upload, rename, move, delete

### Known limitations

- No TLS between the email client and the proxy — traffic stays on localhost, but it is unencrypted. Don't expose the proxy ports to a network.
- SEARCH is minimal — only `ALL` and `UNDELETED` are fully handled. Complex server-side search queries fall back to an empty result.
- Tuta two-factor authentication (2FA) is not supported.
- Only one Tuta account per proxy instance.

---

## Sending encrypted mail to external recipients (Secure External)

Tuta's **Secure External** feature lets you send end-to-end encrypted email to anyone —
even if they don't have a Tuta account. The recipient gets a notification email containing
a link; clicking it opens `app.tuta.com` where they enter a password you share with them
out-of-band to read the message.

The proxy activates this mode when the outgoing message includes the custom SMTP header
`X-Tuta-Password: <password>`. All recipients must be non-Tuta addresses (if any recipient
has a Tuta account the proxy uses standard Tuta E2E encryption instead).

### Setting up Thunderbird for Secure External

1. Open `about:config` (type it in the Thunderbird address bar, or via Help → More Troubleshooting Information).
2. Search for `mail.compose.other.header` and set its value to:
   ```
   X-Tuta-Password
   ```
   If the preference already has other values, append with a comma: `...,X-Tuta-Password`.
3. In the compose window, click the `>>` button (top-right of the header area) and select
   `X-Tuta-Password` from the list of available fields.
4. Type the password in the new field. Share it with your recipient through a separate channel
   (phone call, Signal, etc.).

![Thunderbird compose window with the X-Tuta-Password custom header field](docs/thunderbird-secure-external.png)

*Thunderbird compose window after adding the X-Tuta-Password field (UI shown in Polish:
Nadawca = From, Do = To, Temat = Subject).*

### What happens when you send

1. The proxy reads the password from `X-Tuta-Password` and strips the header.
2. A random salt is generated; `passwordKey = argon2id(password, salt)`.
3. On first send to that address, the proxy creates an encrypted external account via Tuta's
   `ExternalUserService`. On subsequent sends it reuses the existing account's keys.
4. The message is encrypted with a bucket key derived from the recipient's account keys.
5. The recipient receives a plain notification email with a link to `app.tuta.com`.
   After entering the password they can read the fully decrypted message.

### Limitations

- The password must be shared with the recipient through a separate channel.
- All recipients in one message must be non-Tuta addresses.
- Replies from the recipient come through Tuta's web portal, not to your IMAP inbox.

---

## Security notes

- The proxy binds to `127.0.0.1` by default (Docker: `0.0.0.0` inside the container, but ports are mapped to `127.0.0.1` on the host).
- Your Tuta password is passed through by your email client for each session. It is used to authenticate against Tuta's API and is not written to disk.
- For each CalDAV/CardDAV/WebDAV request the proxy compares `sha256(password)` against the cached session hash in constant time; a cached session is reused only when the hash matches.
- All actual email data is fetched from Tuta's servers over HTTPS. Decryption happens in the proxy process on your machine.
- The proxy verifies the HMAC tag on Tuta's AesCbcThenHmac ciphertexts. As of v1.3.7 this is **strict**: a mismatch raises an error and aborts decryption. If you hit a regression on unusual data, set `TUTA_SKIP_HMAC=1` to fall back to warn-only mode.
- Sessions are torn down gracefully on shutdown (since v1.3.3): `SIGTERM`/`SIGINT` triggers a `DELETE /sys/session` for every cached IMAP/CalDAV/CardDAV/WebDAV session, and SMTP logs out after each send. Without this, Tuta's "Active sessions" list would accumulate stale entries until the token TTL expired (hours).

---

## Telemetry

On startup (and then once every 24 hours) tutaproxy sends a single request to the author's server:

```json
{"id": "a3f2b1c8-d4e5-4f6a-87b8-9c0d1e2f3a4b", "version": "1.3.4"}
```

- **`id`** — a random UUID generated on first start, stored locally in `/data/.tutaproxy-id`. It is not linked to your Tuta account, email address, password, or any other personal data.
- **`version`** — the tutaproxy version you are running.

That is all that is sent. Your **IP address is not logged**: the collection server has `access_log off` for this endpoint and strips forwarding headers before the request reaches the application.

The purpose is to estimate the number of active installations and to notify you when a newer version is available — if your version is outdated, a line will appear in the log.

There is no need to trust me — you can always verify the code, and please do so so we're all happy :-)

To **opt out**, set in your `.env` or `docker-compose.yml`:
```
TUTAPROXY_TELEMETRY=false
```

---

## How it works

```
Thunderbird / rclone / davfs2
  │
  ├── IMAP / SMTP        → localhost:1143 / 1025
  ├── CalDAV             → localhost:5232
  ├── CardDAV            → localhost:5233
  └── WebDAV (Drive)     → localhost:5234
         │
    [tuta-proxy]
         │
    HTTPS ──────────────▶ app.tuta.com
    (TLS + E2E crypto)
```

The proxy implements Tuta's REST API, including the end-to-end encryption layer (AES-256 session keys, X25519/ECC key exchange, ML-KEM/Kyber post-quantum hybrid for Tuta→Tuta mail). Your private key never leaves your machine.

---

## If you like it

Feel free to express it by donation in Monero (XMR): 88dSpPtjYmKifkaMQ9Nm7ogD1ZRrk7gdxTp6m8DQEPU5TFoQcDGfED8GfZDVNohqjogZSjFMwa6oY59CDbPTad5TNfwVBTk

---

## License

AGPL v3. See [LICENSE](LICENSE).

This project is not affiliated with Tutao GmbH. The Tuta API is used solely for personal interoperability purposes.

