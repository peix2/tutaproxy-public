# tuta-proxy

An unofficial IMAP/SMTP proxy that lets you access your [Tuta](https://tuta.com) email account from any standard email client — Thunderbird, Apple Mail, Mutt, or anything else that speaks IMAP and SMTP.

> **Disclaimer:** This project is not affiliated with, endorsed by, or connected to Tutanota GmbH in any way. Use at your own risk. "Tuta" and "Tutanota" are trademarks of Tutanota GmbH.

---

## Why

Tuta is a privacy-focused email service with strong end-to-end encryption. It only officially supports its own apps (web, desktop, Android, iOS). This proxy bridges the gap: it runs locally on your machine, speaks IMAP/SMTP to your email client, and translates those requests to Tuta's native API — including proper E2E encryption handling.

---

## Features

- **Read email** — full IMAP access to all your Tuta folders (Inbox, Sent, Drafts, Trash, Spam, Archive, and any custom folders)
- **Send email** — SMTP sending with attachment support
- **End-to-end encryption** — Tuta→Tuta emails are sent with full E2E encryption (ECC + ML-KEM/Kyber); emails to external addresses (@gmail.com etc.) are sent as standard email, same as the official client
- **Attachments** — download and upload, including inline images
- **Folder management** — create, rename, delete folders; move messages between folders (IMAP COPY)
- **Push updates** — IMAP IDLE support so your client gets notified of new mail without polling
- **Flags** — read/unread, deleted (with EXPUNGE)
- **SQLite cache** — folder list and message IDs are cached locally to speed up reconnects
- **Docker-ready** — single container runs both IMAP and SMTP

---

## Requirements

- Python 3.10+ **or** Docker
- A Tuta account (free or paid)

---

## Quick Start — Docker

```bash
git clone https://github.com/peix2/tuta-proxy.git
cd tuta-proxy/docker
docker-compose up -d --build
```

Both servers start automatically:
- IMAP on `127.0.0.1:1143`
- SMTP on `127.0.0.1:1025`

Cache is stored in a Docker volume and survives container restarts.

---

## Quick Start — Python

```bash
git clone https://github.com/peix2/tuta-proxy.git
cd tuta-proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start both IMAP and SMTP:
python run_proxy.py

# Or start separately:
python run_imap.py
python run_smtp.py
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `TUTA_IMAP_HOST` | `0.0.0.0` (proxy) / `127.0.0.1` (standalone) | IMAP bind address |
| `TUTA_IMAP_PORT` | `1143` | IMAP port |
| `TUTA_SMTP_HOST` | `0.0.0.0` (proxy) / `127.0.0.1` (standalone) | SMTP bind address |
| `TUTA_SMTP_PORT` | `1025` | SMTP port |
| `TUTA_CACHE_PATH` | `tuta_cache.db` | SQLite cache file path |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

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
- Folder create / rename / delete
- Moving messages between folders
- Read/unread flags
- Delete + expunge
- IDLE (push notifications)
- Saving drafts (via IMAP APPEND)

### Known limitations

- No TLS between the email client and the proxy — traffic stays on localhost, but it is unencrypted. Don't expose the proxy ports to a network.
- SEARCH is minimal — only `ALL` and `UNDELETED` are fully handled. Complex server-side search queries fall back to an empty result.
- Tuta two-factor authentication (2FA) is not supported.
- Only one Tuta account per proxy instance.

---

## Security notes

- The proxy binds to `127.0.0.1` by default (Docker: `0.0.0.0` inside the container, but ports are mapped to `127.0.0.1` on the host).
- Your Tuta password is passed through by your email client for each session. It is used to authenticate against Tuta's API and is not written to disk.
- All actual email data is fetched from Tuta's servers over HTTPS. Decryption happens in the proxy process on your machine.

---

## How it works

```
Thunderbird ──IMAP/SMTP──▶ tuta-proxy ──HTTPS──▶ app.tuta.com
              localhost                    TLS + E2E crypto
```

The proxy implements Tuta's REST API, including the end-to-end encryption layer (AES-128 session keys, X25519/ECC key exchange, ML-KEM/Kyber post-quantum hybrid for Tuta→Tuta mail).

---

## License

AGPL v3. See [LICENSE](LICENSE).

This project is not affiliated with Tutanota GmbH. The Tuta API is used solely for personal interoperability purposes.
