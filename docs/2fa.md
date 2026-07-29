# 2FA / TOTP

tuta-proxy can log in to an account that has **TOTP** two-factor authentication
(authenticator app) enabled. You just give the proxy the same secret you
configured in the Tuta app.

- Only **TOTP** is supported. U2F / WebAuthn / hardware keys require a browser
  interaction and are not (and will not be) supported.
- The proxy **only logs in** through 2FA. Enabling and disabling the second
  factor is done **in the official Tuta client** — the API does not allow the
  proxy to add or remove factors (it returns 403). This is a deliberate
  server-side restriction and, at the same time, a safer split: security
  management stays in the official app.

## Enable 2FA (in the Tuta app)

1. Settings → **Login** → **Second factor** → **Add**.
2. Choose **Authenticator (TOTP)**.
3. Tuta shows a QR code and a **manual-entry key** (base32, e.g.
   `jbsw y3dp ehpk 3pxp …`). **Save this key** — it is what goes into the proxy
   config.
4. Scan the QR with your authenticator app (or enter the key manually) and
   **confirm with a one-time code** — the factor is not activated without it.

## Configure tuta-proxy

Set the base32 secret in `TUTA_TOTP_SECRET` (spaces and letter case are
normalized, so paste it as shown).

`.env`:

```
TUTA_TOTP_SECRET=jbsw y3dp ehpk 3pxp 65no xi
```

environment variable:

```
export TUTA_TOTP_SECRET="jbsw y3dp ehpk 3pxp 65no xi"
```

`docker-compose.yml` (`environment` section):

```yaml
    environment:
      TUTA_TOTP_SECRET: "jbsw y3dp ehpk 3pxp 65no xi"
```

After that, logging in from Thunderbird (IMAP/SMTP) and the DAV servers works as
usual — the proxy adds the TOTP code during login. The secret is needed **only**
when the account has TOTP enabled; on an account without 2FA, leave it unset.

> **Security trade-off:** keeping the TOTP secret next to the password in `.env`
> technically weakens 2FA (anyone with access to the file has both factors) — the
> same trade-off as `pass-otp` / `bitwarden-cli`. Acceptable on a secured personal
> machine; keep `.env` out of version control and with tight file permissions.

## Disable 2FA (in the Tuta app)

Settings → **Login** → **Second factor** → remove the TOTP entry. Then remove
`TUTA_TOTP_SECRET` from the proxy config.

## How it works

When an account has 2FA, `sessionservice` returns a non-empty `challenges` list
(the session exists but is locked). The proxy:

1. derives the session IdTuple from the `accessToken`
   (`listId = base64Ext(raw[:9])`, `elemId = base64url(sha256(raw[9:]))`),
2. generates a TOTP code (RFC 6238: HMAC-SHA1, 30 s window, 6 digits),
3. POSTs `SecondFactorAuthData` to `secondfactorauthservice`,
4. polls `secondfactorauthservice` until `secondFactorPending == false`,
5. continues loading keys as normal.

Implementation: `_second_factor_auth` in `tuta/api.py`, `generate_totp` in
`tuta/crypto.py`.

## Troubleshooting

- **`Konto wymaga 2FA (TOTP) — ustaw TUTA_TOTP_SECRET`** — the account has TOTP
  enabled but the variable is empty. Set the secret.
- **`Konto wymaga 2FA, ale bez TOTP`** — the account only has U2F/WebAuthn. Add a
  TOTP factor in the Tuta app (factors can coexist).
- **HTTP 429 on login** — Tuta temporarily rate-limits logins after a burst of
  attempts (e.g. wrong codes). Wait a minute and retry; make sure the system
  clock is in sync (TOTP is time-based).
