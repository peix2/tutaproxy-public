# CardDAV (contact sync)

The proxy exposes a CardDAV server on port `5233`. Point your contacts client to:

```
http://localhost:5233/
```

Use your full Tuta email address as the username and your Tuta account password.

## CardBook (Thunderbird add-on)

[CardBook](https://addons.thunderbird.net/en-US/thunderbird/addon/cardbook/) is a separate
Thunderbird add-on for CardDAV contacts. It is not the same as Thunderbird's built-in address book.

1. Install the [CardBook](https://addons.thunderbird.net/en-US/thunderbird/addon/cardbook/) add-on.
2. In CardBook → Address Book → Add an address book → Remote → CardDAV.
3. URL: `http://localhost:5233/`, username: your Tuta email, password: your Tuta password.
4. **Important:** on the last step of the wizard, check **"Available offline"**. Without this
   option, CardBook treats the address book as read-only and will not send PUT or DELETE requests
   even though the server advertises write access.

## Apple Contacts

1. System Settings → Internet Accounts → Add Account → Other → CardDAV account.
2. Account type: **Manual**, server: `http://localhost:5233/`.
3. Username: your Tuta email, password: your Tuta password.

## GNOME Contacts / Evolution

Point to `http://localhost:5233/` with your Tuta credentials.

## What works

- Read, create, update, and delete contacts
- Contact fields: name, email addresses, phone numbers, postal addresses, websites, birthday,
  organization, job title, nickname, notes, social profiles
- vCard 3.0 format (compatible with all major clients)
- Bulk delete (hundreds of contacts at once without stalling)

## Known limitations

- Only one Tuta account per proxy instance.
- Contact photos are not synced (Tuta stores photos, but the proxy does not yet transfer them).
