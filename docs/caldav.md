# CalDAV (calendar sync)

The proxy exposes a CalDAV server on port `5232`. Point your calendar client to:

```
http://localhost:5232/
```

Use your full Tuta email address as the username and your Tuta account password.

## Thunderbird (via TbSync)

1. Install the [TbSync](https://addons.thunderbird.net/en-US/thunderbird/addon/tbsync/) and
   [Provider for CalDAV & CardDAV](https://addons.thunderbird.net/en-US/thunderbird/addon/dav-4-tbsync/) add-ons.
2. In TbSync → Account actions → Add new account → CalDAV & CardDAV.
3. Choose **Manual configuration**:
   - CalDAV server: `http://localhost:5232/`
   - Username: your Tuta email address
   - Password: your Tuta password
4. Synchronize — your Tuta calendars appear in Thunderbird.

## Apple Calendar

1. System Settings → Internet Accounts → Add Account → Other → CalDAV account.
2. Account type: **Manual**, server: `http://localhost:5232/`.
3. Username: your Tuta email, password: your Tuta password.

## GNOME Calendar / Evolution

Point to `http://localhost:5232/` with your Tuta credentials.

## What works

- Read, create, update, and delete calendar events
- Recurring events (RRULE: daily, weekly, monthly, yearly, with exceptions)
- All-day events and timed events
- Event timezone support
- Modified occurrences of recurring events (RECURRENCE-ID)
- Deleted occurrences of recurring events (EXDATE)
- Event location, description, and other standard iCalendar fields
- ETag-based sync (clients only fetch changed events)

## Known limitations

- Only one Tuta account per proxy instance.
- Thunderbird (via TbSync) syncs the full calendar on each sync rather than using per-event diffs.
