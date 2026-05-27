"""
tuta/caldav_server.py
Serwer CalDAV (RFC 4791) dla konta Tuta — odczyt i zapis.

Używa surowego asyncio.start_server() zamiast aiohttp.web, bo aiohttp odrzuca
niestandardowe metody HTTP (PROPFIND, REPORT) na poziomie parsera (400).

URL struktura:
  /.well-known/caldav  → 301 → /
  /                    → PROPFIND/REPORT/GET: eventy kalendarza
  /{uid}.ics           → GET/PUT/DELETE: pojedynczy event

Zapis:
  PUT /{uid}.ics       → utwórz lub zastąp event (parse iCal z body)
  DELETE /{uid}.ics    → usuń event
"""

import asyncio
import base64
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from urllib.parse import unquote
from xml.etree import ElementTree as ET

from .api import CalendarEvent, RepeatRule, RepeatRuleAdvanced, TutaAPIError, TutaClient, Session

logger = logging.getLogger(__name__)

DAV = "DAV:"
CAL = "urn:ietf:params:xml:ns:caldav"
CS  = "http://calendarserver.org/ns/"   # getctag extension (Apple/CalDAV Server)

ET.register_namespace("D", DAV)
ET.register_namespace("C", CAL)
ET.register_namespace("CS", CS)

PRODID = "-//tutaproxy//Tuta CalDAV Proxy//EN"


# ---------------------------------------------------------------------------
# Minimalne HTTP request/response bez zewnętrznych zależności
# ---------------------------------------------------------------------------

@dataclass
class HttpRequest:
    method: str
    path: str
    http_version: str
    headers: dict        # lowercase klucze
    body: bytes


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    def to_bytes(self) -> bytes:
        status_line = f"HTTP/1.1 {self.status} {self.reason}\r\n"
        hdrs = dict(self.headers)
        if "Content-Length" not in hdrs:
            hdrs["Content-Length"] = str(len(self.body))
        if "Connection" not in hdrs:
            hdrs["Connection"] = "close"
        header_str = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        return (status_line + header_str + "\r\n").encode() + self.body


def _text_resp(status: int, reason: str, text: str,
               content_type: str = "text/plain; charset=utf-8",
               extra_headers: dict = None) -> HttpResponse:
    body = text.encode("utf-8")
    hdrs = {"Content-Type": content_type}
    if extra_headers:
        hdrs.update(extra_headers)
    return HttpResponse(status=status, reason=reason, headers=hdrs, body=body)


def _xml_resp(root: ET.Element, status: int = 207) -> HttpResponse:
    ET.indent(root, space="  ")
    body = ('<?xml version="1.0" encoding="utf-8"?>\n'
            + ET.tostring(root, encoding="unicode")).encode("utf-8")
    return HttpResponse(
        status=status, reason="Multi-Status",
        headers={"Content-Type": "application/xml; charset=utf-8"},
        body=body,
    )


# ---------------------------------------------------------------------------
# WebDAV / CalDAV XML helpers
# ---------------------------------------------------------------------------

def _d(tag: str) -> str:
    return f"{{{DAV}}}{tag}"


def _c(tag: str) -> str:
    return f"{{{CAL}}}{tag}"


def _multistatus() -> ET.Element:
    ms = ET.Element(_d("multistatus"))
    ms.set("xmlns:D", DAV)
    ms.set("xmlns:C", CAL)
    return ms


def _add_response(ms: ET.Element, href: str, props: list[ET.Element],
                  status: str = "HTTP/1.1 200 OK") -> None:
    resp = ET.SubElement(ms, _d("response"))
    ET.SubElement(resp, _d("href")).text = href
    pstat = ET.SubElement(resp, _d("propstat"))
    prop_el = ET.SubElement(pstat, _d("prop"))
    for p in props:
        prop_el.append(p)
    ET.SubElement(pstat, _d("status")).text = status


def _p_text(tag: str, text: str) -> ET.Element:
    el = ET.Element(tag)
    el.text = text
    return el


def _p_resourcetype(*type_tags: str) -> ET.Element:
    rt = ET.Element(_d("resourcetype"))
    for t in type_tags:
        ET.SubElement(rt, t)
    return rt


def _p_current_user_principal(href: str) -> ET.Element:
    el = ET.Element(_d("current-user-principal"))
    ET.SubElement(el, _d("href")).text = href
    return el


def _p_calendar_home_set(href: str) -> ET.Element:
    el = ET.Element(_c("calendar-home-set"))
    ET.SubElement(el, _d("href")).text = href
    return el


def _p_supported_components(*names: str) -> ET.Element:
    el = ET.Element(_c("supported-calendar-component-set"))
    for name in names:
        c = ET.SubElement(el, _c("comp"))
        c.set("name", name)
    return el


def _cs(tag: str) -> str:
    return f"{{{CS}}}{tag}"


def _events_ctag(events: list) -> str:
    """Hash zbioru eventów — zmienia się przy dodaniu / usunięciu / edycji."""
    parts = sorted(f"{ev.uid}:{ev.elem_id}:{ev.sequence}" for ev in events)
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:32]


def _event_etag(ev) -> str:
    """Unikalny tag treści eventu — zmienia się gdy zmienia się summary/czas/seq."""
    content = f"{ev.uid}:{ev.summary}:{ev.start}:{ev.end}:{ev.sequence}:{ev.location}"
    return '"' + hashlib.sha256(content.encode()).hexdigest()[:16] + '"'


# ---------------------------------------------------------------------------
# iCalendar
# ---------------------------------------------------------------------------

def _ical_escape(text: str) -> str:
    return (text.replace("\\", "\\\\")
                .replace(";", "\\;")
                .replace(",", "\\,")
                .replace("\n", "\\n"))


def _ical_fold(line: str) -> str:
    if len(line.encode("utf-8")) <= 75:
        return line + "\r\n"
    result, buf = "", ""
    for char in line:
        if len((buf + char).encode("utf-8")) > 75:
            result += buf + "\r\n "
            buf = char
        else:
            buf += char
    return result + buf + "\r\n"


def _fmt_dt(dt: datetime, all_day: bool) -> str:
    return dt.strftime("%Y%m%d") if all_day else dt.strftime("%Y%m%dT%H%M%SZ")


def _fmt_dt_local(dt: datetime, tz_str: str) -> str:
    """Formatuje datetime w podanej strefie czasowej (bez Z na końcu)."""
    try:
        from zoneinfo import ZoneInfo
        from datetime import timezone as _tz
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz.utc)
        local = dt.astimezone(ZoneInfo(tz_str))
        return local.strftime("%Y%m%dT%H%M%S")
    except Exception:
        return dt.strftime("%Y%m%dT%H%M%SZ")


# Mapowania RRULE ↔ Tuta RepeatPeriod/ByRule
_ICAL_FREQ_TO_TUTA = {"DAILY": "0", "WEEKLY": "1", "MONTHLY": "2", "YEARLY": "3"}
_TUTA_FREQ_TO_ICAL = {v: k for k, v in _ICAL_FREQ_TO_TUTA.items()}
_ICAL_BY_TO_TUTA   = {"BYDAY": "2", "BYMONTHDAY": "3", "BYYEARDAY": "4",
                      "BYWEEKNO": "5", "BYMONTH": "6", "BYSETPOS": "7", "WKST": "8"}
_TUTA_BY_TO_ICAL   = {v: k for k, v in _ICAL_BY_TO_TUTA.items()}


def _parse_rrule(rrule_val: str, tzid: str, all_day: bool,
                 exdate_raw_list: list) -> Optional[RepeatRule]:
    """Parsuje wartość RRULE i listę surowych wartości EXDATE, zwraca RepeatRule."""
    from datetime import timezone as _tz, datetime as _dt, timedelta as _td

    parts_dict: dict[str, str] = {}
    for part in rrule_val.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            parts_dict[k.upper()] = v

    freq = _ICAL_FREQ_TO_TUTA.get(parts_dict.get("FREQ", "").upper())
    if not freq:
        return None

    interval = parts_dict.get("INTERVAL", "1")
    end_type = "0"
    end_value = None

    if "COUNT" in parts_dict:
        end_type = "1"
        end_value = parts_dict["COUNT"]
    elif "UNTIL" in parts_dict:
        end_type = "2"
        until_str = parts_dict["UNTIL"]
        try:
            if "T" in until_str:
                fmt = "%Y%m%dT%H%M%SZ" if until_str.endswith("Z") else "%Y%m%dT%H%M%S"
                until_dt = _dt.strptime(until_str, fmt).replace(tzinfo=_tz.utc)
                # iCal: inkluzywny → Tuta: ekskluzywny (+1 sekunda)
                end_value = str(int(until_dt.timestamp() * 1000) + 1000)
            else:
                # all-day: YYYYMMDD inkluzywny → start następnego dnia
                until_dt = _dt.strptime(until_str, "%Y%m%d").replace(tzinfo=_tz.utc)
                end_value = str(int((until_dt + _td(days=1)).timestamp() * 1000))
        except Exception as e:
            logger.warning("CalDAV RRULE: błąd parsowania UNTIL %r: %s", until_str, e)

    # Advanced rules: BYDAY=MO,WE → osobny wpis per wartość
    advanced: list[RepeatRuleAdvanced] = []
    for ical_key, rule_type in _ICAL_BY_TO_TUTA.items():
        raw_val = parts_dict.get(ical_key, "")
        if raw_val:
            for v in raw_val.split(","):
                if v:
                    advanced.append(RepeatRuleAdvanced(rule_type=rule_type, interval=v))

    # EXDATE: lista par (params, value) zebranych z VEVENT
    excluded_dates: list[int] = []
    for (ex_params, ex_val) in exdate_raw_list:
        ex_tzid = None
        for p in ex_params.split(";"):
            if p.upper().startswith("TZID="):
                ex_tzid = p[5:]
        for date_str in ex_val.split(","):
            date_str = date_str.strip()
            if not date_str:
                continue
            try:
                from datetime import timezone as _tz2, datetime as _dt2
                if "T" in date_str:
                    if date_str.endswith("Z"):
                        dt_ex = _dt2.strptime(date_str, "%Y%m%dT%H%M%SZ").replace(tzinfo=_tz2.utc)
                    else:
                        naive = _dt2.strptime(date_str, "%Y%m%dT%H%M%S")
                        if ex_tzid:
                            try:
                                from zoneinfo import ZoneInfo
                                dt_ex = naive.replace(tzinfo=ZoneInfo(ex_tzid)).astimezone(_tz2.utc)
                            except Exception:
                                dt_ex = naive.replace(tzinfo=_tz2.utc)
                        else:
                            dt_ex = naive.replace(tzinfo=_tz2.utc)
                else:
                    dt_ex = _dt2.strptime(date_str, "%Y%m%d").replace(tzinfo=_tz2.utc)
                excluded_dates.append(int(dt_ex.timestamp() * 1000))
            except Exception as e:
                logger.warning("CalDAV EXDATE: błąd parsowania %r: %s", date_str, e)

    return RepeatRule(
        frequency=freq,
        end_type=end_type,
        end_value=end_value,
        interval=interval,
        time_zone=tzid or "UTC",
        excluded_dates=excluded_dates,
        advanced_rules=advanced,
    )


def _rrule_to_ical(rr: RepeatRule, all_day: bool) -> str:
    """Konwertuje RepeatRule do stringa RRULE:..."""
    freq = _TUTA_FREQ_TO_ICAL.get(rr.frequency, "DAILY")
    parts = [f"FREQ={freq}"]
    if rr.interval and rr.interval != "1":
        parts.append(f"INTERVAL={rr.interval}")

    if rr.end_type == "1" and rr.end_value:
        parts.append(f"COUNT={rr.end_value}")
    elif rr.end_type == "2" and rr.end_value:
        # Tuta: ekskluzywny ms → iCal: inkluzywny
        from datetime import timezone as _tz
        until_ms = int(rr.end_value)
        if all_day:
            # Tuta przechowuje start następnego dnia → cofamy o 1 dzień
            until_dt = datetime.utcfromtimestamp((until_ms - 86400000) / 1000).replace(tzinfo=_tz.utc)
            parts.append(f"UNTIL={until_dt.strftime('%Y%m%d')}")
        else:
            # Cofamy o 1 sekundę
            until_dt = datetime.utcfromtimestamp((until_ms - 1000) / 1000).replace(tzinfo=_tz.utc)
            parts.append(f"UNTIL={until_dt.strftime('%Y%m%dT%H%M%SZ')}")

    # Advanced rules: grupuj po typie → BYDAY=MO,WE etc.
    by_type: dict[str, list[str]] = {}
    for ar in (rr.advanced_rules or []):
        ical_key = _TUTA_BY_TO_ICAL.get(ar.rule_type, "")
        if ical_key:
            by_type.setdefault(ical_key, []).append(ar.interval)
    for ical_key, vals in by_type.items():
        parts.append(f"{ical_key}={','.join(vals)}")

    return "RRULE:" + ";".join(parts)


def _event_to_vevent(ev: CalendarEvent) -> str:
    lines = ["BEGIN:VEVENT\r\n"]

    def add(prop: str, val: str) -> None:
        lines.append(_ical_fold(f"{prop}:{val}"))

    def add_text(prop: str, val: str) -> None:
        if val:
            lines.append(_ical_fold(f"{prop}:{_ical_escape(val)}"))

    # Gdy event jest cykliczny, DTSTART używa TZID zamiast UTC (Tuta web app tak robi)
    rr = ev.rrule
    tz_str = (rr.time_zone if rr and rr.time_zone and rr.time_zone != "UTC" else None)

    add("UID", ev.uid)
    if ev.start:
        if ev.all_day:
            add("DTSTART;VALUE=DATE", _fmt_dt(ev.start, True))
        elif tz_str:
            add(f"DTSTART;TZID={tz_str}", _fmt_dt_local(ev.start, tz_str))
        else:
            add("DTSTART", _fmt_dt(ev.start, False))
    if ev.end:
        if ev.all_day:
            add("DTEND;VALUE=DATE", _fmt_dt(ev.end, True))
        elif tz_str:
            add(f"DTEND;TZID={tz_str}", _fmt_dt_local(ev.end, tz_str))
        else:
            add("DTEND", _fmt_dt(ev.end, False))
    add_text("SUMMARY", ev.summary)
    add_text("LOCATION", ev.location)
    add_text("DESCRIPTION", ev.description)
    add("SEQUENCE", str(ev.sequence))

    if rr:
        lines.append(_ical_fold(_rrule_to_ical(rr, ev.all_day)))
        # EXDATE — wykluczone daty powtórzeń
        if rr.excluded_dates:
            from datetime import timezone as _tz
            tz_label = rr.time_zone or "UTC"
            ex_vals = []
            for ms in sorted(rr.excluded_dates):
                dt = datetime.utcfromtimestamp(ms / 1000).replace(tzinfo=_tz.utc)
                if ev.all_day:
                    ex_vals.append(dt.strftime("%Y%m%d"))
                elif tz_str:
                    ex_vals.append(_fmt_dt_local(dt, tz_str))
                else:
                    ex_vals.append(dt.strftime("%Y%m%dT%H%M%SZ"))
            if ev.all_day:
                lines.append(_ical_fold(f"EXDATE;VALUE=DATE:{','.join(ex_vals)}"))
            elif tz_str:
                lines.append(_ical_fold(f"EXDATE;TZID={tz_label}:{','.join(ex_vals)}"))
            else:
                lines.append(_ical_fold(f"EXDATE:{','.join(ex_vals)}"))

    lines.append("END:VEVENT\r\n")
    return "".join(lines)


def _ical_unescape(text: str) -> str:
    return (text.replace("\\n", "\n")
                .replace("\\N", "\n")
                .replace("\\;", ";")
                .replace("\\,", ",")
                .replace("\\\\", "\\"))


def _parse_ical_all(ical_text: str) -> list[CalendarEvent]:
    """Parsuje wszystkie VEVENTy z VCALENDAR body, zwraca listę CalendarEvent z UID."""
    text = ical_text.replace("\r\n ", "").replace("\r\n\t", "")
    text = text.replace("\n ", "").replace("\n\t", "")

    results = []
    vevent_lines: list[str] = []
    in_vevent = False

    for line in text.splitlines():
        upper = line.upper()
        if upper == "BEGIN:VEVENT":
            in_vevent = True
            vevent_lines = []
        elif upper == "END:VEVENT":
            in_vevent = False
            # Zbuduj minimalne VCALENDAR z jednym VEVENT i przekaż do parsera
            fake = ("BEGIN:VCALENDAR\nBEGIN:VEVENT\n"
                    + "\n".join(vevent_lines)
                    + "\nEND:VEVENT\nEND:VCALENDAR")
            ev = _parse_ical(fake)
            if ev and ev.uid:
                results.append(ev)
        elif in_vevent:
            vevent_lines.append(line)

    return results


def _parse_ical(ical_text: str) -> Optional[CalendarEvent]:
    """
    Parsuje VCALENDAR/VEVENT z body CalDAV PUT i zwraca CalendarEvent.
    Obsługuje: UID, SUMMARY, DTSTART/DTEND (UTC, all-day, TZID), DESCRIPTION,
    LOCATION, SEQUENCE, RRULE, EXDATE.
    """
    from datetime import timezone as _tz, datetime as _dt

    # Unfold: RFC 5545 §3.1 — CRLF + spacja/tab to kontynuacja linii
    text = ical_text.replace("\r\n ", "").replace("\r\n\t", "")
    text = text.replace("\n ", "").replace("\n\t", "")

    props: dict[str, tuple[str, str]] = {}
    exdate_list: list[tuple[str, str]] = []   # para (params, value) dla każdego EXDATE
    rrule_raw: Optional[str] = None
    in_vevent = False
    for line in text.splitlines():
        upper = line.upper()
        if upper == "BEGIN:VEVENT":
            in_vevent = True
            continue
        if upper == "END:VEVENT":
            break
        if not in_vevent or ":" not in line:
            continue
        colon = line.index(":")
        name_params = line[:colon]
        value = line[colon + 1:]
        parts = name_params.split(";")
        prop = parts[0].upper()
        params = ";".join(parts[1:])
        if prop == "EXDATE":
            exdate_list.append((params, value))
        elif prop == "RRULE" and rrule_raw is None:
            rrule_raw = value
        elif prop not in props:   # pierwsza deklaracja wygrywa
            props[prop] = (params, value)

    if not props:
        return None

    def val(name: str) -> str:
        return props.get(name, ("", ""))[1]

    def par(name: str) -> str:
        return props.get(name, ("", ""))[0]

    def parse_dt(name: str) -> Optional[_dt]:
        v = val(name)
        p = par(name)
        if not v:
            return None
        # All-day: VALUE=DATE lub YYYYMMDD bez T
        if "VALUE=DATE" in p or ("T" not in v and len(v) == 8):
            try:
                return _dt(int(v[:4]), int(v[4:6]), int(v[6:8]), tzinfo=_tz.utc)
            except Exception:
                return None
        # UTC: YYYYMMDDTHHMMSSZ
        if v.endswith("Z"):
            try:
                return _dt.strptime(v, "%Y%m%dT%H%M%SZ").replace(tzinfo=_tz.utc)
            except Exception:
                return None
        # Naive lub TZID
        try:
            naive = _dt.strptime(v, "%Y%m%dT%H%M%S")
        except Exception:
            return None
        tzid = next((x[5:] for x in p.split(";") if x.startswith("TZID=")), None)
        if tzid:
            try:
                from zoneinfo import ZoneInfo
                aware = naive.replace(tzinfo=ZoneInfo(tzid))
                return aware.astimezone(_tz.utc).replace(tzinfo=_tz.utc)
            except Exception:
                logger.warning("CalDAV: nieznana strefa %r — traktuję jako UTC", tzid)
        return naive.replace(tzinfo=_tz.utc)

    uid    = val("UID")
    start  = parse_dt("DTSTART")
    end    = parse_dt("DTEND")

    # all-day gdy VALUE=DATE lub sama data (bez T) w DTSTART
    all_day = "VALUE=DATE" in par("DTSTART") or (
        "T" not in val("DTSTART") and len(val("DTSTART")) == 8
    )

    try:
        seq = int(val("SEQUENCE") or "0")
    except Exception:
        seq = 0

    # TZID z DTSTART — przekazywany do RepeatRule
    dtstart_tzid = next(
        (x[5:] for x in par("DTSTART").split(";") if x.upper().startswith("TZID=")), None
    )

    rrule = None
    if rrule_raw:
        rrule = _parse_rrule(rrule_raw, dtstart_tzid or "UTC", all_day, exdate_list)

    return CalendarEvent(
        uid=uid or "",
        summary=_ical_unescape(val("SUMMARY")),
        start=start,
        end=end,
        location=_ical_unescape(val("LOCATION")),
        description=_ical_unescape(val("DESCRIPTION")),
        all_day=all_day,
        sequence=seq,
        rrule=rrule,
    )


def _events_content_equal(a: CalendarEvent, b: CalendarEvent) -> bool:
    """True jeśli treść eventów jest identyczna (do celów wykrywania zmian w blob PUT)."""
    def dt_key(dt):
        if dt is None:
            return None
        return dt.replace(tzinfo=None) if dt.tzinfo else dt

    return (a.summary == b.summary
            and dt_key(a.start) == dt_key(b.start)
            and dt_key(a.end) == dt_key(b.end)
            and a.location == b.location
            and a.description == b.description
            and a.rrule == b.rrule)


def events_to_ical(events: list[CalendarEvent]) -> str:
    parts = [
        "BEGIN:VCALENDAR\r\n",
        "VERSION:2.0\r\n",
        f"PRODID:{PRODID}\r\n",
        "CALSCALE:GREGORIAN\r\n",
        "METHOD:PUBLISH\r\n",
    ]
    parts.extend(_event_to_vevent(ev) for ev in events)
    parts.append("END:VCALENDAR\r\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Serwer CalDAV
# ---------------------------------------------------------------------------

class CalDAVServer:
    """
    Serwer CalDAV read-only dla Tuta.
    Używa asyncio.start_server() — obsługuje dowolne metody HTTP (PROPFIND, REPORT, …).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 5232):
        self.host = host
        self.port = port
        self._sessions: dict[str, tuple[Session, TutaClient]] = {}
        self._event_cache: dict[str, tuple[float, list[CalendarEvent]]] = {}
        self._cache_ttl = 60   # krótki TTL żeby eventy z Tuty pojawiały się w TB po ~1 min
        # (group_id, group_key, short_list_id, long_list_id, key_version) — bez TTL
        self._cal_info: dict[str, tuple[str, bytes, str, str, str]] = {}
        # Blokada na tworzenie sesji — zapobiega race condition przy równoległych żądaniach
        self._login_locks: dict[str, asyncio.Lock] = {}
        # UIDs zwrócone w ostatnim GET / — do bezpiecznego DELETE w trybie blob
        self._last_get_snapshot: dict[str, frozenset] = {}

    # -----------------------------------------------------------------------
    # TCP i HTTP parsing
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_conn, self.host, self.port
        )
        logger.info("CalDAV server nasłuchuje na %s:%d", self.host, self.port)

    async def _handle_conn(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        try:
            req = await self._read_request(reader)
            if req is None:
                return
            resp = await self._dispatch(req)
        except asyncio.TimeoutError:
            resp = HttpResponse(408, "Request Timeout")
        except Exception as e:
            logger.error("CalDAV błąd dla %s: %s", peer, e, exc_info=True)
            resp = HttpResponse(500, "Internal Server Error",
                                body=str(e).encode())
        try:
            writer.write(resp.to_bytes())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def _read_request(self, reader: asyncio.StreamReader) -> Optional[HttpRequest]:
        try:
            raw_line = await asyncio.wait_for(reader.readline(), timeout=15)
        except asyncio.TimeoutError:
            return None
        if not raw_line:
            return None

        try:
            request_line = raw_line.decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ")
            method = parts[0] if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"
            http_version = parts[2] if len(parts) > 2 else "HTTP/1.0"
        except Exception:
            return None

        # Odczyt nagłówków
        headers: dict[str, str] = {}
        for _ in range(200):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
            except asyncio.TimeoutError:
                break
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode("utf-8", errors="replace").strip()
            if ":" in decoded:
                name, _, value = decoded.partition(":")
                headers[name.strip().lower()] = value.strip()

        # Odczyt body
        body = b""
        cl = int(headers.get("content-length", "0") or "0")
        if cl > 0:
            try:
                body = await asyncio.wait_for(reader.read(cl), timeout=15)
            except asyncio.TimeoutError:
                pass

        # URL-decode ścieżki — Thunderbird może kodować '@' jako '%40'
        path = unquote(path)

        return HttpRequest(method=method, path=path, http_version=http_version,
                           headers=headers, body=body)

    # -----------------------------------------------------------------------
    # Auth
    # -----------------------------------------------------------------------

    def _parse_auth(self, req: HttpRequest) -> Optional[tuple[str, str]]:
        auth = req.headers.get("authorization", "")
        if not auth.lower().startswith("basic "):
            return None
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8")
        except Exception:
            return None
        if ":" not in decoded:
            return None
        email, _, password = decoded.partition(":")
        return email, password

    def _unauthorized(self) -> HttpResponse:
        return HttpResponse(
            status=401, reason="Unauthorized",
            headers={
                "WWW-Authenticate": 'Basic realm="Tuta CalDAV"',
                "Content-Type": "text/plain",
            },
            body=b"Unauthorized",
        )

    async def _get_session(self, email: str, password: str) -> tuple[Session, TutaClient]:
        # Szybka ścieżka — sesja już istnieje
        if email in self._sessions:
            return self._sessions[email]
        # Blokada per-email: drugi równoległy request czeka zamiast tworzyć drugiego klienta
        if email not in self._login_locks:
            self._login_locks[email] = asyncio.Lock()
        async with self._login_locks[email]:
            if email in self._sessions:       # mógł zostać dodany gdy czekaliśmy na lock
                return self._sessions[email]
            client = TutaClient()
            await client.__aenter__()
            try:
                session = await client.login(email, password)
            except Exception:
                await client.__aexit__(None, None, None)
                raise
            self._sessions[email] = (session, client)
            logger.info("CalDAV: zalogowano %s", email)
            return session, client

    async def _get_events(self, email: str, session: Session,
                          client: TutaClient) -> list[CalendarEvent]:
        cached = self._event_cache.get(email)
        if cached:
            ts, evs = cached
            if time.time() - ts < self._cache_ttl:
                return evs
        events = await client.get_calendar_events(session)
        self._event_cache[email] = (time.time(), events)
        return events

    async def _get_cal_info(
        self, email: str, session: Session, client: TutaClient
    ) -> tuple[str, bytes, str, str, str]:
        """Zwraca (group_id, group_key, short_list_id, long_list_id, key_version) — cache stały per sesja."""
        if email not in self._cal_info:
            self._cal_info[email] = await client.get_calendar_group_root_info(session)
        return self._cal_info[email]

    @staticmethod
    def _safe_uid(uid: str) -> str:
        return re.sub(r"[^\w\-@.]", "_", uid)

    def _event_href(self, uid: str) -> str:
        return f"/{self._safe_uid(uid)}.ics"

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    async def _dispatch(self, req: HttpRequest) -> HttpResponse:
        path = req.path.rstrip("/") or "/"
        method = req.method.upper()

        logger.info("CalDAV %s %s (depth=%s)", method, path,
                    req.headers.get("depth", "-"))

        # Serwis discovery
        if path == "/.well-known/caldav":
            return HttpResponse(
                status=301, reason="Moved Permanently",
                headers={"Location": "/"},
                body=b"",
            )

        if method == "OPTIONS":
            return HttpResponse(
                status=200, reason="OK",
                headers={
                    "Allow": "OPTIONS, GET, HEAD, PROPFIND, REPORT, PUT, DELETE",
                    "DAV": "1, 2, calendar-access",
                },
                body=b"",
            )

        if method == "PROPFIND":
            return await self._handle_propfind(req, path)

        if method == "REPORT":
            return await self._handle_report(req, path)

        if method in ("GET", "HEAD"):
            resp = await self._handle_get(req, path)
            if method == "HEAD":
                return HttpResponse(resp.status, resp.reason, resp.headers, b"")
            return resp

        if method == "PUT":
            return await self._handle_put(req, path)

        if method == "DELETE":
            return await self._handle_delete(req, path)

        return _text_resp(405, "Method Not Allowed", "Method Not Allowed")

    # -----------------------------------------------------------------------
    # PROPFIND
    # -----------------------------------------------------------------------

    async def _handle_propfind(self, req: HttpRequest, path: str) -> HttpResponse:
        creds = self._parse_auth(req)
        if not creds:
            return self._unauthorized()
        email, password = creds

        try:
            session, client = await self._get_session(email, password)
        except TutaAPIError:
            return self._unauthorized()
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        depth = req.headers.get("depth", "0")
        ms = _multistatus()

        # Właściwości korzenia — "/" jest jednocześnie calendar, principal i home.
        # Thunderbird nie podąża za current-user-principal → wystawiamy wszystko w jednym miejscu.
        # ctag (CalDAV Server extension) powiadamia klientów o zmianach w kalendarzu;
        # po jego otrzymaniu klienci robią PROPFIND depth=1 zamiast GET /.
        events = await self._get_events(email, session, client)
        ctag = _events_ctag(events)

        def _root_props() -> list[ET.Element]:
            return [
                _p_resourcetype(_d("collection"), _c("calendar")),
                _p_current_user_principal("/"),
                _p_calendar_home_set("/"),
                _p_text(_d("displayname"), "Tuta Calendar"),
                _p_supported_components("VEVENT"),
                _p_text(_c("calendar-description"), "Tuta Calendar (tutaproxy)"),
                _p_text(_cs("getctag"), ctag),
            ]

        if path in ("/", "") or path.startswith("/principals"):
            _add_response(ms, "/", _root_props())
            if depth == "1":
                for ev in events:
                    _add_response(ms, self._event_href(ev.uid), [
                        _p_resourcetype(),
                        _p_text(_d("getcontenttype"), "text/calendar;charset=utf-8"),
                        _p_text(_d("getetag"), _event_etag(ev)),
                    ])

        elif path.endswith(".ics"):
            # PROPFIND na pojedynczy event
            safe = path.lstrip("/").removesuffix(".ics")
            uid_map = {self._safe_uid(ev.uid): ev for ev in events}
            ev = uid_map.get(safe)
            if not ev:
                return _text_resp(404, "Not Found", "Event not found")
            _add_response(ms, path, [
                _p_resourcetype(),
                _p_text(_d("getcontenttype"), "text/calendar;charset=utf-8"),
                _p_text(_d("getetag"), _event_etag(ev)),
            ])

        else:
            # Nieznana ścieżka — traktuj jak korzeń (niektóre klienty pytają o podścieżki)
            logger.warning("CalDAV PROPFIND: ścieżka %r → fallback na /", path)
            _add_response(ms, "/", _root_props())

        return _xml_resp(ms)

    # -----------------------------------------------------------------------
    # REPORT
    # -----------------------------------------------------------------------

    async def _handle_report(self, req: HttpRequest, path: str) -> HttpResponse:
        creds = self._parse_auth(req)
        if not creds:
            return self._unauthorized()
        email, password = creds

        try:
            session, client = await self._get_session(email, password)
            events = await self._get_events(email, session, client)
        except TutaAPIError as e:
            if e.status_code == 401:
                return self._unauthorized()
            return _text_resp(502, "Bad Gateway", str(e))
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        body_text = req.body.decode("utf-8", errors="replace")
        href_to_ev = {self._event_href(ev.uid): ev for ev in events}

        if "calendar-multiget" in body_text:
            hrefs = re.findall(r"<[^>]*:?href[^>]*>([^<]+)</[^>]*href>", body_text)
            targets = [h.strip() for h in hrefs] if hrefs else list(href_to_ev.keys())
        else:
            targets = list(href_to_ev.keys())

        ms = _multistatus()
        for href in targets:
            ev = href_to_ev.get(href)
            if not ev:
                _add_response(ms, href, [], status="HTTP/1.1 404 Not Found")
                continue
            ical_data = events_to_ical([ev])
            cal_data_el = ET.Element(_c("calendar-data"))
            cal_data_el.text = ical_data
            _add_response(ms, href, [
                cal_data_el,
                _p_text(_d("getcontenttype"), "text/calendar;charset=utf-8"),
                _p_text(_d("getetag"), _event_etag(ev)),
            ])

        return _xml_resp(ms)

    # -----------------------------------------------------------------------
    # GET
    # -----------------------------------------------------------------------

    async def _handle_get(self, req: HttpRequest, path: str) -> HttpResponse:
        creds = self._parse_auth(req)
        if not creds:
            return self._unauthorized()
        email, password = creds

        try:
            session, client = await self._get_session(email, password)
            events = await self._get_events(email, session, client)
        except TutaAPIError as e:
            if e.status_code == 401:
                return self._unauthorized()
            return _text_resp(502, "Bad Gateway", str(e))
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        # GET na korzeń → cały kalendarz .ics; zapisz snapshot UIDs do obsługi DELETE w blob PUT
        if path in ("/", ""):
            self._last_get_snapshot[email] = frozenset(ev.uid for ev in events)
            return _text_resp(200, "OK", events_to_ical(events),
                              "text/calendar; charset=utf-8")

        # GET na pojedynczy event: /{uid}.ics
        if path.endswith(".ics"):
            safe = path.lstrip("/").removesuffix(".ics")
            uid_to_ev = {self._safe_uid(ev.uid): ev for ev in events}
            ev = uid_to_ev.get(safe)
            if not ev:
                return _text_resp(404, "Not Found", "Event not found")
            return _text_resp(200, "OK", events_to_ical([ev]),
                              "text/calendar; charset=utf-8",
                              extra_headers={"ETag": _event_etag(ev)})

        return _text_resp(404, "Not Found", "Not found")

    # -----------------------------------------------------------------------
    # PUT — tworzenie / aktualizacja eventu
    # -----------------------------------------------------------------------

    async def _handle_put(self, req: HttpRequest, path: str) -> HttpResponse:
        creds = self._parse_auth(req)
        if not creds:
            return self._unauthorized()
        email, password = creds

        ical_text = req.body.decode("utf-8", errors="replace")
        # Blob mode: Thunderbird wysyła PUT do "/" z całym VCALENDAR (wiele VEVENTów).
        # Per-event mode: PUT do "/{uid}.ics" — jeden VEVENT, standard CalDAV.
        is_blob = path in ("/", "")

        if is_blob:
            evs = _parse_ical_all(ical_text)
            if not evs:
                return _text_resp(400, "Bad Request", "Nie można sparsować iCal (brak VEVENT)")
            logger.debug("CalDAV PUT blob: %d eventów w body", len(evs))
        else:
            ev = _parse_ical(ical_text)
            if ev is None:
                return _text_resp(400, "Bad Request", "Nie można sparsować iCal")
            if path.endswith(".ics"):
                safe_from_path = path.lstrip("/").removesuffix(".ics")
            else:
                if not ev.uid:
                    return _text_resp(400, "Bad Request", "PUT do kolekcji wymaga UID w iCal body")
                safe_from_path = self._safe_uid(ev.uid)
                logger.debug("CalDAV PUT: ścieżka=%r UID=%r summary=%r start=%s",
                             path, ev.uid, ev.summary, ev.start)

        try:
            session, client = await self._get_session(email, password)
        except TutaAPIError:
            return self._unauthorized()
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        try:
            group_id, group_key, short_list_id, long_list_id, key_version = \
                await self._get_cal_info(email, session, client)
            events = await self._get_events(email, session, client)
        except TutaAPIError as e:
            if e.status_code == 401:
                return self._unauthorized()
            return _text_resp(502, "Bad Gateway", str(e))
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        uid_map = {self._safe_uid(e.uid): e for e in events}

        if is_blob:
            # Blob mode: pełna synchronizacja z Thunderbirda do Tuty.
            # CREATE  — event w PUT, brak w Tucie
            # UPDATE  — event w PUT i w Tucie, ale treść różna
            # DELETE  — event znany z ostatniego GET / (snapshot), ale brakujący w PUT
            put_uids = {ev_item.uid for ev_item in evs}
            known_uids = self._last_get_snapshot.get(email, frozenset())

            created = updated = deleted = 0
            errors = []

            for ev_item in evs:
                existing = uid_map.get(self._safe_uid(ev_item.uid))
                if existing:
                    if _events_content_equal(ev_item, existing):
                        continue  # brak zmian
                    # UPDATE: treść się zmieniła
                    ev_item.uid = existing.uid
                    try:
                        if existing.list_id and existing.elem_id:
                            await client.delete_calendar_event_api(
                                session, existing.list_id, existing.elem_id
                            )
                        await client.create_calendar_event_api(
                            session, group_key, group_id, short_list_id, long_list_id,
                            ev_item, key_version
                        )
                        updated += 1
                        logger.info("CalDAV PUT blob update: %s summary=%r",
                                    (ev_item.uid or "")[:32], ev_item.summary)
                    except TutaAPIError as e:
                        logger.error("CalDAV PUT blob: błąd update %s: %s",
                                     (ev_item.uid or "")[:16], e)
                        errors.append(str(e))
                    except Exception as e:
                        logger.error("CalDAV PUT blob: wyjątek update %s: %s",
                                     (ev_item.uid or "")[:16], e)
                        errors.append(str(e))
                else:
                    # CREATE
                    try:
                        await client.create_calendar_event_api(
                            session, group_key, group_id, short_list_id, long_list_id,
                            ev_item, key_version
                        )
                        created += 1
                        logger.info("CalDAV PUT blob create: %s summary=%r",
                                    (ev_item.uid or "")[:32], ev_item.summary)
                    except TutaAPIError as e:
                        logger.error("CalDAV PUT blob: błąd create %s: %s",
                                     (ev_item.uid or "")[:16], e)
                        errors.append(str(e))
                    except Exception as e:
                        logger.error("CalDAV PUT blob: wyjątek create %s: %s",
                                     (ev_item.uid or "")[:16], e)
                        errors.append(str(e))

            # DELETE — eventy znane z GET / ale nieobecne w PUT → usunięte w Thunderbirdzie
            for uid in known_uids - put_uids:
                existing = uid_map.get(self._safe_uid(uid))
                if not existing or not existing.list_id or not existing.elem_id:
                    continue
                try:
                    await client.delete_calendar_event_api(
                        session, existing.list_id, existing.elem_id
                    )
                    deleted += 1
                    logger.info("CalDAV PUT blob delete: %s", uid[:32])
                except TutaAPIError as e:
                    if e.status_code != 404:  # 404 = już usunięty, ignoruj
                        logger.error("CalDAV PUT blob: błąd delete %s: %s", uid[:16], e)
                        errors.append(str(e))
                except Exception as e:
                    logger.error("CalDAV PUT blob: wyjątek delete %s: %s", uid[:16], e)
                    errors.append(str(e))

            self._event_cache.pop(email, None)
            if errors:
                return _text_resp(502, "Bad Gateway", "\n".join(errors[:3]))
            unchanged = len(evs) - created - updated
            logger.info("CalDAV PUT blob: %d created, %d updated, %d deleted, %d unchanged",
                        created, updated, deleted, unchanged)
            return HttpResponse(204, "No Content")

        else:
            # Per-event mode: PUT do /{uid}.ics — utwórz lub zaktualizuj jeden event.
            existing = uid_map.get(safe_from_path)
            if existing is None and ev.uid:
                existing = uid_map.get(self._safe_uid(ev.uid))
            if existing:
                ev.uid = existing.uid

            try:
                # UPDATE: usuń stary, utwórz nowy z nową treścią
                if existing and existing.list_id and existing.elem_id:
                    await client.delete_calendar_event_api(
                        session, existing.list_id, existing.elem_id
                    )
                await client.create_calendar_event_api(
                    session, group_key, group_id, short_list_id, long_list_id, ev, key_version
                )
            except TutaAPIError as e:
                logger.error("CalDAV PUT: błąd API HTTP %s: %s", e.status_code, str(e)[:500])
                return _text_resp(502, "Bad Gateway", str(e))
            except Exception as e:
                logger.error("CalDAV PUT: wyjątek: %s", e, exc_info=True)
                return _text_resp(500, "Internal Server Error", str(e))

            self._event_cache.pop(email, None)
            logger.info("CalDAV PUT %s: %s uid=%s",
                        "update" if existing else "create",
                        safe_from_path, (ev.uid or "")[:32])

            etag = _event_etag(ev)
            if existing:
                return HttpResponse(204, "No Content", headers={"ETag": etag})
            return HttpResponse(
                201, "Created",
                headers={"Location": f"/{self._safe_uid(ev.uid)}.ics", "ETag": etag},
            )

    # -----------------------------------------------------------------------
    # DELETE — usunięcie eventu
    # -----------------------------------------------------------------------

    async def _handle_delete(self, req: HttpRequest, path: str) -> HttpResponse:
        creds = self._parse_auth(req)
        if not creds:
            return self._unauthorized()
        email, password = creds

        if not path.endswith(".ics"):
            return _text_resp(400, "Bad Request", "Oczekiwano /{uid}.ics")

        try:
            session, client = await self._get_session(email, password)
            events = await self._get_events(email, session, client)
        except TutaAPIError as e:
            if e.status_code == 401:
                return self._unauthorized()
            return _text_resp(502, "Bad Gateway", str(e))
        except Exception as e:
            return _text_resp(503, "Service Unavailable", str(e))

        safe_from_path = path.lstrip("/").removesuffix(".ics")
        uid_map = {self._safe_uid(e.uid): e for e in events}
        existing = uid_map.get(safe_from_path)

        if not existing:
            return _text_resp(404, "Not Found", "Event not found")
        if not existing.list_id or not existing.elem_id:
            return _text_resp(500, "Internal Server Error", "Brak _id eventu w cache")

        try:
            await client.delete_calendar_event_api(
                session, existing.list_id, existing.elem_id
            )
        except TutaAPIError as e:
            if e.status_code == 404:
                pass  # już usunięty
            else:
                return _text_resp(502, "Bad Gateway", str(e))

        self._event_cache.pop(email, None)
        logger.info("CalDAV DELETE %s", safe_from_path)
        return HttpResponse(204, "No Content")
