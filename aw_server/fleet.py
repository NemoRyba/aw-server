from collections import defaultdict
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import iso8601

WATCHER_KIND_BY_TYPE = {
    "currentwindow": "window",
    "afkstatus": "afk",
    "sessionstate": "session",
}

LIVE_STALE_AFTER = timedelta(minutes=2)
LIVE_TERMINAL_SESSION_RETENTION = timedelta(minutes=15)
LIVE_TERMINAL_STATES = {"disconnected", "logged_off", "no_session"}
DEFAULT_REPORT_RANGE = timedelta(days=7)
AGGREGATED_ACTIVITY_MAX_ROWS_PER_BIN = 120


class FleetEventCache:
    """Request-scoped read cache around the API.

    One fleet request re-reads the same bucket event lists many times
    (afk/session/window intervals, totals, per-app report). Fetching and
    JSON-serializing those events from storage dominates request time, so this
    proxy memoizes get_buckets() and get_events() results for the lifetime of
    a single request. Never keep an instance across requests.
    """

    def __init__(self, api):
        self._api = api
        self._buckets = None
        self._events = {}

    def __getattr__(self, name):
        return getattr(self._api, name)

    def get_buckets(self):
        if self._buckets is None:
            self._buckets = self._api.get_buckets()
        return self._buckets

    def get_events(self, bucket_id, limit=-1, start=None, end=None):
        key = (bucket_id, limit, start, end)
        if key not in self._events:
            self._events[key] = self._api.get_events(
                bucket_id, limit=limit, start=start, end=end
            )
        return self._events[key]


def wrap_fleet_event_cache(api):
    if isinstance(api, FleetEventCache):
        return api
    return FleetEventCache(api)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Optional[Any]) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        dt = iso8601.parse_date(str(value))
    return dt.astimezone(timezone.utc)


def _isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def format_fleet_datetime(value: Optional[datetime]) -> Optional[str]:
    return _isoformat(value)


def parse_fleet_datetime(value: Optional[Any]) -> Optional[datetime]:
    return _parse_datetime(value)


def local_fleet_day_boundary(day, hour: int, minute: int) -> datetime:
    """Return the aware instant for local wall-clock `day` at hour:minute.

    Uses naive-datetime.astimezone(), which interprets the naive value as
    system-local wall time with the correct UTC offset FOR THAT DATE, so
    boundaries stay at e.g. 04:00 local across DST changes.
    """
    return datetime(day.year, day.month, day.day, hour, minute).astimezone()


def parse_start_of_day(start_of_day: str) -> Tuple[int, int]:
    try:
        hour_text, minute_text = str(start_of_day or "04:00").split(":", 1)
        hour, minute = int(hour_text), int(minute_text)
    except (TypeError, ValueError):
        return 4, 0
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return 4, 0
    return hour, minute


def iter_fleet_day_ranges(
    start: datetime, end: datetime, start_of_day: str
) -> List[Tuple[datetime, datetime]]:
    """Split [start, end) into consecutive chunks at local start_of_day
    boundaries. Ranges the webui sends (aligned to start_of_day) split into
    exact fleet days; unaligned edges become partial chunks."""
    hour, minute = parse_start_of_day(start_of_day)
    chunks: List[Tuple[datetime, datetime]] = []
    cur = start
    # Hard safety bound: ~11 years of days.
    for _ in range(4096):
        if cur >= end:
            break
        local = cur.astimezone()
        boundary = local_fleet_day_boundary(local.date(), hour, minute)
        if boundary <= cur:
            boundary = local_fleet_day_boundary(
                local.date() + timedelta(days=1), hour, minute
            )
        nxt = min(boundary, end)
        chunks.append((cur, nxt))
        cur = nxt
    return chunks


def _aggregate_apps_rows(
    rows: Iterable[Dict[str, Any]],
    available_device_catalog: Dict[str, str],
) -> List[Dict[str, Any]]:
    apps_by_name: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        item = apps_by_name.setdefault(
            row["app"],
            {
                "app": row["app"],
                "seconds": 0.0,
                "active_seconds": 0.0,
                "afk_seconds": 0.0,
                "devices": set(),
            },
        )
        item["seconds"] += row["seconds"]
        item["active_seconds"] += row["active_seconds"]
        item["afk_seconds"] += row["afk_seconds"]
        item["devices"].add(row["device_id"])
        available_device_catalog.setdefault(row["device_id"], row["device_name"])

    return [
        {
            "app": item["app"],
            "seconds": item["seconds"],
            "active_seconds": item["active_seconds"],
            "afk_seconds": item["afk_seconds"],
            "devices": sorted(item["devices"]),
        }
        for item in sorted(
            apps_by_name.values(), key=lambda item: item["seconds"], reverse=True
        )
    ]


def calculate_user_summary_day(
    api,
    username: str,
    start: datetime,
    end: datetime,
    device_ids: Optional[Iterable[str]] = None,
    exclude_inactive_session_afk: bool = False,
) -> Dict[str, Any]:
    """Compute one chunk (typically one fleet day): totals AND the per-app
    report, sharing a single event cache so each bucket's events for the day
    are fetched exactly once."""
    api = wrap_fleet_event_cache(api)
    summary = calculate_user_summary_totals(
        api,
        username,
        start,
        end,
        device_ids=device_ids,
        exclude_inactive_session_afk=exclude_inactive_session_afk,
    )
    available_device_catalog = {
        device["device_id"]: device["device_name"]
        for device in summary["available_devices"]
    }
    apps_report = report_time_by_app(
        api,
        username=username,
        device_ids=list(summary["selected_devices"]),
        start=start,
        end=end,
        exclude_inactive_session_afk=exclude_inactive_session_afk,
    )
    summary["apps"] = _aggregate_apps_rows(
        apps_report["rows"], available_device_catalog
    )
    summary["available_devices"] = _user_available_devices_payload(
        available_device_catalog
    )
    summary["devices"] = sorted(available_device_catalog)
    return summary


def merge_user_summary_chunks(
    username: str,
    start: datetime,
    end: datetime,
    exclude_inactive_session_afk: bool,
    chunks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge per-day summaries into one range summary. Interval math is
    time-local, so per-day merged durations sum exactly to the whole-range
    values; app rows and device catalogs merge additively."""
    totals: Dict[str, float] = {}
    catalog: Dict[str, str] = {}
    selected: Set[str] = set()
    apps_by_name: Dict[str, Dict[str, Any]] = {}

    for chunk in chunks:
        for key, value in (chunk.get("totals") or {}).items():
            totals[key] = totals.get(key, 0.0) + float(value or 0.0)
        for device in chunk.get("available_devices") or []:
            device_id = device.get("device_id")
            if not device_id:
                continue
            name = device.get("device_name")
            if device_id not in catalog or (name and name != device_id):
                catalog.setdefault(device_id, name or device_id)
                if name and name != device_id:
                    catalog[device_id] = name
        for device_id in chunk.get("selected_devices") or []:
            selected.add(str(device_id))
        for row in chunk.get("apps") or []:
            item = apps_by_name.setdefault(
                row["app"],
                {
                    "app": row["app"],
                    "seconds": 0.0,
                    "active_seconds": 0.0,
                    "afk_seconds": 0.0,
                    "devices": set(),
                },
            )
            item["seconds"] += float(row.get("seconds") or 0.0)
            item["active_seconds"] += float(row.get("active_seconds") or 0.0)
            item["afk_seconds"] += float(row.get("afk_seconds") or 0.0)
            item["devices"].update(row.get("devices") or [])

    apps = [
        {
            "app": item["app"],
            "seconds": item["seconds"],
            "active_seconds": item["active_seconds"],
            "afk_seconds": item["afk_seconds"],
            "devices": sorted(item["devices"]),
        }
        for item in sorted(
            apps_by_name.values(), key=lambda item: item["seconds"], reverse=True
        )
    ]

    return {
        "username": username,
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "filters": {
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
        },
        "devices": sorted(catalog),
        "available_devices": _user_available_devices_payload(catalog),
        "selected_devices": sorted(selected),
        "totals": totals,
        "apps": apps,
    }


def normalize_fleet_range(
    start: Optional[datetime], end: Optional[datetime]
) -> Tuple[datetime, datetime]:
    return _normalize_range(start, end)


def _coerce_seconds(value: Any) -> float:
    if value is None:
        return 0.0
    return float(value)


def _event_end(event: Optional[Dict[str, Any]]) -> Optional[datetime]:
    if not event:
        return None
    timestamp = _parse_datetime(event.get("timestamp"))
    if timestamp is None:
        return None
    return timestamp + timedelta(seconds=_coerce_seconds(event.get("duration")))


def _clip_event_seconds(
    event: Dict[str, Any], start: Optional[datetime], end: Optional[datetime]
) -> float:
    timestamp = _parse_datetime(event.get("timestamp"))
    if timestamp is None:
        return 0.0
    event_end = timestamp + timedelta(seconds=_coerce_seconds(event.get("duration")))

    if start is not None:
        timestamp = max(timestamp, start)
    if end is not None:
        event_end = min(event_end, end)

    if event_end <= timestamp:
        return 0.0
    return (event_end - timestamp).total_seconds()


def _clip_event_interval(
    event: Dict[str, Any], start: Optional[datetime], end: Optional[datetime]
) -> Optional[Tuple[datetime, datetime]]:
    timestamp = _parse_datetime(event.get("timestamp"))
    if timestamp is None:
        return None
    event_end = timestamp + timedelta(seconds=_coerce_seconds(event.get("duration")))

    if start is not None:
        timestamp = max(timestamp, start)
    if end is not None:
        event_end = min(event_end, end)

    if event_end <= timestamp:
        return None
    return (timestamp, event_end)


def _normalize_range(
    start: Optional[datetime], end: Optional[datetime]
) -> Tuple[datetime, datetime]:
    if end is None:
        end = _utcnow()
    if start is None:
        start = end - DEFAULT_REPORT_RANGE
    if start > end:
        start, end = end, start
    return start, end


def _start_of_timeline_unit(value: datetime, unit: str) -> datetime:
    if unit == "month":
        return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if unit == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    return value.replace(minute=0, second=0, microsecond=0)


def _add_timeline_unit(value: datetime, unit: str) -> datetime:
    if unit == "month":
        year = value.year
        month = value.month + 1
        if month > 12:
            year += 1
            month = 1
        return value.replace(year=year, month=month, day=1)
    if unit == "day":
        return value + timedelta(days=1)
    return value + timedelta(hours=1)


def _timeline_bins(start: datetime, end: datetime) -> Tuple[str, List[Dict[str, Any]]]:
    total_days = max(1.0, (end - start).total_seconds() / 86400.0)
    unit = "day"
    if total_days <= 2:
        unit = "hour"
    elif total_days > 370:
        unit = "month"

    cursor = _start_of_timeline_unit(start, unit)
    max_bins = 400 if unit == "day" else 240
    bins: List[Dict[str, Any]] = []

    while cursor < end and len(bins) < max_bins:
        raw_bin_start = cursor
        raw_bin_end = _add_timeline_unit(cursor, unit)
        bin_start = max(raw_bin_start, start)
        bin_end = min(raw_bin_end, end)
        if bin_end > bin_start:
            bins.append(
                {
                    "index": len(bins),
                    "unit": unit,
                    "start": bin_start,
                    "end": bin_end,
                    "active_session_seconds": 0.0,
                    "not_afk_active_session_seconds": 0.0,
                }
            )
        cursor = raw_bin_end

    return unit, bins


def _normalize_device_ids(
    device_id: Optional[Any] = None, device_ids: Optional[Iterable[Any]] = None
) -> Optional[List[str]]:
    normalized: List[str] = []

    def add(value: Optional[Any]) -> None:
        if value is None:
            return
        text = str(value).strip()
        if not text:
            return
        for part in text.split(","):
            part = part.strip()
            if part:
                normalized.append(part)

    add(device_id)
    for value in device_ids or []:
        add(value)

    if not normalized:
        return None

    unique: List[str] = []
    seen = set()
    for value in normalized:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _matches_device_filter(
    device_id: str, selected_device_ids: Optional[Iterable[str]]
) -> bool:
    if selected_device_ids is None:
        return True
    return device_id in selected_device_ids


def get_bucket_identity(bucket: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(bucket.get("data") or {})
    hostname = data.get("hostname") or bucket.get("hostname") or "unknown"
    device_id = str(data.get("device_id") or hostname or "unknown")
    device_name = str(data.get("device_name") or hostname or device_id)
    username = str(data.get("username") or "unknown")
    session_id = str(data.get("session_id") or "unknown")
    session_type = str(data.get("session_type") or "interactive")

    return {
        "username": username,
        "device_id": device_id,
        "device_name": device_name,
        "session_id": session_id,
        "session_type": session_type,
        "domain": data.get("domain"),
        "hostname": hostname,
    }


def _merge_identity(
    identity: Dict[str, Any], event: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    if not event:
        return identity

    data = dict(event.get("data") or {})
    merged = dict(identity)
    for key in (
        "username",
        "device_id",
        "device_name",
        "session_id",
        "session_type",
        "domain",
        "hostname",
    ):
        if data.get(key) not in (None, ""):
            merged[key] = str(data[key]) if key != "domain" else data[key]
    return merged


def _event_identity(
    classification: Dict[str, Any], event: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    return _merge_identity(classification, event)


def _identity_session_key(identity: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(identity.get("username") or "unknown"),
        str(identity.get("device_id") or "unknown"),
        str(identity.get("session_id") or "unknown"),
    )


def classify_bucket(bucket: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    kind = WATCHER_KIND_BY_TYPE.get(bucket.get("type"))
    if kind is None:
        return None

    identity = get_bucket_identity(bucket)
    return {
        "kind": kind,
        "bucket_id": bucket["id"],
        "client": bucket.get("client"),
        **identity,
    }


def latest_event(api, bucket_id: str) -> Optional[Dict[str, Any]]:
    events = api.get_events(bucket_id, limit=1)
    return events[0] if events else None


def _load_live_snapshots(api) -> List[Dict[str, Any]]:
    snapshots = []
    for bucket in api.get_buckets().values():
        classification = classify_bucket(bucket)
        if classification is None:
            continue

        event = latest_event(api, bucket["id"])
        identity = _merge_identity(classification, event)
        last_updated = (
            _event_end(event)
            or _parse_datetime(bucket.get("last_updated"))
            or _parse_datetime(bucket.get("created"))
        )
        snapshots.append(
            {
                **classification,
                **identity,
                "bucket": bucket,
                "latest_event": event,
                "last_updated": last_updated,
            }
        )
    return snapshots


def _session_key(session: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(session.get("username") or "unknown"),
        str(session.get("device_id") or "unknown"),
        str(session.get("session_id") or "unknown"),
    )


def _derive_effective_state(session_state: Optional[str], afk_status: Optional[str]) -> str:
    if session_state in {"locked", "disconnected", "logged_off", "no_session"}:
        return session_state
    if afk_status == "afk":
        return "afk"
    if session_state:
        return session_state
    if afk_status == "not-afk":
        return "active"
    return "unknown"


def _is_expired_terminal_session(session: Dict[str, Any], now: datetime) -> bool:
    if session.get("state") not in LIVE_TERMINAL_STATES:
        return False

    last_updated = _parse_datetime(session.get("last_updated"))
    if last_updated is None:
        return False

    return now - last_updated > LIVE_TERMINAL_SESSION_RETENTION


def _is_recent_live_update(value: Optional[datetime], now: datetime) -> bool:
    return value is not None and now - value <= LIVE_STALE_AFTER


def _is_newer_update(
    current: Optional[datetime], candidate: Optional[datetime]
) -> bool:
    if current is None:
        return True
    return candidate is not None and candidate >= current


def summarize_live_state(api) -> Dict[str, Any]:
    snapshots = _load_live_snapshots(api)
    sessions: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    for snapshot in snapshots:
        key = _session_key(snapshot)
        session = sessions.setdefault(
            key,
            {
                "username": snapshot["username"],
                "device_id": snapshot["device_id"],
                "device_name": snapshot["device_name"],
                "session_id": snapshot["session_id"],
                "session_type": snapshot["session_type"],
                "domain": snapshot.get("domain"),
                "hostname": snapshot.get("hostname"),
                "state": "unknown",
                "session_state": None,
                "session_reason": None,
                "afk_status": None,
                "current_app": None,
                "current_title": None,
                "process_name": None,
                "process_path": None,
                "explorer_path": None,
                "_last_updated_dt": None,
                "_session_updated_dt": None,
                "_afk_updated_dt": None,
                "_window_updated_dt": None,
            },
        )

        data = dict((snapshot.get("latest_event") or {}).get("data") or {})
        updated = snapshot.get("last_updated")
        if session["_last_updated_dt"] is None or (
            updated is not None and updated > session["_last_updated_dt"]
        ):
            session["_last_updated_dt"] = updated

        if snapshot["kind"] == "session" and _is_newer_update(
            session["_session_updated_dt"], updated
        ):
            session["_session_updated_dt"] = updated
            session["session_state"] = data.get("state") or session["session_state"]
            session["session_reason"] = data.get("reason") or session["session_reason"]
        elif snapshot["kind"] == "afk" and _is_newer_update(
            session["_afk_updated_dt"], updated
        ):
            session["_afk_updated_dt"] = updated
            session["afk_status"] = data.get("status") or session["afk_status"]
        elif snapshot["kind"] == "window" and _is_newer_update(
            session["_window_updated_dt"], updated
        ):
            session["_window_updated_dt"] = updated
            session["current_app"] = data.get("app") or session["current_app"]
            session["current_title"] = data.get("title") or session["current_title"]
            session["process_name"] = data.get("process_name") or session["process_name"]
            session["process_path"] = data.get("process_path") or session["process_path"]
            session["explorer_path"] = data.get("explorer_path") or session["explorer_path"]

    now = _utcnow()
    session_rows = []
    for session in sessions.values():
        session_update = session.pop("_session_updated_dt")
        afk_update = session.pop("_afk_updated_dt")
        window_update = session.pop("_window_updated_dt")
        session_has_state = session.get("session_state") is not None
        session_state_is_recent = _is_recent_live_update(session_update, now)
        session_state = session.get("session_state")

        if session_has_state and not session_state_is_recent:
            if session_state not in LIVE_TERMINAL_STATES:
                continue
        if not session_has_state and not _is_recent_live_update(
            session.get("_last_updated_dt"), now
        ):
            continue

        if not _is_recent_live_update(afk_update, now):
            session["afk_status"] = None
        if not _is_recent_live_update(window_update, now):
            session["current_app"] = None
            session["current_title"] = None
            session["process_name"] = None
            session["process_path"] = None
            session["explorer_path"] = None

        session["state"] = _derive_effective_state(
            session.get("session_state"), session.get("afk_status")
        )
        session["last_updated"] = _isoformat(session.pop("_last_updated_dt"))
        if _is_expired_terminal_session(session, now):
            continue
        session_rows.append(session)

    session_rows = sorted(
        session_rows,
        key=lambda item: (
            item.get("username") or "",
            item.get("device_name") or item.get("device_id") or "",
            item.get("session_id") or "",
        ),
    )

    devices: Dict[str, Dict[str, Any]] = {}
    for session in session_rows:
        device = devices.setdefault(
            session["device_id"],
            {
                "device_id": session["device_id"],
                "device_name": session["device_name"],
                "hostname": session.get("hostname"),
                "status": "stale",
                "users_logged_in": set(),
                "sessions": [],
                "_last_updated_dt": None,
            },
        )
        last_updated = _parse_datetime(session.get("last_updated"))
        if device["_last_updated_dt"] is None or (
            last_updated is not None and last_updated > device["_last_updated_dt"]
        ):
            device["_last_updated_dt"] = last_updated
        if session["username"] != "unknown":
            device["users_logged_in"].add(session["username"])
        device["sessions"].append(
            {
                "username": session["username"],
                "session_id": session["session_id"],
                "state": session["state"],
                "session_state": session["session_state"],
                "afk_status": session["afk_status"],
                "current_app": session["current_app"],
                "last_updated": session["last_updated"],
            }
        )

    device_rows = []
    for device in devices.values():
        last_updated = device.pop("_last_updated_dt")
        device["last_updated"] = _isoformat(last_updated)
        if last_updated is not None and now - last_updated <= LIVE_STALE_AFTER:
            device["status"] = "online"
        device["users_logged_in"] = sorted(device["users_logged_in"])
        device["sessions"] = sorted(
            device["sessions"],
            key=lambda item: (item["username"], item["session_id"]),
        )
        device_rows.append(device)

    device_rows = sorted(
        device_rows,
        key=lambda item: item.get("last_updated") or "",
        reverse=True,
    )

    return {
        "generated_at": _utcnow().isoformat(),
        "users": session_rows,
        "devices": device_rows,
    }


def group_buckets_by_user(api) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for bucket in api.get_buckets().values():
        classification = classify_bucket(bucket)
        if classification is None:
            continue
        grouped[classification["username"]].append(bucket)
    return dict(grouped)


def group_buckets_by_device(api) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for bucket in api.get_buckets().values():
        classification = classify_bucket(bucket)
        if classification is None:
            continue
        grouped[classification["device_id"]].append(bucket)
    return dict(grouped)


def summarize_users(api) -> Dict[str, Any]:
    live = summarize_live_state(api)
    users: Dict[str, Dict[str, Any]] = {}

    for bucket in api.get_buckets().values():
        classification = classify_bucket(bucket)
        if classification is None:
            continue

        user = users.setdefault(
            classification["username"],
            {
                "username": classification["username"],
                "devices": set(),
                "last_seen": None,
                "active_sessions": 0,
            },
        )
        user["devices"].add(classification["device_id"])
        last_updated = _parse_datetime(
            bucket.get("last_updated") or bucket.get("created")
        )
        if user["last_seen"] is None or (
            last_updated is not None and last_updated > user["last_seen"]
        ):
            user["last_seen"] = last_updated

    for session in live["users"]:
        user = users.setdefault(
            session["username"],
            {
                "username": session["username"],
                "devices": set(),
                "last_seen": None,
                "active_sessions": 0,
            },
        )
        user["devices"].add(session["device_id"])
        last_updated = _parse_datetime(session.get("last_updated"))
        if user["last_seen"] is None or (
            last_updated is not None and last_updated > user["last_seen"]
        ):
            user["last_seen"] = last_updated
        if session.get("state") not in LIVE_TERMINAL_STATES:
            user["active_sessions"] += 1

    rows = []
    for user in users.values():
        rows.append(
            {
                "username": user["username"],
                "devices": sorted(user["devices"]),
                "last_seen": _isoformat(user["last_seen"]),
                "active_sessions": user["active_sessions"],
            }
        )

    rows = sorted(rows, key=lambda item: item["username"])
    return {"users": rows}


def summarize_devices(api) -> Dict[str, Any]:
    live = summarize_live_state(api)
    rows = []
    for device in live["devices"]:
        rows.append(
            {
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "status": device["status"],
                "users": list(device["users_logged_in"]),
                "last_seen": device["last_updated"],
                "session_count": len(device["sessions"]),
            }
        )
    rows = sorted(rows, key=lambda item: item["device_name"] or item["device_id"])
    return {"devices": rows}


def _system_metric_buckets(api) -> Iterable[Dict[str, Any]]:
    for bucket in api.get_buckets().values():
        if bucket.get("type") != "systemmetrics":
            continue
        identity = get_bucket_identity(bucket)
        yield {
            "kind": "system",
            "bucket_id": bucket["id"],
            "client": bucket.get("client"),
            **identity,
        }


def _metric_float(data: Dict[str, Any], key: str) -> Optional[float]:
    value = data.get(key)
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _metric_int(data: Dict[str, Any], key: str) -> Optional[int]:
    value = data.get(key)
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _average_present(values: Iterable[Optional[float]]) -> Optional[float]:
    present = [float(value) for value in values if value is not None]
    if not present:
        return None
    return round(sum(present) / len(present), 1)


def _average_present_int(values: Iterable[Optional[int]]) -> Optional[int]:
    present = [int(value) for value in values if value is not None]
    if not present:
        return None
    return int(round(sum(present) / len(present)))


def _downsample_metric_samples(
    samples: List[Dict[str, Any]], max_points: int
) -> List[Dict[str, Any]]:
    if max_points <= 0 or len(samples) <= max_points:
        return samples

    chunk_size = max(1, ceil(len(samples) / max_points))
    downsampled = []
    for index in range(0, len(samples), chunk_size):
        chunk = samples[index : index + chunk_size]
        last = chunk[-1]
        downsampled.append(
            {
                "timestamp": last["timestamp"],
                "cpu_percent": _average_present(
                    sample.get("cpu_percent") for sample in chunk
                ),
                "memory_percent": _average_present(
                    sample.get("memory_percent") for sample in chunk
                ),
                "memory_used_bytes": _average_present_int(
                    sample.get("memory_used_bytes") for sample in chunk
                ),
                "memory_total_bytes": last.get("memory_total_bytes"),
            }
        )
    return downsampled


def summarize_device_metrics(
    api,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    device_ids: Optional[Iterable[str]] = None,
    max_points: int = 180,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    selected_device_ids = _normalize_device_ids(device_ids=device_ids)
    devices: Dict[str, Dict[str, Any]] = {}

    for bucket in _system_metric_buckets(api):
        if not _matches_device_filter(bucket["device_id"], selected_device_ids):
            continue

        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue

            timestamp = _parse_datetime(event.get("timestamp"))
            if timestamp is None:
                continue

            data = dict(event.get("data") or {})
            sample = {
                "timestamp": _isoformat(timestamp),
                "cpu_percent": _metric_float(data, "cpu_percent"),
                "memory_percent": _metric_float(data, "memory_percent"),
                "memory_used_bytes": _metric_int(data, "memory_used_bytes"),
                "memory_total_bytes": _metric_int(data, "memory_total_bytes"),
            }
            if sample["cpu_percent"] is None and sample["memory_percent"] is None:
                continue

            device = devices.setdefault(
                identity["device_id"],
                {
                    "device_id": identity["device_id"],
                    "device_name": identity["device_name"],
                    "samples": [],
                },
            )
            if identity.get("device_name") not in (None, "", "unknown"):
                device["device_name"] = identity["device_name"]
            device["samples"].append(sample)

    rows = []
    for device in devices.values():
        samples = sorted(device["samples"], key=lambda sample: sample["timestamp"])
        latest = samples[-1] if samples else {}
        rows.append(
            {
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "last_updated": latest.get("timestamp"),
                "latest_cpu_percent": latest.get("cpu_percent"),
                "latest_memory_percent": latest.get("memory_percent"),
                "latest_memory_used_bytes": latest.get("memory_used_bytes"),
                "latest_memory_total_bytes": latest.get("memory_total_bytes"),
                "samples": _downsample_metric_samples(samples, max_points),
            }
        )

    rows = sorted(rows, key=lambda item: item["device_name"] or item["device_id"])
    return {
        "generated_at": _utcnow().isoformat(),
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "devices": rows,
    }


def _matching_buckets(
    api,
    *,
    kind: Optional[str] = None,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
) -> Iterable[Dict[str, Any]]:
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    for bucket in api.get_buckets().values():
        classification = classify_bucket(bucket)
        if classification is None:
            continue
        if kind is not None and classification["kind"] != kind:
            continue
        if not _matches_device_filter(
            classification["device_id"], selected_device_ids
        ):
            continue
        # Keep buckets with missing identity in play, and filter at the event level instead.
        if username is not None and classification["username"] not in (username, "unknown"):
            continue
        yield classification


def _sum_bucket_event_seconds(
    api,
    *,
    kind: str,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
    predicate,
    restrict_to_intervals_by_session: Optional[
        Dict[Tuple[str, str, str], List[Tuple[datetime, datetime]]]
    ] = None,
    restrict_known_sessions: Optional[Iterable[Tuple[str, str, str]]] = None,
) -> float:
    intervals_by_session: Dict[
        Tuple[str, str, str], List[Tuple[datetime, datetime]]
    ] = defaultdict(list)
    known_sessions = set(restrict_known_sessions or [])
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    for bucket in _matching_buckets(
        api,
        kind=kind,
        username=username,
        device_id=device_id,
        device_ids=device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if username is not None and identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue
            if predicate(dict(event.get("data") or {})):
                interval = _clip_event_interval(event, start, end)
                if interval is not None:
                    session_key = _identity_session_key(identity)
                    if (
                        restrict_to_intervals_by_session is not None
                        and session_key in known_sessions
                    ):
                        intervals_by_session[session_key].extend(
                            _intersect_interval_with_intervals(
                                interval,
                                restrict_to_intervals_by_session.get(session_key, []),
                            )
                        )
                    else:
                        intervals_by_session[session_key].append(interval)

    total_seconds = 0.0
    for intervals in intervals_by_session.values():
        total_seconds += sum(
            (interval_end - interval_start).total_seconds()
            for interval_start, interval_end in _merge_intervals(intervals)
        )
    return total_seconds


def _intersect_interval_with_intervals(
    interval: Tuple[datetime, datetime],
    restrict_intervals: Iterable[Tuple[datetime, datetime]],
) -> List[Tuple[datetime, datetime]]:
    start, end = interval
    intersections = []
    for other_start, other_end in restrict_intervals:
        if other_end <= start:
            continue
        if other_start >= end:
            break
        overlap_start = max(start, other_start)
        overlap_end = min(end, other_end)
        if overlap_end > overlap_start:
            intersections.append((overlap_start, overlap_end))
    return intersections


def _merge_intervals(
    intervals: Iterable[Tuple[datetime, datetime]]
) -> List[Tuple[datetime, datetime]]:
    sorted_intervals = sorted(intervals, key=lambda item: item[0])
    if not sorted_intervals:
        return []

    merged: List[Tuple[datetime, datetime]] = []
    current_start, current_end = sorted_intervals[0]
    for start, end in sorted_intervals[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
            continue
        merged.append((current_start, current_end))
        current_start, current_end = start, end
    merged.append((current_start, current_end))
    return merged


def _sum_intervals(intervals: Iterable[Tuple[datetime, datetime]]) -> float:
    return sum(
        (interval_end - interval_start).total_seconds()
        for interval_start, interval_end in _merge_intervals(intervals)
    )


def _subtract_intervals(
    intervals: Iterable[Tuple[datetime, datetime]],
    subtract_intervals: Iterable[Tuple[datetime, datetime]],
) -> List[Tuple[datetime, datetime]]:
    subtract = _merge_intervals(subtract_intervals)
    if not subtract:
        return _merge_intervals(intervals)

    result: List[Tuple[datetime, datetime]] = []
    for interval_start, interval_end in _merge_intervals(intervals):
        cursor = interval_start
        for subtract_start, subtract_end in subtract:
            if subtract_end <= cursor:
                continue
            if subtract_start >= interval_end:
                break
            if subtract_start > cursor:
                result.append((cursor, min(subtract_start, interval_end)))
            cursor = max(cursor, subtract_end)
            if cursor >= interval_end:
                break
        if cursor < interval_end:
            result.append((cursor, interval_end))
    return result


def _interval_overlap_seconds(
    start: datetime, end: datetime, other_start: datetime, other_end: datetime
) -> float:
    overlap_start = max(start, other_start)
    overlap_end = min(end, other_end)
    if overlap_end <= overlap_start:
        return 0.0
    return (overlap_end - overlap_start).total_seconds()


def _sum_interval_overlaps(
    start: datetime,
    end: datetime,
    intervals: Iterable[Tuple[datetime, datetime]],
) -> float:
    total = 0.0
    for interval_start, interval_end in intervals:
        if interval_end <= start:
            continue
        if interval_start >= end:
            break
        total += _interval_overlap_seconds(start, end, interval_start, interval_end)
    return total


def _sum_interval_overlaps_with_restriction(
    start: datetime,
    end: datetime,
    intervals: Iterable[Tuple[datetime, datetime]],
    restrict_intervals: Iterable[Tuple[datetime, datetime]],
) -> float:
    total = 0.0
    for segment_start, segment_end in _intersect_interval_with_intervals(
        (start, end), restrict_intervals
    ):
        total += _sum_interval_overlaps(segment_start, segment_end, intervals)
    return total


def _load_afk_intervals(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
) -> Dict[Tuple[str, str, str], Dict[str, List[Tuple[datetime, datetime]]]]:
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    intervals: Dict[Tuple[str, str, str], Dict[str, List[Tuple[datetime, datetime]]]] = {}

    for bucket in _matching_buckets(
        api,
        kind="afk",
        username=username,
        device_id=device_id,
        device_ids=device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if username is not None and identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue

            interval = _clip_event_interval(event, start, end)
            if interval is None:
                continue

            status = str(dict(event.get("data") or {}).get("status") or "")
            if status not in {"afk", "not-afk"}:
                continue

            session_intervals = intervals.setdefault(
                _identity_session_key(identity),
                {"afk": [], "not-afk": []},
            )
            session_intervals[status].append(interval)

    for session_intervals in intervals.values():
        for status in ("afk", "not-afk"):
            session_intervals[status] = _merge_intervals(session_intervals[status])

    return intervals


def _load_active_session_intervals(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
) -> Tuple[
    Dict[Tuple[str, str, str], List[Tuple[datetime, datetime]]],
    Set[Tuple[str, str, str]],
]:
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    active_intervals: Dict[Tuple[str, str, str], List[Tuple[datetime, datetime]]] = {}
    known_sessions: Set[Tuple[str, str, str]] = set()

    for bucket in _matching_buckets(
        api,
        kind="session",
        username=username,
        device_id=device_id,
        device_ids=device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if username is not None and identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue

            interval = _clip_event_interval(event, start, end)
            if interval is None:
                continue

            session_key = _identity_session_key(identity)
            known_sessions.add(session_key)
            if dict(event.get("data") or {}).get("state") == "active":
                active_intervals.setdefault(session_key, []).append(interval)

    for session_key, intervals in list(active_intervals.items()):
        active_intervals[session_key] = _merge_intervals(intervals)

    return active_intervals, known_sessions


def _load_session_state_intervals(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
) -> Dict[str, List[Tuple[datetime, datetime]]]:
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    intervals_by_state: Dict[str, List[Tuple[datetime, datetime]]] = defaultdict(list)

    for bucket in _matching_buckets(
        api,
        kind="session",
        username=username,
        device_id=device_id,
        device_ids=device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if username is not None and identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue

            state = str(dict(event.get("data") or {}).get("state") or "").strip()
            if not state:
                continue

            interval = _clip_event_interval(event, start, end)
            if interval is None:
                continue

            intervals_by_state[state].append(interval)

    return {
        state: _merge_intervals(intervals)
        for state, intervals in intervals_by_state.items()
    }


def _session_state_totals(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
) -> Dict[str, float]:
    intervals_by_state = _load_session_state_intervals(
        api,
        username=username,
        device_id=device_id,
        device_ids=device_ids,
        start=start,
        end=end,
    )

    active_intervals = intervals_by_state.get("active", [])
    locked_intervals = _subtract_intervals(
        intervals_by_state.get("locked", []),
        active_intervals,
    )
    active_or_locked_intervals = _merge_intervals(active_intervals + locked_intervals)
    disconnected_intervals = _subtract_intervals(
        intervals_by_state.get("disconnected", []),
        active_or_locked_intervals,
    )
    occupied_intervals = _merge_intervals(
        active_or_locked_intervals + disconnected_intervals
    )
    logged_in_intervals = _subtract_intervals(
        intervals_by_state.get("logged_in", []),
        occupied_intervals,
    )

    return {
        "active_seconds": _sum_intervals(active_intervals),
        "locked_seconds": _sum_intervals(locked_intervals),
        "disconnected_seconds": _sum_intervals(disconnected_intervals),
        "logged_in_seconds": _sum_intervals(logged_in_intervals),
    }


def _intersect_intervals(
    left: Iterable[Tuple[datetime, datetime]],
    right: Iterable[Tuple[datetime, datetime]],
) -> List[Tuple[datetime, datetime]]:
    intersections: List[Tuple[datetime, datetime]] = []
    right_intervals = list(right)
    for left_start, left_end in left:
        for right_start, right_end in right_intervals:
            start = max(left_start, right_start)
            end = min(left_end, right_end)
            if end > start:
                intersections.append((start, end))
    return intersections


def _not_afk_active_session_seconds(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: datetime,
    end: datetime,
) -> float:
    active_session_intervals, known_session_keys = _load_active_session_intervals(
        api,
        username=username,
        device_id=device_id,
        device_ids=device_ids,
        start=start,
        end=end,
    )
    afk_intervals = _load_afk_intervals(
        api,
        username=username,
        device_id=device_id,
        device_ids=device_ids,
        start=start,
        end=end,
    )

    not_afk_active_intervals: List[Tuple[datetime, datetime]] = []
    for session_key in known_session_keys:
        session_active_intervals = active_session_intervals.get(session_key, [])
        if not session_active_intervals:
            continue

        session_afk_intervals = afk_intervals.get(session_key)
        if session_afk_intervals is None:
            not_afk_active_intervals.extend(session_active_intervals)
            continue

        not_afk_active_intervals.extend(
            _intersect_intervals(
                session_active_intervals,
                session_afk_intervals.get("not-afk", []),
            )
        )

    return _sum_intervals(_merge_intervals(not_afk_active_intervals))


def _window_event_breakdown(
    identity: Dict[str, Any],
    event: Dict[str, Any],
    *,
    start: datetime,
    end: datetime,
    afk_intervals: Dict[Tuple[str, str, str], Dict[str, List[Tuple[datetime, datetime]]]],
    active_session_intervals: Optional[
        Dict[Tuple[str, str, str], List[Tuple[datetime, datetime]]]
    ] = None,
    known_session_keys: Optional[Set[Tuple[str, str, str]]] = None,
) -> Tuple[float, float, float]:
    interval = _clip_event_interval(event, start, end)
    if interval is None:
        return (0.0, 0.0, 0.0)

    interval_start, interval_end = interval
    total_seconds = (interval_end - interval_start).total_seconds()

    session_key = _identity_session_key(identity)
    session_intervals = afk_intervals.get(session_key, {})
    active_seconds = _sum_interval_overlaps(
        interval_start, interval_end, session_intervals.get("not-afk", [])
    )
    if active_session_intervals is not None and session_key in (known_session_keys or set()):
        afk_seconds = _sum_interval_overlaps_with_restriction(
            interval_start,
            interval_end,
            session_intervals.get("afk", []),
            active_session_intervals.get(session_key, []),
        )
    else:
        afk_seconds = _sum_interval_overlaps(
            interval_start, interval_end, session_intervals.get("afk", [])
        )

    if active_seconds > total_seconds:
        active_seconds = total_seconds
    if afk_seconds > total_seconds:
        afk_seconds = total_seconds

    return (total_seconds, active_seconds, afk_seconds)


def _bin_session_seconds(
    bins: List[Dict[str, Any]],
    intervals: Iterable[Tuple[datetime, datetime]],
) -> List[float]:
    totals = [0.0 for _ in bins]
    merged_intervals = _merge_intervals(intervals)
    if not merged_intervals:
        return totals

    for index, bin_row in enumerate(bins):
        totals[index] = _sum_interval_overlaps(
            bin_row["start"], bin_row["end"], merged_intervals
        )
    return totals


def _not_afk_active_session_intervals(
    active_session_intervals: Dict[Tuple[str, str, str], List[Tuple[datetime, datetime]]],
    known_session_keys: Set[Tuple[str, str, str]],
    afk_intervals: Dict[Tuple[str, str, str], Dict[str, List[Tuple[datetime, datetime]]]],
) -> List[Tuple[datetime, datetime]]:
    not_afk_active_intervals: List[Tuple[datetime, datetime]] = []
    for session_key in known_session_keys:
        session_active_intervals = active_session_intervals.get(session_key, [])
        if not session_active_intervals:
            continue

        session_afk_intervals = afk_intervals.get(session_key)
        if session_afk_intervals is None:
            not_afk_active_intervals.extend(session_active_intervals)
            continue

        not_afk_active_intervals.extend(
            _intersect_intervals(
                session_active_intervals,
                session_afk_intervals.get("not-afk", []),
            )
        )
    return _merge_intervals(not_afk_active_intervals)


def _aggregate_window_segment(
    rows: Dict[Tuple[int, str, str, str, str, str, str, bool], Dict[str, Any]],
    *,
    bin_index: int,
    bin_start: datetime,
    identity: Dict[str, Any],
    data: Dict[str, Any],
    seconds: float,
    afk: bool,
) -> None:
    if seconds <= 1:
        return

    app = str(data.get("app") or data.get("process_name") or "Unknown")
    title = str(data.get("title") or "(no title)")
    process_name = str(data.get("process_name") or app)
    process_path = str(data.get("process_path") or "")
    device_id = str(identity.get("device_id") or "unknown")
    device_name = str(identity.get("device_name") or device_id)
    key = (
        bin_index,
        app,
        title,
        process_name,
        process_path,
        device_id,
        device_name,
        afk,
    )
    row = rows.setdefault(
        key,
        {
            "bin_index": bin_index,
            "timestamp": bin_start,
            "duration": 0.0,
            "data": {
                "username": identity.get("username") or "unknown",
                "device_id": device_id,
                "device_name": device_name,
                "session_id": "aggregate",
                "app": app,
                "title": title,
                "process_name": process_name,
                "process_path": process_path,
                "$afk": afk,
                "$aggregate": True,
            },
        },
    )
    row["duration"] += seconds


def _cap_aggregated_activity_events(
    events: List[Dict[str, Any]], max_rows_per_bin: int
) -> Tuple[List[Dict[str, Any]], bool]:
    if max_rows_per_bin <= 0:
        return events, False

    capped: List[Dict[str, Any]] = []
    truncated = False
    events_by_bin: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        events_by_bin[int(event.get("bin_index") or 0)].append(event)

    for bin_index in sorted(events_by_bin):
        bin_events = sorted(
            events_by_bin[bin_index],
            key=lambda event: float(event.get("duration") or 0.0),
            reverse=True,
        )
        if len(bin_events) <= max_rows_per_bin:
            capped.extend(bin_events)
            continue

        truncated = True
        keep_count = max(1, max_rows_per_bin - 2)
        kept = bin_events[:keep_count]
        remainder = bin_events[keep_count:]
        capped.extend(kept)

        other_by_afk: Dict[bool, Dict[str, Any]] = {}
        for event in remainder:
            afk = bool(dict(event.get("data") or {}).get("$afk"))
            other = other_by_afk.get(afk)
            if other is None:
                other = {
                    "bin_index": bin_index,
                    "timestamp": event["timestamp"],
                    "duration": 0.0,
                    "data": {
                        "username": dict(event.get("data") or {}).get(
                            "username", "unknown"
                        ),
                        "device_id": "multiple",
                        "device_name": "Multiple devices",
                        "session_id": "aggregate",
                        "app": "Other",
                        "title": "Aggregated smaller entries",
                        "process_name": "Other",
                        "$afk": afk,
                        "$aggregate": True,
                        "$aggregate_other": True,
                    },
                }
                other_by_afk[afk] = other
            other["duration"] += float(event.get("duration") or 0.0)
        capped.extend(
            other
            for other in other_by_afk.values()
            if float(other.get("duration") or 0.0) > 1
        )

    return capped, truncated


def summarize_user_activity(
    api,
    username: str,
    start: Optional[datetime],
    end: Optional[datetime],
    device_ids: Optional[Iterable[str]] = None,
    include_afk_time: bool = False,
    exclude_inactive_session_afk: bool = False,
    max_rows_per_bin: int = AGGREGATED_ACTIVITY_MAX_ROWS_PER_BIN,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    selected_device_ids = _normalize_device_ids(device_ids=device_ids)
    bin_unit, bins = _timeline_bins(start, end)

    afk_intervals = _load_afk_intervals(
        api,
        username=username,
        device_ids=selected_device_ids,
        start=start,
        end=end,
    )
    active_session_intervals, known_session_keys = _load_active_session_intervals(
        api,
        username=username,
        device_ids=selected_device_ids,
        start=start,
        end=end,
    )
    active_session_totals = _bin_session_seconds(
        bins,
        (
            interval
            for intervals in active_session_intervals.values()
            for interval in intervals
        ),
    )
    not_afk_active_totals = _bin_session_seconds(
        bins,
        _not_afk_active_session_intervals(
            active_session_intervals,
            known_session_keys,
            afk_intervals,
        ),
    )
    for index, bin_row in enumerate(bins):
        bin_row["active_session_seconds"] = active_session_totals[index]
        bin_row["not_afk_active_session_seconds"] = not_afk_active_totals[index]

    aggregate_rows: Dict[
        Tuple[int, str, str, str, str, str, str, bool], Dict[str, Any]
    ] = {}
    source_event_count = 0

    for bucket in _matching_buckets(
        api,
        kind="window",
        username=username,
        device_ids=selected_device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue

            interval = _clip_event_interval(event, start, end)
            if interval is None:
                continue

            source_event_count += 1
            data = dict(event.get("data") or {})
            session_key = _identity_session_key(identity)
            session_afk_intervals = afk_intervals.get(session_key)
            has_afk_data = session_afk_intervals is not None
            not_afk_intervals = (
                session_afk_intervals.get("not-afk", [])
                if session_afk_intervals is not None
                else []
            )
            afk_only_intervals = (
                session_afk_intervals.get("afk", [])
                if session_afk_intervals is not None
                else []
            )
            if (
                exclude_inactive_session_afk
                and session_key in known_session_keys
                and active_session_intervals.get(session_key)
            ):
                afk_only_intervals = _intersect_intervals(
                    afk_only_intervals,
                    active_session_intervals.get(session_key, []),
                )

            event_start, event_end = interval
            for bin_row in bins:
                if bin_row["end"] <= event_start:
                    continue
                if bin_row["start"] >= event_end:
                    break

                segment_start = max(event_start, bin_row["start"])
                segment_end = min(event_end, bin_row["end"])
                if segment_end <= segment_start:
                    continue

                segment_seconds = (segment_end - segment_start).total_seconds()
                if include_afk_time:
                    afk_seconds = (
                        _sum_interval_overlaps(
                            segment_start,
                            segment_end,
                            afk_only_intervals,
                        )
                        if has_afk_data
                        else 0.0
                    )
                    afk_seconds = min(afk_seconds, segment_seconds)
                    active_seconds = max(0.0, segment_seconds - afk_seconds)
                    _aggregate_window_segment(
                        aggregate_rows,
                        bin_index=bin_row["index"],
                        bin_start=bin_row["start"],
                        identity=identity,
                        data=data,
                        seconds=active_seconds,
                        afk=False,
                    )
                    _aggregate_window_segment(
                        aggregate_rows,
                        bin_index=bin_row["index"],
                        bin_start=bin_row["start"],
                        identity=identity,
                        data=data,
                        seconds=afk_seconds,
                        afk=True,
                    )
                    continue

                active_seconds = (
                    _sum_interval_overlaps(
                        segment_start,
                        segment_end,
                        not_afk_intervals,
                    )
                    if has_afk_data
                    else segment_seconds
                )
                _aggregate_window_segment(
                    aggregate_rows,
                    bin_index=bin_row["index"],
                    bin_start=bin_row["start"],
                    identity=identity,
                    data=data,
                    seconds=min(active_seconds, segment_seconds),
                    afk=False,
                )

    aggregate_events = sorted(
        aggregate_rows.values(),
        key=lambda event: (
            event.get("bin_index", 0),
            -float(event.get("duration") or 0.0),
            str(dict(event.get("data") or {}).get("app") or ""),
        ),
    )
    uncapped_event_count = len(aggregate_events)
    aggregate_events, truncated = _cap_aggregated_activity_events(
        aggregate_events, max_rows_per_bin
    )

    payload_events = []
    for index, event in enumerate(aggregate_events, start=1):
        data = dict(event.get("data") or {})
        payload_events.append(
            {
                "id": f"aggregate-{event.get('bin_index', 0)}-{index}",
                "timestamp": _isoformat(event["timestamp"]),
                "duration": round(float(event.get("duration") or 0.0), 3),
                "data": data,
            }
        )

    return {
        "generated_at": _utcnow().isoformat(),
        "mode": "aggregate",
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "filters": {
            "username": username,
            "device_ids": selected_device_ids,
            "include_afk_time": include_afk_time,
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
            "max_rows_per_bin": max_rows_per_bin,
        },
        "bin_unit": bin_unit,
        "bins": [
            {
                "index": bin_row["index"],
                "unit": bin_row["unit"],
                "start": _isoformat(bin_row["start"]),
                "end": _isoformat(bin_row["end"]),
                "active_session_seconds": round(
                    float(bin_row.get("active_session_seconds") or 0.0), 3
                ),
                "not_afk_active_session_seconds": round(
                    float(bin_row.get("not_afk_active_session_seconds") or 0.0), 3
                ),
            }
            for bin_row in bins
        ],
        "events": payload_events,
        "stats": {
            "source_event_count": source_event_count,
            "uncapped_event_count": uncapped_event_count,
            "returned_event_count": len(payload_events),
            "truncated": truncated,
        },
    }


def report_time_by_app(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    app_contains: Optional[str] = None,
    exclude_inactive_session_afk: bool = False,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    selected_device_ids = _normalize_device_ids(device_id=device_id, device_ids=device_ids)
    afk_intervals = _load_afk_intervals(
        api,
        username=username,
        device_id=device_id,
        device_ids=selected_device_ids,
        start=start,
        end=end,
    )
    active_session_intervals = None
    known_session_keys = None
    if exclude_inactive_session_afk:
        active_session_intervals, known_session_keys = _load_active_session_intervals(
            api,
            username=username,
            device_id=device_id,
            device_ids=selected_device_ids,
            start=start,
            end=end,
        )
    rows: Dict[Tuple[str, str, str, str], Dict[str, float]] = defaultdict(
        lambda: {"seconds": 0.0, "active_seconds": 0.0, "afk_seconds": 0.0}
    )

    for bucket in _matching_buckets(
        api,
        kind="window",
        username=username,
        device_id=device_id,
        device_ids=device_ids,
    ):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            data = dict(event.get("data") or {})
            identity = _event_identity(bucket, event)
            if username is not None and identity["username"] != username:
                continue
            if not _matches_device_filter(identity["device_id"], selected_device_ids):
                continue
            app = str(data.get("app") or data.get("process_name") or "Unknown")
            if app_contains and app_contains.lower() not in app.lower():
                continue
            seconds, active_seconds, afk_seconds = _window_event_breakdown(
                identity,
                event,
                start=start,
                end=end,
                afk_intervals=afk_intervals,
                active_session_intervals=active_session_intervals,
                known_session_keys=known_session_keys,
            )
            if seconds <= 0:
                continue
            key = (
                identity["username"],
                identity["device_id"],
                identity["device_name"],
                app,
            )
            rows[key]["seconds"] += seconds
            rows[key]["active_seconds"] += active_seconds
            rows[key]["afk_seconds"] += afk_seconds

    payload_rows = [
        {
            "username": row_username,
            "device_id": row_device_id,
            "device_name": row_device_name,
            "app": app,
            "seconds": totals["seconds"],
            "active_seconds": totals["active_seconds"],
            "afk_seconds": totals["afk_seconds"],
        }
        for (row_username, row_device_id, row_device_name, app), totals in rows.items()
    ]
    payload_rows = sorted(payload_rows, key=lambda row: row["seconds"], reverse=True)

    return {
        "report": "time_by_app",
        "filters": {
            "username": username,
            "device_id": device_id,
            "device_ids": selected_device_ids,
            "app_contains": app_contains,
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
            "start": _isoformat(start),
            "end": _isoformat(end),
        },
        "rows": payload_rows,
    }


def _collect_user_device_catalog(
    api,
    *,
    username: str,
    start: datetime,
    end: datetime,
) -> Dict[str, str]:
    devices: Dict[str, str] = {}

    for bucket in _matching_buckets(api, username=username):
        events = api.get_events(bucket["bucket_id"], limit=-1, start=start, end=end)
        for event in events:
            identity = _event_identity(bucket, event)
            if identity["username"] != username:
                continue
            if _clip_event_seconds(event, start, end) <= 0:
                continue
            devices[identity["device_id"]] = identity["device_name"]

    live = summarize_live_state(api)
    for session in live["users"]:
        if session["username"] != username:
            continue
        devices.setdefault(session["device_id"], session["device_name"])

    return devices


def _resolve_user_device_selection(
    api,
    *,
    username: str,
    start: datetime,
    end: datetime,
    device_ids: Optional[Iterable[str]] = None,
) -> Tuple[Dict[str, str], List[str]]:
    available_device_catalog = _collect_user_device_catalog(
        api,
        username=username,
        start=start,
        end=end,
    )
    selected_device_ids = _normalize_device_ids(device_ids=device_ids)
    if selected_device_ids is None:
        selected_device_ids = sorted(available_device_catalog)
    else:
        for device_id in selected_device_ids:
            available_device_catalog.setdefault(device_id, device_id)

    return available_device_catalog, selected_device_ids


def _user_available_devices_payload(
    available_device_catalog: Dict[str, str],
) -> List[Dict[str, str]]:
    return [
        {"device_id": device_id, "device_name": device_name}
        for device_id, device_name in sorted(
            available_device_catalog.items(), key=lambda item: item[1] or item[0]
        )
    ]


def calculate_user_summary_totals(
    api,
    username: str,
    start: Optional[datetime],
    end: Optional[datetime],
    device_ids: Optional[Iterable[str]] = None,
    exclude_inactive_session_afk: bool = False,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    available_device_catalog, selected_device_ids = _resolve_user_device_selection(
        api,
        username=username,
        start=start,
        end=end,
        device_ids=device_ids,
    )

    active_session_intervals = None
    known_session_keys = None
    if exclude_inactive_session_afk:
        active_session_intervals, known_session_keys = _load_active_session_intervals(
            api,
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
        )

    totals = {
        **_session_state_totals(
            api,
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
        ),
        "afk_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "afk",
            restrict_to_intervals_by_session=active_session_intervals,
            restrict_known_sessions=known_session_keys,
        ),
        "not_afk_active_seconds": _not_afk_active_session_seconds(
            api,
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
        ),
    }

    return {
        "username": username,
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "filters": {
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
        },
        "devices": sorted(available_device_catalog),
        "available_devices": _user_available_devices_payload(available_device_catalog),
        "selected_devices": sorted(selected_device_ids),
        "totals": totals,
    }


def build_user_detail_from_summary(api, username: str, summary: Dict[str, Any]) -> Dict[str, Any]:
    """Build the user detail payload from a fully cached summary (totals + apps +
    available_devices) without scanning any events; only live session state is read."""
    api = wrap_fleet_event_cache(api)
    live = summarize_live_state(api)
    selected_device_ids = [str(value) for value in (summary.get("selected_devices") or [])]
    selected_device_set = set(selected_device_ids)
    sessions = [
        session
        for session in live["users"]
        if session["username"] == username
        and (not selected_device_ids or session["device_id"] in selected_device_set)
    ]
    available_devices = list(summary.get("available_devices") or [])
    available_device_catalog = {
        device["device_id"]: device["device_name"] for device in available_devices
    }

    return {
        "username": username,
        "range": dict(summary.get("range") or {}),
        "filters": {
            "exclude_inactive_session_afk": bool(
                (summary.get("filters") or {}).get("exclude_inactive_session_afk")
            ),
        },
        "devices": sorted(available_device_catalog),
        "available_devices": _user_available_devices_payload(available_device_catalog),
        "selected_devices": sorted(selected_device_ids),
        "totals": summary["totals"],
        "apps": list(summary.get("apps") or []),
        "sessions": sessions,
    }


def summarize_user(
    api,
    username: str,
    start: Optional[datetime],
    end: Optional[datetime],
    device_ids: Optional[Iterable[str]] = None,
    exclude_inactive_session_afk: bool = False,
    precomputed_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    live = summarize_live_state(api)
    all_sessions = [session for session in live["users"] if session["username"] == username]
    summary = precomputed_summary
    if summary is None:
        summary = calculate_user_summary_totals(
            api,
            username,
            start,
            end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )
    if summary.get("available_devices"):
        available_device_catalog = {
            device["device_id"]: device["device_name"]
            for device in summary["available_devices"]
        }
        selected_device_ids = list(summary["selected_devices"])
    else:
        # Totals-only cache entries (e.g. from nightly precompute) do not carry
        # the device catalog; resolve it from events (shared via the event cache).
        available_device_catalog, selected_device_ids = _resolve_user_device_selection(
            api,
            username=username,
            start=start,
            end=end,
            device_ids=device_ids,
        )

    selected_device_set = set(selected_device_ids)
    sessions = [
        session
        for session in all_sessions
        if session["device_id"] in selected_device_set or not selected_device_ids
    ]

    apps_report = report_time_by_app(
        api,
        username=username,
        device_ids=selected_device_ids,
        start=start,
        end=end,
        exclude_inactive_session_afk=exclude_inactive_session_afk,
    )
    apps_by_name: Dict[str, Dict[str, Any]] = {}
    for row in apps_report["rows"]:
        item = apps_by_name.setdefault(
            row["app"],
            {
                "app": row["app"],
                "seconds": 0.0,
                "active_seconds": 0.0,
                "afk_seconds": 0.0,
                "devices": set(),
            },
        )
        item["seconds"] += row["seconds"]
        item["active_seconds"] += row["active_seconds"]
        item["afk_seconds"] += row["afk_seconds"]
        item["devices"].add(row["device_id"])
        available_device_catalog.setdefault(row["device_id"], row["device_name"])

    apps = [
        {
            "app": item["app"],
            "seconds": item["seconds"],
            "active_seconds": item["active_seconds"],
            "afk_seconds": item["afk_seconds"],
            "devices": sorted(item["devices"]),
        }
        for item in sorted(
            apps_by_name.values(), key=lambda item: item["seconds"], reverse=True
        )
    ]

    return {
        "username": username,
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "filters": {
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
        },
        "devices": sorted(available_device_catalog),
        "available_devices": [
            {"device_id": device_id, "device_name": device_name}
            for device_id, device_name in sorted(
                available_device_catalog.items(), key=lambda item: item[1] or item[0]
            )
        ],
        "selected_devices": sorted(selected_device_ids),
        "totals": summary["totals"],
        "apps": apps,
        "sessions": sessions,
    }


def summarize_device(
    api,
    device_id: str,
    start: Optional[datetime],
    end: Optional[datetime],
    exclude_inactive_session_afk: bool = False,
) -> Dict[str, Any]:
    api = wrap_fleet_event_cache(api)
    start, end = _normalize_range(start, end)
    live = summarize_live_state(api)
    device = next(
        (device for device in live["devices"] if device["device_id"] == device_id), None
    )
    sessions = device["sessions"] if device else []
    users = sorted({session["username"] for session in sessions})
    active_session_intervals = None
    known_session_keys = None
    if exclude_inactive_session_afk:
        active_session_intervals, known_session_keys = _load_active_session_intervals(
            api,
            device_id=device_id,
            start=start,
            end=end,
        )

    totals = {
        **_session_state_totals(
            api,
            device_id=device_id,
            start=start,
            end=end,
        ),
        "afk_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "afk",
            restrict_to_intervals_by_session=active_session_intervals,
            restrict_known_sessions=known_session_keys,
        ),
    }

    apps_report = report_time_by_app(
        api,
        device_id=device_id,
        start=start,
        end=end,
        exclude_inactive_session_afk=exclude_inactive_session_afk,
    )
    apps = [
        {
            "username": row["username"],
            "app": row["app"],
            "seconds": row["seconds"],
            "active_seconds": row["active_seconds"],
            "afk_seconds": row["afk_seconds"],
        }
        for row in apps_report["rows"]
    ]

    return {
        "device_id": device_id,
        "device_name": device["device_name"] if device else device_id,
        "users": users,
        "status": device["status"] if device else "stale",
        "last_updated": device["last_updated"] if device else None,
        "range": {"start": _isoformat(start), "end": _isoformat(end)},
        "filters": {
            "exclude_inactive_session_afk": exclude_inactive_session_afk,
        },
        "totals": totals,
        "apps": apps,
        "sessions": sessions,
    }


def run_report(api, report_spec: Dict[str, Any]) -> Dict[str, Any]:
    report_name = report_spec.get("report")
    filters = dict(report_spec.get("filters") or {})
    start = _parse_datetime(filters.get("start"))
    end = _parse_datetime(filters.get("end"))

    if report_name == "time_by_app":
        return report_time_by_app(
            api,
            username=filters.get("username"),
            device_id=filters.get("device_id"),
            device_ids=filters.get("device_ids"),
            start=start,
            end=end,
            app_contains=filters.get("app_contains"),
            exclude_inactive_session_afk=bool(
                filters.get("exclude_inactive_session_afk")
            ),
        )

    raise ValueError(f"Unknown fleet report '{report_name}'")
