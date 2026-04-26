from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import iso8601

WATCHER_KIND_BY_TYPE = {
    "currentwindow": "window",
    "afkstatus": "afk",
    "sessionstate": "session",
}

LIVE_STALE_AFTER = timedelta(minutes=2)
DEFAULT_REPORT_RANGE = timedelta(days=7)


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
            },
        )

        data = dict((snapshot.get("latest_event") or {}).get("data") or {})
        updated = snapshot.get("last_updated")
        if session["_last_updated_dt"] is None or (
            updated is not None and updated > session["_last_updated_dt"]
        ):
            session["_last_updated_dt"] = updated

        if snapshot["kind"] == "session":
            session["session_state"] = data.get("state") or session["session_state"]
            session["session_reason"] = data.get("reason") or session["session_reason"]
        elif snapshot["kind"] == "afk":
            session["afk_status"] = data.get("status") or session["afk_status"]
        elif snapshot["kind"] == "window":
            session["current_app"] = data.get("app") or session["current_app"]
            session["current_title"] = data.get("title") or session["current_title"]
            session["process_name"] = data.get("process_name") or session["process_name"]
            session["process_path"] = data.get("process_path") or session["process_path"]
            session["explorer_path"] = data.get("explorer_path") or session["explorer_path"]

    session_rows = []
    for session in sessions.values():
        session["state"] = _derive_effective_state(
            session.get("session_state"), session.get("afk_status")
        )
        session["last_updated"] = _isoformat(session.pop("_last_updated_dt"))
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
    now = _utcnow()
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
        if session.get("state") not in {"logged_off", "no_session"}:
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
) -> float:
    total_seconds = 0.0
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
                total_seconds += _clip_event_seconds(event, start, end)
    return total_seconds


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


def _window_event_breakdown(
    identity: Dict[str, Any],
    event: Dict[str, Any],
    *,
    start: datetime,
    end: datetime,
    afk_intervals: Dict[Tuple[str, str, str], Dict[str, List[Tuple[datetime, datetime]]]],
) -> Tuple[float, float, float]:
    interval = _clip_event_interval(event, start, end)
    if interval is None:
        return (0.0, 0.0, 0.0)

    interval_start, interval_end = interval
    total_seconds = (interval_end - interval_start).total_seconds()

    session_intervals = afk_intervals.get(_identity_session_key(identity), {})
    active_seconds = _sum_interval_overlaps(
        interval_start, interval_end, session_intervals.get("not-afk", [])
    )
    afk_seconds = _sum_interval_overlaps(
        interval_start, interval_end, session_intervals.get("afk", [])
    )

    if active_seconds > total_seconds:
        active_seconds = total_seconds
    if afk_seconds > total_seconds:
        afk_seconds = total_seconds

    return (total_seconds, active_seconds, afk_seconds)


def report_time_by_app(
    api,
    *,
    username: Optional[str] = None,
    device_id: Optional[str] = None,
    device_ids: Optional[Iterable[str]] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    app_contains: Optional[str] = None,
) -> Dict[str, Any]:
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


def summarize_user(
    api,
    username: str,
    start: Optional[datetime],
    end: Optional[datetime],
    device_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    start, end = _normalize_range(start, end)
    live = summarize_live_state(api)
    all_sessions = [session for session in live["users"] if session["username"] == username]
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

    selected_device_set = set(selected_device_ids)
    sessions = [
        session
        for session in all_sessions
        if session["device_id"] in selected_device_set or not selected_device_ids
    ]

    totals = {
        "active_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "not-afk",
        ),
        "afk_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "afk",
        ),
        "locked_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "locked",
        ),
        "disconnected_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "disconnected",
        ),
        "logged_in_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            username=username,
            device_ids=selected_device_ids,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "logged_in",
        ),
    }

    apps_report = report_time_by_app(
        api,
        username=username,
        device_ids=selected_device_ids,
        start=start,
        end=end,
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
        "devices": sorted(available_device_catalog),
        "available_devices": [
            {"device_id": device_id, "device_name": device_name}
            for device_id, device_name in sorted(
                available_device_catalog.items(), key=lambda item: item[1] or item[0]
            )
        ],
        "selected_devices": sorted(selected_device_ids),
        "totals": totals,
        "apps": apps,
        "sessions": sessions,
    }


def summarize_device(
    api, device_id: str, start: Optional[datetime], end: Optional[datetime]
) -> Dict[str, Any]:
    start, end = _normalize_range(start, end)
    live = summarize_live_state(api)
    device = next(
        (device for device in live["devices"] if device["device_id"] == device_id), None
    )
    sessions = device["sessions"] if device else []
    users = sorted({session["username"] for session in sessions})

    totals = {
        "active_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "not-afk",
        ),
        "afk_seconds": _sum_bucket_event_seconds(
            api,
            kind="afk",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("status") == "afk",
        ),
        "locked_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "locked",
        ),
        "disconnected_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "disconnected",
        ),
        "logged_in_seconds": _sum_bucket_event_seconds(
            api,
            kind="session",
            device_id=device_id,
            start=start,
            end=end,
            predicate=lambda data: data.get("state") == "logged_in",
        ),
    }

    apps_report = report_time_by_app(api, device_id=device_id, start=start, end=end)
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
        )

    raise ValueError(f"Unknown fleet report '{report_name}'")
