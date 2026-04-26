import logging
from typing import Any, Dict, Optional


logger = logging.getLogger(__name__)

REQUIRED_IDENTITY_FIELDS = (
    "username",
    "device_id",
    "device_name",
    "session_id",
    "session_type",
    "hostname",
)

IDENTITY_FIELDS = (
    "username",
    "device_id",
    "device_name",
    "session_id",
    "session_type",
    "domain",
    "hostname",
)


def _is_missing_value(key: str, value: Any) -> bool:
    if value is None:
        return True

    if not isinstance(value, str):
        return False

    normalized = value.strip()
    if normalized == "":
        return True

    if key != "domain" and normalized.lower() == "unknown":
        return True

    return False


def _merged_identity_data(bucket: Dict[str, Any], event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    bucket_data = dict(bucket.get("data") or {})
    event_data = dict((event or {}).get("data") or {})
    merged = dict(bucket_data)

    for key in IDENTITY_FIELDS:
        current = merged.get(key)
        candidate = event_data.get(key)

        if key == "hostname" and _is_missing_value(key, candidate):
            candidate = bucket.get("hostname")

        if _is_missing_value(key, current) and not _is_missing_value(key, candidate):
            merged[key] = candidate

    hostname = merged.get("hostname") or bucket.get("hostname")
    if _is_missing_value("device_id", merged.get("device_id")) and not _is_missing_value(
        "device_id", hostname
    ):
        merged["device_id"] = hostname

    if _is_missing_value("device_name", merged.get("device_name")):
        device_name = merged.get("hostname") or merged.get("device_id")
        if not _is_missing_value("device_name", device_name):
            merged["device_name"] = device_name

    return merged


def backfill_bucket_identities(api) -> int:
    updated = 0

    for bucket in api.db.buckets().values():
        bucket_type = str(bucket.get("type") or "")
        if bucket_type.startswith("general.stopwatch"):
            continue

        current_data = dict(bucket.get("data") or {})
        if all(
            not _is_missing_value(key, current_data.get(key))
            for key in REQUIRED_IDENTITY_FIELDS
        ):
            continue

        events = api.get_events(bucket["id"], limit=1)
        latest_event = events[0] if events else None
        merged_data = _merged_identity_data(bucket, latest_event)

        if merged_data == current_data:
            continue

        api.update_bucket(bucket["id"], data=merged_data)
        updated += 1
        logger.info("Backfilled identity metadata for bucket '%s'", bucket["id"])

    return updated
