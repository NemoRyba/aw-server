import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import iso8601
from aw_core.models import Event


PROTOCOL_VERSION = 1
SYNC_MARKER_KEY = "_aw_fleet_sync"
SYNC_CLIENT_NAME = "aw-fleet-sync"


class FleetSyncConflict(Exception):
    def __init__(
        self,
        *,
        stream_id: str,
        need_resync_from_seq: int,
        last_acked_seq: int,
    ) -> None:
        self.payload = {
            "stream_id": stream_id,
            "need_resync_from_seq": need_resync_from_seq,
            "last_acked_seq": last_acked_seq,
        }
        super().__init__(json.dumps(self.payload, sort_keys=True))


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def checksum_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf8")).hexdigest()


def sync_handshake(api, payload: Dict[str, Any]) -> Dict[str, Any]:
    _require_protocol_version(payload)
    agent = _require_dict(payload, "agent")
    streams = payload.get("streams", [])
    if not isinstance(streams, list):
        raise ValueError("streams must be a list")

    _require_agent(agent)
    server_time = _utcnow()
    response_streams = []

    with api.sync_store.transaction() as conn:
        api.sync_store.upsert_agent(agent, conn)
        for stream in streams:
            stream_id = _require_str(stream, "stream_id")
            bucket_id = _require_str(stream, "bucket_id")
            bucket_type = _require_str(stream, "bucket_type")
            bucket_metadata = _require_dict(stream, "bucket_metadata")

            if not stream_id.startswith(f"{agent['agent_id']}:"):
                raise ValueError("stream_id must be prefixed by agent_id")

            central_bucket_id = bucket_id
            api.sync_store.upsert_stream(
                stream_id=stream_id,
                agent_id=agent["agent_id"],
                device_id=agent["device_id"],
                device_name=agent["device_name"],
                hostname=agent["hostname"],
                bucket_id=bucket_id,
                bucket_type=bucket_type,
                central_bucket_id=central_bucket_id,
                bucket_metadata=bucket_metadata,
                conn=conn,
                touch_received_at=True,
            )
            stream_row = api.sync_store.get_stream(stream_id, conn)
            assert stream_row is not None
            response_streams.append(
                {
                    "stream_id": stream_id,
                    "central_bucket_id": central_bucket_id,
                    "last_acked_seq": int(stream_row["last_acked_seq"]),
                }
            )

    return {
        "protocol_version": PROTOCOL_VERSION,
        "server_time": server_time,
        "streams": response_streams,
    }


def sync_batch(api, payload: Dict[str, Any]) -> Dict[str, Any]:
    _require_protocol_version(payload)
    agent_id = _require_str(payload, "agent_id")
    stream_id = _require_str(payload, "stream_id")
    from_seq = _require_int(payload, "from_seq")
    to_seq = _require_int(payload, "to_seq")
    ops = payload.get("ops")

    if not isinstance(ops, list) or not ops:
        raise ValueError("ops must be a non-empty list")
    if from_seq > to_seq:
        raise ValueError("from_seq must be <= to_seq")

    expected_seqs = list(range(from_seq, to_seq + 1))
    actual_seqs = [_require_int(op, "seq") for op in ops]
    if actual_seqs != expected_seqs:
        raise ValueError("ops must use strict contiguous seq values from from_seq to to_seq")

    applied_ops = 0
    replaced_events = 0
    deduplicated_ops = 0
    received_at = _utcnow()

    with api.sync_store.transaction() as conn:
        stream_row = api.sync_store.get_stream(stream_id, conn)
        if stream_row is None:
            raise ValueError(f"Unknown stream_id: {stream_id}")
        if stream_row["agent_id"] != agent_id:
            raise ValueError("agent_id does not match the registered stream owner")

        last_acked_seq = int(stream_row["last_acked_seq"])
        need_resync_from_seq = last_acked_seq + 1
        if from_seq != need_resync_from_seq:
            raise FleetSyncConflict(
                stream_id=stream_id,
                need_resync_from_seq=need_resync_from_seq,
                last_acked_seq=last_acked_seq,
            )

        api.sync_store.touch_stream_received(stream_id, conn, received_at=received_at)
        central_bucket_id = str(stream_row["central_bucket_id"])

        for op in ops:
            op_type = _require_str(op, "op_type")
            seq = _require_int(op, "seq")
            op_payload = _require_dict(op, "payload")

            if op_type == "bucket_upsert":
                central_bucket_id = _apply_bucket_upsert(
                    api, conn, stream_row, op_payload
                )
                stream_row = api.sync_store.get_stream(stream_id, conn)
                assert stream_row is not None
            elif op_type == "event_upsert":
                applied, replaced, deduped = _apply_event_upsert(
                    api,
                    conn,
                    stream_row,
                    central_bucket_id,
                    seq,
                    op_payload,
                )
                replaced_events += replaced
                deduplicated_ops += deduped
                if applied:
                    applied_ops += 1
                continue
            else:
                raise ValueError(f"Unsupported op_type: {op_type}")

            applied_ops += 1

        api.sync_store.update_stream_ack(
            stream_id,
            to_seq,
            conn,
            received_at=received_at,
        )

    return {
        "stream_id": stream_id,
        "acked_through_seq": to_seq,
        "applied_ops": applied_ops,
        "replaced_events": replaced_events,
        "deduplicated_ops": deduplicated_ops,
        "central_bucket_id": central_bucket_id,
    }


def _apply_bucket_upsert(api, conn, stream_row, payload: Dict[str, Any]) -> str:
    bucket_id = _require_str(payload, "bucket_id")
    bucket_type = _require_str(payload, "bucket_type")
    bucket_metadata = _require_dict(payload, "bucket_metadata")

    if bucket_id != stream_row["bucket_id"]:
        raise ValueError("bucket_upsert bucket_id does not match registered stream bucket_id")
    if bucket_type != stream_row["bucket_type"]:
        raise ValueError("bucket_upsert bucket_type does not match registered stream bucket_type")

    central_bucket_id = bucket_id
    _ensure_central_bucket(api, central_bucket_id, bucket_type, bucket_metadata)
    api.sync_store.upsert_stream(
        stream_id=str(stream_row["stream_id"]),
        agent_id=str(stream_row["agent_id"]),
        device_id=str(stream_row["device_id"]),
        device_name=str(stream_row["device_name"]),
        hostname=str(stream_row["hostname"]),
        bucket_id=bucket_id,
        bucket_type=bucket_type,
        central_bucket_id=central_bucket_id,
        bucket_metadata=bucket_metadata,
        conn=conn,
    )
    return central_bucket_id


def _apply_event_upsert(
    api,
    conn,
    stream_row,
    central_bucket_id: str,
    seq: int,
    payload: Dict[str, Any],
) -> Tuple[bool, int, int]:
    source_event_id = _require_int(payload, "source_event_id")
    source_event_version = _require_int(payload, "source_event_version")
    timestamp = _parse_datetime(_require_str(payload, "timestamp"))
    duration_seconds = _require_number(payload, "duration")
    source_data = _require_dict(payload, "data")

    bucket_metadata = json.loads(stream_row["bucket_metadata_json"])
    _ensure_central_bucket(
        api,
        central_bucket_id,
        str(stream_row["bucket_type"]),
        bucket_metadata,
    )

    event_checksum = checksum_payload(
        {
            "timestamp": timestamp.isoformat(),
            "duration": duration_seconds,
            "data": source_data,
        }
    )

    event_payload = deepcopy(source_data)
    for key, value in bucket_metadata.items():
        event_payload.setdefault(key, value)
    event_payload[SYNC_MARKER_KEY] = {
        "agent_id": str(stream_row["agent_id"]),
        "stream_id": str(stream_row["stream_id"]),
        "source_event_id": source_event_id,
        "source_event_version": source_event_version,
        "seq": seq,
        "checksum": event_checksum,
    }

    mapping = api.sync_store.get_event_map(str(stream_row["stream_id"]), source_event_id, conn)
    if mapping is None:
        recovered = _recover_existing_mapping(
            api,
            central_bucket_id,
            str(stream_row["stream_id"]),
            source_event_id,
        )
        if recovered is not None:
            central_event_id, recovered_version, recovered_checksum = recovered
            api.sync_store.upsert_event_map(
                stream_id=str(stream_row["stream_id"]),
                source_event_id=source_event_id,
                source_event_version=recovered_version,
                central_bucket_id=central_bucket_id,
                central_event_id=central_event_id,
                event_checksum=recovered_checksum,
                last_seq=seq,
                conn=conn,
            )
            mapping = api.sync_store.get_event_map(
                str(stream_row["stream_id"]), source_event_id, conn
            )

    if mapping is None:
        event = Event(
            timestamp=timestamp,
            duration=timedelta(seconds=duration_seconds),
            data=event_payload,
        )
        inserted = api.db[central_bucket_id].insert(event)
        assert inserted is not None and inserted.id is not None
        api.sync_store.upsert_event_map(
            stream_id=str(stream_row["stream_id"]),
            source_event_id=source_event_id,
            source_event_version=source_event_version,
            central_bucket_id=central_bucket_id,
            central_event_id=int(inserted.id),
            event_checksum=event_checksum,
            last_seq=seq,
            conn=conn,
        )
        return True, 0, 0

    stored_version = int(mapping["source_event_version"])
    stored_checksum = str(mapping["event_checksum"])
    mapped_bucket_id = str(mapping["central_bucket_id"])
    mapped_event_id = int(mapping["central_event_id"])

    if source_event_version < stored_version:
        api.sync_store.upsert_event_map(
            stream_id=str(stream_row["stream_id"]),
            source_event_id=source_event_id,
            source_event_version=stored_version,
            central_bucket_id=mapped_bucket_id,
            central_event_id=mapped_event_id,
            event_checksum=stored_checksum,
            last_seq=seq,
            conn=conn,
        )
        return False, 0, 1

    if source_event_version == stored_version:
        if event_checksum != stored_checksum:
            raise ValueError(
                f"Conflicting event_upsert for source_event_id={source_event_id} with equal version"
            )
        api.sync_store.upsert_event_map(
            stream_id=str(stream_row["stream_id"]),
            source_event_id=source_event_id,
            source_event_version=stored_version,
            central_bucket_id=mapped_bucket_id,
            central_event_id=mapped_event_id,
            event_checksum=stored_checksum,
            last_seq=seq,
            conn=conn,
        )
        return False, 0, 1

    event = Event(
        timestamp=timestamp,
        duration=timedelta(seconds=duration_seconds),
        data=event_payload,
    )
    current = api.db[mapped_bucket_id].get_by_id(mapped_event_id)
    if current is None:
        recovered = _recover_existing_mapping(
            api,
            mapped_bucket_id,
            str(stream_row["stream_id"]),
            source_event_id,
        )
        if recovered is not None:
            mapped_event_id, _, _ = recovered
            current = api.db[mapped_bucket_id].get_by_id(mapped_event_id)

    if current is None:
        inserted = api.db[mapped_bucket_id].insert(event)
        assert inserted is not None and inserted.id is not None
        mapped_event_id = int(inserted.id)
    else:
        api.db[mapped_bucket_id].replace(mapped_event_id, event)

    api.sync_store.upsert_event_map(
        stream_id=str(stream_row["stream_id"]),
        source_event_id=source_event_id,
        source_event_version=source_event_version,
        central_bucket_id=mapped_bucket_id,
        central_event_id=mapped_event_id,
        event_checksum=event_checksum,
        last_seq=seq,
        conn=conn,
    )
    return True, 1, 0


def _recover_existing_mapping(
    api,
    central_bucket_id: str,
    stream_id: str,
    source_event_id: int,
) -> Optional[Tuple[int, int, str]]:
    if central_bucket_id not in api.db.buckets():
        return None

    matches = []
    for event in api.get_events(central_bucket_id, limit=-1):
        marker = event["data"].get(SYNC_MARKER_KEY, {})
        if (
            marker.get("stream_id") == stream_id
            and marker.get("source_event_id") == source_event_id
        ):
            matches.append(
                (
                    event["id"],
                    int(marker.get("source_event_version", 0)),
                    str(marker.get("checksum", "")),
                )
            )

    if not matches:
        return None

    matches.sort(key=lambda item: (item[1], item[0]), reverse=True)
    keep_id, keep_version, keep_checksum = matches[0]

    for duplicate_id, _version, _checksum in matches[1:]:
        api.db[central_bucket_id].delete(duplicate_id)

    return keep_id, keep_version, keep_checksum


def _ensure_central_bucket(
    api,
    central_bucket_id: str,
    bucket_type: str,
    bucket_metadata: Dict[str, Any],
) -> None:
    hostname = str(
        bucket_metadata.get("hostname")
        or bucket_metadata.get("device_name")
        or bucket_metadata.get("device_id")
        or "unknown"
    )

    if central_bucket_id in api.db.buckets():
        current = api.db[central_bucket_id].metadata()
        if (
            current.get("type") != bucket_type
            or current.get("client") != SYNC_CLIENT_NAME
            or current.get("hostname") != hostname
            or current.get("data") != bucket_metadata
        ):
            api.update_bucket(
                central_bucket_id,
                event_type=bucket_type,
                client=SYNC_CLIENT_NAME,
                hostname=hostname,
                data=bucket_metadata,
            )
        return

    api.create_bucket(
        central_bucket_id,
        event_type=bucket_type,
        client=SYNC_CLIENT_NAME,
        hostname=hostname,
        data=bucket_metadata,
    )


def _require_protocol_version(payload: Dict[str, Any]) -> None:
    version = payload.get("protocol_version")
    if version != PROTOCOL_VERSION:
        raise ValueError(
            f"Unsupported protocol_version {version}, expected {PROTOCOL_VERSION}"
        )


def _require_agent(agent: Dict[str, Any]) -> None:
    _require_str(agent, "agent_id")
    _require_str(agent, "device_id")
    _require_str(agent, "device_name")
    _require_str(agent, "hostname")


def _require_dict(payload: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object")
    return value


def _require_str(payload: Dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _require_int(payload: Dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def _require_number(payload: Dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, (int, float)):
        raise ValueError(f"{key} must be a number")
    return float(value)


def _parse_datetime(value: str):
    return iso8601.parse_date(value)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
