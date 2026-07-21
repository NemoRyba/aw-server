import random
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def bucket(flask_client):
    "Context manager for creating and deleting a testing bucket"
    try:
        bucket_id = "test"
        r = flask_client.post(
            f"/api/0/buckets/{bucket_id}",
            json={"client": "test", "type": "test", "hostname": "test"},
        )
        assert r.status_code == 200
        yield bucket_id
    finally:
        r = flask_client.delete(f"/api/0/buckets/{bucket_id}")
        assert r.status_code == 200


def test_info(flask_client):
    r = flask_client.get("/api/0/info")
    assert r.status_code == 200
    assert r.json["testing"]


def test_fleet_storage(flask_client, tmp_path, monkeypatch):
    data_dir = tmp_path / "aw-server"
    data_dir.mkdir()
    (data_dir / "events.db").write_bytes(b"stored data")
    nested = data_dir / "nested"
    nested.mkdir()
    (nested / "sync.db").write_bytes(b"sync")

    monkeypatch.setattr("aw_server.api.get_data_dir", lambda _app: str(data_dir))

    r = flask_client.get("/api/0/fleet/storage")

    assert r.status_code == 200
    assert r.json["data_dir"] == str(data_dir)
    assert r.json["data_size_bytes"] == len(b"stored data") + len(b"sync")
    assert r.json["disk_total_bytes"] >= r.json["disk_free_bytes"] >= 0
    assert r.json["disk_used_bytes"] >= 0
    assert r.json["generated_at"]


def test_buckets(flask_client, bucket, benchmark):
    @benchmark
    def list_buckets():
        r = flask_client.get("/api/0/buckets/")
        print(r.json)
        assert r.status_code == 200
        assert len(r.json) == 1


def test_heartbeats(flask_client, bucket, benchmark):
    # FIXME: Currently tests using the memory storage method
    # TODO: Test with a longer data section and see if there's a significant difference
    # TODO: Test with a larger bucket and see if there's a significant difference
    @benchmark
    def heartbeat():
        now = datetime.now()
        r = flask_client.post(
            f"/api/0/buckets/{bucket}/heartbeat?pulsetime=1",
            json={"timestamp": now, "duration": 0, "data": {"random": random.random()}},
        )
        assert r.status_code == 200


def test_get_events(flask_client, bucket, benchmark):
    n_events = 100
    start_time = datetime.now() - timedelta(days=100)
    for i in range(n_events):
        now = start_time + timedelta(hours=i)
        r = flask_client.post(
            f"/api/0/buckets/{bucket}/heartbeat?pulsetime=0",
            json={"timestamp": now, "duration": 0, "data": {"random": random.random()}},
        )
        assert r.status_code == 200

    @benchmark
    def get_events():
        r = flask_client.get(f"/api/0/buckets/{bucket}/events")
        assert r.status_code == 200
        assert r.json
        assert len(r.json) == n_events

        r = flask_client.get(f"/api/0/buckets/{bucket}/events?limit=-1")
        assert r.status_code == 200
        assert r.json
        assert len(r.json) == n_events

        r = flask_client.get(f"/api/0/buckets/{bucket}/events?limit=10")
        assert r.status_code == 200
        assert r.json
        assert len(r.json) == 10

        r = flask_client.get(f"/api/0/buckets/{bucket}/events?limit=100")
        assert r.status_code == 200
        assert r.json
        assert len(r.json) == n_events

        r = flask_client.get(f"/api/0/buckets/{bucket}/events?limit=1000")
        assert r.status_code == 200
        assert r.json
        assert len(r.json) == n_events


# TODO: Add benchmark for basic AFK-filtering query


def _create_bucket(flask_client, bucket_id, bucket_type, hostname, data):
    r = flask_client.post(
        f"/api/0/buckets/{bucket_id}",
        json={
            "client": bucket_id.split("__")[0],
            "type": bucket_type,
            "hostname": hostname,
            "data": data,
        },
    )
    assert r.status_code == 200


def _create_event(flask_client, bucket_id, timestamp, duration, data):
    r = flask_client.post(
        f"/api/0/buckets/{bucket_id}/events",
        json={
            "timestamp": timestamp.isoformat(),
            "duration": duration,
            "data": data,
        },
    )
    assert r.status_code == 200


def _delete_bucket(flask_client, bucket_id):
    r = flask_client.delete(f"/api/0/buckets/{bucket_id}")
    assert r.status_code == 200


def _fleet_sync_handshake(flask_client, agent, streams):
    r = flask_client.post(
        "/api/0/fleet/sync/handshake",
        json={
            "protocol_version": 1,
            "agent": agent,
            "streams": streams,
        },
    )
    assert r.status_code == 200
    return r.json


def _fleet_sync_batch(flask_client, payload):
    return flask_client.post("/api/0/fleet/sync/batch", json=payload)


def test_fleet_live(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetuser-{suffix}"
    device_id = f"pc-{suffix}"
    hostname = f"host-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "2",
        "session_type": "console",
    }
    bucket_ids = [
        f"aw-watcher-session__{device_id}__{username}__2",
        f"aw-watcher-afk__{device_id}__{username}__2",
        f"aw-watcher-window__{device_id}__{username}__2",
    ]
    now = datetime.now(timezone.utc)

    try:
        _create_bucket(flask_client, bucket_ids[0], "sessionstate", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[1], "afkstatus", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[2], "currentwindow", hostname, metadata)

        _create_event(
            flask_client,
            bucket_ids[0],
            now - timedelta(seconds=45),
            45,
            {**metadata, "state": "active", "reason": "interactive"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            now - timedelta(seconds=45),
            45,
            {**metadata, "status": "not-afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[2],
            now - timedelta(seconds=45),
            45,
            {
                **metadata,
                "app": "Inventor.exe",
                "title": "Assembly.iam - Autodesk Inventor",
                "process_name": "Inventor.exe",
                "process_path": r"C:\Program Files\Autodesk\Inventor.exe",
            },
        )

        r = flask_client.get("/api/0/fleet/live")
        assert r.status_code == 200

        session = next(
            row
            for row in r.json["users"]
            if row["username"] == username and row["device_id"] == device_id
        )
        assert session["state"] == "active"
        assert session["session_state"] == "active"
        assert session["afk_status"] == "not-afk"
        assert session["current_app"] == "Inventor.exe"

        device = next(
            row for row in r.json["devices"] if row["device_id"] == device_id
        )
        assert device["status"] == "online"
        assert username in device["users_logged_in"]
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_user_and_device_summary(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetreport-{suffix}"
    device_id = f"pc-{suffix}"
    hostname = f"host-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "4",
        "session_type": "rdp",
    }
    bucket_ids = [
        f"aw-watcher-session__{device_id}__{username}__4",
        f"aw-watcher-afk__{device_id}__{username}__4",
        f"aw-watcher-window__{device_id}__{username}__4",
    ]
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)
    end = now + timedelta(minutes=1)

    try:
        _create_bucket(flask_client, bucket_ids[0], "sessionstate", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[1], "afkstatus", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[2], "currentwindow", hostname, metadata)

        _create_event(
            flask_client,
            bucket_ids[0],
            now - timedelta(minutes=20),
            60,
            {**metadata, "state": "locked", "reason": "workstation-lock"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            now - timedelta(minutes=10),
            120,
            {**metadata, "status": "not-afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            now - timedelta(minutes=8),
            60,
            {**metadata, "status": "afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[2],
            now - timedelta(minutes=10),
            180,
            {
                **metadata,
                "app": "Inventor.exe",
                "title": "Part.ipt - Autodesk Inventor",
                "process_name": "Inventor.exe",
            },
        )

        users_r = flask_client.get("/api/0/fleet/users")
        assert users_r.status_code == 200
        user_row = next(row for row in users_r.json["users"] if row["username"] == username)
        assert device_id in user_row["devices"]

        detail_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )
        assert detail_r.status_code == 200
        assert detail_r.json["username"] == username
        assert detail_r.json["totals"]["active_seconds"] >= 119
        assert detail_r.json["totals"]["afk_seconds"] >= 59
        assert detail_r.json["totals"]["locked_seconds"] >= 59
        assert detail_r.json["apps"][0]["app"] == "Inventor.exe"
        assert detail_r.json["apps"][0]["active_seconds"] >= 119
        assert detail_r.json["apps"][0]["afk_seconds"] >= 59

        device_r = flask_client.get(
            f"/api/0/fleet/devices/{device_id}?start={start.isoformat()}&end={end.isoformat()}"
        )
        assert device_r.status_code == 200
        assert device_r.json["device_id"] == device_id
        assert username in device_r.json["users"]
        assert device_r.json["apps"][0]["app"] == "Inventor.exe"
        assert device_r.json["apps"][0]["active_seconds"] >= 119
        assert device_r.json["apps"][0]["afk_seconds"] >= 59
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_user_multi_device_filter(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetmulti-{suffix}"
    devices = [
        {"device_id": f"pc-a-{suffix}", "device_name": f"Host A {suffix}"},
        {"device_id": f"pc-b-{suffix}", "device_name": f"Host B {suffix}"},
    ]
    bucket_ids = []
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=1)
    end = now + timedelta(minutes=1)

    try:
        for index, device in enumerate(devices, start=1):
            metadata = {
                "username": username,
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "session_id": str(index),
                "session_type": "console",
            }
            device_bucket_ids = [
                f"aw-watcher-session__{device['device_id']}__{username}__{index}",
                f"aw-watcher-afk__{device['device_id']}__{username}__{index}",
                f"aw-watcher-window__{device['device_id']}__{username}__{index}",
            ]
            bucket_ids.extend(device_bucket_ids)

            _create_bucket(
                flask_client, device_bucket_ids[0], "sessionstate", device["device_name"], metadata
            )
            _create_bucket(
                flask_client, device_bucket_ids[1], "afkstatus", device["device_name"], metadata
            )
            _create_bucket(
                flask_client, device_bucket_ids[2], "currentwindow", device["device_name"], metadata
            )

            _create_event(
                flask_client,
                device_bucket_ids[0],
                now - timedelta(minutes=20),
                600,
                {**metadata, "state": "logged_in"},
            )
            _create_event(
                flask_client,
                device_bucket_ids[1],
                now - timedelta(minutes=20),
                600 if index == 1 else 300,
                {**metadata, "status": "not-afk"},
            )
            _create_event(
                flask_client,
                device_bucket_ids[2],
                now - timedelta(minutes=20),
                600 if index == 1 else 300,
                {
                    **metadata,
                    "app": "Inventor.exe" if index == 1 else "Code.exe",
                    "title": "Work",
                    "process_name": "Inventor.exe" if index == 1 else "Code.exe",
                },
            )

        all_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )
        assert all_r.status_code == 200
        assert sorted(all_r.json["devices"]) == sorted(
            [device["device_id"] for device in devices]
        )
        assert sorted(all_r.json["selected_devices"]) == sorted(
            [device["device_id"] for device in devices]
        )
        assert len(all_r.json["available_devices"]) == 2
        assert all_r.json["totals"]["active_seconds"] >= 899
        assert {row["app"] for row in all_r.json["apps"]} == {"Inventor.exe", "Code.exe"}

        filtered_r = flask_client.get(
            f"/api/0/fleet/users/{username}"
            f"?start={start.isoformat()}&end={end.isoformat()}"
            f"&device_ids={devices[0]['device_id']}"
        )
        assert filtered_r.status_code == 200
        assert filtered_r.json["selected_devices"] == [devices[0]["device_id"]]
        assert sorted(filtered_r.json["devices"]) == sorted(
            [device["device_id"] for device in devices]
        )
        assert filtered_r.json["totals"]["active_seconds"] >= 599
        assert filtered_r.json["totals"]["active_seconds"] < 700
        assert [row["app"] for row in filtered_r.json["apps"]] == ["Inventor.exe"]
        assert all(
            session["device_id"] == devices[0]["device_id"]
            for session in filtered_r.json["sessions"]
        )
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_sync_handshake_and_batch_insert(flask_client):
    suffix = str(random.randint(0, 10**6))
    agent = {
        "agent_id": f"agent-{suffix}",
        "device_id": f"device-{suffix}",
        "device_name": f"Device-{suffix}",
        "hostname": f"host-{suffix}",
    }
    bucket_id = f"aw-watcher-window__{agent['device_id']}__syncuser-{suffix}__1"
    stream = {
        "stream_id": f"{agent['agent_id']}:{bucket_id}",
        "bucket_id": bucket_id,
        "bucket_type": "currentwindow",
        "bucket_metadata": {
            "username": f"syncuser-{suffix}",
            "device_id": agent["device_id"],
            "device_name": agent["device_name"],
            "session_id": "1",
            "session_type": "console",
            "hostname": agent["hostname"],
        },
        "next_seq": 3,
    }
    now = datetime.now(timezone.utc)

    try:
        handshake = _fleet_sync_handshake(flask_client, agent, [stream])
        assert handshake["protocol_version"] == 1
        assert handshake["streams"][0]["stream_id"] == stream["stream_id"]
        assert handshake["streams"][0]["central_bucket_id"] == bucket_id
        assert handshake["streams"][0]["last_acked_seq"] == 0

        batch = _fleet_sync_batch(
            flask_client,
            {
                "protocol_version": 1,
                "agent_id": agent["agent_id"],
                "stream_id": stream["stream_id"],
                "from_seq": 1,
                "to_seq": 2,
                "ops": [
                    {
                        "seq": 1,
                        "op_type": "bucket_upsert",
                        "payload": {
                            "bucket_id": bucket_id,
                            "bucket_type": "currentwindow",
                            "bucket_metadata": stream["bucket_metadata"],
                        },
                    },
                    {
                        "seq": 2,
                        "op_type": "event_upsert",
                        "payload": {
                            "source_event_id": 101,
                            "source_event_version": 1,
                            "timestamp": now.isoformat(),
                            "duration": 45.0,
                            "data": {
                                "app": "Code.exe",
                                "title": "main.py - Visual Studio Code",
                            },
                        },
                    },
                ],
            },
        )
        assert batch.status_code == 200
        assert batch.json["acked_through_seq"] == 2
        assert batch.json["central_bucket_id"] == bucket_id

        events_r = flask_client.get(f"/api/0/buckets/{bucket_id}/events")
        assert events_r.status_code == 200
        assert len(events_r.json) == 1
        event = events_r.json[0]
        assert event["data"]["app"] == "Code.exe"
        assert event["data"]["username"] == stream["bucket_metadata"]["username"]
        assert event["data"]["device_id"] == agent["device_id"]
        assert event["data"]["_aw_fleet_sync"]["source_event_id"] == 101
        assert event["data"]["_aw_fleet_sync"]["source_event_version"] == 1
    finally:
        if bucket_id in flask_client.get("/api/0/buckets/").json:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_sync_replace_deduplicate_and_conflict(flask_client):
    suffix = str(random.randint(0, 10**6))
    agent = {
        "agent_id": f"agent-{suffix}",
        "device_id": f"device-{suffix}",
        "device_name": f"Device-{suffix}",
        "hostname": f"host-{suffix}",
    }
    username = f"syncuser-{suffix}"
    bucket_id = f"aw-watcher-window__{agent['device_id']}__{username}__9"
    stream = {
        "stream_id": f"{agent['agent_id']}:{bucket_id}",
        "bucket_id": bucket_id,
        "bucket_type": "currentwindow",
        "bucket_metadata": {
            "username": username,
            "device_id": agent["device_id"],
            "device_name": agent["device_name"],
            "session_id": "9",
            "session_type": "console",
            "hostname": agent["hostname"],
        },
        "next_seq": 5,
    }
    now = datetime.now(timezone.utc)

    try:
        _fleet_sync_handshake(flask_client, agent, [stream])

        first = _fleet_sync_batch(
            flask_client,
            {
                "protocol_version": 1,
                "agent_id": agent["agent_id"],
                "stream_id": stream["stream_id"],
                "from_seq": 1,
                "to_seq": 2,
                "ops": [
                    {
                        "seq": 1,
                        "op_type": "bucket_upsert",
                        "payload": {
                            "bucket_id": bucket_id,
                            "bucket_type": "currentwindow",
                            "bucket_metadata": stream["bucket_metadata"],
                        },
                    },
                    {
                        "seq": 2,
                        "op_type": "event_upsert",
                        "payload": {
                            "source_event_id": 22,
                            "source_event_version": 1,
                            "timestamp": now.isoformat(),
                            "duration": 30.0,
                            "data": {
                                "app": "Inventor.exe",
                                "title": "Part.ipt - Autodesk Inventor",
                            },
                        },
                    },
                ],
            },
        )
        assert first.status_code == 200

        replace = _fleet_sync_batch(
            flask_client,
            {
                "protocol_version": 1,
                "agent_id": agent["agent_id"],
                "stream_id": stream["stream_id"],
                "from_seq": 3,
                "to_seq": 3,
                "ops": [
                    {
                        "seq": 3,
                        "op_type": "event_upsert",
                        "payload": {
                            "source_event_id": 22,
                            "source_event_version": 2,
                            "timestamp": now.isoformat(),
                            "duration": 90.0,
                            "data": {
                                "app": "Inventor.exe",
                                "title": "Assembly.iam - Autodesk Inventor",
                            },
                        },
                    }
                ],
            },
        )
        assert replace.status_code == 200
        assert replace.json["acked_through_seq"] == 3
        assert replace.json["replaced_events"] == 1

        dedupe = _fleet_sync_batch(
            flask_client,
            {
                "protocol_version": 1,
                "agent_id": agent["agent_id"],
                "stream_id": stream["stream_id"],
                "from_seq": 4,
                "to_seq": 4,
                "ops": [
                    {
                        "seq": 4,
                        "op_type": "event_upsert",
                        "payload": {
                            "source_event_id": 22,
                            "source_event_version": 2,
                            "timestamp": now.isoformat(),
                            "duration": 90.0,
                            "data": {
                                "app": "Inventor.exe",
                                "title": "Assembly.iam - Autodesk Inventor",
                            },
                        },
                    }
                ],
            },
        )
        assert dedupe.status_code == 200
        assert dedupe.json["deduplicated_ops"] == 1

        conflict = _fleet_sync_batch(
            flask_client,
            {
                "protocol_version": 1,
                "agent_id": agent["agent_id"],
                "stream_id": stream["stream_id"],
                "from_seq": 4,
                "to_seq": 4,
                "ops": [
                    {
                        "seq": 4,
                        "op_type": "event_upsert",
                        "payload": {
                            "source_event_id": 23,
                            "source_event_version": 1,
                            "timestamp": now.isoformat(),
                            "duration": 15.0,
                            "data": {"app": "Code.exe"},
                        },
                    }
                ],
            },
        )
        assert conflict.status_code == 409
        assert conflict.json["need_resync_from_seq"] == 5
        assert conflict.json["last_acked_seq"] == 4

        events_r = flask_client.get(f"/api/0/buckets/{bucket_id}/events")
        assert events_r.status_code == 200
        assert len(events_r.json) == 1
        event = events_r.json[0]
        assert event["duration"] == pytest.approx(90.0)
        assert event["data"]["title"] == "Assembly.iam - Autodesk Inventor"
        assert event["data"]["_aw_fleet_sync"]["source_event_version"] == 2

        handshake = _fleet_sync_handshake(flask_client, agent, [stream])
        assert handshake["streams"][0]["last_acked_seq"] == 4
    finally:
        if bucket_id in flask_client.get("/api/0/buckets/").json:
            _delete_bucket(flask_client, bucket_id)


def test_admin_ui_config_endpoint(flask_client):
    config_r = flask_client.get("/api/0/admin/ui-config")
    assert config_r.status_code == 200
    assert config_r.json == {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
    }

    update_r = flask_client.post(
        "/api/0/admin/ui-config",
        json={
            "show_stopwatch_menu": True,
            "show_tools_menu": False,
        },
    )
    assert update_r.status_code == 200
    assert update_r.json == {
        "show_stopwatch_menu": True,
        "show_tools_menu": False,
    }

    updated_r = flask_client.get("/api/0/admin/ui-config")
    assert updated_r.status_code == 200
    assert updated_r.json == update_r.json
