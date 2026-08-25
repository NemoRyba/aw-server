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


def test_admin_auth_ldap_config_hides_bind_password(flask_client):
    settings = flask_client.application.api.settings
    original = settings.data.get(settings.LDAP_CONFIG_KEY)

    try:
        r = flask_client.post(
            "/api/0/admin/auth/ldap",
            json={
                "enabled": True,
                "server_url": "ldap://dc.example.local",
                "default_domain": "example.local",
                "base_dn": "DC=example,DC=local",
                "bind_dn": "CN=aw,DC=example,DC=local",
                "bind_password": "secret-password",
                "user_search_filter": "(sAMAccountName={username})",
            },
        )
        assert r.status_code == 200
        assert "bind_password" not in r.json
        assert r.json["bind_password_present"] is True

        r = flask_client.post(
            "/api/0/admin/auth/ldap",
            json={
                **r.json,
                "default_domain": "changed.local",
            },
        )
        assert r.status_code == 200
        assert r.json["bind_password_present"] is True
        assert (
            settings.data[settings.LDAP_CONFIG_KEY]["bind_password"]
            == "secret-password"
        )

        r = flask_client.post(
            "/api/0/admin/auth/ldap",
            json={
                **r.json,
                "clear_bind_password": True,
            },
        )
        assert r.status_code == 200
        assert r.json["bind_password_present"] is False
        assert settings.data[settings.LDAP_CONFIG_KEY]["bind_password"] == ""
    finally:
        if original is None:
            settings.data.pop(settings.LDAP_CONFIG_KEY, None)
        else:
            settings.data[settings.LDAP_CONFIG_KEY] = original
        settings.save()


def test_ldap_login_creates_non_admin_user_that_can_be_promoted(
    flask_client, monkeypatch
):
    suffix = str(random.randint(0, 10**6))
    raw_username = f"DOMAIN\\LdapUser{suffix}"
    canonical_username = f"ldapuser{suffix}".lower()
    settings = flask_client.application.api.settings
    original_config = settings.data.get(settings.LDAP_CONFIG_KEY)
    original_user = settings.data.get(settings.AUTH_USERS_KEY, {}).get(canonical_username)

    def fake_ldap_auth(username, password, config=None, persist=True):
        assert password == "correct-password"
        attrs = {
            "sAMAccountName": [canonical_username],
            "displayName": ["LDAP User"],
            "mail": [f"{canonical_username}@example.local"],
        }
        if not persist:
            return {
                "username": canonical_username,
                "is_admin": False,
                "source": settings.LDAP_AUTH_SOURCE,
            }
        return settings._record_ldap_login(
            username,
            attrs=attrs,
            dn=f"CN={canonical_username},DC=example,DC=local",
        )

    monkeypatch.setattr(settings, "_authenticate_ldap_user", fake_ldap_auth)

    try:
        settings.set_ldap_config(
            {
                "enabled": True,
                "server_url": "ldap://dc.example.local",
                "default_domain": "example.local",
                "base_dn": "DC=example,DC=local",
            }
        )

        r = flask_client.post(
            "/api/0/auth/login",
            json={"username": raw_username, "password": "correct-password"},
        )
        assert r.status_code == 200
        assert r.json["user"]["username"] == canonical_username
        assert r.json["user"]["source"] == "ldap"
        assert r.json["user"]["is_admin"] is False

        r = flask_client.get("/api/0/admin/auth/users")
        assert r.status_code == 200
        ldap_user = next(
            user for user in r.json["users"] if user["username"] == canonical_username
        )
        assert ldap_user["source"] == "ldap"
        assert ldap_user["is_admin"] is False

        r = flask_client.post(
            f"/api/0/admin/auth/users/{canonical_username}",
            json={"is_admin": True},
        )
        assert r.status_code == 200
        assert r.json["is_admin"] is True

        r = flask_client.post(
            "/api/0/auth/login",
            json={"username": raw_username, "password": "correct-password"},
        )
        assert r.status_code == 200
        assert r.json["user"]["username"] == canonical_username
        assert r.json["user"]["is_admin"] is True
    finally:
        if original_config is None:
            settings.data.pop(settings.LDAP_CONFIG_KEY, None)
        else:
            settings.data[settings.LDAP_CONFIG_KEY] = original_config

        users = settings.data.setdefault(settings.AUTH_USERS_KEY, {})
        if original_user is None:
            users.pop(canonical_username, None)
        else:
            users[canonical_username] = original_user
        settings.save()


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


def test_buckets_include_event_count(flask_client):
    suffix = str(random.randint(0, 10**6))
    bucket_id = f"test-event-count-{suffix}"
    now = datetime.now(timezone.utc)

    try:
        _create_bucket(flask_client, bucket_id, "test", "test-host", {})
        _create_event(flask_client, bucket_id, now, 1, {"state": "one"})
        _create_event(flask_client, bucket_id, now + timedelta(seconds=1), 1, {"state": "two"})

        r = flask_client.get("/api/0/buckets/")
        assert r.status_code == 200
        assert r.json[bucket_id]["event_count"] == 2
    finally:
        _delete_bucket(flask_client, bucket_id)


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


def test_fleet_live_hides_old_terminal_sessions(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleettermdone-{suffix}"
    device_id = f"pc-term-done-{suffix}"
    hostname = f"host-term-done-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "8",
        "session_type": "console",
    }
    bucket_id = f"aw-watcher-session__{device_id}__{username}__8"
    old_terminal_time = datetime.now(timezone.utc) - timedelta(minutes=20)

    try:
        _create_bucket(flask_client, bucket_id, "sessionstate", hostname, metadata)
        _create_event(
            flask_client,
            bucket_id,
            old_terminal_time,
            0,
            {**metadata, "state": "disconnected", "reason": "rdp"},
        )

        r = flask_client.get("/api/0/fleet/live")
        assert r.status_code == 200
        assert not any(
            row["username"] == username and row["device_id"] == device_id
            for row in r.json["users"]
        )
        assert not any(row["device_id"] == device_id for row in r.json["devices"])
    finally:
        _delete_bucket(flask_client, bucket_id)


def test_fleet_device_metrics(flask_client):
    suffix = str(random.randint(0, 10**6))
    device_id = f"metrics-pc-{suffix}"
    hostname = f"metrics-host-{suffix}"
    bucket_id = f"aw-watcher-system__{device_id}__system__machine"
    now = datetime.now(timezone.utc)
    metadata = {
        "username": "system",
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "machine",
        "session_type": "machine",
    }

    try:
        _create_bucket(flask_client, bucket_id, "systemmetrics", hostname, metadata)
        _create_event(
            flask_client,
            bucket_id,
            now - timedelta(minutes=2),
            60,
            {**metadata, "metric": "cpu_load", "cpu_percent": 21.0},
        )
        _create_event(
            flask_client,
            bucket_id,
            now - timedelta(minutes=1),
            60,
            {
                **metadata,
                "metric": "system_load",
                "cpu_percent": 33.5,
                "memory_percent": 68.2,
                "memory_used_bytes": 6_820,
                "memory_total_bytes": 10_000,
            },
        )

        r = flask_client.get(
            "/api/0/fleet/devices/metrics"
            f"?device_id={device_id}&start={(now - timedelta(minutes=5)).isoformat()}"
            f"&end={now.isoformat()}&max_points=20"
        )

        assert r.status_code == 200
        assert len(r.json["devices"]) == 1
        device = r.json["devices"][0]
        assert device["device_id"] == device_id
        assert device["device_name"] == hostname
        assert device["latest_cpu_percent"] == 33.5
        assert device["latest_memory_percent"] == 68.2
        assert len(device["samples"]) == 2
        assert device["samples"][0]["cpu_percent"] == 21.0
        assert device["samples"][0]["memory_percent"] is None
        assert device["samples"][1]["memory_used_bytes"] == 6_820
    finally:
        _delete_bucket(flask_client, bucket_id)


def test_fleet_users_does_not_count_disconnected_as_active(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetdisconnected-{suffix}"
    device_id = f"pc-disconnected-{suffix}"
    hostname = f"host-disconnected-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "9",
        "session_type": "console",
    }
    bucket_id = f"aw-watcher-session__{device_id}__{username}__9"
    recent_terminal_time = datetime.now(timezone.utc) - timedelta(minutes=1)

    try:
        _create_bucket(flask_client, bucket_id, "sessionstate", hostname, metadata)
        _create_event(
            flask_client,
            bucket_id,
            recent_terminal_time,
            0,
            {**metadata, "state": "disconnected", "reason": "rdp"},
        )

        live_r = flask_client.get("/api/0/fleet/live")
        assert live_r.status_code == 200
        session = next(
            row
            for row in live_r.json["users"]
            if row["username"] == username and row["device_id"] == device_id
        )
        assert session["state"] == "disconnected"

        users_r = flask_client.get("/api/0/fleet/users")
        assert users_r.status_code == 200
        user = next(row for row in users_r.json["users"] if row["username"] == username)
        assert user["active_sessions"] == 0
    finally:
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
            bucket_ids[0],
            now - timedelta(minutes=10),
            180,
            {**metadata, "state": "active", "reason": "interactive"},
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


def test_fleet_user_summary_merges_overlapping_state_events(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetoverlap-{suffix}"
    device_id = f"pc-{suffix}"
    hostname = f"host-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "1",
        "session_type": "interactive",
    }
    bucket_ids = [
        f"aw-watcher-session__{device_id}__{username}__1",
        f"aw-watcher-afk__{device_id}__{username}__1",
    ]
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)

    try:
        _create_bucket(flask_client, bucket_ids[0], "sessionstate", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[1], "afkstatus", hostname, metadata)

        _create_event(
            flask_client,
            bucket_ids[0],
            start + timedelta(minutes=30),
            600,
            {**metadata, "state": "active"},
        )
        _create_event(
            flask_client,
            bucket_ids[0],
            start + timedelta(minutes=35),
            600,
            {**metadata, "state": "active"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start + timedelta(minutes=10),
            600,
            {**metadata, "status": "afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start + timedelta(minutes=10),
            300,
            {**metadata, "status": "afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start + timedelta(minutes=15),
            600,
            {**metadata, "status": "afk"},
        )

        detail_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )

        assert detail_r.status_code == 200
        assert detail_r.json["totals"]["afk_seconds"] == 900
        assert detail_r.json["totals"]["active_seconds"] == 900
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_user_summary_unions_active_sessions_across_devices(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetactiveunion-{suffix}"
    devices = [
        {"device_id": f"pc-a-{suffix}", "device_name": f"Host A {suffix}", "session_id": "1"},
        {"device_id": f"pc-b-{suffix}", "device_name": f"Host B {suffix}", "session_id": "2"},
        {"device_id": f"pc-c-{suffix}", "device_name": f"Host C {suffix}", "session_id": "3"},
    ]
    bucket_ids = []
    start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
    end = start + timedelta(hours=5)

    try:
        for device in devices:
            metadata = {
                "username": username,
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "session_id": device["session_id"],
                "session_type": "interactive",
            }
            bucket_id = (
                f"aw-watcher-session__{device['device_id']}__"
                f"{username}__{device['session_id']}"
            )
            bucket_ids.append(bucket_id)
            _create_bucket(flask_client, bucket_id, "sessionstate", device["device_name"], metadata)

        _create_event(
            flask_client,
            bucket_ids[0],
            start,
            7200,
            {
                "username": username,
                "device_id": devices[0]["device_id"],
                "device_name": devices[0]["device_name"],
                "session_id": devices[0]["session_id"],
                "session_type": "interactive",
                "state": "active",
            },
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start + timedelta(hours=1),
            7200,
            {
                "username": username,
                "device_id": devices[1]["device_id"],
                "device_name": devices[1]["device_name"],
                "session_id": devices[1]["session_id"],
                "session_type": "interactive",
                "state": "active",
            },
        )
        _create_event(
            flask_client,
            bucket_ids[2],
            start + timedelta(hours=1, minutes=30),
            3600,
            {
                "username": username,
                "device_id": devices[2]["device_id"],
                "device_name": devices[2]["device_name"],
                "session_id": devices[2]["session_id"],
                "session_type": "interactive",
                "state": "locked",
            },
        )

        detail_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )

        assert detail_r.status_code == 200
        assert detail_r.json["totals"]["active_seconds"] == 10800
        assert detail_r.json["totals"]["locked_seconds"] == 0
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_user_summary_reports_not_afk_active_session_time(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetnotafkactive-{suffix}"
    devices = [
        {
            "device_id": f"pc-a-{suffix}",
            "device_name": f"Host A {suffix}",
            "session_id": "1",
        },
        {
            "device_id": f"pc-b-{suffix}",
            "device_name": f"Host B {suffix}",
            "session_id": "2",
        },
    ]
    bucket_ids = []
    start = datetime(2026, 1, 1, 8, tzinfo=timezone.utc)
    end = start + timedelta(hours=4)

    try:
        for device in devices:
            metadata = {
                "username": username,
                "device_id": device["device_id"],
                "device_name": device["device_name"],
                "session_id": device["session_id"],
                "session_type": "interactive",
            }
            session_bucket_id = (
                f"aw-watcher-session__{device['device_id']}__"
                f"{username}__{device['session_id']}"
            )
            afk_bucket_id = (
                f"aw-watcher-afk__{device['device_id']}__"
                f"{username}__{device['session_id']}"
            )
            bucket_ids.extend([session_bucket_id, afk_bucket_id])
            _create_bucket(
                flask_client,
                session_bucket_id,
                "sessionstate",
                device["device_name"],
                metadata,
            )
            _create_bucket(
                flask_client,
                afk_bucket_id,
                "afkstatus",
                device["device_name"],
                metadata,
            )

        first_metadata = {
            "username": username,
            "device_id": devices[0]["device_id"],
            "device_name": devices[0]["device_name"],
            "session_id": devices[0]["session_id"],
            "session_type": "interactive",
        }
        second_metadata = {
            "username": username,
            "device_id": devices[1]["device_id"],
            "device_name": devices[1]["device_name"],
            "session_id": devices[1]["session_id"],
            "session_type": "interactive",
        }

        _create_event(
            flask_client,
            bucket_ids[0],
            start,
            7200,
            {**first_metadata, "state": "active"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start,
            1800,
            {**first_metadata, "status": "not-afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[2],
            start + timedelta(hours=1),
            7200,
            {**second_metadata, "state": "active"},
        )
        _create_event(
            flask_client,
            bucket_ids[3],
            start + timedelta(hours=1, minutes=30),
            3600,
            {**second_metadata, "status": "not-afk"},
        )

        detail_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )

        assert detail_r.status_code == 200
        assert detail_r.json["totals"]["active_seconds"] == 10800
        assert detail_r.json["totals"]["not_afk_active_seconds"] == 5400
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)


def test_fleet_user_summary_can_exclude_afk_outside_active_session(flask_client):
    suffix = str(random.randint(0, 10**6))
    username = f"fleetafksession-{suffix}"
    device_id = f"pc-{suffix}"
    hostname = f"host-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "1",
        "session_type": "interactive",
    }
    bucket_ids = [
        f"aw-watcher-session__{device_id}__{username}__1",
        f"aw-watcher-afk__{device_id}__{username}__1",
        f"aw-watcher-window__{device_id}__{username}__1",
    ]
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = start + timedelta(hours=1)

    try:
        _create_bucket(flask_client, bucket_ids[0], "sessionstate", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[1], "afkstatus", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[2], "currentwindow", hostname, metadata)

        _create_event(
            flask_client,
            bucket_ids[0],
            start,
            600,
            {**metadata, "state": "active"},
        )
        _create_event(
            flask_client,
            bucket_ids[0],
            start + timedelta(minutes=10),
            1200,
            {**metadata, "state": "locked"},
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            start,
            1800,
            {**metadata, "status": "afk"},
        )
        _create_event(
            flask_client,
            bucket_ids[2],
            start,
            1800,
            {
                **metadata,
                "app": "Code.exe",
                "title": "ActivityWatch",
                "process_name": "Code.exe",
            },
        )

        raw_r = flask_client.get(
            f"/api/0/fleet/users/{username}?start={start.isoformat()}&end={end.isoformat()}"
        )
        filtered_r = flask_client.get(
            f"/api/0/fleet/users/{username}"
            f"?start={start.isoformat()}&end={end.isoformat()}"
            "&exclude_inactive_session_afk=true"
        )

        assert raw_r.status_code == 200
        assert filtered_r.status_code == 200
        assert raw_r.json["totals"]["afk_seconds"] == 1800
        assert raw_r.json["apps"][0]["afk_seconds"] == 1800
        assert filtered_r.json["totals"]["afk_seconds"] == 600
        assert filtered_r.json["apps"][0]["afk_seconds"] == 600
        assert filtered_r.json["filters"]["exclude_inactive_session_afk"] is True
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

            event_start = (
                now - timedelta(minutes=20)
                if index == 1
                else now - timedelta(minutes=10)
            )
            event_duration = 600 if index == 1 else 300
            _create_event(
                flask_client,
                device_bucket_ids[0],
                event_start,
                event_duration,
                {**metadata, "state": "active"},
            )
            _create_event(
                flask_client,
                device_bucket_ids[1],
                event_start,
                event_duration,
                {**metadata, "status": "not-afk"},
            )
            _create_event(
                flask_client,
                device_bucket_ids[2],
                event_start,
                event_duration,
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
    reset_r = flask_client.post(
        "/api/0/admin/ui-config",
        json={
            "show_stopwatch_menu": False,
            "show_tools_menu": True,
        },
    )
    assert reset_r.status_code == 200

    config_r = flask_client.get("/api/0/admin/ui-config")
    assert config_r.status_code == 200
    assert config_r.json == {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
        "landing_page_admin": "/fleet",
        "landing_page_user": "/fleet",
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
        "landing_page_admin": "/fleet",
        "landing_page_user": "/fleet",
    }

    updated_r = flask_client.get("/api/0/admin/ui-config")
    assert updated_r.status_code == 200
    assert updated_r.json == update_r.json


#
# Session type normalization
#


def test_session_type_normalization_is_shared_by_all_watchers():
    from aw_core.identity import (
        normalize_session_state,
        normalize_session_type,
        session_type_from_protocol,
    )

    # The placeholder the afk/window watchers used to ship was never a session
    # type - it collapses to "unknown" so it can never contradict the real
    # value the session watcher reports for the same session.
    assert normalize_session_type("interactive") == "unknown"
    assert normalize_session_type("") == "unknown"
    assert normalize_session_type(None) == "unknown"
    assert normalize_session_type("Console") == "console"
    assert normalize_session_type("RDP-Tcp") == "rdp"
    assert normalize_session_type("citrix") == "virtual"
    assert normalize_session_type("machine") == "machine"
    assert normalize_session_type("something-new") == "unknown"

    assert session_type_from_protocol(0) == "console"
    assert session_type_from_protocol(1) == "virtual"
    assert session_type_from_protocol(2) == "rdp"
    assert session_type_from_protocol(None) == "unknown"

    assert normalize_session_state("logged_off") == "no_session"
    assert normalize_session_state("not-afk") == "active"
    assert normalize_session_state(" LOCKED ") == "locked"


def test_bucket_identity_normalizes_legacy_session_type():
    from aw_server.fleet import _merge_identity, get_bucket_identity

    bucket = {
        "hostname": "PC-01",
        "data": {
            "username": "mstep",
            "device_id": "PC-01",
            "session_id": "2",
            "session_type": "console",
        },
    }
    identity = get_bucket_identity(bucket)
    assert identity["session_type"] == "console"

    # An afk/window event carrying the old placeholder must not overwrite the
    # precise value - that is what produced "2 (console)" next to
    # "2 (interactive)" for one physical session.
    merged = _merge_identity(identity, {"data": {"session_type": "interactive"}})
    assert merged["session_type"] == "console"

    # A real value still wins.
    merged = _merge_identity(identity, {"data": {"session_type": "rdp"}})
    assert merged["session_type"] == "rdp"

    legacy = get_bucket_identity({"hostname": "PC-02", "data": {"session_type": "interactive"}})
    assert legacy["session_type"] == "unknown"


#
# API auth classification
#


def test_machine_endpoints_are_separated_from_session_endpoints():
    from aw_server.server import _is_machine_api_request, _is_public_api_request

    # Watcher ingest and the supervisor's own update poll are machine traffic.
    assert _is_machine_api_request("/api/0/buckets/some-bucket", "POST")
    assert _is_machine_api_request("/api/0/buckets/some-bucket/heartbeat", "POST")
    assert _is_machine_api_request("/api/0/buckets/some-bucket/events", "POST")
    assert _is_machine_api_request("/api/0/fleet/watcher-update/manifest", "GET")
    assert _is_machine_api_request("/api/0/fleet/watcher-update/payload", "GET")
    assert _is_machine_api_request("/api/0/fleet/watcher-update/status", "POST")
    assert _is_machine_api_request("/api/0/fleet/sync/batch", "POST")

    # Everything a browser reads requires a login, with no token bypass.
    for path in (
        "/api/0/fleet/live",
        "/api/0/fleet/users",
        "/api/0/fleet/summary",
        "/api/0/fleet/devices",
        "/api/0/buckets/",
        "/api/0/buckets/some-bucket/events",
        "/api/0/query/",
        "/api/0/export",
        "/api/0/settings",
        "/api/0/fleet/watcher-update/devices",
        "/api/0/fleet/watcher-update/request",
    ):
        method = "GET" if not path.endswith(("query/", "request")) else "POST"
        assert not _is_machine_api_request(path, method), path
        assert not _is_public_api_request(path, method), path

    # Only the liveness probe, the login flow and enrollment are open.
    assert _is_public_api_request("/api/0/info", "GET")
    assert _is_public_api_request("/api/0/auth/login", "POST")

    # Enrollment must be open - it is how a device with no credential asks for
    # one - but it grants nothing until an admin approves the device.
    assert _is_public_api_request("/api/0/fleet/enroll", "POST")
    assert _is_public_api_request("/api/0/fleet/enroll/status", "GET")

    # Approving devices and announcing a server move stay admin-only.
    assert not _is_public_api_request("/api/0/fleet/devices/enrollment", "GET")
    assert not _is_machine_api_request("/api/0/fleet/devices/enrollment", "POST")
    assert not _is_public_api_request("/api/0/admin/fleet-endpoint", "POST")
    assert not _is_machine_api_request("/api/0/admin/fleet-endpoint", "POST")


def test_fleet_device_lists_users_for_a_past_range(flask_client):
    """A device opened for a HISTORICAL range must list who worked on it.

    Regression: the user list was derived from the live state, which only keeps
    sessions updated within the last two minutes, so any past range showed no
    users at all.
    """
    suffix = str(random.randint(0, 10**6))
    username = f"pastuser-{suffix}"
    device_id = f"pc-{suffix}"
    hostname = f"host-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "1",
        "session_type": "console",
    }
    bucket_id = f"aw-watcher-window__{device_id}__{username}__1"

    # Deliberately far outside the live window.
    now = datetime.now(timezone.utc)
    long_ago = now - timedelta(days=3)
    start = long_ago - timedelta(hours=1)
    end = long_ago + timedelta(hours=1)

    try:
        _create_bucket(flask_client, bucket_id, "currentwindow", hostname, metadata)
        _create_event(
            flask_client,
            bucket_id,
            long_ago,
            120,
            {**metadata, "app": "Inventor.exe", "title": "part", "state": "active"},
        )

        device_r = flask_client.get(
            f"/api/0/fleet/devices/{device_id}?start={start.isoformat()}&end={end.isoformat()}"
        )
        assert device_r.status_code == 200
        assert username in device_r.json["users"]

        # A range with no activity must not invent users.
        quiet_start = now - timedelta(days=30)
        quiet_end = now - timedelta(days=29)
        quiet_r = flask_client.get(
            f"/api/0/fleet/devices/{device_id}"
            f"?start={quiet_start.isoformat()}&end={quiet_end.isoformat()}"
        )
        assert quiet_r.status_code == 200
        assert username not in quiet_r.json["users"]
    finally:
        _delete_bucket(flask_client, bucket_id)


#
# "Eigene Zusammenfassung": the summary page restricted to the user's own row
#


def _login_as(flask_client, username, allowed_pages, is_admin=False):
    """Register an auth user and put them in the session."""
    settings = flask_client.application.api.settings
    users = settings.data.setdefault(settings.AUTH_USERS_KEY, {})
    users[username] = {
        "password_hash": "pbkdf2:sha256:dummy",
        "is_admin": is_admin,
        "source": "local",
        "allowed_pages": list(allowed_pages),
    }
    with flask_client.session_transaction() as session:
        session["aw_auth_user"] = username


def _logout(flask_client):
    with flask_client.session_transaction() as session:
        session.pop("aw_auth_user", None)


def _seed_summary_user(flask_client, username, device_id, hostname):
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "1",
        "session_type": "console",
    }
    bucket_id = f"aw-watcher-session__{device_id}__{username}__1"
    _create_bucket(flask_client, bucket_id, "sessionstate", hostname, metadata)
    _create_event(
        flask_client,
        bucket_id,
        datetime.now(timezone.utc) - timedelta(minutes=30),
        600,
        {**metadata, "state": "active"},
    )
    return bucket_id


def test_own_summary_grant_cannot_see_other_users(flask_client):
    suffix = str(random.randint(0, 10**6))
    me = f"ownsum-{suffix}"
    other = f"othersum-{suffix}"
    buckets = []
    try:
        buckets.append(_seed_summary_user(flask_client, me, f"pc-a-{suffix}", f"host-a-{suffix}"))
        buckets.append(
            _seed_summary_user(flask_client, other, f"pc-b-{suffix}", f"host-b-{suffix}")
        )

        _login_as(flask_client, me, ["fleet-summary-own"])

        # Even when explicitly asking for somebody else, the answer is scoped
        # to the caller - the restriction cannot be phrased away.
        r = flask_client.get(f"/api/0/fleet/summary?usernames={other}")
        assert r.status_code == 200
        returned = {row["username"] for row in r.json["users"]}
        assert other not in returned
        assert returned <= {me}

        # Asking for nobody in particular is scoped the same way.
        r = flask_client.get("/api/0/fleet/summary")
        assert r.status_code == 200
        assert {row["username"] for row in r.json["users"]} <= {me}

        # Recomputing is scoped too - it must not be usable to churn the whole
        # fleet on someone else's behalf.
        r = flask_client.post(
            "/api/0/fleet/summary/precompute", json={"usernames": [other], "force": True}
        )
        assert r.status_code == 200

        # NOTE: the server-wide precompute settings are admin-only in
        # production, but _require_admin_user() short-circuits to "is admin"
        # whenever api.testing is set, so that gate cannot be asserted from
        # this harness - it is why no admin endpoint is covered here.
    finally:
        _logout(flask_client)
        for bucket_id in buckets:
            _delete_bucket(flask_client, bucket_id)


def test_full_summary_grant_is_not_restricted(flask_client):
    suffix = str(random.randint(0, 10**6))
    me = f"fullsum-{suffix}"
    other = f"peer-{suffix}"
    buckets = []
    try:
        buckets.append(_seed_summary_user(flask_client, me, f"pc-c-{suffix}", f"host-c-{suffix}"))
        buckets.append(
            _seed_summary_user(flask_client, other, f"pc-d-{suffix}", f"host-d-{suffix}")
        )

        _login_as(flask_client, me, ["fleet-summary"])
        r = flask_client.get(f"/api/0/fleet/summary?usernames={other}")
        assert r.status_code == 200
        assert {row["username"] for row in r.json["users"]} == {other}
    finally:
        _logout(flask_client)
        for bucket_id in buckets:
            _delete_bucket(flask_client, bucket_id)


def test_summary_needs_one_of_the_two_grants(flask_client):
    suffix = str(random.randint(0, 10**6))
    me = f"nosum-{suffix}"
    try:
        _login_as(flask_client, me, ["fleet-live"])
        assert flask_client.get("/api/0/fleet/summary").status_code == 401
        assert (
            flask_client.post("/api/0/fleet/redmine-comparison", json={}).status_code == 401
        )
    finally:
        _logout(flask_client)


def test_devices_list_includes_offline_devices(flask_client):
    """A switched-off PC must stay in Geraete so its history is reachable.

    Regression: the list was built from the live state (a two-minute window),
    so any device that was not currently reporting disappeared entirely - and
    with it the only link to its historical data.
    """
    suffix = str(random.randint(0, 10**6))
    username = f"offlineuser-{suffix}"
    device_id = f"pc-off-{suffix}"
    hostname = f"host-off-{suffix}"
    metadata = {
        "username": username,
        "device_id": device_id,
        "device_name": hostname,
        "session_id": "1",
        "session_type": "console",
    }
    bucket_ids = [
        f"aw-watcher-session__{device_id}__{username}__1",
        f"aw-watcher-window__{device_id}__{username}__1",
    ]

    # Far outside the live window: this device is "off".
    long_ago = datetime.now(timezone.utc) - timedelta(days=2)

    try:
        _create_bucket(flask_client, bucket_ids[0], "sessionstate", hostname, metadata)
        _create_bucket(flask_client, bucket_ids[1], "currentwindow", hostname, metadata)
        _create_event(
            flask_client, bucket_ids[0], long_ago, 600, {**metadata, "state": "active"}
        )
        _create_event(
            flask_client,
            bucket_ids[1],
            long_ago,
            600,
            {**metadata, "app": "Inventor.exe", "title": "part", "state": "active"},
        )

        list_r = flask_client.get("/api/0/fleet/devices")
        assert list_r.status_code == 200
        row = next(
            (d for d in list_r.json["devices"] if d["device_id"] == device_id), None
        )
        assert row is not None, "offline device missing from the device list"
        assert row["status"] == "offline"
        assert row["device_name"] == hostname
        # The row still says whose machine it is, and when it was last heard from.
        assert username in row["users"]
        assert row["last_seen"]

        # ...and the detail page it links to actually returns historical data.
        start = long_ago - timedelta(hours=1)
        end = long_ago + timedelta(hours=1)
        detail_r = flask_client.get(
            f"/api/0/fleet/devices/{device_id}?start={start.isoformat()}&end={end.isoformat()}"
        )
        assert detail_r.status_code == 200
        assert username in detail_r.json["users"]
        assert detail_r.json["apps"][0]["app"] == "Inventor.exe"
        assert detail_r.json["totals"]["active_seconds"] >= 599
    finally:
        for bucket_id in bucket_ids:
            _delete_bucket(flask_client, bucket_id)
