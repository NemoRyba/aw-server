import json

from aw_server.settings import Settings


def test_settings_migrate_plaintext_password_to_hash(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)

    config_file = tmp_path / "settings.json"
    config_file.write_text(
        json.dumps(
            {
                "_auth_users": {
                    "admin": {
                        "password": "admin",
                        "is_admin": True,
                    }
                }
            }
        )
    )

    settings = Settings(testing=False)
    admin = settings.get_auth_user("admin")

    assert admin is not None
    assert "password" not in admin
    assert "password_hash" in admin
    assert admin["password_hash"] != "admin"
    assert settings.authenticate_user("admin", "admin") == {
        "username": "admin",
        "is_admin": True,
        "source": "local",
    }
    assert settings.authenticate_user("admin", "wrong") is None

    saved = json.loads(config_file.read_text())
    assert "password" not in saved["_auth_users"]["admin"]
    assert "password_hash" in saved["_auth_users"]["admin"]


def test_settings_admin_ui_config_defaults_and_update(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)

    settings = Settings(testing=False)

    assert settings.get_admin_ui_config() == {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
        "landing_page_admin": "/fleet",
        "landing_page_user": "/fleet",
    }

    updated = settings.set_admin_ui_config({"show_stopwatch_menu": True})
    assert updated == {
        "show_stopwatch_menu": True,
        "show_tools_menu": True,
        "landing_page_admin": "/fleet",
        "landing_page_user": "/fleet",
    }

    saved = json.loads((tmp_path / "settings.json").read_text())
    assert saved["_admin_ui_config"] == updated


#
# Crash-safe settings persistence
#


def test_settings_save_is_atomic_and_keeps_a_backup(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)

    settings = Settings(testing=False)
    settings.set("first", "one")
    settings.set("second", "two")

    config_file = tmp_path / "settings.json"
    backup_file = tmp_path / "settings.json.bak"

    assert json.loads(config_file.read_text(encoding="utf-8"))["second"] == "two"
    # The previous good version survives every write.
    assert json.loads(backup_file.read_text(encoding="utf-8"))["first"] == "one"
    # No temp files are left behind.
    assert not list(tmp_path.glob("*.tmp"))


def test_settings_recovers_from_truncated_file(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)

    settings = Settings(testing=False)
    settings.set_ldap_config({"enabled": True, "server_url": "ldap://dc"})
    settings.set("marker", "keep-me")
    # The backup always lags the primary by exactly one save, so recovery
    # loses at most the most recent change - never the accounts or the
    # LDAP/Redmine credentials, which is the whole point.
    settings.set("newest", "may-be-lost")

    config_file = tmp_path / "settings.json"
    # Simulate a crash halfway through the old truncate-then-write save().
    config_file.write_text("", encoding="utf-8")

    recovered = Settings(testing=False)
    assert recovered.get_ldap_config()["server_url"] == "ldap://dc"
    assert recovered.get("marker") == "keep-me"
    assert recovered.get_auth_user("admin") is not None
    # The damaged file is preserved rather than silently overwritten.
    assert list(tmp_path.glob("settings.json.corrupt-*"))


def test_settings_survive_concurrent_writers(tmp_path, monkeypatch):
    import threading

    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    errors = []

    def writer(index):
        try:
            for i in range(20):
                settings.set(f"key-{index}", f"value-{i}")
        except Exception as error:  # pragma: no cover - only on regression
            errors.append(error)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    # The file must be parseable after every interleaving.
    data = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert len([k for k in data if k.startswith("key-")]) == 8


#
# Fleet token
#


def test_fleet_token_is_generated_and_hidden_from_the_public_config(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    public = settings.get_fleet_auth_config()
    assert public["require_watcher_token"] is False
    assert public["token"] == ""
    assert public["token_hint"]

    token = settings.get_fleet_token()
    assert len(token) > 20
    assert token.startswith(public["token_hint"])

    # Rotation replaces the token; enforcement is a separate switch.
    settings.set_fleet_auth_config({"rotate_token": True})
    assert settings.get_fleet_token() != token
    assert settings.is_watcher_token_required() is False

    settings.set_fleet_auth_config({"require_watcher_token": True})
    assert settings.is_watcher_token_required() is True


#
# Manual watcher update requests
#


def test_watcher_update_request_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    entry = settings.request_watcher_update("PC-01", "abc123", "admin", 60)
    assert entry["request_id"]
    assert entry["requested_version"] == "abc123"

    # Lookup is case-insensitive: status is keyed by COMPUTERNAME casing while
    # never-reported rows come from the fleet device name.
    assert settings.get_watcher_update_request("pc-01")["request_id"] == entry["request_id"]

    acked = settings.acknowledge_watcher_update_request("PC-01", entry["request_id"])
    assert acked["acknowledged_at"]
    # Acknowledging twice must not rewrite the file again.
    assert (
        settings.acknowledge_watcher_update_request("PC-01", entry["request_id"])[
            "acknowledged_at"
        ]
        == acked["acknowledged_at"]
    )

    assert settings.clear_watcher_update_request("PC-01") is True
    assert settings.get_watcher_update_request("PC-01") is None


def test_watcher_update_request_expires(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    settings.request_watcher_update("PC-02", "abc123", "admin", 60)
    # A device that is powered off must not stay pending forever.
    requests = settings.get_watcher_update_requests()
    requests["pc-02"]["expires_at"] = "2000-01-01T00:00:00+00:00"
    settings._write_watcher_update_requests(requests)

    assert settings.get_watcher_update_request("PC-02") is None
    assert settings.get_watcher_update_requests() == {}


#
# Device enrollment
#


def test_device_enrollment_lifecycle(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    key = "k" * 64
    entry = settings.enroll_device(key, "PC-01", "192.168.0.11")
    assert entry["status"] == "pending"
    # Enrolling grants nothing on its own.
    assert settings.is_device_key_approved(key) is False

    # Re-enrolling the same key is idempotent, not a second device.
    settings.enroll_device(key, "PC-01", "192.168.0.11")
    assert len(settings.get_fleet_devices()) == 1

    key_hash = settings.hash_device_key(key)
    assert settings.set_device_status(key_hash, "approved", "admin")["approved_by"] == "admin"
    assert settings.is_device_key_approved(key) is True

    # Revoking takes access away again.
    settings.set_device_status(key_hash, "rejected", "admin")
    assert settings.is_device_key_approved(key) is False

    # The raw key is never stored, only its hash.
    stored = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert key not in json.dumps(stored)
    assert key_hash in stored["_fleet_devices"]

    assert settings.delete_device(key_hash) is True
    assert settings.get_fleet_devices() == {}


def test_device_enrollment_does_not_downgrade_an_approved_device(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    key = "a" * 64
    settings.enroll_device(key, "PC-02", "192.168.0.12")
    settings.set_device_status(settings.hash_device_key(key), "approved", "admin")

    # The supervisor re-posts its key on every start; that must not send an
    # already-approved device back to pending.
    settings.enroll_device(key, "PC-02", "192.168.0.12")
    assert settings.is_device_key_approved(key) is True


def test_pending_device_enrollments_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)
    monkeypatch.setattr(Settings, "MAX_PENDING_DEVICES", 3)

    for index in range(3):
        assert settings.enroll_device("key-%d" % index + "0" * 40, "PC-%d" % index, "1.2.3.4")
    # An open endpoint must not let anyone grow settings.json without bound.
    assert settings.enroll_device("key-overflow" + "0" * 40, "PC-X", "1.2.3.4") is None


#
# Fleet server endpoint (server move)
#


def test_fleet_endpoint_announcement(tmp_path, monkeypatch):
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    assert settings.get_fleet_endpoint_config()["server_endpoint"] == ""

    config = settings.set_fleet_endpoint("http://192.168.0.200:5600/", "admin")
    # Trailing slash is normalized away so device-side comparisons are stable.
    assert config["server_endpoint"] == "http://192.168.0.200:5600"
    assert config["updated_by"] == "admin"

    cleared = settings.set_fleet_endpoint("", "admin")
    assert cleared["server_endpoint"] == ""
    stored = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert "_fleet_endpoint_config" not in stored


def test_own_summary_page_grant_is_accepted(tmp_path, monkeypatch):
    """The "Eigene Zusammenfassung" grant round-trips like any other page."""
    monkeypatch.setattr("aw_server.settings.get_config_dir", lambda _app: tmp_path)
    settings = Settings(testing=False)

    settings.data[settings.AUTH_USERS_KEY]["worker"] = {
        "password_hash": "pbkdf2:sha256:dummy",
        "is_admin": False,
        "source": "local",
    }

    public = settings.set_auth_user_access(
        "worker",
        allowed_pages=["fleet-summary-own", "not-a-real-page"],
        landing_page="fleet-summary-own",
    )
    # Unknown keys are dropped, the new one survives.
    assert public["allowed_pages"] == ["fleet-summary-own"]
    # It is also usable as a start page, because it is a granted page.
    assert public["landing_page"] == "fleet-summary-own"

    # Revoking the grant must not strand the user on a page they cannot open.
    clamped = settings.set_auth_user_access("worker", allowed_pages=[])
    assert clamped["allowed_pages"] == []
    assert clamped["landing_page"] in ("", "own")
