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
    }

    updated = settings.set_admin_ui_config({"show_stopwatch_menu": True})
    assert updated == {
        "show_stopwatch_menu": True,
        "show_tools_menu": True,
    }

    saved = json.loads((tmp_path / "settings.json").read_text())
    assert saved["_admin_ui_config"] == updated
