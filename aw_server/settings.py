import json
import secrets
from pathlib import Path

from aw_core.dirs import get_config_dir
from werkzeug.security import check_password_hash, generate_password_hash


class Settings:
    AUTH_USERS_KEY = "_auth_users"
    USER_PROFILES_KEY = "_user_profiles"
    SESSION_SECRET_KEY = "_session_secret"
    ADMIN_UI_CONFIG_KEY = "_admin_ui_config"
    PASSWORD_HASH_KEY = "password_hash"
    LEGACY_PASSWORD_KEY = "password"
    DEFAULT_ADMIN_UI_CONFIG = {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
    }
    RESERVED_KEYS = {
        AUTH_USERS_KEY,
        USER_PROFILES_KEY,
        SESSION_SECRET_KEY,
        ADMIN_UI_CONFIG_KEY,
    }

    def __init__(self, testing: bool):
        filename = "settings.json" if not testing else "settings-testing.json"
        self.config_file = Path(get_config_dir("aw-server")) / filename
        self.load()

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def load(self):
        if self.config_file.exists():
            with open(self.config_file) as f:
                self.data = json.load(f)
        else:
            self.data = {}
        self._ensure_internal_defaults()

    def save(self):
        with open(self.config_file, "w") as f:
            json.dump(self.data, f, indent=4)

    def _ensure_internal_defaults(self):
        changed = False

        auth_users = self.data.get(self.AUTH_USERS_KEY)
        if not isinstance(auth_users, dict):
            auth_users = {}
            changed = True

        admin = auth_users.get("admin")
        if not isinstance(admin, dict):
            admin = {}
            changed = True

        password_hash = admin.get(self.PASSWORD_HASH_KEY)
        legacy_password = admin.get(self.LEGACY_PASSWORD_KEY)
        if not self._is_password_hash(password_hash):
            admin[self.PASSWORD_HASH_KEY] = self._hash_password(
                str(legacy_password or "admin")
            )
            changed = True

        if self.LEGACY_PASSWORD_KEY in admin:
            del admin[self.LEGACY_PASSWORD_KEY]
            changed = True

        if "is_admin" not in admin:
            admin["is_admin"] = True
            changed = True
        auth_users["admin"] = admin

        if self.data.get(self.AUTH_USERS_KEY) != auth_users:
            self.data[self.AUTH_USERS_KEY] = auth_users
            changed = True

        if not isinstance(self.data.get(self.USER_PROFILES_KEY), dict):
            self.data[self.USER_PROFILES_KEY] = {}
            changed = True

        if not self.data.get(self.SESSION_SECRET_KEY):
            self.data[self.SESSION_SECRET_KEY] = secrets.token_hex(32)
            changed = True

        admin_ui_config = self._normalize_admin_ui_config(
            self.data.get(self.ADMIN_UI_CONFIG_KEY)
        )
        if self.data.get(self.ADMIN_UI_CONFIG_KEY) != admin_ui_config:
            self.data[self.ADMIN_UI_CONFIG_KEY] = admin_ui_config
            changed = True

        if changed:
            self.save()

    def _is_password_hash(self, value) -> bool:
        if not isinstance(value, str):
            return False
        return value.startswith("scrypt:") or value.startswith("pbkdf2:")

    def _hash_password(self, password: str) -> str:
        return generate_password_hash(password)

    def _normalize_admin_ui_config(self, value):
        config = dict(self.DEFAULT_ADMIN_UI_CONFIG)
        if isinstance(value, dict):
            for key in self.DEFAULT_ADMIN_UI_CONFIG:
                if key in value:
                    config[key] = bool(value[key])
        return config

    def get(self, key: str, default=None):
        if not key:
            return self.data
        return self.data.get(key, default)

    def set(self, key, value):
        if value:
            self.data[key] = value
        else:
            if key in self.data:
                del self.data[key]
        self.save()

    def get_session_secret(self) -> str:
        self._ensure_internal_defaults()
        return str(self.data[self.SESSION_SECRET_KEY])

    def get_auth_users(self):
        self._ensure_internal_defaults()
        return dict(self.data.get(self.AUTH_USERS_KEY, {}))

    def get_auth_user(self, username: str):
        if not username:
            return None
        return self.get_auth_users().get(username)

    def authenticate_user(self, username: str, password: str):
        user = self.get_auth_user(username)
        if not user:
            return None
        password_hash = user.get(self.PASSWORD_HASH_KEY)
        if not self._is_password_hash(password_hash):
            return None
        if not check_password_hash(str(password_hash), password):
            return None
        return {
            "username": username,
            "is_admin": bool(user.get("is_admin", False)),
        }

    def get_admin_ui_config(self):
        self._ensure_internal_defaults()
        config = self._normalize_admin_ui_config(
            self.data.get(self.ADMIN_UI_CONFIG_KEY)
        )
        if self.data.get(self.ADMIN_UI_CONFIG_KEY) != config:
            self.data[self.ADMIN_UI_CONFIG_KEY] = config
            self.save()
        return dict(config)

    def set_admin_ui_config(self, value):
        config = self.get_admin_ui_config()
        if isinstance(value, dict):
            for key in self.DEFAULT_ADMIN_UI_CONFIG:
                if key in value:
                    config[key] = bool(value[key])
        self.data[self.ADMIN_UI_CONFIG_KEY] = self._normalize_admin_ui_config(config)
        self.save()
        return dict(self.data[self.ADMIN_UI_CONFIG_KEY])

    def _global_settings_view(self):
        return {
            key: value
            for key, value in self.data.items()
            if key not in self.RESERVED_KEYS
        }

    def get_user_settings(self, username: str):
        settings = self._global_settings_view()
        if not username:
            return settings

        profiles = self.data.get(self.USER_PROFILES_KEY, {})
        profile = profiles.get(username, {})
        if isinstance(profile, dict):
            settings.update(profile)
        return settings

    def get_user_setting(self, username: str, key: str, default=None):
        if not key:
            return self.get_user_settings(username)
        settings = self.get_user_settings(username)
        return settings.get(key, default)

    def set_user_setting(self, username: str, key: str, value):
        if not username:
            return self.set(key, value)

        profiles = self.data.setdefault(self.USER_PROFILES_KEY, {})
        profile = profiles.setdefault(username, {})
        if value:
            profile[key] = value
        else:
            if key in profile:
                del profile[key]
        self.save()
