import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from string import Formatter

from aw_core.dirs import get_config_dir
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)


class Settings:
    AUTH_USERS_KEY = "_auth_users"
    USER_PROFILES_KEY = "_user_profiles"
    SESSION_SECRET_KEY = "_session_secret"
    ADMIN_UI_CONFIG_KEY = "_admin_ui_config"
    LDAP_CONFIG_KEY = "_ldap_config"
    PASSWORD_HASH_KEY = "password_hash"
    LEGACY_PASSWORD_KEY = "password"
    LOCAL_AUTH_SOURCE = "local"
    LDAP_AUTH_SOURCE = "ldap"
    DEFAULT_ADMIN_UI_CONFIG = {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
    }
    DEFAULT_LDAP_CONFIG = {
        "enabled": False,
        "server_url": "",
        "default_domain": "",
        "base_dn": "",
        "bind_dn": "",
        "bind_password": "",
        "user_search_filter": "(&(objectClass=user)(|(sAMAccountName={username})(userPrincipalName={raw_username})(userPrincipalName={upn})))",
    }
    RESERVED_KEYS = {
        AUTH_USERS_KEY,
        USER_PROFILES_KEY,
        SESSION_SECRET_KEY,
        ADMIN_UI_CONFIG_KEY,
        LDAP_CONFIG_KEY,
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
        if admin.get("source") != self.LOCAL_AUTH_SOURCE:
            admin["source"] = self.LOCAL_AUTH_SOURCE
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

    def _normalize_ldap_config(self, value, previous=None):
        config = dict(self.DEFAULT_LDAP_CONFIG)
        previous = previous if isinstance(previous, dict) else {}
        if previous.get("bind_password"):
            config["bind_password"] = str(previous.get("bind_password") or "")
        if isinstance(value, dict):
            keep_existing_password = bool(value.get("bind_password_present"))
            for key in self.DEFAULT_LDAP_CONFIG:
                if key not in value:
                    continue
                if key == "enabled":
                    config[key] = bool(value[key])
                elif key == "bind_password" and (
                    value.get(key) in (None, "") or keep_existing_password
                ):
                    config[key] = str(previous.get(key) or "")
                elif key == "bind_password":
                    config[key] = str(value[key] or "")
                else:
                    config[key] = str(value[key] or "").strip()
            if value.get("clear_bind_password"):
                config["bind_password"] = ""
        return config

    def _public_ldap_config(self, config=None):
        config = self._normalize_ldap_config(
            self.data.get(self.LDAP_CONFIG_KEY) if config is None else config
        )
        public_config = {key: value for key, value in config.items() if key != "bind_password"}
        public_config["bind_password_present"] = bool(config.get("bind_password"))
        return public_config

    def _public_auth_user(self, username, user):
        user = user if isinstance(user, dict) else {}
        return {
            "username": username,
            "is_admin": bool(user.get("is_admin", False)),
            "source": str(user.get("source") or self.LOCAL_AUTH_SOURCE),
            "display_name": str(user.get("display_name") or ""),
            "email": str(user.get("email") or ""),
            "last_login": user.get("last_login"),
        }

    def _normalize_lookup_username(self, username: str) -> str:
        value = str(username or "").strip()
        if "\\" in value:
            value = value.split("\\")[-1]
        if "@" in value:
            value = value.split("@")[0]
        return value.lower()

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
        auth_users = self.get_auth_users()
        if username in auth_users:
            return auth_users.get(username)
        normalized = self._normalize_lookup_username(username)
        return auth_users.get(normalized)

    def list_auth_users(self):
        users = self.get_auth_users()
        return [
            self._public_auth_user(username, user)
            for username, user in sorted(users.items(), key=lambda item: item[0].lower())
        ]

    def set_auth_user_admin(self, username: str, is_admin: bool):
        username = self._normalize_lookup_username(username)
        if not username:
            return None
        if username == "admin":
            return self._public_auth_user("admin", self.get_auth_user("admin"))

        users = self.data.setdefault(self.AUTH_USERS_KEY, {})
        user = users.get(username)
        if not isinstance(user, dict):
            return None
        user["is_admin"] = bool(is_admin)
        users[username] = user
        self.save()
        return self._public_auth_user(username, user)

    def authenticate_user(self, username: str, password: str):
        user = self.get_auth_user(username)
        normalized_username = self._normalize_lookup_username(username)
        if user and user.get("source", self.LOCAL_AUTH_SOURCE) == self.LOCAL_AUTH_SOURCE:
            password_hash = user.get(self.PASSWORD_HASH_KEY)
            if not self._is_password_hash(password_hash):
                return None
            if not check_password_hash(str(password_hash), password):
                return None
            return {
                "username": normalized_username if normalized_username == "admin" else username,
                "is_admin": bool(user.get("is_admin", False)),
                "source": self.LOCAL_AUTH_SOURCE,
            }

        if normalized_username == "admin":
            return None

        ldap_user = self._authenticate_ldap_user(username, password)
        if not ldap_user:
            return None
        return ldap_user

    def get_ldap_config(self):
        config = self._normalize_ldap_config(self.data.get(self.LDAP_CONFIG_KEY))
        if self.data.get(self.LDAP_CONFIG_KEY) != config:
            self.data[self.LDAP_CONFIG_KEY] = config
            self.save()
        return self._public_ldap_config(config)

    def set_ldap_config(self, value):
        previous = self.data.get(self.LDAP_CONFIG_KEY)
        config = self._normalize_ldap_config(value, previous=previous)
        self.data[self.LDAP_CONFIG_KEY] = config
        self.save()
        return self._public_ldap_config(config)

    def test_ldap_config(self, value=None, username="", password=""):
        previous = self.data.get(self.LDAP_CONFIG_KEY)
        config = self._normalize_ldap_config(value or previous, previous=previous)
        if not config.get("enabled"):
            return {"ok": False, "message": "LDAP is disabled"}
        if username and password:
            user = self._authenticate_ldap_user(
                username, password, config=config, persist=False
            )
            if user:
                return {"ok": True, "message": "LDAP user authentication succeeded"}
            return {"ok": False, "message": "LDAP user authentication failed"}

        try:
            connection = self._ldap_service_connection(config)
            connection.unbind()
            return {"ok": True, "message": "LDAP service bind succeeded"}
        except Exception as error:
            logger.warning("LDAP service bind test failed: %s", error)
            return {"ok": False, "message": str(error)}

    def _ldap_config_for_auth(self):
        config = self._normalize_ldap_config(self.data.get(self.LDAP_CONFIG_KEY))
        if not config.get("enabled"):
            return None
        return config

    def _ldap_dependencies(self):
        try:
            from ldap3 import ALL, Connection, Server
            from ldap3.core.exceptions import LDAPException
            from ldap3.utils.conv import escape_filter_chars

            return ALL, Connection, Server, LDAPException, escape_filter_chars
        except ImportError as error:
            raise RuntimeError(
                "LDAP support requires the optional ldap3 Python package"
            ) from error

    def _ldap_server(self, config):
        ALL, _Connection, Server, _LDAPException, _escape_filter_chars = (
            self._ldap_dependencies()
        )
        server_url = str(config.get("server_url") or "").strip()
        if not server_url:
            raise RuntimeError("LDAP server URL is required")
        return Server(server_url, get_info=ALL)

    def _ldap_service_connection(self, config):
        _ALL, Connection, _Server, _LDAPException, _escape_filter_chars = (
            self._ldap_dependencies()
        )
        server = self._ldap_server(config)
        bind_dn = str(config.get("bind_dn") or "").strip()
        bind_password = str(config.get("bind_password") or "")
        if bind_dn:
            return Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        return Connection(server, auto_bind=True)

    def _ldap_auth_principal(self, username, config):
        raw_username = str(username or "").strip()
        default_domain = str(config.get("default_domain") or "").strip()
        if "\\" in raw_username or "@" in raw_username or not default_domain:
            return raw_username
        return f"{raw_username}@{default_domain}"

    def _ldap_search_filter(self, config, username):
        _ALL, _Connection, _Server, _LDAPException, escape_filter_chars = (
            self._ldap_dependencies()
        )
        raw_username = str(username or "").strip()
        normalized = self._normalize_lookup_username(raw_username)
        upn = self._ldap_auth_principal(normalized, config)
        values = {
            "username": escape_filter_chars(normalized),
            "raw_username": escape_filter_chars(raw_username),
            "upn": escape_filter_chars(upn),
        }
        template = str(config.get("user_search_filter") or "").strip()
        if not template:
            template = self.DEFAULT_LDAP_CONFIG["user_search_filter"]

        allowed_fields = set(values)
        for literal_text, field_name, _format_spec, _conversion in Formatter().parse(
            template
        ):
            if field_name and field_name not in allowed_fields:
                raise RuntimeError(f"Unsupported LDAP search filter field: {field_name}")
        return template.format(**values)

    def _ldap_search_user(self, connection, config, username):
        base_dn = str(config.get("base_dn") or "").strip()
        if not base_dn:
            return None
        search_filter = self._ldap_search_filter(config, username)
        attributes = [
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "mail",
        ]
        if not connection.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=attributes,
            size_limit=1,
        ):
            return None
        if not connection.entries:
            return None
        entry = connection.entries[0]
        attrs = entry.entry_attributes_as_dict or {}
        dn = str(entry.entry_dn)
        return dn, attrs

    def _first_ldap_attr(self, attrs, key):
        value = attrs.get(key)
        if isinstance(value, list):
            value = value[0] if value else ""
        return str(value or "").strip()

    def _canonical_ldap_username(self, raw_username, attrs):
        sam = self._first_ldap_attr(attrs, "sAMAccountName")
        upn = self._first_ldap_attr(attrs, "userPrincipalName")
        return self._normalize_lookup_username(sam or upn or raw_username)

    def _record_ldap_login(self, raw_username, attrs=None, dn=""):
        attrs = attrs or {}
        username = self._canonical_ldap_username(raw_username, attrs)
        if not username or username == "admin":
            return None

        users = self.data.setdefault(self.AUTH_USERS_KEY, {})
        existing = users.get(username)
        if not isinstance(existing, dict):
            existing = {}
        user = {
            **existing,
            "source": self.LDAP_AUTH_SOURCE,
            "is_admin": bool(existing.get("is_admin", False)),
            "display_name": self._first_ldap_attr(attrs, "displayName"),
            "email": self._first_ldap_attr(attrs, "mail"),
            "ldap_dn": str(dn or existing.get("ldap_dn") or ""),
            "last_login": datetime.now().astimezone().isoformat(),
        }
        users[username] = user
        self.save()
        return {
            "username": username,
            "is_admin": bool(user.get("is_admin", False)),
            "source": self.LDAP_AUTH_SOURCE,
        }

    def _authenticate_ldap_user(self, username, password, config=None, persist=True):
        if not username or not password:
            return None
        config = config or self._ldap_config_for_auth()
        if not config:
            return None

        _ALL, Connection, _Server, LDAPException, _escape_filter_chars = (
            self._ldap_dependencies()
        )
        user_connection = None
        service_connection = None
        try:
            server = self._ldap_server(config)
            bind_dn = str(config.get("bind_dn") or "").strip()
            dn = ""
            attrs = {}

            if bind_dn:
                service_connection = self._ldap_service_connection(config)
                search_result = self._ldap_search_user(
                    service_connection, config, username
                )
                if not search_result:
                    return None
                dn, attrs = search_result
                user_connection = Connection(
                    server, user=dn, password=password, auto_bind=True
                )
            else:
                principal = self._ldap_auth_principal(username, config)
                user_connection = Connection(
                    server, user=principal, password=password, auto_bind=True
                )
                search_result = self._ldap_search_user(user_connection, config, username)
                if search_result:
                    dn, attrs = search_result

            if persist:
                return self._record_ldap_login(username, attrs=attrs, dn=dn)

            canonical = self._canonical_ldap_username(username, attrs)
            return {"username": canonical, "is_admin": False, "source": self.LDAP_AUTH_SOURCE}
        except (LDAPException, RuntimeError) as error:
            logger.warning("LDAP authentication failed for %s: %s", username, error)
            return None
        finally:
            if user_connection is not None:
                user_connection.unbind()
            if service_connection is not None:
                service_connection.unbind()

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
