import hashlib
import json
import logging
import os
import secrets
import shutil
import tempfile
import threading
import time
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path
from string import Formatter

from aw_core.dirs import get_config_dir
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)


def synchronized(method):
    """Serialize a Settings method against every other synchronized method.

    Flask runs threaded (server.py: app.run(..., threaded=True)), so any
    request thread can mutate self.data. Without this, two effects break the
    file: read-modify-write pairs lose updates, and a `del self.data[key]`
    landing inside save()'s json.dumps raises "dictionary changed size during
    iteration". The lock is re-entrant because mutators call save().
    """

    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class Settings:
    AUTH_USERS_KEY = "_auth_users"
    USER_PROFILES_KEY = "_user_profiles"
    SESSION_SECRET_KEY = "_session_secret"
    ADMIN_UI_CONFIG_KEY = "_admin_ui_config"
    LDAP_CONFIG_KEY = "_ldap_config"
    REDMINE_CONFIG_KEY = "_redmine_config"
    REDMINE_USER_MAPPINGS_KEY = "_redmine_user_mappings"
    WATCHER_UPDATE_CONFIG_KEY = "_watcher_update_config"
    WATCHER_UPDATE_STATUS_KEY = "_watcher_update_status"
    WATCHER_UPDATE_REQUESTS_KEY = "_watcher_update_requests"
    FLEET_AUTH_CONFIG_KEY = "_fleet_auth_config"
    FLEET_DEVICES_KEY = "_fleet_devices"
    FLEET_ENDPOINT_KEY = "_fleet_endpoint_config"
    PASSWORD_HASH_KEY = "password_hash"
    LEGACY_PASSWORD_KEY = "password"
    LOCAL_AUTH_SOURCE = "local"
    LDAP_AUTH_SOURCE = "ldap"
    # Fleet pages a non-admin user can be granted individually. Their own
    # single-user view is always allowed and needs no grant.
    # "fleet-summary-own" is the same Zusammenfassung page restricted to the
    # user's own row - granted instead of "fleet-summary", not as well as it.
    FLEET_PAGE_KEYS = (
        "fleet-live",
        "fleet-summary",
        "fleet-summary-own",
        "fleet-users",
        "fleet-devices",
    )
    # Additional start-page keys only meaningful for admins.
    ADMIN_LANDING_KEYS = ("timeline", "buckets")
    DEFAULT_ADMIN_UI_CONFIG = {
        "show_stopwatch_menu": False,
        "show_tools_menu": True,
        "landing_page_admin": "/fleet",
        "landing_page_user": "/fleet",
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
    DEFAULT_REDMINE_CONFIG = {
        "enabled": False,
        "driver": "auto",
        "host": "",
        "port": 3306,
        "database": "redmine",
        "username": "",
        "password": "",
        "table_prefix": "",
        "mysql_cli_path": "mysql",
        "connect_timeout": 10,
    }
    DEFAULT_WATCHER_UPDATE_CONFIG = {
        "auto_update_enabled": False,
        # How long a manually requested update stays pending for a device that
        # is powered off / off the LAN before it is dropped as expired.
        "manual_update_ttl_minutes": 360,
    }
    DEFAULT_FLEET_AUTH_CONFIG = {
        # When True, machine-to-machine endpoints (watcher ingest, watcher
        # update, fleet sync) require the fleet token. Ships DISABLED so
        # enabling it is a deliberate act AFTER the token reached the devices -
        # flipping it early would stop the whole fleet from recording.
        "require_watcher_token": False,
        "token": "",
    }
    RESERVED_KEYS = {
        AUTH_USERS_KEY,
        USER_PROFILES_KEY,
        SESSION_SECRET_KEY,
        ADMIN_UI_CONFIG_KEY,
        LDAP_CONFIG_KEY,
        REDMINE_CONFIG_KEY,
        REDMINE_USER_MAPPINGS_KEY,
        WATCHER_UPDATE_CONFIG_KEY,
        WATCHER_UPDATE_STATUS_KEY,
        WATCHER_UPDATE_REQUESTS_KEY,
        FLEET_AUTH_CONFIG_KEY,
        FLEET_DEVICES_KEY,
        FLEET_ENDPOINT_KEY,
    }
    # A device that enrolls but is never approved must not be able to grow the
    # settings file without bound.
    MAX_PENDING_DEVICES = 200

    def __init__(self, testing: bool):
        filename = "settings.json" if not testing else "settings-testing.json"
        self.config_file = Path(get_config_dir("aw-server")) / filename
        # Same directory => same volume => os.replace() is atomic on NTFS.
        self.backup_file = self.config_file.with_name(self.config_file.name + ".bak")
        # Re-entrant: nearly every mutator calls save() while already holding it.
        self._lock = threading.RLock()
        self._last_written = None
        self.load()

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        return self.set(key, value)

    def load(self):
        """Read settings.json, falling back to the .bak written by the previous
        save() when the primary file is missing or unreadable.

        This file holds the only copy of the password hashes, the LDAP bind
        password and the Redmine DB password, so a damaged primary must never
        silently become "no users" - that would regenerate admin/admin on a
        LAN-reachable admin UI. A file we cannot use is quarantined (renamed),
        never overwritten, so the evidence survives for a manual repair.
        """
        with self._lock:
            self.data = None
            for candidate in (self.config_file, self.backup_file):
                if not candidate.exists():
                    continue
                try:
                    with open(candidate, encoding="utf-8") as f:
                        loaded = json.load(f)
                except (OSError, UnicodeDecodeError, ValueError) as error:
                    logger.error("Settings file %s is unreadable: %s", candidate, error)
                    self._quarantine(candidate)
                    continue
                if not isinstance(loaded, dict):
                    logger.error("Settings file %s is not a JSON object", candidate)
                    self._quarantine(candidate)
                    continue
                if candidate == self.backup_file:
                    logger.warning("RECOVERED settings from backup %s", candidate)
                self.data = loaded
                break

            if self.data is None:
                if self.config_file.exists() or self.backup_file.exists():
                    logger.error(
                        "No usable settings file at %s - starting from defaults. "
                        "Accounts, LDAP and Redmine configuration have been lost.",
                        self.config_file,
                    )
                self.data = {}

            self._ensure_internal_defaults()

    def _quarantine(self, path: Path):
        """Move an unusable settings file aside so the next save() cannot
        overwrite it and a human can still inspect what was left of it."""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            os.replace(str(path), str(path.with_name(f"{path.name}.corrupt-{stamp}")))
        except OSError as error:
            logger.warning("Could not quarantine %s: %s", path, error)

    def save(self):
        """Crash-safe write: serialize first, then temp file + fsync + rename.

        The previous implementation truncated settings.json with open(...,"w")
        before a single new byte existed, so any interruption in that window
        (power loss, disk full, a kill, an AV lock, or a concurrent mutation
        raising mid-json.dump) left a truncated file - and load() had no
        recovery, so the server either crashed at startup or came back with
        default credentials.
        """
        with self._lock:
            # Serializing under the lock means a concurrent mutation raises
            # BEFORE the file is touched, instead of halfway through writing it.
            payload = json.dumps(self.data, indent=4, ensure_ascii=True)
            if payload == self._last_written and self.config_file.exists():
                # Several getters normalize-and-save; skip the no-op rewrites.
                return
            self._atomic_write(payload)
            self._last_written = payload

    def _atomic_write(self, payload: str):
        directory = self.config_file.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.config_file.name + ".", suffix=".tmp", dir=str(directory)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            # Copy (never move) the current file aside: the primary must stay a
            # complete file at every instant.
            if self.config_file.exists():
                try:
                    shutil.copyfile(str(self.config_file), str(self.backup_file))
                except OSError as error:
                    logger.warning("Could not refresh settings backup: %s", error)
            self._replace_with_retry(tmp_name, self.config_file)
            tmp_name = None
        finally:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    def _replace_with_retry(self, source: str, target: Path, attempts: int = 12):
        # os.replace maps to MoveFileExW(MOVEFILE_REPLACE_EXISTING), atomic on
        # NTFS, but it fails while another process holds the target open
        # (Defender, a backup agent, an admin with the file in Notepad).
        # Retrying is correct; falling back to a truncating write is not.
        delay = 0.05
        for attempt in range(attempts):
            try:
                os.replace(source, str(target))
                return
            except PermissionError as error:
                if attempt == attempts - 1:
                    logger.error(
                        "Could not replace %s after %s attempts: %s",
                        target,
                        attempts,
                        error,
                    )
                    raise
                time.sleep(delay)
                delay = min(delay * 2, 0.5)

    @synchronized
    def _ensure_internal_defaults(self):
        changed = False

        auth_users = self.data.get(self.AUTH_USERS_KEY)
        if not isinstance(auth_users, dict):
            if auth_users is not None or self.data:
                # Falling back to a fresh admin/admin on a LAN-reachable admin
                # UI must never be a quiet event.
                logger.error(
                    "Settings contained no usable user accounts - recreating the "
                    "built-in admin with the DEFAULT password. Change it and "
                    "re-enter the LDAP/Redmine configuration."
                )
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
            for key, default in self.DEFAULT_ADMIN_UI_CONFIG.items():
                if key not in value:
                    continue
                if isinstance(default, bool):
                    config[key] = bool(value[key])
                else:
                    text = str(value[key] or "").strip()
                    config[key] = text if text.startswith("/") else default
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

    def _normalize_redmine_config(self, value, previous=None):
        config = dict(self.DEFAULT_REDMINE_CONFIG)
        previous = previous if isinstance(previous, dict) else {}
        if previous.get("password"):
            config["password"] = str(previous.get("password") or "")
        if isinstance(value, dict):
            keep_existing_password = bool(value.get("password_present"))
            for key in self.DEFAULT_REDMINE_CONFIG:
                if key not in value:
                    continue
                if key == "enabled":
                    config[key] = bool(value[key])
                elif key == "port":
                    try:
                        config[key] = int(value[key])
                    except (TypeError, ValueError):
                        config[key] = self.DEFAULT_REDMINE_CONFIG[key]
                elif key == "connect_timeout":
                    try:
                        config[key] = max(1, min(120, int(value[key])))
                    except (TypeError, ValueError):
                        config[key] = self.DEFAULT_REDMINE_CONFIG[key]
                elif key == "password" and (
                    value.get(key) in (None, "") or keep_existing_password
                ):
                    config[key] = str(previous.get(key) or "")
                elif key == "password":
                    config[key] = str(value[key] or "")
                else:
                    config[key] = str(value[key] or "").strip()
            if value.get("clear_password"):
                config["password"] = ""
        return config

    def _public_redmine_config(self, config=None):
        config = self._normalize_redmine_config(
            self.data.get(self.REDMINE_CONFIG_KEY) if config is None else config
        )
        public_config = {key: value for key, value in config.items() if key != "password"}
        public_config["password_present"] = bool(config.get("password"))
        return public_config

    def _normalize_redmine_user_mappings(self, value):
        mappings = {}
        if not isinstance(value, dict):
            return mappings
        for username, redmine_user_id in value.items():
            normalized_username = self._normalize_lookup_username(username)
            if not normalized_username:
                continue
            try:
                parsed_user_id = int(redmine_user_id)
            except (TypeError, ValueError):
                continue
            if parsed_user_id > 0:
                mappings[normalized_username] = parsed_user_id
        return mappings

    def _normalize_allowed_pages(self, value):
        if not isinstance(value, (list, tuple)):
            return []
        allowed = []
        for entry in value:
            key = str(entry or "").strip().lower()
            if key in self.FLEET_PAGE_KEYS and key not in allowed:
                allowed.append(key)
        return allowed

    def _normalize_user_landing(self, value):
        key = str(value or "").strip().lower()
        if key == "own" or key in self.FLEET_PAGE_KEYS or key in self.ADMIN_LANDING_KEYS:
            return key
        return ""

    def _public_auth_user(self, username, user):
        user = user if isinstance(user, dict) else {}
        return {
            "username": username,
            "is_admin": bool(user.get("is_admin", False)),
            "source": str(user.get("source") or self.LOCAL_AUTH_SOURCE),
            "display_name": str(user.get("display_name") or ""),
            "email": str(user.get("email") or ""),
            "last_login": user.get("last_login"),
            "allowed_pages": self._normalize_allowed_pages(user.get("allowed_pages")),
            "landing_page": self._normalize_user_landing(user.get("landing_page")),
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

    @synchronized
    def set(self, key, value):
        if value:
            self.data[key] = value
        else:
            if key in self.data:
                del self.data[key]
        self.save()

    @synchronized
    def get_session_secret(self) -> str:
        self._ensure_internal_defaults()
        return str(self.data[self.SESSION_SECRET_KEY])

    @synchronized
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

    @synchronized
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
        self._clamp_user_landing(user)
        users[username] = user
        self.save()
        return self._public_auth_user(username, user)

    def _clamp_user_landing(self, user):
        # Non-admins: a landing override onto a page they are not granted falls
        # back to the default (their own view), so revoking a page never
        # strands them. Admins see everything, so no clamping there.
        if not isinstance(user, dict) or bool(user.get("is_admin", False)):
            return
        landing = user.get("landing_page")
        if landing and landing != "own" and landing not in self._normalize_allowed_pages(user.get("allowed_pages")):
            del user["landing_page"]

    @synchronized
    def set_auth_user_access(self, username: str, allowed_pages=None, landing_page=None):
        username = self._normalize_lookup_username(username)
        if not username:
            return None

        users = self.data.setdefault(self.AUTH_USERS_KEY, {})
        user = users.get(username)
        if not isinstance(user, dict):
            return None

        # Page grants are meaningless for the built-in admin, but a start-page
        # override is allowed for every account, admin included.
        if allowed_pages is not None and username != "admin":
            user["allowed_pages"] = self._normalize_allowed_pages(allowed_pages)
        if landing_page is not None:
            normalized_landing = self._normalize_user_landing(landing_page)
            if normalized_landing:
                user["landing_page"] = normalized_landing
            elif "landing_page" in user:
                del user["landing_page"]

        self._clamp_user_landing(user)

        users[username] = user
        self.save()
        return self._public_auth_user(username, user)

    @synchronized
    def authenticate_user(self, username: str, password: str):
        user = self.get_auth_user(username)
        normalized_username = self._normalize_lookup_username(username)
        if user and user.get("source", self.LOCAL_AUTH_SOURCE) == self.LOCAL_AUTH_SOURCE:
            password_hash = user.get(self.PASSWORD_HASH_KEY)
            if not self._is_password_hash(password_hash):
                return None
            if not check_password_hash(str(password_hash), password):
                return None
            # Record the login time for local accounts too; before this only
            # LDAP logins stamped last_login, so 'admin' always showed '-'.
            try:
                user["last_login"] = datetime.now().astimezone().isoformat()
                self.save()
            except Exception:
                pass
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

    @synchronized
    def get_ldap_config(self):
        config = self._normalize_ldap_config(self.data.get(self.LDAP_CONFIG_KEY))
        if self.data.get(self.LDAP_CONFIG_KEY) != config:
            self.data[self.LDAP_CONFIG_KEY] = config
            self.save()
        return self._public_ldap_config(config)

    @synchronized
    def set_ldap_config(self, value):
        previous = self.data.get(self.LDAP_CONFIG_KEY)
        config = self._normalize_ldap_config(value, previous=previous)
        self.data[self.LDAP_CONFIG_KEY] = config
        self.save()
        return self._public_ldap_config(config)

    @synchronized
    def get_redmine_config(self, include_secret=False):
        config = self._normalize_redmine_config(self.data.get(self.REDMINE_CONFIG_KEY))
        if self.data.get(self.REDMINE_CONFIG_KEY) != config:
            self.data[self.REDMINE_CONFIG_KEY] = config
            self.save()
        if include_secret:
            return dict(config)
        return self._public_redmine_config(config)

    @synchronized
    def set_redmine_config(self, value):
        previous = self.data.get(self.REDMINE_CONFIG_KEY)
        config = self._normalize_redmine_config(value, previous=previous)
        self.data[self.REDMINE_CONFIG_KEY] = config
        self.save()
        return self._public_redmine_config(config)

    @synchronized
    def get_redmine_user_mappings(self):
        mappings = self._normalize_redmine_user_mappings(
            self.data.get(self.REDMINE_USER_MAPPINGS_KEY)
        )
        if self.data.get(self.REDMINE_USER_MAPPINGS_KEY) != mappings:
            if mappings:
                self.data[self.REDMINE_USER_MAPPINGS_KEY] = mappings
            elif self.REDMINE_USER_MAPPINGS_KEY in self.data:
                del self.data[self.REDMINE_USER_MAPPINGS_KEY]
            self.save()
        return mappings

    @synchronized
    def set_redmine_user_mapping(self, username: str, redmine_user_id):
        normalized_username = self._normalize_lookup_username(username)
        if not normalized_username:
            return self.get_redmine_user_mappings()

        mappings = self.get_redmine_user_mappings()
        try:
            parsed_user_id = int(redmine_user_id)
        except (TypeError, ValueError):
            parsed_user_id = 0

        if parsed_user_id > 0:
            mappings[normalized_username] = parsed_user_id
        elif normalized_username in mappings:
            del mappings[normalized_username]

        if mappings:
            self.data[self.REDMINE_USER_MAPPINGS_KEY] = mappings
        elif self.REDMINE_USER_MAPPINGS_KEY in self.data:
            del self.data[self.REDMINE_USER_MAPPINGS_KEY]
        self.save()
        return mappings

    def _coerce_watcher_update_value(self, key, value, default):
        if isinstance(default, bool):
            return bool(value)
        if key == "manual_update_ttl_minutes":
            try:
                minutes = int(value)
            except (TypeError, ValueError):
                return default
            return max(5, min(minutes, 10080))
        return value

    @synchronized
    def get_watcher_update_config(self):
        config = dict(self.DEFAULT_WATCHER_UPDATE_CONFIG)
        stored = self.data.get(self.WATCHER_UPDATE_CONFIG_KEY)
        if isinstance(stored, dict):
            for key, default in self.DEFAULT_WATCHER_UPDATE_CONFIG.items():
                if key not in stored:
                    continue
                config[key] = self._coerce_watcher_update_value(
                    key, stored[key], default
                )
        return config

    @synchronized
    def set_watcher_update_config(self, value):
        config = self.get_watcher_update_config()
        if isinstance(value, dict):
            for key, default in self.DEFAULT_WATCHER_UPDATE_CONFIG.items():
                if key not in value:
                    continue
                config[key] = self._coerce_watcher_update_value(
                    key, value[key], default
                )
        self.data[self.WATCHER_UPDATE_CONFIG_KEY] = config
        self.save()
        return dict(config)

    @synchronized
    def get_watcher_update_status(self):
        stored = self.data.get(self.WATCHER_UPDATE_STATUS_KEY)
        if not isinstance(stored, dict):
            return {}
        return {
            hostname: dict(info)
            for hostname, info in stored.items()
            if isinstance(info, dict)
        }

    @synchronized
    def record_watcher_update_status(self, hostname: str, info: dict):
        hostname = str(hostname or "").strip()
        if not hostname or not isinstance(info, dict):
            return {}
        statuses = self.data.get(self.WATCHER_UPDATE_STATUS_KEY)
        if not isinstance(statuses, dict):
            statuses = {}
        previous = statuses.get(hostname)
        previous = dict(previous) if isinstance(previous, dict) else {}
        entry = dict(previous)
        entry.update(info)
        statuses[hostname] = entry
        self.data[self.WATCHER_UPDATE_STATUS_KEY] = statuses
        # Devices report once a minute; only write the file when something
        # durable changed, not for the reported_at refresh alone.
        durable_keys = ("version", "message", "updating")
        if any(previous.get(key) != entry.get(key) for key in durable_keys):
            self.save()
        return dict(entry)

    #
    # Manually requested watcher updates
    #
    # The server cannot push to a device, so "update now" is a pending record
    # the supervisor picks up on its next (<=60 s) manifest poll. Requests are
    # keyed by the lower-cased hostname, because _watcher_update_status is
    # keyed by the raw $env:COMPUTERNAME while never-reported rows come from
    # the fleet device name.

    @staticmethod
    def watcher_request_key(hostname) -> str:
        return str(hostname or "").strip().lower()

    @synchronized
    def get_watcher_update_requests(self):
        stored = self.data.get(self.WATCHER_UPDATE_REQUESTS_KEY)
        if not isinstance(stored, dict):
            return {}
        return {
            key: dict(entry)
            for key, entry in stored.items()
            if isinstance(entry, dict)
        }

    @synchronized
    def _write_watcher_update_requests(self, requests):
        if requests:
            self.data[self.WATCHER_UPDATE_REQUESTS_KEY] = requests
        elif self.WATCHER_UPDATE_REQUESTS_KEY in self.data:
            del self.data[self.WATCHER_UPDATE_REQUESTS_KEY]
        self.save()

    @synchronized
    def request_watcher_update(self, hostname, version, requested_by, ttl_minutes):
        key = self.watcher_request_key(hostname)
        if not key:
            return None
        requests = self.get_watcher_update_requests()
        now = datetime.now().astimezone()
        entry = {
            # A fresh id per request: the supervisor stores it and only skips
            # the 15-minute cooldown once per id, so a permanently failing
            # install retries on the normal cooldown instead of every minute.
            "request_id": secrets.token_hex(8),
            "hostname": str(hostname or "").strip(),
            "requested_version": str(version or "").strip().lower(),
            "requested_by": str(requested_by or "").strip(),
            "requested_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=int(ttl_minutes))).isoformat(),
            "acknowledged_at": None,
        }
        requests[key] = entry
        self._write_watcher_update_requests(requests)
        return dict(entry)

    @synchronized
    def clear_watcher_update_request(self, hostname):
        key = self.watcher_request_key(hostname)
        requests = self.get_watcher_update_requests()
        if key not in requests:
            return False
        del requests[key]
        self._write_watcher_update_requests(requests)
        return True

    @synchronized
    def get_watcher_update_request(self, hostname):
        """Pending request for one device, dropping it when it has expired."""
        key = self.watcher_request_key(hostname)
        if not key:
            return None
        requests = self.get_watcher_update_requests()
        entry = requests.get(key)
        if not entry:
            return None
        expires_at = entry.get("expires_at")
        if expires_at:
            try:
                if datetime.fromisoformat(str(expires_at)) < datetime.now().astimezone():
                    del requests[key]
                    self._write_watcher_update_requests(requests)
                    return None
            except ValueError:
                pass
        return dict(entry)

    @synchronized
    def acknowledge_watcher_update_request(self, hostname, request_id):
        """Mark that the device has seen the request and started installing.

        Only writes when something actually changed, so an already-acknowledged
        request does not rewrite settings.json on every one-minute poll.
        """
        key = self.watcher_request_key(hostname)
        requests = self.get_watcher_update_requests()
        entry = requests.get(key)
        if not entry or (request_id and entry.get("request_id") != request_id):
            return None
        if entry.get("acknowledged_at"):
            return dict(entry)
        entry["acknowledged_at"] = datetime.now().astimezone().isoformat()
        requests[key] = entry
        self._write_watcher_update_requests(requests)
        return dict(entry)

    #
    # Fleet machine-to-machine authentication
    #

    @synchronized
    def get_fleet_auth_config(self, include_secret: bool = False):
        config = dict(self.DEFAULT_FLEET_AUTH_CONFIG)
        stored = self.data.get(self.FLEET_AUTH_CONFIG_KEY)
        if isinstance(stored, dict):
            config["require_watcher_token"] = bool(
                stored.get("require_watcher_token", False)
            )
            config["token"] = str(stored.get("token") or "")

        if not config["token"]:
            # Generated on first access so a fresh server always has a token to
            # hand out, long before enforcement is switched on.
            config["token"] = secrets.token_urlsafe(32)
            self.data[self.FLEET_AUTH_CONFIG_KEY] = dict(config)
            self.save()

        if include_secret:
            return dict(config)
        public = dict(config)
        public["token"] = ""
        public["token_hint"] = config["token"][:6] if config["token"] else ""
        return public

    @synchronized
    def set_fleet_auth_config(self, value):
        config = self.get_fleet_auth_config(include_secret=True)
        if isinstance(value, dict):
            if "require_watcher_token" in value:
                config["require_watcher_token"] = bool(value["require_watcher_token"])
            if value.get("rotate_token"):
                config["token"] = secrets.token_urlsafe(32)
        self.data[self.FLEET_AUTH_CONFIG_KEY] = dict(config)
        self.save()
        return self.get_fleet_auth_config()

    def get_fleet_token(self) -> str:
        return str(self.get_fleet_auth_config(include_secret=True).get("token") or "")

    def is_watcher_token_required(self) -> bool:
        return bool(
            self.get_fleet_auth_config(include_secret=True).get(
                "require_watcher_token", False
            )
        )

    #
    # Device enrollment
    #
    # A device generates its own high-entropy key on first start and posts it
    # here; an admin approves it in the GUI, and from then on that key is the
    # device's credential. Only the SHA256 of the key is stored, and it doubles
    # as the record's id, so authenticating a request is a single dict lookup.
    # SHA256 (not a password KDF) is correct here precisely because the key is
    # 256 bits of randomness rather than a human-chosen secret - and a KDF per
    # heartbeat would be far too slow.

    STATUS_PENDING = "pending"
    STATUS_APPROVED = "approved"
    STATUS_REJECTED = "rejected"

    @staticmethod
    def hash_device_key(device_key: str) -> str:
        return hashlib.sha256(str(device_key or "").encode("utf-8")).hexdigest()

    @synchronized
    def get_fleet_devices(self):
        stored = self.data.get(self.FLEET_DEVICES_KEY)
        if not isinstance(stored, dict):
            return {}
        return {
            key: dict(entry)
            for key, entry in stored.items()
            if isinstance(entry, dict)
        }

    @synchronized
    def _write_fleet_devices(self, devices):
        if devices:
            self.data[self.FLEET_DEVICES_KEY] = devices
        elif self.FLEET_DEVICES_KEY in self.data:
            del self.data[self.FLEET_DEVICES_KEY]
        self.save()

    @synchronized
    def enroll_device(self, device_key: str, hostname: str, address: str, details=None):
        """Record (or refresh) a device's enrollment request.

        Re-enrolling with the SAME key is idempotent and never downgrades an
        already-approved device, so a supervisor that re-posts on every start
        costs nothing.
        """
        key_hash = self.hash_device_key(device_key)
        if not device_key:
            return None

        devices = self.get_fleet_devices()
        now = datetime.now().astimezone().isoformat()
        entry = devices.get(key_hash)

        if isinstance(entry, dict):
            changed = False
            for field, value in (
                ("hostname", str(hostname or "").strip()),
                ("address", str(address or "").strip()),
            ):
                if value and entry.get(field) != value:
                    entry[field] = value
                    changed = True
            entry["last_seen"] = now
            devices[key_hash] = entry
            # last_seen alone must not rewrite the file on every poll.
            if changed:
                self._write_fleet_devices(devices)
            return dict(entry)

        pending = [
            e for e in devices.values() if e.get("status") == self.STATUS_PENDING
        ]
        if len(pending) >= self.MAX_PENDING_DEVICES:
            logger.warning(
                "Refusing enrollment from %s (%s): %s pending devices already",
                hostname,
                address,
                len(pending),
            )
            return None

        entry = {
            "hostname": str(hostname or "").strip() or "unknown",
            "address": str(address or "").strip(),
            "status": self.STATUS_PENDING,
            "first_seen": now,
            "last_seen": now,
            "approved_at": None,
            "approved_by": None,
        }
        if isinstance(details, dict):
            entry["package_version"] = str(details.get("package_version") or "")[:64]
        devices[key_hash] = entry
        self._write_fleet_devices(devices)
        logger.info("Device %s (%s) requested enrollment", entry["hostname"], address)
        return dict(entry)

    @synchronized
    def get_device_by_key(self, device_key: str):
        return self.get_fleet_devices().get(self.hash_device_key(device_key))

    @synchronized
    def is_device_key_approved(self, device_key: str) -> bool:
        entry = self.get_device_by_key(device_key)
        return bool(entry and entry.get("status") == self.STATUS_APPROVED)

    @synchronized
    def set_device_status(self, key_hash: str, status: str, actor: str = ""):
        if status not in (self.STATUS_PENDING, self.STATUS_APPROVED, self.STATUS_REJECTED):
            return None
        devices = self.get_fleet_devices()
        entry = devices.get(key_hash)
        if not entry:
            return None
        entry["status"] = status
        if status == self.STATUS_APPROVED:
            entry["approved_at"] = datetime.now().astimezone().isoformat()
            entry["approved_by"] = str(actor or "")
        else:
            entry["approved_at"] = None
            entry["approved_by"] = None
        devices[key_hash] = entry
        self._write_fleet_devices(devices)
        logger.info("Device %s set to %s by %s", entry.get("hostname"), status, actor)
        return dict(entry)

    @synchronized
    def delete_device(self, key_hash: str) -> bool:
        devices = self.get_fleet_devices()
        if key_hash not in devices:
            return False
        del devices[key_hash]
        self._write_fleet_devices(devices)
        return True

    #
    # Fleet server endpoint (moving the server to another machine / IP)
    #

    @synchronized
    def get_fleet_endpoint_config(self):
        stored = self.data.get(self.FLEET_ENDPOINT_KEY)
        config = {"server_endpoint": "", "updated_at": "", "updated_by": ""}
        if isinstance(stored, dict):
            for key in config:
                config[key] = str(stored.get(key) or "")
        return config

    @synchronized
    def set_fleet_endpoint(self, server_endpoint: str, actor: str = ""):
        endpoint = str(server_endpoint or "").strip().rstrip("/")
        config = {
            "server_endpoint": endpoint,
            "updated_at": datetime.now().astimezone().isoformat() if endpoint else "",
            "updated_by": str(actor or "") if endpoint else "",
        }
        if endpoint:
            self.data[self.FLEET_ENDPOINT_KEY] = config
        elif self.FLEET_ENDPOINT_KEY in self.data:
            del self.data[self.FLEET_ENDPOINT_KEY]
        self.save()
        logger.info("Fleet server endpoint announced as %r by %s", endpoint, actor)
        return self.get_fleet_endpoint_config()

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

    def lookup_ldap_user_profile(self, username: str):
        normalized = self._normalize_lookup_username(username)
        profile = {
            "username": normalized,
            "raw_username": str(username or "").strip(),
            "display_name": "",
            "email": "",
            "source": "unknown",
        }

        cached_user = self.get_auth_user(normalized) or self.get_auth_user(username)
        if isinstance(cached_user, dict):
            profile.update(
                {
                    "display_name": str(cached_user.get("display_name") or ""),
                    "email": str(cached_user.get("email") or "").strip(),
                    "source": str(cached_user.get("source") or "cached"),
                }
            )

        config = self._ldap_config_for_auth()
        if not config:
            return profile

        connection = None
        try:
            connection = self._ldap_service_connection(config)
            search_result = self._ldap_search_user(connection, config, username)
            if not search_result:
                return profile
            _dn, attrs = search_result
            profile.update(
                {
                    "username": self._canonical_ldap_username(username, attrs),
                    "display_name": self._first_ldap_attr(attrs, "displayName"),
                    "email": self._first_ldap_attr(attrs, "mail"),
                    "source": "ldap",
                }
            )
        except Exception as error:
            logger.warning("LDAP profile lookup failed for %s: %s", username, error)
        finally:
            if connection is not None:
                connection.unbind()
        return profile

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

    @synchronized
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

    @synchronized
    def get_admin_ui_config(self):
        self._ensure_internal_defaults()
        config = self._normalize_admin_ui_config(
            self.data.get(self.ADMIN_UI_CONFIG_KEY)
        )
        if self.data.get(self.ADMIN_UI_CONFIG_KEY) != config:
            self.data[self.ADMIN_UI_CONFIG_KEY] = config
            self.save()
        return dict(config)

    @synchronized
    def set_admin_ui_config(self, value):
        config = self.get_admin_ui_config()
        if isinstance(value, dict):
            for key in self.DEFAULT_ADMIN_UI_CONFIG:
                if key in value:
                    config[key] = value[key]
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

    @synchronized
    def get_user_setting(self, username: str, key: str, default=None):
        if not key:
            return self.get_user_settings(username)
        settings = self.get_user_settings(username)
        return settings.get(key, default)

    @synchronized
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
