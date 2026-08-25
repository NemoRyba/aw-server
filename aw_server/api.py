import functools
import hashlib
import json
import logging
import shutil
import threading
import time
import zipfile
from collections import defaultdict
from hmac import compare_digest
from datetime import datetime, timedelta
from pathlib import Path
from socket import gethostname
from urllib.parse import urlparse
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
)
from uuid import uuid4

import iso8601
from aw_core.dirs import get_data_dir
from aw_core.log import get_log_file_path
from aw_core.models import Event
from aw_query import query2
from aw_transform import heartbeat_merge

from .__about__ import __version__
from .exceptions import NotFound
from .fleet import (
    build_user_detail_from_summary,
    calculate_user_summary_day,
    calculate_user_summary_totals,
    format_fleet_datetime,
    iter_fleet_day_ranges,
    merge_user_summary_chunks,
    parse_fleet_datetime,
    get_bucket_identity,
    group_buckets_by_device,
    group_buckets_by_user,
    normalize_fleet_range,
    run_report,
    summarize_device,
    summarize_device_metrics,
    summarize_devices,
    summarize_live_state,
    summarize_user,
    summarize_user_activity,
    summarize_users,
    wrap_fleet_event_cache,
)
from .fleet_sync import sync_batch, sync_handshake
from .fleet_sync_store import FleetSyncStore
from .fleet_summary_store import FleetSummaryStore
from .fleet_summary_store import _normalize_device_ids_key as normalize_device_ids_key
from .redmine import (
    RedmineReadOnlyError,
    RedmineReadOnlySource,
    describe_redmine_error,
    normalize_email,
    redmine_spent_on_range,
)
from .settings import Settings

logger = logging.getLogger(__name__)

FLEET_SUMMARY_PRECOMPUTE_CONFIG_KEY = "fleetSummaryPrecomputeConfig"
DEFAULT_FLEET_SUMMARY_PRECOMPUTE_CONFIG = {
    "auto_enabled": False,
    "start_of_day": "04:00",
}


def _normalize_time_of_day(value: Any, default: str = "04:00") -> str:
    text = str(value or default).strip()
    parts = text.split(":")
    if len(parts) < 2:
        return default
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except (TypeError, ValueError):
        return default
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return default
    return f"{hour:02d}:{minute:02d}"


def get_device_id() -> str:
    path = Path(get_data_dir("aw-server")) / "device_id"
    if path.exists():
        with open(path) as f:
            return f.read()
    else:
        uuid = str(uuid4())
        with open(path, "w") as f:
            f.write(uuid)
        return uuid


def check_bucket_exists(f):
    @functools.wraps(f)
    def g(self, bucket_id, *args, **kwargs):
        if bucket_id not in self.db.buckets():
            raise NotFound("NoSuchBucket", f"There's no bucket named {bucket_id}")
        return f(self, bucket_id, *args, **kwargs)

    return g


def _directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return total

    for child in path.rglob("*"):
        try:
            if child.is_file():
                total += child.stat().st_size
        except OSError:
            logger.warning("Unable to include path in storage size scan: %s", child)
    return total


class ServerAPI:
    def __init__(self, db, testing) -> None:
        self.db = db
        self.settings = Settings(testing)
        self.sync_store = FleetSyncStore(testing=testing)
        self.summary_store = FleetSummaryStore(testing=testing)
        # In-memory progress of running chunked user-summary computations,
        # keyed by (username, range, devices, flag). Read by the progress
        # endpoint so the UI can show "day X of Y" during long loads.
        self._user_summary_progress = {}
        self.testing = testing
        self.last_event = {}  # type: dict
        self._summary_precompute_lock = threading.Lock()
        self._summary_precompute_stop = threading.Event()
        self._summary_precompute_thread = None
        if not testing:
            self._start_summary_precompute_worker()

    def get_info(self) -> Dict[str, Any]:
        """Get server info"""
        payload = {
            "hostname": gethostname(),
            "version": __version__,
            "testing": self.testing,
            "device_id": get_device_id(),
        }
        return payload

    def get_buckets(self) -> Dict[str, Dict]:
        """Get dict {bucket_name: Bucket} of all buckets"""
        logger.debug("Received get request for buckets")
        buckets = self.db.buckets()
        for b in buckets:
            buckets[b]["event_count"] = self.db[b].get_eventcount()
            # TODO: Move this code to aw-core?
            last_events = self.db[b].get(limit=1)
            if len(last_events) > 0:
                last_event = last_events[0]
                last_updated = last_event.timestamp + last_event.duration
                buckets[b]["last_updated"] = last_updated.isoformat()
        return buckets

    @check_bucket_exists
    def get_bucket_metadata(self, bucket_id: str) -> Dict[str, Any]:
        """Get metadata about bucket."""
        bucket = self.db[bucket_id]
        return bucket.metadata()

    @check_bucket_exists
    def export_bucket(self, bucket_id: str) -> Dict[str, Any]:
        """Export a bucket to a dataformat consistent across versions, including all events in it."""
        bucket = self.get_bucket_metadata(bucket_id)
        bucket["events"] = self.get_events(bucket_id, limit=-1)
        # Scrub event IDs
        for event in bucket["events"]:
            del event["id"]
        return bucket

    def export_all(self) -> Dict[str, Any]:
        """Exports all buckets and their events to a format consistent across versions"""
        buckets = self.get_buckets()
        exported_buckets = {}
        for bid in buckets.keys():
            exported_buckets[bid] = self.export_bucket(bid)
        return exported_buckets

    def import_bucket(self, bucket_data: Any):
        bucket_id = bucket_data["id"]
        logger.info(f"Importing bucket {bucket_id}")

        # TODO: Check that bucket doesn't already exist
        self.db.create_bucket(
            bucket_id,
            type=bucket_data["type"],
            client=bucket_data["client"],
            hostname=bucket_data["hostname"],
            created=(
                bucket_data["created"]
                if isinstance(bucket_data["created"], datetime)
                else iso8601.parse_date(bucket_data["created"])
            ),
        )

        # scrub IDs from events
        # (otherwise causes weird bugs with no events seemingly imported when importing events exported from aw-server-rust, which contains IDs)
        for event in bucket_data["events"]:
            if "id" in event:
                del event["id"]

        self.create_events(
            bucket_id,
            [Event(**e) if isinstance(e, dict) else e for e in bucket_data["events"]],
        )

    def import_all(self, buckets: Dict[str, Any]):
        for bid, bucket in buckets.items():
            self.import_bucket(bucket)

    def create_bucket(
        self,
        bucket_id: str,
        event_type: str,
        client: str,
        hostname: str,
        created: Optional[datetime] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Create a bucket.

        If hostname is "!local", the hostname and device_id will be set from the server info.
        This is useful for watchers which are known/assumed to run locally but might not know their hostname (like aw-watcher-web).

        Returns True if successful, otherwise false if a bucket with the given ID already existed.
        """
        if created is None:
            created = datetime.now()
        if bucket_id in self.db.buckets():
            return False
        if hostname == "!local":
            info = self.get_info()
            if data is None:
                data = {}
            hostname = info["hostname"]
            data["device_id"] = info["device_id"]
        self.db.create_bucket(
            bucket_id,
            type=event_type,
            client=client,
            hostname=hostname,
            created=created,
            data=data,
        )
        return True

    @check_bucket_exists
    def update_bucket(
        self,
        bucket_id: str,
        event_type: Optional[str] = None,
        client: Optional[str] = None,
        hostname: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update bucket metadata"""
        self.db.update_bucket(
            bucket_id,
            type_id=event_type,
            client=client,
            hostname=hostname,
            data=data,
        )
        return None

    @check_bucket_exists
    def delete_bucket(self, bucket_id: str) -> None:
        """Delete a bucket"""
        self.db.delete_bucket(bucket_id)
        logger.debug(f"Deleted bucket '{bucket_id}'")
        return None

    @check_bucket_exists
    def get_event(
        self,
        bucket_id: str,
        event_id: int,
    ) -> Optional[Event]:
        """Get a single event from a bucket"""
        logger.debug(
            f"Received get request for event {event_id} in bucket '{bucket_id}'"
        )
        event = self.db[bucket_id].get_by_id(event_id)
        return event.to_json_dict() if event else None

    @check_bucket_exists
    def get_events(
        self,
        bucket_id: str,
        limit: int = -1,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> List[Event]:
        """Get events from a bucket"""
        logger.debug(f"Received get request for events in bucket '{bucket_id}'")
        if limit is None:  # Let limit = None also mean "no limit"
            limit = -1
        events = [
            event.to_json_dict() for event in self.db[bucket_id].get(limit, start, end)
        ]
        return events

    @check_bucket_exists
    def create_events(self, bucket_id: str, events: List[Event]) -> Optional[Event]:
        """Create events for a bucket. Can handle both single events and multiple ones.

        Returns the inserted event when a single event was inserted, otherwise None."""
        return self.db[bucket_id].insert(events)

    @check_bucket_exists
    def get_eventcount(
        self,
        bucket_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> int:
        """Get eventcount from a bucket"""
        logger.debug(f"Received get request for eventcount in bucket '{bucket_id}'")
        return self.db[bucket_id].get_eventcount(start, end)

    @check_bucket_exists
    def delete_event(self, bucket_id: str, event_id) -> bool:
        """Delete a single event from a bucket"""
        return self.db[bucket_id].delete(event_id)

    @check_bucket_exists
    def heartbeat(self, bucket_id: str, heartbeat: Event, pulsetime: float) -> Event:
        """
        Heartbeats are useful when implementing watchers that simply keep
        track of a state, how long it's in that state and when it changes.
        A single heartbeat always has a duration of zero.

        If the heartbeat was identical to the last (apart from timestamp), then the last event has its duration updated.
        If the heartbeat differed, then a new event is created.

        Such as:
         - Active application and window title
           - Example: aw-watcher-window
         - Currently open document/browser tab/playing song
           - Example: wakatime
           - Example: aw-watcher-web
           - Example: aw-watcher-spotify
         - Is the user active/inactive?
           Send an event on some interval indicating if the user is active or not.
           - Example: aw-watcher-afk

        Inspired by: https://wakatime.com/developers#heartbeats
        """
        logger.debug(
            "Received heartbeat in bucket '{}'\n\ttimestamp: {}, duration: {}, pulsetime: {}\n\tdata: {}".format(
                bucket_id,
                heartbeat.timestamp,
                heartbeat.duration,
                pulsetime,
                heartbeat.data,
            )
        )

        # The endtime here is set such that in the event that the heartbeat is older than an
        # existing event we should try to merge it with the last event before the heartbeat instead.
        # FIXME: This (the endtime=heartbeat.timestamp) gets rid of the "heartbeat was older than last event"
        #        warning and also causes a already existing "newer" event to be overwritten in the
        #        replace_last call below. This is problematic.
        # Solution: This could be solved if we were able to replace arbitrary events.
        #           That way we could double check that the event has been applied
        #           and if it hasn't we simply replace it with the updated counterpart.

        last_event = None
        if bucket_id not in self.last_event:
            last_events = self.db[bucket_id].get(limit=1)
            if len(last_events) > 0:
                last_event = last_events[0]
        else:
            last_event = self.last_event[bucket_id]

        if last_event:
            if last_event.data == heartbeat.data:
                merged = heartbeat_merge(last_event, heartbeat, pulsetime)
                if merged is not None:
                    # Heartbeat was merged into last_event
                    logger.debug(
                        "Received valid heartbeat, merging. (bucket: {})".format(
                            bucket_id
                        )
                    )
                    self.last_event[bucket_id] = merged
                    self.db[bucket_id].replace_last(merged)
                    return merged
                else:
                    logger.info(
                        "Received heartbeat after pulse window, inserting as new event. (bucket: {})".format(
                            bucket_id
                        )
                    )
            else:
                logger.debug(
                    "Received heartbeat with differing data, inserting as new event. (bucket: {})".format(
                        bucket_id
                    )
                )
        else:
            logger.info(
                "Received heartbeat, but bucket was previously empty, inserting as new event. (bucket: {})".format(
                    bucket_id
                )
            )

        self.db[bucket_id].insert(heartbeat)
        self.last_event[bucket_id] = heartbeat
        return heartbeat

    def query2(self, name, query, timeperiods, cache):
        result = []
        for timeperiod in timeperiods:
            period = timeperiod.split("/")[
                :2
            ]  # iso8601 timeperiods are separated by a slash
            starttime = iso8601.parse_date(period[0])
            endtime = iso8601.parse_date(period[1])
            query = "".join(query)
            result.append(query2.query(name, query, starttime, endtime, self.db))
        return result

    # TODO: Right now the log format on disk has to be JSON, this is hard to read by humans...
    def get_log(self):
        """Get the server log in json format"""
        payload = []
        with open(get_log_file_path()) as log_file:
            for line in log_file.readlines()[::-1]:
                payload.append(json.loads(line))
        return payload, 200

    def get_session_secret(self):
        return self.settings.get_session_secret()

    def get_auth_user(self, username):
        return self.settings.get_auth_user(username)

    def authenticate_user(self, username, password):
        return self.settings.authenticate_user(username, password)

    def list_auth_users(self):
        return self.settings.list_auth_users()

    def set_auth_user_admin(self, username, is_admin):
        return self.settings.set_auth_user_admin(username, is_admin)

    def set_auth_user_access(self, username, allowed_pages=None, landing_page=None):
        return self.settings.set_auth_user_access(
            username, allowed_pages=allowed_pages, landing_page=landing_page
        )

    def get_ldap_config(self):
        return self.settings.get_ldap_config()

    def set_ldap_config(self, value):
        return self.settings.set_ldap_config(value)

    def test_ldap_config(self, value=None, username="", password=""):
        return self.settings.test_ldap_config(
            value=value,
            username=username,
            password=password,
        )

    def get_admin_ui_config(self):
        return self.settings.get_admin_ui_config()

    def set_admin_ui_config(self, value):
        return self.settings.set_admin_ui_config(value)

    def get_setting(self, key, user=None):
        """Get a setting"""
        if user is not None:
            return self.settings.get_user_setting(user, key, None)
        return self.settings.get(key, None)

    def set_setting(self, key, value, user=None):
        """Set a setting"""
        if user is not None:
            self.settings.set_user_setting(user, key, value)
        else:
            self.settings[key] = value
        return value

    def get_redmine_config(self):
        return self.settings.get_redmine_config(include_secret=False)

    def set_redmine_config(self, value):
        return self.settings.set_redmine_config(value)

    # Watcher auto-update
    #
    # Two package locations exist: the package EMBEDDED into the server build
    # (read-only, staged by rebuild-server-setup.ps1) and a package UPLOADED at
    # runtime through the admin GUI (lives in the server data dir, survives
    # server reinstalls). An uploaded package always wins until it is removed,
    # so new watcher builds can be distributed without rebuilding the server.

    def _embedded_watcher_package_dir(self) -> Path:
        return Path(__file__).parent / "watcher_package"

    def _uploaded_watcher_package_dir(self) -> Path:
        return Path(get_data_dir("aw-server")) / "watcher_package_uploaded"

    def _read_watcher_package_info(self, package_dir: Path, source: str) -> Optional[dict]:
        try:
            with open(package_dir / "manifest.json", encoding="utf-8") as f:
                manifest = json.load(f)
        except FileNotFoundError:
            return None
        except Exception:
            logger.exception("Could not read watcher package manifest in %s", package_dir)
            return None

        version = str(manifest.get("version") or "").strip().lower()
        payload_file = package_dir / "payload.zip"
        installer_file = package_dir / "install-watchers.ps1"
        if not version or not payload_file.is_file() or not installer_file.is_file():
            return None
        return {
            "version": version,
            "sha256": str(manifest.get("sha256") or version).strip().lower(),
            "created": manifest.get("created"),
            "payload_bytes": payload_file.stat().st_size,
            "source": source,
        }

    def _active_watcher_package(self) -> Optional[dict]:
        uploaded = self._read_watcher_package_info(
            self._uploaded_watcher_package_dir(), "uploaded"
        )
        if uploaded:
            return uploaded
        return self._read_watcher_package_info(
            self._embedded_watcher_package_dir(), "embedded"
        )

    def get_watcher_update_manifest(self, hostname: Optional[str] = None) -> dict:
        config = self.settings.get_watcher_update_config()
        uploaded = self._read_watcher_package_info(
            self._uploaded_watcher_package_dir(), "uploaded"
        )
        embedded = self._read_watcher_package_info(
            self._embedded_watcher_package_dir(), "embedded"
        )
        active = uploaded or embedded
        payload = {
            "available": bool(active),
            "auto_update_enabled": bool(config.get("auto_update_enabled")),
            # Detail for the admin GUI; supervisors only read the top-level keys.
            "uploaded": uploaded,
            "embedded": embedded,
        }
        if active:
            payload.update(active)

        # A supervisor identifies itself with ?hostname=<COMPUTERNAME> so the
        # manifest it already polls every minute can also carry an admin's
        # "update now" request - no extra request, no server->device push.
        # Where the fleet should talk to the server from now on. Rides the
        # manifest the supervisor already polls, so moving the server to a new
        # machine/IP does not need a visit to every device - as long as it is
        # announced while the OLD server is still reachable.
        payload["server_endpoint"] = str(
            self.settings.get_fleet_endpoint_config().get("server_endpoint") or ""
        )

        payload["update_requested"] = False
        payload["request_id"] = ""
        if hostname:
            request = self.settings.get_watcher_update_request(hostname)
            if request:
                payload["update_requested"] = True
                payload["request_id"] = str(request.get("request_id") or "")
                payload["requested_version"] = str(
                    request.get("requested_version") or ""
                )
        return payload

    def get_watcher_update_file(self, name: str) -> Optional[Path]:
        if name not in {"payload.zip", "install-watchers.ps1", "manifest.json"}:
            return None
        active = self._active_watcher_package()
        if not active:
            return None
        base = (
            self._uploaded_watcher_package_dir()
            if active["source"] == "uploaded"
            else self._embedded_watcher_package_dir()
        )
        path = base / name
        return path if path.is_file() else None

    def upload_watcher_update_package(self, file_storage) -> dict:
        """Accepts the wrapper zip from build-setup.ps1 (payload.zip +
        install-watchers.ps1 [+ manifest.json]) or a bare watcher payload.zip.
        The version/sha256 are always recomputed server-side."""
        if file_storage is None:
            return {"ok": False, "error": "No file uploaded"}

        final_dir = self._uploaded_watcher_package_dir()
        data_dir = final_dir.parent
        data_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir = data_dir / f"watcher_package_uploaded.tmp-{uuid4().hex[:8]}"
        tmp_dir.mkdir(parents=True, exist_ok=True)

        try:
            upload_path = tmp_dir / "upload.zip"
            file_storage.save(str(upload_path))

            payload_path = tmp_dir / "payload.zip"
            installer_path = tmp_dir / "install-watchers.ps1"

            classification = None
            try:
                with zipfile.ZipFile(upload_path) as zf:
                    entries = [info for info in zf.infolist() if not info.is_dir()]
                    by_basename: Dict[str, Any] = {}
                    for info in entries:
                        base = (
                            info.filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
                        )
                        if base and base not in by_basename:
                            by_basename[base] = info
                    if "payload.zip" in by_basename:
                        classification = "wrapper"
                        with zf.open(by_basename["payload.zip"]) as src, open(
                            payload_path, "wb"
                        ) as dst:
                            shutil.copyfileobj(src, dst)
                        if "install-watchers.ps1" in by_basename:
                            with zf.open(
                                by_basename["install-watchers.ps1"]
                            ) as src, open(installer_path, "wb") as dst:
                                shutil.copyfileobj(src, dst)
                    elif "supervise-watchers.ps1" in by_basename or any(
                        info.filename.replace("\\", "/").lstrip("/").startswith(
                            "aw-watcher-"
                        )
                        for info in entries
                    ):
                        classification = "payload"
            except zipfile.BadZipFile:
                return {"ok": False, "error": "Uploaded file is not a valid zip"}

            if classification is None:
                return {
                    "ok": False,
                    "error": (
                        "Unrecognized zip: expected the watcher update zip "
                        "(ActivityWatch-Fleet-Watchers-Update.zip) or a watcher payload.zip"
                    ),
                }
            if classification == "payload":
                upload_path.replace(payload_path)

            try:
                with zipfile.ZipFile(payload_path) as pz:
                    payload_names = pz.namelist()
                if not any(
                    name.replace("\\", "/").lstrip("/").startswith("aw-watcher-")
                    for name in payload_names
                ):
                    return {
                        "ok": False,
                        "error": "payload.zip contains no aw-watcher-* folders",
                    }
            except zipfile.BadZipFile:
                return {
                    "ok": False,
                    "error": "payload.zip inside the upload is not a valid zip",
                }

            if not installer_path.is_file():
                fallback = None
                for candidate_dir in (
                    self._uploaded_watcher_package_dir(),
                    self._embedded_watcher_package_dir(),
                ):
                    candidate = candidate_dir / "install-watchers.ps1"
                    if candidate.is_file():
                        fallback = candidate
                        break
                if fallback is None:
                    return {
                        "ok": False,
                        "error": (
                            "install-watchers.ps1 missing: upload the full "
                            "ActivityWatch-Fleet-Watchers-Update.zip"
                        ),
                    }
                shutil.copyfile(fallback, installer_path)

            digest = hashlib.sha256()
            with open(payload_path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            version = digest.hexdigest().lower()

            manifest = {
                "version": version,
                "sha256": version,
                "created": datetime.now().astimezone().isoformat(),
                "source": "uploaded",
                "original_filename": str(
                    getattr(file_storage, "filename", "") or ""
                )[:200],
            }
            with open(tmp_dir / "manifest.json", "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

            if upload_path.exists():
                upload_path.unlink()

            # Swap into place; retry once in case a download briefly holds a
            # handle on the old package (Windows).
            for attempt in (1, 2):
                try:
                    if final_dir.exists():
                        shutil.rmtree(final_dir)
                    tmp_dir.rename(final_dir)
                    break
                except OSError:
                    if attempt == 2:
                        raise
                    time.sleep(2)

            logger.info("Watcher update package uploaded: version %s", version)
            return {"ok": True, "manifest": self.get_watcher_update_manifest()}
        except Exception as exc:
            logger.exception("Watcher update package upload failed")
            return {"ok": False, "error": f"Upload failed: {exc}"}
        finally:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

    def delete_uploaded_watcher_package(self) -> dict:
        final_dir = self._uploaded_watcher_package_dir()
        if final_dir.exists():
            try:
                shutil.rmtree(final_dir)
            except OSError as exc:
                logger.exception("Could not remove uploaded watcher package")
                return {
                    "ok": False,
                    "error": f"Could not remove uploaded package: {exc}",
                }
        logger.info("Uploaded watcher package removed")
        return {"ok": True, "manifest": self.get_watcher_update_manifest()}

    def record_watcher_update_status(self, data) -> dict:
        data = data if isinstance(data, dict) else {}
        hostname = str(data.get("hostname") or "").strip()
        if not hostname:
            return {"ok": False, "error": "hostname required"}
        version = str(data.get("version") or "").strip().lower()
        info = {
            "version": version,
            "updating": bool(data.get("updating")),
            "message": str(data.get("message") or "").strip()[:200],
            "reported_at": datetime.now().astimezone().isoformat(),
        }
        self.settings.record_watcher_update_status(hostname, info)
        self._reconcile_watcher_update_request(hostname, data, version)
        return {"ok": True}

    def _reconcile_watcher_update_request(self, hostname, data, version) -> None:
        """Close the loop on a manually requested update.

        Cleared when the device reports the requested version (the install
        landed), or when it reports being already up to date. Otherwise the
        request is marked acknowledged so the GUI can show that the device
        picked it up.
        """
        request = self.settings.get_watcher_update_request(hostname)
        if not request:
            return
        requested_version = str(request.get("requested_version") or "").strip().lower()
        message = str(data.get("message") or "").strip()

        if requested_version and version == requested_version and not data.get("updating"):
            self.settings.clear_watcher_update_request(hostname)
            return
        if message == "up_to_date" and not requested_version:
            self.settings.clear_watcher_update_request(hostname)
            return

        reported_request_id = str(data.get("request_id") or "").strip()
        if reported_request_id or data.get("updating"):
            self.settings.acknowledge_watcher_update_request(
                hostname, reported_request_id or request.get("request_id")
            )

    def get_fleet_auth_config(self) -> dict:
        config = self.settings.get_fleet_auth_config()
        # Devices that have proved they can authenticate: used by the GUI to
        # warn before enforcement is switched on.
        config["devices_total"], config["devices_reporting"] = (
            self._watcher_token_readiness()
        )
        return config

    def _watcher_token_readiness(self):
        statuses = self.settings.get_watcher_update_status()
        reporting = sum(1 for info in statuses.values() if info.get("version"))
        try:
            total = len(self.get_fleet_devices().get("devices", []))
        except Exception:
            total = reporting
        return max(total, reporting), reporting

    def set_fleet_auth_config(self, value) -> dict:
        self.settings.set_fleet_auth_config(value if isinstance(value, dict) else {})
        return self.get_fleet_auth_config()

    def reveal_fleet_token(self) -> dict:
        """Full token, for the admin to paste into the watcher installer."""
        return {"token": self.settings.get_fleet_token()}

    def is_watcher_token_required(self) -> bool:
        return self.settings.is_watcher_token_required()

    def get_fleet_token(self) -> str:
        return self.settings.get_fleet_token()

    def is_machine_credential_valid(self, token: str) -> bool:
        """A machine request is authenticated by either the shared fleet token
        or the per-device key of an APPROVED enrolled device."""
        if not token:
            return False
        shared = self.settings.get_fleet_token()
        if shared and compare_digest(token, shared):
            return True
        return self.settings.is_device_key_approved(token)

    #
    # Device enrollment
    #

    def enroll_device(self, data, address: str) -> dict:
        data = data if isinstance(data, dict) else {}
        device_key = str(data.get("device_key") or "").strip()
        if len(device_key) < 32:
            return {"ok": False, "error": "device_key missing or too short"}

        entry = self.settings.enroll_device(
            device_key,
            hostname=str(data.get("hostname") or "").strip(),
            address=address,
            details=data,
        )
        if entry is None:
            return {
                "ok": False,
                "error": "Enrollment refused (too many devices are already waiting for approval)",
            }
        return {"ok": True, "status": entry.get("status")}

    def get_device_enrollment_status(self, token: str) -> dict:
        """Lets a device ask 'am I approved yet?' using its own key."""
        entry = self.settings.get_device_by_key(token) if token else None
        if not entry:
            return {"enrolled": False, "status": "unknown"}
        return {
            "enrolled": True,
            "status": entry.get("status"),
            "hostname": entry.get("hostname"),
        }

    def list_enrolled_devices(self) -> dict:
        devices = self.settings.get_fleet_devices()
        rows = [
            {
                "id": key_hash,
                "hostname": entry.get("hostname"),
                "address": entry.get("address"),
                "status": entry.get("status"),
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "approved_at": entry.get("approved_at"),
                "approved_by": entry.get("approved_by"),
                # Short, non-reversible fingerprint so an admin can tell two
                # rows with the same hostname apart before approving.
                "fingerprint": str(key_hash)[:12],
            }
            for key_hash, entry in devices.items()
        ]
        rows.sort(
            key=lambda row: (
                row["status"] != Settings.STATUS_PENDING,
                str(row.get("hostname") or "").lower(),
            )
        )
        return {
            "devices": rows,
            "pending": sum(
                1 for row in rows if row["status"] == Settings.STATUS_PENDING
            ),
            "enforcement_enabled": self.settings.is_watcher_token_required(),
        }

    def set_device_enrollment(self, device_ids, status: str, actor: str = "") -> dict:
        updated = [
            entry
            for entry in (
                self.settings.set_device_status(device_id, status, actor)
                for device_id in (device_ids or [])
            )
            if entry
        ]
        if not updated:
            return {"ok": False, "error": "No matching devices"}
        return {"ok": True, "updated": len(updated)}

    def delete_enrolled_devices(self, device_ids) -> dict:
        removed = [
            device_id
            for device_id in (device_ids or [])
            if self.settings.delete_device(device_id)
        ]
        return {"ok": True, "removed": len(removed)}

    #
    # Fleet server endpoint
    #

    def get_fleet_endpoint(self) -> dict:
        config = self.settings.get_fleet_endpoint_config()
        config["current_request_host"] = ""
        return config

    def set_fleet_endpoint(self, data, actor: str = "") -> dict:
        data = data if isinstance(data, dict) else {}
        endpoint = str(data.get("server_endpoint") or "").strip().rstrip("/")

        if endpoint:
            parsed = urlparse(endpoint)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return {
                    "ok": False,
                    "error": "Enter a full address, e.g. http://192.168.0.200:5600",
                }
            # Refuse an address that is not actually serving an aw-server.
            # Announcing a dead endpoint would send every device somewhere
            # unreachable, and the only way back is walking the fleet.
            if not data.get("skip_check"):
                reachable, detail = self._probe_fleet_endpoint(endpoint)
                if not reachable:
                    return {
                        "ok": False,
                        "error": f"No ActivityWatch server answered at {endpoint} ({detail}). "
                        "Start the new server first, or tick 'announce anyway'.",
                    }

        config = self.settings.set_fleet_endpoint(endpoint, actor)
        return {"ok": True, "config": config}

    def _probe_fleet_endpoint(self, endpoint: str):
        try:
            import urllib.request

            with urllib.request.urlopen(
                f"{endpoint.rstrip('/')}/api/0/info", timeout=5
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if "hostname" in payload and "version" in payload:
                return True, str(payload.get("hostname"))
            return False, "unexpected response"
        except Exception as error:
            return False, str(error)

    def request_watcher_updates(self, hostnames, requested_by="") -> dict:
        """Queue an immediate watcher update for the given devices.

        The server cannot push, so this records a pending request that each
        device's supervisor picks up on its next manifest poll (<=60 s). It
        deliberately bypasses the auto-update switch and installs even when the
        reported version already matches, so the button also works as a repair.
        """
        manifest = self.get_watcher_update_manifest()
        if not manifest.get("available"):
            return {"ok": False, "error": "No watcher package available on the server"}

        ttl = int(
            self.settings.get_watcher_update_config().get(
                "manual_update_ttl_minutes", 360
            )
        )
        version = str(manifest.get("version") or "")
        requested = []
        for hostname in hostnames or []:
            entry = self.settings.request_watcher_update(
                hostname, version, requested_by, ttl
            )
            if entry:
                requested.append(entry)
        if not requested:
            return {"ok": False, "error": "No valid devices selected"}
        logger.info(
            "Manual watcher update requested by %s for %s device(s), target %s",
            requested_by or "admin",
            len(requested),
            version[:12],
        )
        return {"ok": True, "requested": requested, "version": version}

    def cancel_watcher_update_requests(self, hostnames) -> dict:
        cancelled = [
            hostname
            for hostname in hostnames or []
            if self.settings.clear_watcher_update_request(hostname)
        ]
        return {"ok": True, "cancelled": cancelled}

    def get_watcher_update_config(self) -> dict:
        return self.settings.get_watcher_update_config()

    def set_watcher_update_config(self, value) -> dict:
        return self.settings.set_watcher_update_config(
            value if isinstance(value, dict) else {}
        )

    def get_watcher_update_devices(self) -> dict:
        manifest = self.get_watcher_update_manifest()
        server_version = manifest.get("version") if manifest.get("available") else None
        statuses = self.settings.get_watcher_update_status()
        requests = self.settings.get_watcher_update_requests()

        def request_for(name):
            entry = requests.get(self.settings.watcher_request_key(name))
            if not entry:
                return {"update_requested": False}
            return {
                "update_requested": True,
                "requested_at": entry.get("requested_at"),
                "requested_by": entry.get("requested_by"),
                "request_acknowledged": bool(entry.get("acknowledged_at")),
                "request_expires_at": entry.get("expires_at"),
            }

        rows = []
        seen = set()
        for hostname, info in statuses.items():
            version = str(info.get("version") or "")
            row = {
                "hostname": hostname,
                "version": version,
                "reported_at": info.get("reported_at"),
                "updating": bool(info.get("updating")),
                "message": info.get("message") or "",
                "up_to_date": bool(server_version) and version == server_version,
            }
            row.update(request_for(hostname))
            rows.append(row)
            seen.add(hostname.strip().lower())

        # Fleet devices that never reported a watcher version run a supervisor
        # from before the auto-update feature: they need one manual update.
        try:
            for device in self.get_fleet_devices().get("devices", []):
                name = str(
                    device.get("device_name") or device.get("device_id") or ""
                ).strip()
                if not name or name.lower() in seen:
                    continue
                seen.add(name.lower())
                row = {
                    "hostname": name,
                    "version": "",
                    "reported_at": None,
                    "updating": False,
                    "message": "never_reported",
                    "up_to_date": False,
                }
                row.update(request_for(name))
                rows.append(row)
        except Exception:
            logger.exception("Could not merge fleet devices into watcher update list")

        rows.sort(key=lambda row: str(row["hostname"]).lower())
        return {"manifest": manifest, "devices": rows}

    def get_redmine_user_mappings(self):
        config = self.settings.get_redmine_config(include_secret=True)
        public_config = self.settings.get_redmine_config(include_secret=False)
        mappings = self.settings.get_redmine_user_mappings()
        users = self.get_fleet_users()["users"]
        payload = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "enabled": bool(config.get("enabled")),
            "users": [],
            "redmine_users": [],
            "config": {
                "driver": public_config.get("driver"),
                "host": public_config.get("host"),
                "database": public_config.get("database"),
            },
        }
        profiles = {
            user["username"]: self.settings.lookup_ldap_user_profile(user["username"])
            for user in users
        }

        if not config.get("enabled"):
            payload["message"] = "Redmine integration is disabled"
            payload["users"] = [
                self._redmine_mapping_payload(
                    username=user["username"],
                    profile=profiles[user["username"]],
                    mappings=mappings,
                )
                for user in users
            ]
            return payload

        try:
            redmine_users = RedmineReadOnlySource(config).active_users()
        except Exception as error:
            readable_error = describe_redmine_error(error, config)
            logger.warning("Redmine mapping lookup failed: %s", readable_error)
            payload["error"] = str(readable_error)
            payload["error_code"] = readable_error.code
            payload["error_detail"] = readable_error.detail
            payload["users"] = [
                self._redmine_mapping_payload(
                    username=user["username"],
                    profile=profiles[user["username"]],
                    mappings=mappings,
                )
                for user in users
            ]
            return payload

        redmine_users_by_email, redmine_users_by_id = self._redmine_user_indexes(
            redmine_users
        )
        payload["redmine_users"] = [
            self._redmine_public_user_payload(user) for user in redmine_users
        ]
        payload["users"] = [
            self._redmine_mapping_payload(
                username=user["username"],
                profile=profiles[user["username"]],
                mappings=mappings,
                redmine_users_by_email=redmine_users_by_email,
                redmine_users_by_id=redmine_users_by_id,
            )
            for user in users
        ]
        return payload

    def set_redmine_user_mapping(self, username, redmine_user_id=None):
        self.settings.set_redmine_user_mapping(username, redmine_user_id)
        return self.get_redmine_user_mappings()

    def test_redmine_config(self, value=None):
        config = self.settings._normalize_redmine_config(
            value or self.settings.get_redmine_config(include_secret=True),
            previous=self.settings.get_redmine_config(include_secret=True),
        )
        if not config.get("enabled"):
            return {"ok": False, "message": "Redmine integration is disabled"}
        try:
            users = RedmineReadOnlySource(config).active_users(limit=1)
            return {
                "ok": True,
                "message": "Redmine read-only query succeeded",
                "sample_users": len(users),
            }
        except Exception as error:
            logger.warning("Redmine read-only query test failed: %s", error)
            return {"ok": False, "message": str(error)}

    def get_fleet_redmine_comparison(self, start=None, end=None, usernames=None):
        start, end = normalize_fleet_range(start, end)
        selected_usernames = [
            str(username).strip()
            for username in (usernames or [])
            if str(username).strip()
        ]
        config = self.settings.get_redmine_config(include_secret=True)
        public_config = self.settings.get_redmine_config(include_secret=False)

        payload = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "enabled": bool(config.get("enabled")),
            "range": {
                "start": format_fleet_datetime(start),
                "end": format_fleet_datetime(end),
            },
            "spent_on_range": None,
            "users": [],
            "totals": {
                "redmine_hours": 0.0,
                "redmine_seconds": 0.0,
            },
            "config": {
                "driver": public_config.get("driver"),
                "host": public_config.get("host"),
                "database": public_config.get("database"),
            },
        }
        if not config.get("enabled"):
            payload["message"] = "Redmine integration is disabled"
            return payload
        if not selected_usernames:
            return payload

        spent_from, spent_to = redmine_spent_on_range(start, end)
        payload["spent_on_range"] = {
            "from": spent_from.isoformat(),
            "to": spent_to.isoformat(),
        }

        profiles = {
            username: self.settings.lookup_ldap_user_profile(username)
            for username in selected_usernames
        }

        try:
            source = RedmineReadOnlySource(config)
            redmine_users = source.active_users()
            redmine_users_by_email, redmine_users_by_id = self._redmine_user_indexes(
                redmine_users
            )
            mappings = self.settings.get_redmine_user_mappings()

            matched_by_username = {}
            match_by_username = {}
            for username, profile in profiles.items():
                match = self._redmine_match_for_profile(
                    username=username,
                    profile=profile,
                    mappings=mappings,
                    redmine_users_by_email=redmine_users_by_email,
                    redmine_users_by_id=redmine_users_by_id,
                )
                match_by_username[username] = match
                if match.get("matched"):
                    matched_by_username[username] = match["redmine_user"]

            project_rows = source.time_by_project(
                user_ids=[user["id"] for user in matched_by_username.values()],
                spent_from=spent_from,
                spent_to=spent_to,
            )
        except Exception as error:
            readable_error = describe_redmine_error(error, config)
            if isinstance(error, RedmineReadOnlyError):
                logger.warning("Redmine comparison failed: %s", readable_error)
            else:
                logger.exception("Redmine comparison failed: %s", readable_error)
            payload["error"] = str(readable_error)
            payload["error_code"] = readable_error.code
            payload["error_detail"] = readable_error.detail
            payload["users"] = [
                self._redmine_unmatched_user_payload(username, profiles[username])
                for username in selected_usernames
            ]
            return payload

        projects_by_user_id = defaultdict(list)
        hours_by_user_id = defaultdict(float)
        entry_count_by_user_id = defaultdict(int)
        for row in project_rows:
            user_id = int(row.get("user_id") or 0)
            hours = float(row.get("hours") or 0.0)
            entry_count = int(row.get("entry_count") or 0)
            hours_by_user_id[user_id] += hours
            entry_count_by_user_id[user_id] += entry_count
            projects_by_user_id[user_id].append(
                {
                    "project_id": row.get("project_id"),
                    "project_name": row.get("project_name") or "",
                    "hours": hours,
                    "seconds": hours * 3600.0,
                    "entry_count": entry_count,
                }
            )

        rows = []
        total_hours = 0.0
        for username in selected_usernames:
            profile = profiles[username]
            match = match_by_username.get(username, {})
            redmine_user = matched_by_username.get(username)
            if not redmine_user:
                rows.append(
                    self._redmine_unmatched_user_payload(
                        username, profile, match=match
                    )
                )
                continue

            user_id = int(redmine_user["id"])
            hours = float(hours_by_user_id.get(user_id, 0.0))
            total_hours += hours
            rows.append(
                {
                    "username": username,
                    "email": profile.get("email") or "",
                    "display_name": profile.get("display_name") or "",
                    "ldap_source": profile.get("source") or "",
                    "matched": True,
                    "status": "matched",
                    "match_source": match.get("match_source") or "unknown",
                    "match_reason": match.get("match_reason") or "",
                    "redmine_user_id": user_id,
                    "redmine_login": redmine_user.get("login") or "",
                    "redmine_name": " ".join(
                        part
                        for part in (
                            redmine_user.get("firstname"),
                            redmine_user.get("lastname"),
                        )
                        if part
                    ),
                    "redmine_hours": hours,
                    "redmine_seconds": hours * 3600.0,
                    "entry_count": int(entry_count_by_user_id.get(user_id, 0)),
                    "projects": projects_by_user_id.get(user_id, []),
                }
            )

        payload["users"] = rows
        payload["totals"] = {
            "redmine_hours": total_hours,
            "redmine_seconds": total_hours * 3600.0,
        }
        return payload

    def get_fleet_redmine_daily_comparison(
        self, start=None, end=None, usernames=None, force=False
    ):
        """Per fleet-day comparison: active session time (from the day-chunk
        cache) vs the Redmine bookings of that day, entry by entry (project,
        hours, comment) for every selected, mapped user."""
        start, end = normalize_fleet_range(start, end)
        selected_usernames = [
            str(username).strip()
            for username in (usernames or [])
            if str(username).strip()
        ]
        config = self.settings.get_redmine_config(include_secret=True)

        payload = {
            "generated_at": datetime.now().astimezone().isoformat(),
            "enabled": bool(config.get("enabled")),
            "range": {
                "start": format_fleet_datetime(start),
                "end": format_fleet_datetime(end),
            },
            "days": [],
        }
        if not config.get("enabled"):
            payload["message"] = "Redmine integration is disabled"
            return payload
        if not selected_usernames:
            return payload

        spent_from, spent_to = redmine_spent_on_range(start, end)
        profiles = {
            username: self.settings.lookup_ldap_user_profile(username)
            for username in selected_usernames
        }

        try:
            source = RedmineReadOnlySource(config)
            redmine_users = source.active_users()
            redmine_users_by_email, redmine_users_by_id = self._redmine_user_indexes(
                redmine_users
            )
            mappings = self.settings.get_redmine_user_mappings()

            matched_by_username = {}
            for username, profile in profiles.items():
                match = self._redmine_match_for_profile(
                    username=username,
                    profile=profile,
                    mappings=mappings,
                    redmine_users_by_email=redmine_users_by_email,
                    redmine_users_by_id=redmine_users_by_id,
                )
                if match.get("matched"):
                    matched_by_username[username] = match["redmine_user"]

            entry_rows = source.daily_time_entries(
                user_ids=[user["id"] for user in matched_by_username.values()],
                spent_from=spent_from,
                spent_to=spent_to,
            )
        except Exception as error:
            readable_error = describe_redmine_error(error, config)
            if isinstance(error, RedmineReadOnlyError):
                logger.warning("Redmine daily comparison failed: %s", readable_error)
            else:
                logger.exception("Redmine daily comparison failed: %s", readable_error)
            payload["error"] = str(readable_error)
            payload["error_code"] = readable_error.code
            payload["error_detail"] = readable_error.detail
            return payload

        username_by_user_id = {
            int(user["id"]): username for username, user in matched_by_username.items()
        }
        entries_by_day_user = defaultdict(list)
        for row in entry_rows:
            username = username_by_user_id.get(int(row.get("user_id") or 0))
            if not username:
                continue
            entries_by_day_user[(str(row.get("spent_on") or ""), username)].append(
                {
                    "project_id": row.get("project_id"),
                    "project_name": row.get("project_name") or "",
                    "hours": float(row.get("hours") or 0.0),
                    "seconds": float(row.get("hours") or 0.0) * 3600.0,
                    "comments": row.get("comments") or "",
                }
            )

        # Per-user, per-fleet-day active seconds straight from the chunk cache.
        precompute_config = self._normalize_fleet_summary_precompute_config(
            self.settings.get(FLEET_SUMMARY_PRECOMPUTE_CONFIG_KEY, None)
        )
        day_ranges = iter_fleet_day_ranges(
            start, end, precompute_config["start_of_day"]
        )

        days = []
        for chunk_start, chunk_end in day_ranges:
            day_key = chunk_start.astimezone().date().isoformat()
            user_rows = []
            day_active_total = 0.0
            day_redmine_total = 0.0
            for username in selected_usernames:
                try:
                    summary = self.get_fleet_user_summary_value(
                        username,
                        start=chunk_start,
                        end=chunk_end,
                        exclude_inactive_session_afk=True,
                        force=force,
                    )
                    active_seconds = float(
                        (summary.get("totals") or {}).get("active_seconds") or 0.0
                    )
                except Exception:
                    logger.exception(
                        "Unable to load daily totals for user %s on %s",
                        username,
                        day_key,
                    )
                    active_seconds = 0.0

                matched = username in matched_by_username
                entries = entries_by_day_user.get((day_key, username), [])
                redmine_seconds = sum(entry["seconds"] for entry in entries)
                if active_seconds < 1 and not entries:
                    continue

                day_active_total += active_seconds
                day_redmine_total += redmine_seconds
                user_rows.append(
                    {
                        "username": username,
                        "matched": matched,
                        "active_seconds": active_seconds,
                        "redmine_seconds": redmine_seconds if matched else None,
                        "redmine_hours": (
                            redmine_seconds / 3600.0 if matched else None
                        ),
                        "delta_seconds": (
                            active_seconds - redmine_seconds if matched else None
                        ),
                        "entries": entries,
                    }
                )

            if user_rows:
                days.append(
                    {
                        "date": day_key,
                        "range": {
                            "start": format_fleet_datetime(chunk_start),
                            "end": format_fleet_datetime(chunk_end),
                        },
                        "totals": {
                            "active_seconds": day_active_total,
                            "redmine_seconds": day_redmine_total,
                        },
                        "users": user_rows,
                    }
                )

        # Most recent day first.
        days.sort(key=lambda day: day["date"], reverse=True)
        payload["days"] = days
        return payload

    def _redmine_user_indexes(self, redmine_users):
        users_by_email = {}
        users_by_id = {}
        for user in redmine_users:
            user_id = int(user.get("id") or 0)
            if user_id > 0:
                users_by_id[user_id] = user
            email = normalize_email(user.get("mail"))
            if email and email not in users_by_email:
                users_by_email[email] = user
        return users_by_email, users_by_id

    def _redmine_public_user_payload(self, user):
        return {
            "id": int(user.get("id") or 0),
            "login": str(user.get("login") or ""),
            "firstname": str(user.get("firstname") or ""),
            "lastname": str(user.get("lastname") or ""),
            "mail": normalize_email(user.get("mail")),
            "name": self._redmine_user_name(user),
        }

    def _redmine_user_name(self, user):
        return " ".join(
            part
            for part in (
                str(user.get("firstname") or "").strip(),
                str(user.get("lastname") or "").strip(),
            )
            if part
        )

    def _redmine_match_for_profile(
        self,
        *,
        username,
        profile,
        mappings,
        redmine_users_by_email,
        redmine_users_by_id,
    ):
        normalized_username = self.settings._normalize_lookup_username(username)
        override_user_id = int(mappings.get(normalized_username) or 0)
        if override_user_id:
            redmine_user = redmine_users_by_id.get(override_user_id)
            if redmine_user:
                return {
                    "matched": True,
                    "status": "matched",
                    "match_source": "manual",
                    "match_reason": "Manual Redmine user override from settings.",
                    "redmine_user": redmine_user,
                    "override_redmine_user_id": override_user_id,
                    "automatic_redmine_user": None,
                }
            return {
                "matched": False,
                "status": "manual_missing",
                "match_source": "manual",
                "match_reason": (
                    f"Manual override points to Redmine user ID {override_user_id}, "
                    "but that active Redmine user was not found."
                ),
                "redmine_user": None,
                "override_redmine_user_id": override_user_id,
                "automatic_redmine_user": None,
            }

        email = normalize_email(profile.get("email"))
        if not email:
            return {
                "matched": False,
                "status": "missing_email",
                "match_source": "none",
                "match_reason": "No LDAP email address was found for this Windows user.",
                "redmine_user": None,
                "override_redmine_user_id": None,
                "automatic_redmine_user": None,
            }

        redmine_user = redmine_users_by_email.get(email)
        if redmine_user:
            return {
                "matched": True,
                "status": "matched",
                "match_source": "email",
                "match_reason": f"Matched automatically by email address {email}.",
                "redmine_user": redmine_user,
                "override_redmine_user_id": None,
                "automatic_redmine_user": redmine_user,
            }

        return {
            "matched": False,
            "status": "no_redmine_user",
            "match_source": "none",
            "match_reason": (
                f"No active Redmine user was found with email address {email}."
            ),
            "redmine_user": None,
            "override_redmine_user_id": None,
            "automatic_redmine_user": None,
        }

    def _redmine_mapping_payload(
        self,
        *,
        username,
        profile,
        mappings,
        redmine_users_by_email=None,
        redmine_users_by_id=None,
    ):
        redmine_users_by_email = redmine_users_by_email or {}
        redmine_users_by_id = redmine_users_by_id or {}
        match = self._redmine_match_for_profile(
            username=username,
            profile=profile,
            mappings=mappings,
            redmine_users_by_email=redmine_users_by_email,
            redmine_users_by_id=redmine_users_by_id,
        )
        automatic_user = match.get("automatic_redmine_user")
        effective_user = match.get("redmine_user")
        return {
            "username": username,
            "email": profile.get("email") or "",
            "display_name": profile.get("display_name") or "",
            "ldap_source": profile.get("source") or "",
            "status": match.get("status") or "not_loaded",
            "match_source": match.get("match_source") or "none",
            "match_reason": match.get("match_reason") or "",
            "override_redmine_user_id": match.get("override_redmine_user_id"),
            "automatic_redmine_user": (
                self._redmine_public_user_payload(automatic_user)
                if automatic_user
                else None
            ),
            "redmine_user": (
                self._redmine_public_user_payload(effective_user)
                if effective_user
                else None
            ),
        }

    def _redmine_unmatched_user_payload(self, username, profile, match=None):
        match = match or {}
        status = match.get("status") or "missing_email"
        if not match and profile.get("email"):
            status = "no_redmine_user"
        return {
            "username": username,
            "email": profile.get("email") or "",
            "display_name": profile.get("display_name") or "",
            "ldap_source": profile.get("source") or "",
            "matched": False,
            "status": status,
            "match_source": match.get("match_source") or "none",
            "match_reason": match.get("match_reason") or "",
            "redmine_user_id": None,
            "redmine_login": "",
            "redmine_name": "",
            "redmine_hours": None,
            "redmine_seconds": None,
            "entry_count": 0,
            "projects": [],
        }

    def _normalize_fleet_summary_precompute_config(self, value=None):
        config = dict(DEFAULT_FLEET_SUMMARY_PRECOMPUTE_CONFIG)
        if isinstance(value, dict):
            config["auto_enabled"] = bool(value.get("auto_enabled", False))
            config["start_of_day"] = _normalize_time_of_day(
                value.get("start_of_day") or value.get("startOfDay"),
                config["start_of_day"],
            )
        return config

    def get_fleet_summary_precompute_config(self):
        config = self._normalize_fleet_summary_precompute_config(
            self.settings.get(FLEET_SUMMARY_PRECOMPUTE_CONFIG_KEY, None)
        )
        return {
            **config,
            "runs": self.summary_store.latest_precompute_runs(limit=10),
        }

    def set_fleet_summary_precompute_config(self, value):
        config = self._normalize_fleet_summary_precompute_config(value)
        self.settings[FLEET_SUMMARY_PRECOMPUTE_CONFIG_KEY] = config
        return self.get_fleet_summary_precompute_config()

    def _start_summary_precompute_worker(self):
        self._summary_precompute_thread = threading.Thread(
            target=self._summary_precompute_loop,
            name="fleet-summary-precompute",
            daemon=True,
        )
        self._summary_precompute_thread.start()

    def _summary_precompute_loop(self):
        while not self._summary_precompute_stop.wait(60):
            try:
                self.maybe_auto_precompute_fleet_summary()
            except Exception:
                logger.exception("Fleet summary auto precompute failed")

    def _previous_summary_period(self, start_of_day: str):
        from .fleet import local_fleet_day_boundary, parse_start_of_day

        hour, minute = parse_start_of_day(start_of_day)
        now = datetime.now().astimezone()
        anchor = now.date()
        boundary = local_fleet_day_boundary(anchor, hour, minute)
        if now < boundary:
            anchor = anchor - timedelta(days=1)
            boundary = local_fleet_day_boundary(anchor, hour, minute)
        previous = local_fleet_day_boundary(anchor - timedelta(days=1), hour, minute)
        return previous, boundary

    def maybe_auto_precompute_fleet_summary(self):
        config = self.get_fleet_summary_precompute_config()
        if not config["auto_enabled"]:
            return None

        start, end = self._previous_summary_period(config["start_of_day"])
        start, end = normalize_fleet_range(start, end)
        range_start = format_fleet_datetime(start)
        range_end = format_fleet_datetime(end)
        run_key = f"auto:{range_start}:{range_end}:{config['start_of_day']}"
        previous_run = self.summary_store.get_precompute_run(run_key)
        if previous_run and previous_run.get("status") == "completed":
            return previous_run

        return self.precompute_fleet_user_summaries(
            start=start,
            end=end,
            force=False,
            source="auto",
            run_key=run_key,
            start_of_day=config["start_of_day"],
        )

    def invalidate_fleet_user_summaries(self, start, end, username=None):
        """Invalidate cached summaries overlapping [start, end) after a manual
        event edit/creation/deletion, so affected days recompute on demand."""
        if start is None or end is None:
            return 0
        if end <= start:
            end = start
        return self.summary_store.delete_user_summaries_in_range(
            range_start=format_fleet_datetime(start),
            range_end=format_fleet_datetime(end),
            username=username,
        )

    @staticmethod
    def _user_summary_progress_key(
        username, range_start, range_end, device_ids, exclude_inactive_session_afk
    ):
        return "|".join(
            [
                str(username),
                str(range_start),
                str(range_end),
                normalize_device_ids_key(device_ids),
                "1" if exclude_inactive_session_afk else "0",
            ]
        )

    def get_fleet_user_summary_progress(
        self,
        username,
        start=None,
        end=None,
        device_ids=None,
        exclude_inactive_session_afk=True,
    ):
        start, end = normalize_fleet_range(start, end)
        key = self._user_summary_progress_key(
            username,
            format_fleet_datetime(start),
            format_fleet_datetime(end),
            device_ids,
            exclude_inactive_session_afk,
        )
        record = self._user_summary_progress.get(key)
        if not record:
            return {"active": False}
        return {"active": not record.get("finished", False), **record}

    @staticmethod
    def _fleet_day_row_valid(row, chunk_end) -> bool:
        """A cached day row is trustworthy only if it was calculated AFTER the
        day ended; otherwise it is a partial snapshot and must be recomputed."""
        calculated_at = parse_fleet_datetime(
            (row.get("summary_cache") or {}).get("calculated_at")
        )
        if calculated_at is None:
            return False
        return calculated_at >= chunk_end

    def get_fleet_user_summary_value(
        self,
        username,
        start=None,
        end=None,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk=True,
        force=False,
        source="on_demand",
        events_api=None,
    ):
        """Chunked, cache-backed user summary.

        The range is split into fleet days (local start_of_day boundaries).
        Complete days are served from the summary store and persisted after
        computation (totals + apps + devices), so a multi-month range costs a
        handful of SQLite lookups plus computation of only the days that are
        missing — which the nightly precompute keeps filled. The current,
        still-running day is always computed live and never persisted.
        """
        start, end = normalize_fleet_range(start, end)
        # Read start_of_day without get_fleet_summary_precompute_config(),
        # which also queries the run history — this path runs once per user
        # on the summary page and should stay lookup-cheap.
        config = self._normalize_fleet_summary_precompute_config(
            self.settings.get(FLEET_SUMMARY_PRECOMPUTE_CONFIG_KEY, None)
        )
        chunks = iter_fleet_day_ranges(start, end, config["start_of_day"])
        now = datetime.now().astimezone()

        progress_key = self._user_summary_progress_key(
            username,
            format_fleet_datetime(start),
            format_fleet_datetime(end),
            device_ids,
            exclude_inactive_session_afk,
        )
        # Sweep finished entries so the registry stays small.
        if len(self._user_summary_progress) > 100:
            cutoff = datetime.now().astimezone() - timedelta(hours=1)

            def _keep_progress(value):
                if value.get("finished"):
                    return False
                try:
                    started = datetime.fromisoformat(str(value.get("started_at")))
                except (TypeError, ValueError):
                    return False
                return started >= cutoff

            self._user_summary_progress = {
                key: value
                for key, value in self._user_summary_progress.items()
                if _keep_progress(value)
            }
        progress = {
            "total_days": len(chunks),
            "days_done": 0,
            "days_computed": 0,
            "current_day": None,
            "started_at": datetime.now().astimezone().isoformat(),
            "finished": False,
        }
        self._user_summary_progress[progress_key] = progress

        chunk_summaries = []
        all_cached = bool(chunks) and not force
        for chunk_start, chunk_end in chunks:
            progress["current_day"] = chunk_start.astimezone().date().isoformat()
            chunk_range_start = format_fleet_datetime(chunk_start)
            chunk_range_end = format_fleet_datetime(chunk_end)
            complete = chunk_end <= now

            row = None
            if not force and complete:
                row = self.summary_store.get_user_summary(
                    username=username,
                    range_start=chunk_range_start,
                    range_end=chunk_range_end,
                    device_ids=device_ids,
                    exclude_inactive_session_afk=exclude_inactive_session_afk,
                )
                if row is not None and (
                    row.get("apps") is None
                    or not row.get("available_devices")
                    or not self._fleet_day_row_valid(row, chunk_end)
                ):
                    row = None

            if row is None:
                # Fresh event cache per day keeps memory bounded on long ranges.
                day = calculate_user_summary_day(
                    self,
                    username,
                    chunk_start,
                    chunk_end,
                    device_ids=device_ids,
                    exclude_inactive_session_afk=exclude_inactive_session_afk,
                )
                all_cached = False
                if complete:
                    row = self.summary_store.upsert_user_summary(
                        username=username,
                        range_start=chunk_range_start,
                        range_end=chunk_range_end,
                        device_ids=device_ids,
                        exclude_inactive_session_afk=exclude_inactive_session_afk,
                        selected_devices=day["selected_devices"],
                        totals=day["totals"],
                        source=source,
                        apps=day["apps"],
                        available_devices=day["available_devices"],
                    )
                else:
                    row = day
                progress["days_computed"] += 1
            chunk_summaries.append(row)
            progress["days_done"] += 1

        progress["finished"] = True
        merged = merge_user_summary_chunks(
            username,
            start,
            end,
            exclude_inactive_session_afk,
            chunk_summaries,
        )
        merged["summary_cache"] = {
            "cached": all_cached,
            "calculated_at": datetime.now().astimezone().isoformat(),
            "source": source,
        }
        return merged

    def recalculate_fleet_user_summary(
        self,
        username,
        start=None,
        end=None,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk=True,
    ):
        # Force a full recompute (totals AND the per-app report) so the cached
        # detail stays coherent; returns the fresh detail payload.
        return self.get_fleet_user(
            username,
            start=start,
            end=end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
            force=True,
        )

    def get_fleet_summary(
        self,
        start=None,
        end=None,
        exclude_inactive_session_afk=True,
        usernames: Optional[Iterable[str]] = None,
    ):
        start, end = normalize_fleet_range(start, end)
        users = self.get_fleet_users()["users"]
        if usernames is not None:
            users_by_username = {
                str(user.get("username") or "").lower(): user for user in users
            }
            selected_users = []
            seen = set()
            for username in usernames:
                normalized = str(username or "").strip().lower()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                user = users_by_username.get(normalized)
                if user:
                    selected_users.append(user)
            users = selected_users

        rows = []
        for user in users:
            summary = self.get_fleet_user_summary_value(
                user["username"],
                start=start,
                end=end,
                exclude_inactive_session_afk=exclude_inactive_session_afk,
            )
            rows.append(
                {
                    **user,
                    "totals": summary["totals"],
                    "summary_cache": summary["summary_cache"],
                    "selected_devices": summary["selected_devices"],
                }
            )

        return {
            "generated_at": datetime.now().astimezone().isoformat(),
            "range": {
                "start": format_fleet_datetime(start),
                "end": format_fleet_datetime(end),
            },
            "filters": {
                "exclude_inactive_session_afk": exclude_inactive_session_afk,
            },
            "users": rows,
        }

    def precompute_fleet_user_summaries(
        self,
        start=None,
        end=None,
        usernames: Optional[Iterable[str]] = None,
        force=True,
        source="manual",
        run_key=None,
        start_of_day=None,
    ):
        if not self._summary_precompute_lock.acquire(blocking=False):
            return {
                "status": "busy",
                "message": "A fleet summary precompute is already running.",
                "runs": self.summary_store.latest_precompute_runs(limit=10),
            }

        try:
            start, end = normalize_fleet_range(start, end)
            range_start = format_fleet_datetime(start)
            range_end = format_fleet_datetime(end)
            config = self.get_fleet_summary_precompute_config()
            start_of_day = _normalize_time_of_day(
                start_of_day or config["start_of_day"],
                config["start_of_day"],
            )
            user_rows = self.get_fleet_users()["users"]
            if usernames is None:
                selected_usernames = [row["username"] for row in user_rows]
            else:
                selected_usernames = sorted(
                    {
                        str(username).strip()
                        for username in usernames
                        if str(username).strip()
                    }
                )
            run_key = run_key or f"{source}:{range_start}:{range_end}:{uuid4()}"
            self.summary_store.start_precompute_run(
                run_key=run_key,
                range_start=range_start,
                range_end=range_end,
                start_of_day=start_of_day,
                source=source,
                users_total=len(selected_usernames),
            )

            errors = []
            users_done = 0
            for username in selected_usernames:
                try:
                    self.get_fleet_user_summary_value(
                        username,
                        start=start,
                        end=end,
                        exclude_inactive_session_afk=True,
                        force=force,
                        source=source,
                    )
                except Exception as exc:
                    logger.exception(
                        "Unable to precompute fleet summary for user %s", username
                    )
                    errors.append(f"{username}: {exc}")
                users_done += 1
                self.summary_store.update_precompute_progress(run_key, users_done)

            status = "completed" if not errors else "completed_with_errors"
            message = "; ".join(errors[:5])
            run = self.summary_store.finish_precompute_run(
                run_key=run_key,
                status=status,
                message=message,
            )
            return {
                "status": status,
                "run": run,
                "users_total": len(selected_usernames),
                "users_done": users_done,
                "errors": errors,
                "runs": self.summary_store.latest_precompute_runs(limit=10),
            }
        finally:
            self._summary_precompute_lock.release()

    def get_bucket_identity(self, bucket):
        return get_bucket_identity(bucket)

    def group_buckets_by_user(self):
        return group_buckets_by_user(self)

    def group_buckets_by_device(self):
        return group_buckets_by_device(self)

    def get_live_fleet_summary(self):
        return summarize_live_state(self)

    def get_fleet_storage(self):
        data_dir = Path(get_data_dir("aw-server"))
        data_dir.mkdir(parents=True, exist_ok=True)
        disk_usage = shutil.disk_usage(data_dir)

        return {
            "generated_at": datetime.now().astimezone().isoformat(),
            "data_dir": str(data_dir),
            "data_size_bytes": _directory_size(data_dir),
            "disk_total_bytes": disk_usage.total,
            "disk_used_bytes": disk_usage.used,
            "disk_free_bytes": disk_usage.free,
        }

    def get_fleet_users(self):
        return summarize_users(self)

    def get_fleet_user(
        self,
        username,
        start=None,
        end=None,
        device_ids=None,
        exclude_inactive_session_afk=False,
        force=False,
    ):
        # Chunked summary: complete days come from (and are persisted to) the
        # summary store; only missing days and the current day are computed.
        summary = self.get_fleet_user_summary_value(
            username,
            start=start,
            end=end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
            force=force,
            source="manual" if force else "on_demand",
        )
        detail = build_user_detail_from_summary(self, username, summary)
        detail["totals"] = summary["totals"]
        detail["summary_cache"] = summary["summary_cache"]
        return detail

    def get_fleet_user_activity(
        self,
        username,
        start=None,
        end=None,
        device_ids=None,
        include_afk_time=False,
        exclude_inactive_session_afk=False,
        max_rows_per_bin=120,
    ):
        return summarize_user_activity(
            self,
            username,
            start=start,
            end=end,
            device_ids=device_ids,
            include_afk_time=include_afk_time,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
            max_rows_per_bin=max_rows_per_bin,
        )

    def get_fleet_devices(self):
        return summarize_devices(self)

    def get_fleet_device_metrics(
        self, start=None, end=None, device_ids=None, max_points=180
    ):
        return summarize_device_metrics(
            self,
            start=start,
            end=end,
            device_ids=device_ids,
            max_points=max_points,
        )

    def get_fleet_device(
        self, device_id, start=None, end=None, exclude_inactive_session_afk=False
    ):
        return summarize_device(
            self,
            device_id,
            start,
            end,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )

    def run_fleet_report(self, report_spec):
        return run_report(self, report_spec)

    def fleet_sync_handshake(self, payload):
        return sync_handshake(self, payload)

    def fleet_sync_batch(self, payload):
        return sync_batch(self, payload)
