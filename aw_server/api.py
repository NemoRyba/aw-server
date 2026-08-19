import functools
import json
import logging
import shutil
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from socket import gethostname
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
    calculate_user_summary_totals,
    format_fleet_datetime,
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
    summarize_users,
)
from .fleet_sync import sync_batch, sync_handshake
from .fleet_sync_store import FleetSyncStore
from .fleet_summary_store import FleetSummaryStore
from .redmine import (
    RedmineReadOnlyError,
    RedmineReadOnlySource,
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
            redmine_users_by_email = {
                normalize_email(user.get("mail")): user
                for user in redmine_users
                if normalize_email(user.get("mail"))
            }

            matched_by_username = {}
            for username, profile in profiles.items():
                redmine_user = redmine_users_by_email.get(
                    normalize_email(profile.get("email"))
                )
                if redmine_user:
                    matched_by_username[username] = redmine_user

            project_rows = source.time_by_project(
                user_ids=[user["id"] for user in matched_by_username.values()],
                spent_from=spent_from,
                spent_to=spent_to,
            )
        except (RedmineReadOnlyError, RuntimeError) as error:
            payload["error"] = str(error)
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
            redmine_user = matched_by_username.get(username)
            if not redmine_user:
                rows.append(self._redmine_unmatched_user_payload(username, profile))
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

    def _redmine_unmatched_user_payload(self, username, profile):
        status = "missing_email"
        if profile.get("email"):
            status = "no_redmine_user"
        return {
            "username": username,
            "email": profile.get("email") or "",
            "display_name": profile.get("display_name") or "",
            "ldap_source": profile.get("source") or "",
            "matched": False,
            "status": status,
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
        hour, minute = [int(part) for part in start_of_day.split(":", 1)]
        now = datetime.now().astimezone()
        boundary = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if now < boundary:
            boundary -= timedelta(days=1)
        return boundary - timedelta(days=1), boundary

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

    def get_fleet_user_summary_value(
        self,
        username,
        start=None,
        end=None,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk=True,
        force=False,
        source="on_demand",
    ):
        start, end = normalize_fleet_range(start, end)
        range_start = format_fleet_datetime(start)
        range_end = format_fleet_datetime(end)
        cached = None
        if not force:
            cached = self.summary_store.get_user_summary(
                username=username,
                range_start=range_start,
                range_end=range_end,
                device_ids=device_ids,
                exclude_inactive_session_afk=exclude_inactive_session_afk,
            )
        if cached:
            return cached

        summary = calculate_user_summary_totals(
            self,
            username,
            start,
            end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )
        return self.summary_store.upsert_user_summary(
            username=username,
            range_start=summary["range"]["start"],
            range_end=summary["range"]["end"],
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
            selected_devices=summary["selected_devices"],
            totals=summary["totals"],
            source=source,
        )

    def recalculate_fleet_user_summary(
        self,
        username,
        start=None,
        end=None,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk=True,
    ):
        return self.get_fleet_user_summary_value(
            username,
            start=start,
            end=end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
            force=True,
            source="manual",
        )

    def get_fleet_summary(
        self,
        start=None,
        end=None,
        exclude_inactive_session_afk=True,
    ):
        start, end = normalize_fleet_range(start, end)
        users = self.get_fleet_users()["users"]
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
    ):
        summary = self.get_fleet_user_summary_value(
            username,
            start=start,
            end=end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )
        detail = summarize_user(
            self,
            username,
            start,
            end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )
        detail["totals"] = summary["totals"]
        detail["summary_cache"] = summary["summary_cache"]
        return detail

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
