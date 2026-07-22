import json
import traceback
from functools import wraps
from threading import Lock
from typing import Dict

import iso8601
from aw_core import schema
from aw_core.models import Event
from aw_query.exceptions import QueryException
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    request,
    session,
)
from flask_restx import Api, Resource, fields

from . import logger
from .api import ServerAPI
from .exceptions import BadRequest, Unauthorized
from .fleet_sync import FleetSyncConflict


def host_header_check(f):
    """
    Protects against DNS rebinding attacks (see https://github.com/ActivityWatch/activitywatch/security/advisories/GHSA-v9fg-6g9j-h4x4)

    Some discussion in Syncthing how they do it: https://github.com/syncthing/syncthing/issues/4819
    """

    @wraps(f)
    def decorator(*args, **kwargs):
        server_host = current_app.config["HOST"]
        req_host = request.headers.get("host", None)
        if server_host == "0.0.0.0":
            logger.warning(
                "Server is listening on 0.0.0.0, host header check is disabled (potential security issue)."
            )
        elif req_host is None:
            return {"message": "host header is missing"}, 400
        else:
            if req_host.split(":")[0] not in ["localhost", "127.0.0.1", server_host]:
                return {"message": f"host header is invalid (was {req_host})"}, 400
        return f(*args, **kwargs)

    return decorator


blueprint = Blueprint("api", __name__, url_prefix="/api")
api = Api(blueprint, doc="/", decorators=[host_header_check])


# Loads event and bucket schema from JSONSchema in aw_core
event = api.schema_model("Event", schema.get_json_schema("event"))
bucket = api.schema_model("Bucket", schema.get_json_schema("bucket"))
buckets_export = api.schema_model("Export", schema.get_json_schema("export"))

# TODO: Construct all the models from JSONSchema?
#       A downside to contructing from JSONSchema: flask-restplus does not have marshalling support

info = api.model(
    "Info",
    {
        "hostname": fields.String(),
        "version": fields.String(),
        "testing": fields.Boolean(),
        "device_id": fields.String(),
    },
)

create_bucket = api.model(
    "CreateBucket",
    {
        "client": fields.String(required=True),
        "type": fields.String(required=True),
        "hostname": fields.String(required=True),
        "data": fields.Raw(required=False),
    },
)

update_bucket = api.model(
    "UpdateBucket",
    {
        "client": fields.String(required=False),
        "type": fields.String(required=False),
        "hostname": fields.String(required=False),
        "data": fields.Raw(required=False),
    },
)

query = api.model(
    "Query",
    {
        "timeperiods": fields.List(
            fields.String, required=True, description="List of periods to query"
        ),
        "query": fields.List(
            fields.String, required=True, description="String list of query statements"
        ),
    },
)

fleet_report = api.model(
    "FleetReport",
    {
        "report": fields.String(required=True),
        "filters": fields.Raw(required=False),
    },
)

auth_login = api.model(
    "AuthLogin",
    {
        "username": fields.String(required=True),
        "password": fields.String(required=True),
    },
)


def copy_doc(api_method):
    """Decorator that copies another functions docstring to the decorated function.
    Used to copy the docstrings in ServerAPI over to the flask-restplus Resources.
    (The copied docstrings are then used by flask-restplus/swagger)"""

    def decorator(f):
        f.__doc__ = api_method.__doc__
        return f

    return decorator


# SERVER INFO


@api.route("/0/info")
class InfoResource(Resource):
    @api.marshal_with(info)
    @copy_doc(ServerAPI.get_info)
    def get(self) -> Dict[str, Dict]:
        return current_app.api.get_info()


def _auth_payload():
    username, user = _current_auth_user()
    if not username or not user:
        return {"authenticated": False, "user": None}

    return {
        "authenticated": True,
        "user": {
            "username": username,
            "is_admin": bool(user.get("is_admin", False)),
        },
    }


def _current_auth_user():
    username = session.get("aw_auth_user")
    if not username:
        return None, None

    user = current_app.api.get_auth_user(username)
    if not user:
        session.pop("aw_auth_user", None)
        return None, None

    return username, user


def _settings_user():
    if current_app.api.testing:
        return None
    username, _user = _current_auth_user()
    return username


def _require_admin_user():
    if current_app.api.testing:
        return {"username": "testing", "is_admin": True}

    username, user = _current_auth_user()
    if not username or not user:
        raise Unauthorized("AuthRequired", "Authentication required")

    if not bool(user.get("is_admin", False)):
        raise Unauthorized("AdminRequired", "Admin access required")

    return {
        "username": username,
        "is_admin": True,
    }


@api.route("/0/auth/session")
class AuthSessionResource(Resource):
    def get(self):
        return jsonify(_auth_payload())


@api.route("/0/auth/login")
class AuthLoginResource(Resource):
    @api.expect(auth_login)
    def post(self):
        data = request.get_json() or {}
        username = str(data.get("username") or "").strip()
        password = str(data.get("password") or "")

        user = current_app.api.authenticate_user(username, password)
        if not user:
            raise Unauthorized("InvalidCredentials", "Invalid username or password")

        session["aw_auth_user"] = username
        session.permanent = True
        return jsonify(_auth_payload())


@api.route("/0/auth/logout")
class AuthLogoutResource(Resource):
    def post(self):
        session.pop("aw_auth_user", None)
        return jsonify({"authenticated": False, "user": None})


# BUCKETS


@api.route("/0/buckets/")
class BucketsResource(Resource):
    # TODO: Add response marshalling/validation
    @copy_doc(ServerAPI.get_buckets)
    def get(self) -> Dict[str, Dict]:
        return current_app.api.get_buckets()


@api.route("/0/buckets/<string:bucket_id>")
class BucketResource(Resource):
    @api.doc(model=bucket)
    @copy_doc(ServerAPI.get_bucket_metadata)
    def get(self, bucket_id):
        return current_app.api.get_bucket_metadata(bucket_id)

    @api.expect(create_bucket)
    @copy_doc(ServerAPI.create_bucket)
    def post(self, bucket_id):
        data = request.get_json()
        bucket_created = current_app.api.create_bucket(
            bucket_id,
            event_type=data["type"],
            client=data["client"],
            hostname=data["hostname"],
            data=data.get("data"),
        )
        if bucket_created:
            return {}, 200
        else:
            return {}, 304

    @api.expect(update_bucket)
    @copy_doc(ServerAPI.update_bucket)
    def put(self, bucket_id):
        data = request.get_json()
        current_app.api.update_bucket(
            bucket_id,
            event_type=data.get("type"),
            client=data.get("client"),
            hostname=data.get("hostname"),
            data=data.get("data"),
        )
        return {}, 200

    @copy_doc(ServerAPI.delete_bucket)
    @api.param("force", "Needs to be =1 to delete a bucket it non-testing mode")
    def delete(self, bucket_id):
        args = request.args
        if not current_app.api.testing:
            if "force" not in args or args["force"] != "1":
                msg = "Deleting buckets is only permitted if aw-server is running in testing mode or if ?force=1"
                raise Unauthorized("DeleteBucketUnauthorized", msg)

        current_app.api.delete_bucket(bucket_id)
        return {}, 200


# EVENTS


@api.route("/0/buckets/<string:bucket_id>/events")
class EventsResource(Resource):
    # For some reason this doesn't work with the JSONSchema variant
    # Marshalling doesn't work with JSONSchema events
    # @api.marshal_list_with(event)
    @api.doc(model=event)
    @api.param("limit", "the maximum number of requests to get")
    @api.param("start", "Start date of events")
    @api.param("end", "End date of events")
    @copy_doc(ServerAPI.get_events)
    def get(self, bucket_id):
        args = request.args
        limit = int(args["limit"]) if "limit" in args else -1
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_events(
            bucket_id, limit=limit, start=start, end=end
        )
        return events, 200

    # TODO: How to tell expect that it could be a list of events? Until then we can't use validate.
    @api.expect(event)
    @copy_doc(ServerAPI.create_events)
    def post(self, bucket_id):
        data = request.get_json()
        logger.debug(
            "Received post request for event in bucket '{}' and data: {}".format(
                bucket_id, data
            )
        )

        if isinstance(data, dict):
            events = [Event(**data)]
        elif isinstance(data, list):
            events = [Event(**e) for e in data]
        else:
            raise BadRequest("Invalid POST data", "")

        event = current_app.api.create_events(bucket_id, events)
        return event.to_json_dict() if event else None, 200


@api.route("/0/buckets/<string:bucket_id>/events/count")
class EventCountResource(Resource):
    @api.doc(model=fields.Integer)
    @api.param("start", "Start date of eventcount")
    @api.param("end", "End date of eventcount")
    @copy_doc(ServerAPI.get_eventcount)
    def get(self, bucket_id):
        args = request.args
        start = iso8601.parse_date(args["start"]) if "start" in args else None
        end = iso8601.parse_date(args["end"]) if "end" in args else None

        events = current_app.api.get_eventcount(bucket_id, start=start, end=end)
        return events, 200


@api.route("/0/buckets/<string:bucket_id>/events/<int:event_id>")
class EventResource(Resource):
    @api.doc(model=event)
    @copy_doc(ServerAPI.get_event)
    def get(self, bucket_id: str, event_id: int):
        logger.debug(
            f"Received get request for event with id '{event_id}' in bucket '{bucket_id}'"
        )
        event = current_app.api.get_event(bucket_id, event_id)
        if event:
            return event, 200
        else:
            return None, 404

    @copy_doc(ServerAPI.delete_event)
    def delete(self, bucket_id: str, event_id: int):
        logger.debug(
            "Received delete request for event with id '{}' in bucket '{}'".format(
                event_id, bucket_id
            )
        )
        success = current_app.api.delete_event(bucket_id, event_id)
        return {"success": success}, 200


@api.route("/0/buckets/<string:bucket_id>/heartbeat")
class HeartbeatResource(Resource):
    def __init__(self, *args, **kwargs):
        self.lock = Lock()
        super().__init__(*args, **kwargs)

    @api.expect(event, validate=True)
    @api.param(
        "pulsetime", "Largest timewindow allowed between heartbeats for them to merge"
    )
    @copy_doc(ServerAPI.heartbeat)
    def post(self, bucket_id):
        heartbeat = Event(**request.get_json())

        if "pulsetime" in request.args:
            pulsetime = float(request.args["pulsetime"])
        else:
            raise BadRequest("MissingParameter", "Missing required parameter pulsetime")

        # This lock is meant to ensure that only one heartbeat is processed at a time,
        # as the heartbeat function is not thread-safe.
        # This should maybe be moved into the api.py file instead (but would be very messy).
        aquired = self.lock.acquire(timeout=1)
        if not aquired:
            logger.warning(
                "Heartbeat lock could not be aquired within a reasonable time, this likely indicates a bug."
            )
        try:
            event = current_app.api.heartbeat(bucket_id, heartbeat, pulsetime)
        finally:
            self.lock.release()
        return event.to_json_dict(), 200


# QUERY


@api.route("/0/query/")
class QueryResource(Resource):
    # TODO Docs
    @api.expect(query, validate=True)
    @api.param("name", "Name of the query (required if using cache)")
    def post(self):
        name = ""
        if "name" in request.args:
            name = request.args["name"]
        query = request.get_json()
        try:
            result = current_app.api.query2(
                name, query["query"], query["timeperiods"], False
            )
            return jsonify(result)
        except QueryException as qe:
            traceback.print_exc()
            return {"type": type(qe).__name__, "message": str(qe)}, 400


# EXPORT AND IMPORT


@api.route("/0/export")
class ExportAllResource(Resource):
    @api.doc(model=buckets_export)
    @copy_doc(ServerAPI.export_all)
    def get(self):
        buckets_export = current_app.api.export_all()
        payload = {"buckets": buckets_export}
        response = make_response(json.dumps(payload))
        filename = "aw-buckets-export.json"
        response.headers["Content-Disposition"] = "attachment; filename={}".format(
            filename
        )
        return response


# TODO: Perhaps we don't need this, could be done with a query argument to /0/export instead
@api.route("/0/buckets/<string:bucket_id>/export")
class BucketExportResource(Resource):
    @api.doc(model=buckets_export)
    @copy_doc(ServerAPI.export_bucket)
    def get(self, bucket_id):
        bucket_export = current_app.api.export_bucket(bucket_id)
        payload = {"buckets": {bucket_export["id"]: bucket_export}}
        response = make_response(json.dumps(payload))
        filename = "aw-bucket-export_{}.json".format(bucket_export["id"])
        response.headers["Content-Disposition"] = "attachment; filename={}".format(
            filename
        )
        return response


@api.route("/0/import")
class ImportAllResource(Resource):
    @api.expect(buckets_export)
    @copy_doc(ServerAPI.import_all)
    def post(self):
        # If import comes from a form in th web-ui
        if len(request.files) > 0:
            # web-ui form only allows one file, but technically it's possible to
            # upload multiple files at the same time
            for filename, f in request.files.items():
                buckets = json.loads(f.stream.read())["buckets"]
                current_app.api.import_all(buckets)
        # Normal import from body
        else:
            buckets = request.get_json()["buckets"]
            current_app.api.import_all(buckets)
        return None, 200


# LOGGING


@api.route("/0/log")
class LogResource(Resource):
    @copy_doc(ServerAPI.get_log)
    def get(self):
        return current_app.api.get_log(), 200


# SETTINGS


@api.route("/0/settings", defaults={"key": ""})
@api.route("/0/settings/<string:key>")
class SettingsResource(Resource):
    def get(self, key: str):
        data = current_app.api.get_setting(key, user=_settings_user())
        return jsonify(data)

    def post(self, key: str):
        if not key:
            raise BadRequest("MissingParameter", "Missing required parameter key")
        data = current_app.api.set_setting(
            key,
            request.get_json(),
            user=_settings_user(),
        )
        return data


@api.route("/0/admin/ui-config")
class AdminUiConfigResource(Resource):
    def get(self):
        return jsonify(current_app.api.get_admin_ui_config())

    def post(self):
        _require_admin_user()
        return jsonify(current_app.api.set_admin_ui_config(request.get_json() or {}))


# FLEET


def _fleet_range():
    args = request.args
    start = _parse_query_date(args["start"]) if "start" in args else None
    end = _parse_query_date(args["end"]) if "end" in args else None
    return start, end


def _fleet_device_ids():
    values = []
    for key in ("device_id", "device_ids", "device_ids[]"):
        values.extend(request.args.getlist(key))
    device_ids = []
    for value in values:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                device_ids.append(part)
    if not device_ids:
        return None
    unique = []
    seen = set()
    for device_id in device_ids:
        if device_id in seen:
            continue
        seen.add(device_id)
        unique.append(device_id)
    return unique


def _fleet_bool_arg(name: str, default: bool = False) -> bool:
    if name not in request.args:
        return default
    value = str(request.args.get(name) or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _parse_query_date(value: str):
    normalized = value.replace(" ", "+")
    return iso8601.parse_date(normalized)


@api.route("/0/fleet/live")
class FleetLiveResource(Resource):
    def get(self):
        return jsonify(current_app.api.get_live_fleet_summary())


@api.route("/0/fleet/storage")
class FleetStorageResource(Resource):
    def get(self):
        return jsonify(current_app.api.get_fleet_storage())


@api.route("/0/fleet/users")
class FleetUsersResource(Resource):
    def get(self):
        return jsonify(current_app.api.get_fleet_users())


@api.route("/0/fleet/users/<string:username>")
class FleetUserResource(Resource):
    def get(self, username: str):
        start, end = _fleet_range()
        return jsonify(
            current_app.api.get_fleet_user(
                username,
                start=start,
                end=end,
                device_ids=_fleet_device_ids(),
                exclude_inactive_session_afk=_fleet_bool_arg(
                    "exclude_inactive_session_afk"
                ),
            )
        )


@api.route("/0/fleet/devices")
class FleetDevicesResource(Resource):
    def get(self):
        return jsonify(current_app.api.get_fleet_devices())


@api.route("/0/fleet/devices/<string:device_id>")
class FleetDeviceResource(Resource):
    def get(self, device_id: str):
        start, end = _fleet_range()
        return jsonify(
            current_app.api.get_fleet_device(
                device_id,
                start=start,
                end=end,
                exclude_inactive_session_afk=_fleet_bool_arg(
                    "exclude_inactive_session_afk"
                ),
            )
        )


@api.route("/0/fleet/report")
class FleetReportResource(Resource):
    @api.expect(fleet_report)
    def post(self):
        try:
            return jsonify(current_app.api.run_fleet_report(request.get_json()))
        except ValueError as exc:
            raise BadRequest("InvalidFleetReport", str(exc))


@api.route("/0/fleet/sync/handshake")
class FleetSyncHandshakeResource(Resource):
    def post(self):
        try:
            return current_app.api.fleet_sync_handshake(request.get_json())
        except ValueError as exc:
            raise BadRequest("InvalidFleetSyncHandshake", str(exc))


@api.route("/0/fleet/sync/batch")
class FleetSyncBatchResource(Resource):
    def post(self):
        try:
            return current_app.api.fleet_sync_batch(request.get_json())
        except FleetSyncConflict as exc:
            return exc.payload, 409
        except ValueError as exc:
            raise BadRequest("InvalidFleetSyncBatch", str(exc))
