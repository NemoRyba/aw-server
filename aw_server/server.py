import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List

import aw_datastore
import flask.json.provider
from aw_datastore import Datastore
from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    jsonify,
    request,
    send_from_directory,
    session,
)
from flask_cors import CORS

from . import rest
from .api import ServerAPI
from .bucket_backfill import backfill_bucket_identities
from .custom_static import get_custom_static_blueprint
from .log import FlaskLogHandler

logger = logging.getLogger(__name__)

app_folder = os.path.dirname(os.path.abspath(__file__))
static_folder = os.path.join(app_folder, "static")

root = Blueprint("root", __name__, url_prefix="/")


def _normalize_path(path: str) -> str:
    if path == "/":
        return path
    return path.rstrip("/")


def _is_bucket_write_request(path: str, method: str) -> bool:
    if not path.startswith("/api/0/buckets/"):
        return False

    remainder = path[len("/api/0/buckets/") :]
    if not remainder:
        return False

    parts = [part for part in remainder.split("/") if part]
    if len(parts) == 1 and method in {"POST", "PUT"}:
        return True
    if len(parts) == 2 and parts[1] in {"events", "heartbeat"} and method == "POST":
        return True
    return False


def _is_public_api_request(path: str, method: str) -> bool:
    if method == "OPTIONS":
        return True

    if path in {
        "/api/0/info",
        "/api/0/auth/login",
        "/api/0/auth/session",
        "/api/0/auth/logout",
    }:
        return True

    if path in {"/api/0/fleet/sync/handshake", "/api/0/fleet/sync/batch"} and method == "POST":
        return True

    return _is_bucket_write_request(path, method)


class AWFlask(Flask):
    def __init__(
        self,
        host: str,
        testing: bool,
        storage_method=None,
        cors_origins=[],
        custom_static=dict(),
        static_folder=static_folder,
        static_url_path="",
    ):
        name = "aw-server"
        self.json_provider_class = CustomJSONProvider
        # only prettyprint JSON if testing (due to perf)
        self.json_provider_class.compact = not testing

        # Initialize Flask
        Flask.__init__(
            self,
            name,
            static_folder=static_folder,
            static_url_path=static_url_path,
        )
        self.config["HOST"] = host  # needed for host-header check
        with self.app_context():
            _config_cors(cors_origins, testing)

        # Initialize datastore and API
        if storage_method is None:
            storage_method = aw_datastore.get_storage_methods()["memory"]
        db = Datastore(storage_method, testing=testing)
        self.api = ServerAPI(db=db, testing=testing)
        try:
            updated_buckets = backfill_bucket_identities(self.api)
            if updated_buckets > 0:
                logger.info("Backfilled identity metadata for %s bucket(s)", updated_buckets)
        except Exception:
            logger.exception("Failed while backfilling bucket identity metadata")
        self.config["SECRET_KEY"] = self.api.get_session_secret()
        self.config["SESSION_COOKIE_NAME"] = "aw-session"
        self.config["SESSION_COOKIE_HTTPONLY"] = True
        self.config["SESSION_COOKIE_SAMESITE"] = "Lax"

        self.register_blueprint(root)
        self.register_blueprint(rest.blueprint)
        self.register_blueprint(get_custom_static_blueprint(custom_static))
        self.before_request(self._enforce_api_auth)
        self.register_error_handler(404, self._handle_not_found)

    def _enforce_api_auth(self):
        if self.api.testing:
            return None

        path = _normalize_path(request.path)
        if not path.startswith("/api"):
            return None

        if _is_public_api_request(path, request.method):
            return None

        if session.get("aw_auth_user"):
            return None

        return jsonify(
            {
                "type": "AuthRequired",
                "message": "Authentication required",
            }
        ), 401

    def _handle_not_found(self, error):
        path = _normalize_path(request.path)
        if (
            request.method == "GET"
            and not path.startswith("/api")
            and "." not in os.path.basename(path)
        ):
            return current_app.send_static_file("index.html")
        return error


class CustomJSONProvider(flask.json.provider.DefaultJSONProvider):
    # encoding/decoding of datetime as iso8601 strings
    # encoding of timedelta as second floats
    def default(self, obj, *args, **kwargs):
        try:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, timedelta):
                return obj.total_seconds()
        except TypeError:
            pass
        return super().default(obj)


@root.route("/")
def static_root():
    return current_app.send_static_file("index.html")


@root.route("/css/<path:path>")
def static_css(path):
    return send_from_directory(static_folder + "/css", path)


@root.route("/js/<path:path>")
def static_js(path):
    return send_from_directory(static_folder + "/js", path)


@root.route("/<path:path>")
def static_path(path):
    if path.startswith("api/"):
        abort(404)

    absolute_path = os.path.join(static_folder, path)
    if os.path.isfile(absolute_path):
        return send_from_directory(static_folder, path)

    return current_app.send_static_file("index.html")


def _config_cors(cors_origins: List[str], testing: bool):
    if cors_origins:
        logger.warning(
            "Running with additional allowed CORS origins specified through config "
            "or CLI argument (could be a security risk): {}".format(cors_origins)
        )

    if testing:
        # Used for development of aw-webui
        cors_origins.append("http://127.0.0.1:27180/*")

    # TODO: This could probably be more specific
    #       See https://github.com/ActivityWatch/aw-server/pull/43#issuecomment-386888769
    cors_origins.append("moz-extension://*")

    # See: https://flask-cors.readthedocs.org/en/latest/
    CORS(
        current_app,
        resources={r"/api/*": {"origins": cors_origins}},
        supports_credentials=True,
    )


# Only to be called from aw_server.main function!
def _start(
    storage_method,
    host: str,
    port: int,
    testing: bool = False,
    cors_origins: List[str] = [],
    custom_static: Dict[str, str] = dict(),
):
    app = AWFlask(
        host,
        testing=testing,
        storage_method=storage_method,
        cors_origins=cors_origins,
        custom_static=custom_static,
    )
    try:
        app.run(
            debug=testing,
            host=host,
            port=port,
            request_handler=FlaskLogHandler,
            use_reloader=False,
            threaded=True,
        )
    except OSError as e:
        logger.exception(e)
        raise e
