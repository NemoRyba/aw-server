import logging
import socket
from threading import Thread
from time import sleep

import pytest
import requests
from aw_client import ActivityWatchClient
from aw_datastore import get_storage_methods
from aw_server.server import AWFlask

logging.basicConfig(level=logging.WARN)

# Port aw-client uses for its "server-testing" profile; the aw_client fixture
# below connects here, so the test server has to listen on it.
TESTING_HOST = "127.0.0.1"
TESTING_PORT = 5666


@pytest.fixture(scope="session")
def app():
    return AWFlask("127.0.0.1", testing=True)


@pytest.fixture(scope="session")
def flask_client(app):
    yield app.test_client()


def _server_is_up(timeout=0.25) -> bool:
    try:
        with socket.create_connection((TESTING_HOST, TESTING_PORT), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def aw_server():
    """A real aw-server on the testing port, for the tests that talk HTTP.

    aw_client below is a genuine HTTP client, so something has to be listening.
    Upstream expects you to have started `aw-server --testing` by hand, which
    means these tests fail with a ConnectionError on a clean checkout. Starting
    it here makes the suite self-contained.

    If a server is already listening (someone running one for development), it
    is reused rather than fought over.
    """
    if _server_is_up():
        yield f"http://{TESTING_HOST}:{TESTING_PORT}"
        return

    # Use the SAME storage the real server uses (aw_server/config.py sets
    # storage = "peewee" for both profiles). AWFlask defaults to the in-memory
    # store, which differs in behaviour that these tests assert on: peewee
    # clips an event's duration to the queried range, memory does not.
    server_app = AWFlask(
        TESTING_HOST,
        testing=True,
        storage_method=get_storage_methods()["peewee"],
    )
    thread = Thread(
        target=server_app.run,
        kwargs=dict(
            host=TESTING_HOST,
            port=TESTING_PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        ),
        daemon=True,  # never block pytest from exiting
    )
    thread.start()

    for _ in range(100):
        if _server_is_up():
            break
        sleep(0.1)
    else:
        pytest.skip(
            f"test server did not start on {TESTING_HOST}:{TESTING_PORT}"
        )

    yield f"http://{TESTING_HOST}:{TESTING_PORT}"
    # Daemon thread: werkzeug's dev server has no clean in-process shutdown,
    # and the interpreter exiting takes it with us.


@pytest.fixture(scope="session")
def aw_client(aw_server):
    # TODO: Could it be possible to write a sisterclass of ActivityWatchClient
    # which calls aw_server.api directly? Would it be of use? Would add another
    # layer of integration tests that are actually more like unit tests.
    c = ActivityWatchClient("aw-client-test", testing=True)
    yield c

    # Delete test buckets after all tests needing the fixture have been run
    try:
        buckets = c.get_buckets()
    except requests.RequestException:
        return
    for bucket_id in buckets:
        if bucket_id.startswith("test-"):
            c.delete_bucket(bucket_id)
