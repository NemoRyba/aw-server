import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from aw_core.dirs import get_data_dir


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class FleetSyncStore:
    VERSION = 1

    def __init__(self, testing: bool = False) -> None:
        data_dir = Path(get_data_dir("aw-server"))
        filename = f"fleet-sync{'-testing' if testing else ''}.v{self.VERSION}.db"
        self.path = data_dir / filename
        self.testing = testing
        self._lock = threading.Lock()

        if testing and self.path.exists():
            os.remove(self.path)

        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sync_streams (
                    stream_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    bucket_id TEXT NOT NULL,
                    bucket_type TEXT NOT NULL,
                    central_bucket_id TEXT NOT NULL,
                    bucket_metadata_json TEXT NOT NULL,
                    last_acked_seq INTEGER NOT NULL DEFAULT 0,
                    last_received_at TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_stream_bucket
                    ON sync_streams(bucket_id);

                CREATE TABLE IF NOT EXISTS sync_event_map (
                    stream_id TEXT NOT NULL,
                    source_event_id INTEGER NOT NULL,
                    source_event_version INTEGER NOT NULL,
                    central_bucket_id TEXT NOT NULL,
                    central_event_id INTEGER NOT NULL,
                    event_checksum TEXT NOT NULL,
                    last_seq INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (stream_id, source_event_id),
                    FOREIGN KEY (stream_id) REFERENCES sync_streams(stream_id)
                );
                """
            )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def upsert_agent(self, agent: Dict[str, Any], conn: sqlite3.Connection) -> None:
        now = _utcnow()
        conn.execute(
            """
            INSERT INTO agents (
                agent_id, device_id, device_name, hostname, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                device_id = excluded.device_id,
                device_name = excluded.device_name,
                hostname = excluded.hostname,
                updated_at = excluded.updated_at
            """,
            (
                agent["agent_id"],
                agent["device_id"],
                agent["device_name"],
                agent["hostname"],
                now,
                now,
            ),
        )

    def get_stream(
        self, stream_id: str, conn: sqlite3.Connection
    ) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM sync_streams WHERE stream_id = ?", (stream_id,)
        ).fetchone()

    def upsert_stream(
        self,
        *,
        stream_id: str,
        agent_id: str,
        device_id: str,
        device_name: str,
        hostname: str,
        bucket_id: str,
        bucket_type: str,
        central_bucket_id: str,
        bucket_metadata: Dict[str, Any],
        conn: sqlite3.Connection,
        touch_received_at: bool = False,
    ) -> None:
        now = _utcnow()
        last_received_at = now if touch_received_at else None
        conn.execute(
            """
            INSERT INTO sync_streams (
                stream_id,
                agent_id,
                device_id,
                device_name,
                hostname,
                bucket_id,
                bucket_type,
                central_bucket_id,
                bucket_metadata_json,
                last_received_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stream_id) DO UPDATE SET
                agent_id = excluded.agent_id,
                device_id = excluded.device_id,
                device_name = excluded.device_name,
                hostname = excluded.hostname,
                bucket_id = excluded.bucket_id,
                bucket_type = excluded.bucket_type,
                central_bucket_id = excluded.central_bucket_id,
                bucket_metadata_json = excluded.bucket_metadata_json,
                last_received_at = COALESCE(excluded.last_received_at, sync_streams.last_received_at),
                updated_at = excluded.updated_at
            """,
            (
                stream_id,
                agent_id,
                device_id,
                device_name,
                hostname,
                bucket_id,
                bucket_type,
                central_bucket_id,
                json.dumps(bucket_metadata, sort_keys=True),
                last_received_at,
                now,
            ),
        )

    def touch_stream_received(
        self, stream_id: str, conn: sqlite3.Connection, received_at: Optional[str] = None
    ) -> None:
        received_at = received_at or _utcnow()
        conn.execute(
            """
            UPDATE sync_streams
            SET last_received_at = ?, updated_at = ?
            WHERE stream_id = ?
            """,
            (received_at, received_at, stream_id),
        )

    def update_stream_ack(
        self,
        stream_id: str,
        last_acked_seq: int,
        conn: sqlite3.Connection,
        received_at: Optional[str] = None,
    ) -> None:
        received_at = received_at or _utcnow()
        conn.execute(
            """
            UPDATE sync_streams
            SET last_acked_seq = ?,
                last_received_at = ?,
                updated_at = ?
            WHERE stream_id = ?
            """,
            (last_acked_seq, received_at, received_at, stream_id),
        )

    def get_event_map(
        self,
        stream_id: str,
        source_event_id: int,
        conn: sqlite3.Connection,
    ) -> Optional[sqlite3.Row]:
        return conn.execute(
            """
            SELECT *
            FROM sync_event_map
            WHERE stream_id = ? AND source_event_id = ?
            """,
            (stream_id, source_event_id),
        ).fetchone()

    def upsert_event_map(
        self,
        *,
        stream_id: str,
        source_event_id: int,
        source_event_version: int,
        central_bucket_id: str,
        central_event_id: int,
        event_checksum: str,
        last_seq: int,
        conn: sqlite3.Connection,
    ) -> None:
        now = _utcnow()
        conn.execute(
            """
            INSERT INTO sync_event_map (
                stream_id,
                source_event_id,
                source_event_version,
                central_bucket_id,
                central_event_id,
                event_checksum,
                last_seq,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(stream_id, source_event_id) DO UPDATE SET
                source_event_version = excluded.source_event_version,
                central_bucket_id = excluded.central_bucket_id,
                central_event_id = excluded.central_event_id,
                event_checksum = excluded.event_checksum,
                last_seq = excluded.last_seq,
                updated_at = excluded.updated_at
            """,
            (
                stream_id,
                source_event_id,
                source_event_version,
                central_bucket_id,
                central_event_id,
                event_checksum,
                last_seq,
                now,
            ),
        )
