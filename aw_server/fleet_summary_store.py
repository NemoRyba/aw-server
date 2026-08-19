import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aw_core.dirs import get_data_dir


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_device_ids_key(device_ids: Optional[Iterable[Any]]) -> str:
    if not device_ids:
        return "[]"

    normalized: List[str] = []
    seen = set()
    for value in device_ids:
        text = str(value or "").strip()
        if not text:
            continue
        for part in text.split(","):
            part = part.strip()
            if part and part not in seen:
                seen.add(part)
                normalized.append(part)

    return json.dumps(sorted(normalized), separators=(",", ":"))


def _row_to_summary(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None

    return {
        "username": row["username"],
        "range": {
            "start": row["range_start"],
            "end": row["range_end"],
        },
        "filters": {
            "device_ids": json.loads(row["device_ids_json"]),
            "exclude_inactive_session_afk": bool(row["exclude_inactive_session_afk"]),
        },
        "selected_devices": json.loads(row["selected_devices_json"] or "[]"),
        "totals": json.loads(row["totals_json"]),
        "summary_cache": {
            "cached": True,
            "calculated_at": row["calculated_at"],
            "source": row["source"],
        },
    }


def _row_to_run(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None

    return {
        "run_key": row["run_key"],
        "range": {
            "start": row["range_start"],
            "end": row["range_end"],
        },
        "start_of_day": row["start_of_day"],
        "source": row["source"],
        "status": row["status"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "users_total": row["users_total"],
        "users_done": row["users_done"],
        "message": row["message"],
    }


class FleetSummaryStore:
    VERSION = 1

    def __init__(self, testing: bool = False) -> None:
        data_dir = Path(get_data_dir("aw-server"))
        filename = f"fleet-summary{'-testing' if testing else ''}.v{self.VERSION}.db"
        self.path = data_dir / filename
        self.testing = testing
        self._lock = threading.Lock()

        if testing and self.path.exists():
            os.remove(self.path)

        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS user_summary_cache (
                    username TEXT NOT NULL,
                    range_start TEXT NOT NULL,
                    range_end TEXT NOT NULL,
                    device_ids_json TEXT NOT NULL,
                    exclude_inactive_session_afk INTEGER NOT NULL,
                    selected_devices_json TEXT NOT NULL,
                    totals_json TEXT NOT NULL,
                    calculated_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    PRIMARY KEY (
                        username,
                        range_start,
                        range_end,
                        device_ids_json,
                        exclude_inactive_session_afk
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_user_summary_cache_range
                    ON user_summary_cache(range_start, range_end);

                CREATE TABLE IF NOT EXISTS precompute_runs (
                    run_key TEXT PRIMARY KEY,
                    range_start TEXT NOT NULL,
                    range_end TEXT NOT NULL,
                    start_of_day TEXT NOT NULL,
                    source TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    users_total INTEGER NOT NULL DEFAULT 0,
                    users_done INTEGER NOT NULL DEFAULT 0,
                    message TEXT
                );
                """
            )

    def get_user_summary(
        self,
        *,
        username: str,
        range_start: str,
        range_end: str,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk: bool,
    ) -> Optional[Dict[str, Any]]:
        device_ids_json = _normalize_device_ids_key(device_ids)
        with self._lock:
            row = self._conn.execute(
                """
                SELECT *
                FROM user_summary_cache
                WHERE username = ?
                    AND range_start = ?
                    AND range_end = ?
                    AND device_ids_json = ?
                    AND exclude_inactive_session_afk = ?
                """,
                (
                    username,
                    range_start,
                    range_end,
                    device_ids_json,
                    1 if exclude_inactive_session_afk else 0,
                ),
            ).fetchone()
        return _row_to_summary(row)

    def upsert_user_summary(
        self,
        *,
        username: str,
        range_start: str,
        range_end: str,
        device_ids: Optional[Iterable[Any]] = None,
        exclude_inactive_session_afk: bool,
        selected_devices: Iterable[Any],
        totals: Dict[str, Any],
        source: str,
    ) -> Dict[str, Any]:
        device_ids_json = _normalize_device_ids_key(device_ids)
        calculated_at = _utcnow()
        selected_devices_json = json.dumps(sorted(str(value) for value in selected_devices))
        totals_json = json.dumps(totals, sort_keys=True)

        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO user_summary_cache (
                        username,
                        range_start,
                        range_end,
                        device_ids_json,
                        exclude_inactive_session_afk,
                        selected_devices_json,
                        totals_json,
                        calculated_at,
                        source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(
                        username,
                        range_start,
                        range_end,
                        device_ids_json,
                        exclude_inactive_session_afk
                    ) DO UPDATE SET
                        selected_devices_json = excluded.selected_devices_json,
                        totals_json = excluded.totals_json,
                        calculated_at = excluded.calculated_at,
                        source = excluded.source
                    """,
                    (
                        username,
                        range_start,
                        range_end,
                        device_ids_json,
                        1 if exclude_inactive_session_afk else 0,
                        selected_devices_json,
                        totals_json,
                        calculated_at,
                        source,
                    ),
                )

        row = self.get_user_summary(
            username=username,
            range_start=range_start,
            range_end=range_end,
            device_ids=device_ids,
            exclude_inactive_session_afk=exclude_inactive_session_afk,
        )
        if row:
            row["summary_cache"]["cached"] = False
            return row

        return {
            "username": username,
            "range": {"start": range_start, "end": range_end},
            "filters": {
                "device_ids": json.loads(device_ids_json),
                "exclude_inactive_session_afk": bool(exclude_inactive_session_afk),
            },
            "selected_devices": sorted(str(value) for value in selected_devices),
            "totals": totals,
            "summary_cache": {
                "cached": False,
                "calculated_at": calculated_at,
                "source": source,
            },
        }

    def start_precompute_run(
        self,
        *,
        run_key: str,
        range_start: str,
        range_end: str,
        start_of_day: str,
        source: str,
        users_total: int,
    ) -> Dict[str, Any]:
        started_at = _utcnow()
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO precompute_runs (
                        run_key,
                        range_start,
                        range_end,
                        start_of_day,
                        source,
                        status,
                        started_at,
                        finished_at,
                        users_total,
                        users_done,
                        message
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 0, NULL)
                    ON CONFLICT(run_key) DO UPDATE SET
                        range_start = excluded.range_start,
                        range_end = excluded.range_end,
                        start_of_day = excluded.start_of_day,
                        source = excluded.source,
                        status = excluded.status,
                        started_at = excluded.started_at,
                        finished_at = NULL,
                        users_total = excluded.users_total,
                        users_done = 0,
                        message = NULL
                    """,
                    (
                        run_key,
                        range_start,
                        range_end,
                        start_of_day,
                        source,
                        "running",
                        started_at,
                        users_total,
                    ),
                )
        return self.get_precompute_run(run_key) or {}

    def update_precompute_progress(self, run_key: str, users_done: int) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE precompute_runs
                    SET users_done = ?
                    WHERE run_key = ?
                    """,
                    (users_done, run_key),
                )

    def finish_precompute_run(
        self,
        *,
        run_key: str,
        status: str,
        message: str = "",
    ) -> Dict[str, Any]:
        finished_at = _utcnow()
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    UPDATE precompute_runs
                    SET status = ?,
                        finished_at = ?,
                        message = ?
                    WHERE run_key = ?
                    """,
                    (status, finished_at, message, run_key),
                )
        return self.get_precompute_run(run_key) or {}

    def get_precompute_run(self, run_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT *
                FROM precompute_runs
                WHERE run_key = ?
                """,
                (run_key,),
            ).fetchone()
        return _row_to_run(row)

    def latest_precompute_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT *
                FROM precompute_runs
                ORDER BY started_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_run(row) for row in rows if row is not None]
