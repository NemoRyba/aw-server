import csv
import os
import re
import shutil
import subprocess
from datetime import date, datetime, timedelta
from io import StringIO
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class RedmineReadOnlyError(RuntimeError):
    pass


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _date_literal(value: Any) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value or "")


def redmine_spent_on_range(start: datetime, end: datetime) -> Tuple[date, date]:
    local_start = start.astimezone()
    local_end = end.astimezone()
    if local_end <= local_start:
        return local_start.date(), local_start.date()
    return local_start.date(), (local_end - timedelta(microseconds=1)).date()


def normalize_email(value: Any) -> str:
    return str(value or "").strip().lower()


class RedmineReadOnlySource:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = dict(config or {})
        self.driver = str(self.config.get("driver") or "auto").strip().lower()

    def active_users(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        users_table = self._table("users")
        limit_sql = f" LIMIT {max(1, int(limit))}" if limit else ""
        rows = self._query(
            f"""
            SELECT
                id,
                login,
                firstname,
                lastname,
                mail
            FROM {users_table}
            WHERE status = 1
                AND login <> ''
            ORDER BY login
            {limit_sql}
            """
        )
        return [
            {
                "id": _coerce_int(row.get("id")),
                "login": str(row.get("login") or ""),
                "firstname": str(row.get("firstname") or ""),
                "lastname": str(row.get("lastname") or ""),
                "mail": normalize_email(row.get("mail")),
            }
            for row in rows
        ]

    def time_by_project(
        self,
        *,
        user_ids: Iterable[int],
        spent_from: date,
        spent_to: date,
    ) -> List[Dict[str, Any]]:
        normalized_user_ids = sorted(
            {int(user_id) for user_id in user_ids if int(user_id) > 0}
        )
        if not normalized_user_ids:
            return []

        time_entries_table = self._table("time_entries")
        projects_table = self._table("projects")
        placeholders = ", ".join(["%s"] * len(normalized_user_ids))
        rows = self._query(
            f"""
            SELECT
                te.user_id,
                te.project_id,
                COALESCE(p.name, '') AS project_name,
                SUM(te.hours) AS hours,
                COUNT(*) AS entry_count
            FROM {time_entries_table} te
            LEFT JOIN {projects_table} p ON p.id = te.project_id
            WHERE te.user_id IN ({placeholders})
                AND te.spent_on >= %s
                AND te.spent_on <= %s
            GROUP BY te.user_id, te.project_id, p.name
            ORDER BY te.user_id, p.name
            """,
            [*normalized_user_ids, spent_from.isoformat(), spent_to.isoformat()],
        )
        return [
            {
                "user_id": _coerce_int(row.get("user_id")),
                "project_id": _coerce_int(row.get("project_id")),
                "project_name": str(row.get("project_name") or ""),
                "hours": _coerce_float(row.get("hours")),
                "entry_count": _coerce_int(row.get("entry_count")),
            }
            for row in rows
        ]

    def _table(self, name: str) -> str:
        prefix = str(self.config.get("table_prefix") or "").strip()
        if not re.match(r"^[A-Za-z0-9_]*$", prefix):
            raise RedmineReadOnlyError("Redmine table prefix may only contain letters, numbers, and underscores")
        return f"`{prefix}{name}`"

    def _query(
        self,
        sql: str,
        params: Optional[Sequence[Any]] = None,
    ) -> List[Dict[str, Any]]:
        params = list(params or [])
        self._assert_select_only(sql)

        if self.driver in {"auto", "pymysql"}:
            try:
                return self._query_pymysql(sql, params)
            except ImportError:
                if self.driver == "pymysql":
                    raise RedmineReadOnlyError("PyMySQL is not installed")

        if self.driver in {"auto", "mysql-connector", "mysql_connector"}:
            try:
                return self._query_mysql_connector(sql, params)
            except ImportError:
                if self.driver in {"mysql-connector", "mysql_connector"}:
                    raise RedmineReadOnlyError("mysql-connector-python is not installed")

        if self.driver in {"auto", "mysql-cli", "mysql_cli", "cli"}:
            return self._query_mysql_cli(sql, params)

        raise RedmineReadOnlyError(f"Unsupported Redmine MySQL driver: {self.driver}")

    def _assert_select_only(self, sql: str) -> None:
        normalized = " ".join(str(sql or "").strip().split()).lower()
        if not normalized.startswith("select "):
            raise RedmineReadOnlyError("Only SELECT statements are allowed for Redmine")
        blocked = (" insert ", " update ", " delete ", " replace ", " alter ", " drop ", " create ")
        if any(token in f" {normalized} " for token in blocked):
            raise RedmineReadOnlyError("Only read-only Redmine statements are allowed")

    def _connection_kwargs(self) -> Dict[str, Any]:
        return {
            "host": str(self.config.get("host") or "localhost").strip(),
            "port": _coerce_int(self.config.get("port"), 3306),
            "user": str(self.config.get("username") or "").strip(),
            "password": str(self.config.get("password") or ""),
            "database": str(self.config.get("database") or "").strip(),
            "connect_timeout": _coerce_int(self.config.get("connect_timeout"), 10),
        }

    def _query_pymysql(self, sql: str, params: Sequence[Any]) -> List[Dict[str, Any]]:
        import pymysql

        kwargs = self._connection_kwargs()
        connection = pymysql.connect(
            **kwargs,
            autocommit=True,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        finally:
            connection.close()

    def _query_mysql_connector(
        self, sql: str, params: Sequence[Any]
    ) -> List[Dict[str, Any]]:
        import mysql.connector

        kwargs = self._connection_kwargs()
        connection = mysql.connector.connect(**kwargs)
        try:
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
            finally:
                cursor.close()
        finally:
            connection.close()

    def _query_mysql_cli(self, sql: str, params: Sequence[Any]) -> List[Dict[str, Any]]:
        cli_path = str(self.config.get("mysql_cli_path") or "mysql").strip() or "mysql"
        resolved = cli_path if os.path.sep in cli_path else shutil.which(cli_path)
        if not resolved:
            raise RedmineReadOnlyError(
                "No Python MySQL driver is installed and the mysql CLI was not found"
            )

        kwargs = self._connection_kwargs()
        query = self._format_cli_sql(sql, params)
        env = dict(os.environ)
        if kwargs["password"]:
            env["MYSQL_PWD"] = kwargs["password"]

        result = subprocess.run(
            [
                resolved,
                f"--host={kwargs['host']}",
                f"--port={kwargs['port']}",
                f"--user={kwargs['user']}",
                f"--database={kwargs['database']}",
                f"--connect-timeout={kwargs['connect_timeout']}",
                "--default-character-set=utf8mb4",
                "--batch",
                "--raw",
                "--execute",
                query,
            ],
            capture_output=True,
            env=env,
            text=True,
            timeout=kwargs["connect_timeout"] + 30,
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            raise RedmineReadOnlyError(message or "mysql CLI query failed")
        return self._parse_mysql_cli_rows(result.stdout)

    def _format_cli_sql(self, sql: str, params: Sequence[Any]) -> str:
        parts = sql.split("%s")
        if len(parts) - 1 != len(params):
            raise RedmineReadOnlyError("Redmine SQL parameter count mismatch")
        query = parts[0]
        for index, param in enumerate(params):
            query += self._literal(param) + parts[index + 1]
        return query

    def _literal(self, value: Any) -> str:
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, float):
            return str(value)
        text = _date_literal(value).replace("\\", "\\\\").replace("'", "''")
        return f"'{text}'"

    def _parse_mysql_cli_rows(self, output: str) -> List[Dict[str, Any]]:
        if not output.strip():
            return []
        reader = csv.reader(StringIO(output), delimiter="\t")
        rows = list(reader)
        if not rows:
            return []
        headers = rows[0]
        parsed_rows = []
        for row in rows[1:]:
            parsed_rows.append(
                {
                    headers[index]: None if value == "NULL" else value
                    for index, value in enumerate(row)
                    if index < len(headers)
                }
            )
        return parsed_rows
