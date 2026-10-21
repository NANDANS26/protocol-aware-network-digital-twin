"""Database Engine abstraction supporting PostgreSQL (via psycopg pool) and SQLite."""

from __future__ import annotations

import atexit
import logging
import sqlite3
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from network_twin.config import AppSettings, settings

logger = logging.getLogger(__name__)


class DatabaseConnectionError(RuntimeError):
    """Raised when the database connection fails or cannot be established."""


class DbRow(dict):
    """Dictionary subclass that supports both key-based and integer-index access.

    Provides compatibility with sqlite3.Row across PostgreSQL results.
    """

    def __init__(self, cols: list[str], values: Sequence[Any]):
        self._values = tuple(values)
        self._cols = cols
        super().__init__(zip(cols, values, strict=False))

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


def db_row_factory(cursor: Any):
    """psycopg 3 row factory that produces DbRow instances."""
    if cursor.description is None:
        return None
    cols = [col.name for col in cursor.description]

    def make_row(values: Sequence[Any]) -> DbRow:
        return DbRow(cols, values)

    return make_row


def translate_placeholders(sql: str) -> str:
    """Translates SQLite '?' parameter placeholders to PostgreSQL '%s' style,
    skipping characters inside single and double quoted literals.
    """
    parts: list[str] = []
    in_quote = False
    quote_char = ""
    for char in sql:
        if in_quote:
            parts.append(char)
            if char == quote_char:
                in_quote = False
        else:
            if char in ("'", '"'):
                in_quote = True
                quote_char = char
                parts.append(char)
            elif char == "?":
                parts.append("%s")
            else:
                parts.append(char)
    return "".join(parts)


class DatabaseConnection:
    """Unified wrapper around sqlite3.Connection and psycopg.Connection."""

    def __init__(self, raw_conn: Any, db_type: str):
        self._raw_conn = raw_conn
        self.db_type = db_type

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> Any:
        if self.db_type == "postgresql":
            translated = translate_placeholders(sql)
            if params is None:
                return self._raw_conn.execute(translated)
            return self._raw_conn.execute(translated, params)
        else:
            if params is None:
                return self._raw_conn.execute(sql)
            return self._raw_conn.execute(sql, params)

    def executemany(self, sql: str, params_seq: Sequence[Sequence[Any]]) -> Any:
        if self.db_type == "postgresql":
            translated = translate_placeholders(sql)
            with self._raw_conn.cursor() as cur:
                return cur.executemany(translated, params_seq)
        else:
            return self._raw_conn.executemany(sql, params_seq)

    def executescript(self, script: str) -> Any:
        if hasattr(self._raw_conn, "executescript"):
            return self._raw_conn.executescript(script)
        return self._raw_conn.execute(script)

    def commit(self) -> None:
        self._raw_conn.commit()

    def rollback(self) -> None:
        self._raw_conn.rollback()

    def cursor(self) -> Any:
        return self._raw_conn.cursor()

    @property
    def raw_conn(self) -> Any:
        return self._raw_conn


class DatabaseEngine:
    """Manages database connection lifecycle, pooling, and health telemetry.

    Supports:
      - PostgreSQL via psycopg 3 ConnectionPool.
      - SQLite via WAL mode sqlite3 connection.
      - Refuses silent fallback when PostgreSQL is configured.
    """

    def __init__(self, config: AppSettings = settings):
        self.config = config
        self.db_type: str = "sqlite"
        self.is_connected: bool = False
        self.last_error: str | None = None
        self.pool: Any = None
        self.db_path: Path | None = None
        self.db_name: str = "metadata.db"

        url = config.database_url
        if url and (url.startswith("postgresql://") or url.startswith("postgres://")):
            self.db_type = "postgresql"
            self._init_postgresql(url)
        elif url and url.startswith("sqlite://"):
            self.db_type = "sqlite"
            parsed = urlparse(url)
            path_str = parsed.path.lstrip("/") if parsed.netloc == "" else parsed.netloc + parsed.path
            self.db_path = Path(path_str) if path_str else Path(config.data_dir) / "metadata.db"
            self.db_name = self.db_path.name
            self.is_connected = True
        else:
            self.db_type = "sqlite"
            self.db_path = Path(config.data_dir) / "metadata.db"
            self.db_name = self.db_path.name
            self.is_connected = True

    def _init_postgresql(self, url: str) -> None:
        """Initialize PostgreSQL connection pool and verify startup connectivity."""
        try:
            from psycopg_pool import ConnectionPool

            parsed = urlparse(url)
            self.db_name = parsed.path.lstrip("/") or "network_twin"

            self.pool = ConnectionPool(
                conninfo=url,
                min_size=1,
                max_size=10,
                timeout=3.0,
                kwargs={"row_factory": db_row_factory},
                open=False,
            )
            self.pool.open()
            atexit.register(self._atexit_close)

            # Test connection immediately
            with self.pool.connection() as conn:
                cur = conn.execute("SELECT 1;")
                cur.fetchone()

            self.is_connected = True
            self.last_error = None
            logger.info("PostgreSQL database connection pool established successfully (database: %s)", self.db_name)
        except Exception as e:
            self.is_connected = False
            self.last_error = f"{type(e).__name__}: {e}"
            logger.error("Failed to connect to configured PostgreSQL database: %s", self.last_error)
            if self.config.require_database:
                raise DatabaseConnectionError(f"PostgreSQL connection failed: {self.last_error}") from e

    @contextmanager
    def get_connection(self) -> Generator[DatabaseConnection, None, None]:
        """Provides a database connection with transaction boundaries.

        Commits on normal exit, rolls back on exception.
        """
        if self.db_type == "postgresql":
            if not self.is_connected or self.pool is None:
                # Attempt one retry if pool failed previously
                if self.config.database_url:
                    self._init_postgresql(self.config.database_url)
                if not self.is_connected or self.pool is None:
                    raise DatabaseConnectionError(
                        f"Configured PostgreSQL database is unavailable: {self.last_error}. "
                        "Application will not silently fall back to SQLite."
                    )

            conn = self.pool.getconn()
            wrapper = DatabaseConnection(conn, "postgresql")
            try:
                yield wrapper
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                self.pool.putconn(conn)
        else:
            if self.db_path is None:
                self.db_path = Path(self.config.data_dir) / "metadata.db"
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            raw_conn = sqlite3.connect(str(self.db_path), timeout=30.0)
            raw_conn.row_factory = sqlite3.Row
            raw_conn.execute("PRAGMA journal_mode=WAL;")
            raw_conn.execute("PRAGMA foreign_keys=ON;")
            wrapper = DatabaseConnection(raw_conn, "sqlite")
            try:
                yield wrapper
                raw_conn.commit()
            except Exception:
                raw_conn.rollback()
                raise
            finally:
                raw_conn.close()

    def check_health(self) -> dict[str, Any]:
        """Inspects connection status, schema version, and pool health."""
        if self.db_type == "postgresql":
            if not self.is_connected or self.pool is None:
                return {
                    "backend": "postgresql",
                    "connected": False,
                    "database_name": self.db_name,
                    "schema_version": None,
                    "pool_stats": None,
                    "error": self.last_error or "PostgreSQL connection pool not initialized",
                }
            try:
                with self.get_connection() as conn:
                    cur = conn.execute("SELECT MAX(version) FROM schema_migrations;")
                    row = cur.fetchone()
                    version = row[0] if row and row[0] is not None else 0
                return {
                    "backend": "postgresql",
                    "connected": True,
                    "database_name": self.db_name,
                    "schema_version": version,
                    "pool_stats": {
                        "min_size": self.pool.min_size,
                        "max_size": self.pool.max_size,
                    },
                    "error": None,
                }
            except Exception as e:
                self.is_connected = False
                self.last_error = str(e)
                return {
                    "backend": "postgresql",
                    "connected": False,
                    "database_name": self.db_name,
                    "schema_version": None,
                    "pool_stats": None,
                    "error": str(e),
                }
        else:
            # SQLite check
            try:
                with self.get_connection() as conn:
                    cur = conn.execute("SELECT MAX(version) FROM schema_migrations;")
                    row = cur.fetchone()
                    version = row[0] if row and row[0] is not None else 0
                return {
                    "backend": "sqlite",
                    "connected": True,
                    "database_name": self.db_name,
                    "schema_version": version,
                    "pool_stats": None,
                    "error": None,
                }
            except Exception as e:
                return {
                    "backend": "sqlite",
                    "connected": False,
                    "database_name": self.db_name,
                    "schema_version": None,
                    "pool_stats": None,
                    "error": str(e),
                }

    def _atexit_close(self) -> None:
        """Silent cleanup hook for interpreter shutdown."""
        try:
            if self.pool is not None:
                logging.getLogger("psycopg.pool").setLevel(logging.CRITICAL)
                self.pool.close(timeout=0.0)
        except Exception:
            pass

    def close(self) -> None:
        """Closes any open connection pools."""
        if self.pool is not None:
            try:
                self.pool.close(timeout=1.0)
            except Exception as e:
                logger.warning("Error closing PostgreSQL connection pool: %s", e)
            self.pool = None
            self.is_connected = False


# Shared default engine instance
db_engine = DatabaseEngine()
