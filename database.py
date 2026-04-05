"""SQLite-backed storage for API keys and monthly usage tracking."""

import sqlite3
import secrets
import datetime
from contextlib import contextmanager

UTC = datetime.timezone.utc

DB_PATH = "email_validator.db"
FREE_TIER_LIMIT = 100  # requests per month


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db():
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if they do not already exist."""
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key        TEXT PRIMARY KEY,
                owner      TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage (
                key        TEXT NOT NULL,
                year_month TEXT NOT NULL,  -- format: YYYY-MM
                count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (key, year_month),
                FOREIGN KEY (key) REFERENCES api_keys(key)
            )
            """
        )


def create_api_key(owner: str) -> str:
    """Generate a new API key for *owner* and persist it.  Returns the key."""
    key = secrets.token_urlsafe(32)
    now = datetime.datetime.now(UTC).isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT INTO api_keys (key, owner, created_at) VALUES (?, ?, ?)",
            (key, owner, now),
        )
    return key


def _current_year_month() -> str:
    return datetime.datetime.now(UTC).strftime("%Y-%m")


def is_valid_key(key: str) -> bool:
    """Return True if *key* exists in the database."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM api_keys WHERE key = ?", (key,)
        ).fetchone()
    return row is not None


def get_monthly_usage(key: str) -> int:
    """Return the number of requests made by *key* in the current month."""
    ym = _current_year_month()
    with get_db() as conn:
        row = conn.execute(
            "SELECT count FROM usage WHERE key = ? AND year_month = ?",
            (key, ym),
        ).fetchone()
    return row["count"] if row else 0


def increment_usage(key: str) -> int:
    """Increment usage counter for *key* this month and return new count."""
    ym = _current_year_month()
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO usage (key, year_month, count)
            VALUES (?, ?, 1)
            ON CONFLICT(key, year_month) DO UPDATE SET count = count + 1
            """,
            (key, ym),
        )
        row = conn.execute(
            "SELECT count FROM usage WHERE key = ? AND year_month = ?",
            (key, ym),
        ).fetchone()
    return row["count"]
