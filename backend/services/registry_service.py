"""
Persistent endpoint registry backed by SQLite.
Users have hashed passwords. All registered endpoints survive server restarts.
"""
import json
import logging
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import bcrypt

from backend.models.endpoint_model import (
    EndpointConfig,
    EndpointConfigCreate,
    EndpointConfigUpdate,
    InputField,
)

logger = logging.getLogger(__name__)

# ── Database location ──────────────────────────────────────────────────────────
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "registry.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ── Schema ─────────────────────────────────────────────────────────────────────
_DDL = """
CREATE TABLE IF NOT EXISTS endpoints (
    username        TEXT    NOT NULL,
    endpoint_name   TEXT    NOT NULL,
    input_fields    TEXT    NOT NULL,
    output_schema   TEXT    NOT NULL,
    ai_prompt       TEXT    NOT NULL,
    description     TEXT,
    gemini_api_key  TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    PRIMARY KEY (username, endpoint_name)
);

CREATE TABLE IF NOT EXISTS users (
    username        TEXT    PRIMARY KEY,
    password_hash   TEXT    NOT NULL,
    gemini_api_key  TEXT,
    token           TEXT
);
"""


@contextmanager
def _conn():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _init_db() -> None:
    with _conn() as con:
        con.executescript(_DDL)

    # Migration: add password_hash column to users if upgrading from old schema
    with _conn() as con:
        cols = [r[1] for r in con.execute("PRAGMA table_info(users)").fetchall()]
        if "password_hash" not in cols:
            con.execute("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''")
        if "token" not in cols:
            con.execute("ALTER TABLE users ADD COLUMN token TEXT")


_init_db()


# ── Password helpers ───────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ── Serialisation helpers ──────────────────────────────────────────────────────

def _row_to_config(row: sqlite3.Row) -> EndpointConfig:
    input_fields = [InputField(**f) for f in json.loads(row["input_fields"])]
    return EndpointConfig(
        endpoint_name=row["endpoint_name"],
        username=row["username"],
        input_fields=input_fields,
        output_schema=json.loads(row["output_schema"]),
        ai_prompt=row["ai_prompt"],
        description=row["description"],
        gemini_api_key=row["gemini_api_key"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


# ── User management ────────────────────────────────────────────────────────────

def register_user(username: str, password: str, gemini_api_key: Optional[str] = None) -> None:
    """Create a new user. Raises ValueError if username already exists."""
    username = username.lower()
    with _conn() as con:
        existing = con.execute(
            "SELECT username FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            raise ValueError(f"Username '{username}' is already taken.")
        con.execute(
            "INSERT INTO users (username, password_hash, gemini_api_key) VALUES (?, ?, ?)",
            (username, _hash_password(password), gemini_api_key),
        )
    logger.info("Registered new user: %s", username)


def authenticate_user(username: str, password: str) -> Optional[str]:
    """
    Verify credentials. On success, generates + stores a session token and returns it.
    Returns None if credentials are invalid.
    """
    username = username.lower()
    with _conn() as con:
        row = con.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not row or not _verify_password(password, row["password_hash"]):
            return None
        token = secrets.token_urlsafe(32)
        con.execute("UPDATE users SET token = ? WHERE username = ?", (token, username))
    logger.info("User logged in: %s", username)
    return token


def verify_token(username: str, token: str) -> bool:
    """Check that a bearer token matches the stored token for this user."""
    username = username.lower()
    with _conn() as con:
        row = con.execute(
            "SELECT token FROM users WHERE username = ?", (username,)
        ).fetchone()
    return bool(row and row["token"] and secrets.compare_digest(row["token"], token))


def verify_password_for_user(username: str, password: str) -> bool:
    """Lightweight credential check without issuing a token."""
    username = username.lower()
    with _conn() as con:
        row = con.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return bool(row and _verify_password(password, row["password_hash"]))


def upsert_user_api_key(username: str, gemini_api_key: str) -> None:
    """Update a user's stored Gemini API key (user must already exist)."""
    with _conn() as con:
        con.execute(
            "UPDATE users SET gemini_api_key = ? WHERE username = ?",
            (gemini_api_key, username.lower()),
        )
    logger.info("Updated Gemini API key for user: %s", username)


def get_user_api_key(username: str) -> Optional[str]:
    with _conn() as con:
        row = con.execute(
            "SELECT gemini_api_key FROM users WHERE username = ?",
            (username.lower(),),
        ).fetchone()
    return row["gemini_api_key"] if row else None


# ── Endpoint CRUD ──────────────────────────────────────────────────────────────

def register_endpoint(payload: EndpointConfigCreate) -> EndpointConfig:
    username = payload.username.lower()
    endpoint_name = payload.endpoint_name.lower()

    gemini_api_key = payload.gemini_api_key or get_user_api_key(username)
    if not gemini_api_key:
        raise ValueError(
            f"No Gemini API key found for user '{username}'. "
            "Either pass gemini_api_key in this request or set it via POST /users/api-key."
        )

    upsert_user_api_key(username, gemini_api_key)

    now = datetime.utcnow().isoformat()
    with _conn() as con:
        con.execute(
            """
            INSERT INTO endpoints
                (username, endpoint_name, input_fields, output_schema,
                 ai_prompt, description, gemini_api_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, endpoint_name) DO UPDATE SET
                input_fields   = excluded.input_fields,
                output_schema  = excluded.output_schema,
                ai_prompt      = excluded.ai_prompt,
                description    = excluded.description,
                gemini_api_key = excluded.gemini_api_key
            """,
            (
                username,
                endpoint_name,
                json.dumps([f.model_dump() for f in payload.input_fields]),
                json.dumps(payload.output_schema),
                payload.ai_prompt,
                payload.description,
                gemini_api_key,
                now,
            ),
        )
    logger.info("Registered endpoint: /%s/%s", username, endpoint_name)
    return get_endpoint(username, endpoint_name)


def update_endpoint(
    username: str, endpoint_name: str, patch: EndpointConfigUpdate
) -> Optional[EndpointConfig]:
    """
    Partially update an existing endpoint. Only fields explicitly set in `patch` are changed.
    Returns the updated config, or None if the endpoint doesn't exist.
    """
    username = username.lower()
    endpoint_name = endpoint_name.lower()

    existing = get_endpoint(username, endpoint_name)
    if not existing:
        return None

    # Build SET clause dynamically from non-None patch fields
    updates: Dict[str, object] = {}
    if patch.input_fields is not None:
        updates["input_fields"] = json.dumps([f.model_dump() for f in patch.input_fields])
    if patch.output_schema is not None:
        updates["output_schema"] = json.dumps(patch.output_schema)
    if patch.ai_prompt is not None:
        updates["ai_prompt"] = patch.ai_prompt
    if patch.description is not None:
        updates["description"] = patch.description
    if patch.gemini_api_key is not None:
        updates["gemini_api_key"] = patch.gemini_api_key
        upsert_user_api_key(username, patch.gemini_api_key)

    if not updates:
        return existing  # nothing to change

    set_clause = ", ".join(f"{col} = ?" for col in updates)
    values = list(updates.values()) + [username, endpoint_name]

    with _conn() as con:
        con.execute(
            f"UPDATE endpoints SET {set_clause} WHERE username = ? AND endpoint_name = ?",
            values,
        )

    logger.info("Updated endpoint: /%s/%s | fields: %s", username, endpoint_name, list(updates))
    return get_endpoint(username, endpoint_name)


def get_endpoint(username: str, endpoint_name: str) -> Optional[EndpointConfig]:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM endpoints WHERE username = ? AND endpoint_name = ?",
            (username.lower(), endpoint_name.lower()),
        ).fetchone()
    return _row_to_config(row) if row else None


def list_endpoints(username: Optional[str] = None) -> List[EndpointConfig]:
    with _conn() as con:
        if username:
            rows = con.execute(
                "SELECT * FROM endpoints WHERE username = ?",
                (username.lower(),),
            ).fetchall()
        else:
            rows = con.execute("SELECT * FROM endpoints").fetchall()
    return [_row_to_config(r) for r in rows]


def delete_endpoint(username: str, endpoint_name: str) -> bool:
    with _conn() as con:
        cur = con.execute(
            "DELETE FROM endpoints WHERE username = ? AND endpoint_name = ?",
            (username.lower(), endpoint_name.lower()),
        )
    if cur.rowcount:
        logger.info("Deleted endpoint: /%s/%s", username, endpoint_name)
        return True
    return False