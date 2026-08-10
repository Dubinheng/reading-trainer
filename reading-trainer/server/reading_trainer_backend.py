"""Reading Trainer v2 backend.

This module is deliberately self-contained so the production application can
mount it with ``register_reading_trainer_v2(app)``.  It keeps Reading Trainer
state in its own SQLite database and does not import or mutate the existing
resume database.

The API uses an HttpOnly cookie for the session identifier.  Session tokens,
password hashes, provider keys, and Feishu credentials are kept out of JSON
responses and out of Feishu record fields.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

try:  # Flask is supplied by the production application.
    from flask import Blueprint, current_app, g, jsonify, make_response, request, session
except ModuleNotFoundError:  # pragma: no cover - useful error for bare imports
    Blueprint = None  # type: ignore[assignment,misc]
    current_app = g = jsonify = make_response = request = session = None  # type: ignore[assignment]

try:
    import requests
except ModuleNotFoundError:  # pragma: no cover - live integrations are optional
    requests = None  # type: ignore[assignment]


API_PREFIX = "/reading-trainer/api/v2"
DB_FILENAME = "reading_trainer.db"
LEGACY_FILENAME = ".reading_trainer_state.json"
GLOBAL_OWNER_ID = "__global__"
BUSINESS_SECTIONS = (
    "settings",
    "favorites",
    "vbook",
    "wbook",
    "grades",
    "library",
)
ROLES = ("student", "teacher", "admin")

# AI calls can legitimately take longer than a normal API request (especially
# when a reading passage contains several question types), but the values are
# still bounded so a client/configuration mistake cannot pin a worker forever.
AI_TIMEOUT_DEFAULT_SECONDS = 110
AI_TIMEOUT_MIN_SECONDS = 30
# The browser waits 310 seconds for one batch.  Keep a margin so the backend
# can always return its structured timeout error before the browser aborts.
AI_TIMEOUT_MAX_SECONDS = 300
AI_MAX_TOKENS_MIN = 256
AI_MAX_TOKENS_MAX = 8192

# These identifiers are the ones used by the existing remote app.py.  They
# are identifiers, not credentials.  Every value can be overridden with a
# FEISHU_* environment variable.
FEISHU_APP_ID = "cli_aacb9445df389be8"
FEISHU_BASE_TOKEN = "TmNvbO1ypahHLksucmFcKpZJnJe"
FEISHU_TABLES = {
    "accounts": "tblCtUT0ycLQ6BNu",
    "classes": "tblkUyz3diZ7EZ8l",
    "wbook": "tblVR35eEUrM3ES5",
    "vbook": "tblbIuMHf8RwoVkT",
    "grades": "tbl0KO8yrcZMiTzP",
    "library": "tblFfhGzCg9EL1n5",
    "invites": "tblsCIOlB3QCp1D9",
    "settings": "tbl062TIlW8iEPXB",
}
_FEISHU_TOKEN_LOCK = threading.Lock()

_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_-])(pass(?:word)?|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|secret|token|session|cookie|authorization|bearer|private[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
_SENSITIVE_EXACT_KEYS = {
    "pass",
    "password",
    "password_hash",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
    "client_secret",
    "secret",
    "session",
    "sessions",
    "cookie",
    "authorization",
    "token",
    "key",
}
_SECTION_ALIASES = {
    "settings": "settings",
    "setting": "settings",
    "favs": "favorites",
    "favorite": "favorites",
    "favorites": "favorites",
    "vbook": "vbook",
    "vocabulary": "vbook",
    "wbook": "wbook",
    "wrongbook": "wbook",
    "grades": "grades",
    "grade": "grades",
    "library": "library",
    "libraries": "library",
}


def _is_sensitive_key(key: Any) -> bool:
    """Return whether a JSON field name carries a credential or session."""

    raw = str(key).strip().replace(" ", "_")
    raw = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", raw)
    normalized = raw.lower()
    return normalized in _SENSITIVE_EXACT_KEYS or bool(_SENSITIVE_KEY_RE.search(normalized))


def sanitize_json(value: Any) -> Any:
    """Recursively remove credential-like keys from JSON-compatible data.

    The same function is used before storage and before every external
    response.  This intentionally drops fields rather than masking them so a
    caller cannot infer the original value from a response.
    """

    if isinstance(value, Mapping):
        return {
            str(key): sanitize_json(item)
            for key, item in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_json(item) for item in value]
    return value


def _safe_text(value: Any, limit: int = 500) -> str:
    if value is None:
        return ""
    return str(value).strip()[:limit]


def hash_password(password: str) -> str:
    """Create a salted password hash using only Python's standard library."""

    raw = str(password).encode("utf-8")
    salt = secrets.token_bytes(16)
    rounds = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", raw, salt, rounds)
    return "pbkdf2_sha256${}${}${}".format(
        rounds,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, encoded: str) -> bool:
    """Verify hashes produced by :func:`hash_password`.

    A small compatibility branch accepts the legacy SHA-256 format only when
    explicitly marked as ``legacy_sha256$``.  Plaintext is never treated as a
    valid stored hash.
    """

    if not encoded or not isinstance(encoded, str):
        return False
    if encoded.startswith("pbkdf2_sha256$"):
        try:
            _, rounds_text, salt_hex, digest_hex = encoded.split("$", 3)
            rounds = int(rounds_text)
            if rounds < 100_000 or len(salt_hex) < 16:
                return False
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            actual = hashlib.pbkdf2_hmac(
                "sha256", str(password).encode("utf-8"), salt, rounds
            )
            return hmac.compare_digest(actual, expected)
        except (TypeError, ValueError):
            return False
    if encoded.startswith("legacy_sha256$"):
        expected = encoded.split("$", 1)[1]
        actual = hashlib.sha256(str(password).encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual, expected)
    return False


def _legacy_password_hash(raw: Mapping[str, Any]) -> str:
    """Hash a legacy credential without returning or persisting plaintext."""

    candidate_hash = raw.get("password_hash")
    if isinstance(candidate_hash, str):
        if candidate_hash.startswith(("pbkdf2_sha256$", "legacy_sha256$")):
            return candidate_hash
        # The previous remote app.py stored a bare SHA-256 digest.  Preserve
        # login compatibility while making the legacy format explicit.
        if re.fullmatch(r"[0-9a-fA-F]{64}", candidate_hash):
            return "legacy_sha256$" + candidate_hash.lower()
    for key in ("pass", "password", "pwd"):
        value = raw.get(key)
        if value is not None and str(value):
            return hash_password(str(value))
    return ""


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _now() -> int:
    return int(time.time())


def _default_path(config_value: Any, env_name: str, default: Path) -> Path:
    configured = config_value or os.environ.get(env_name) or default
    return Path(configured).expanduser().resolve()


class ReadingTrainerStore:
    """SQLite persistence for auth, documents, and migration metadata."""

    def __init__(
        self,
        app: Any | None = None,
        *,
        db_path: str | os.PathLike[str] | None = None,
        legacy_state_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.app = app
        root = Path(__file__).resolve().parent.parent
        app_config = getattr(app, "config", {}) if app is not None else {}
        self.db_path = _default_path(
            db_path
            or app_config.get("READING_TRAINER_DB_PATH")
            or app_config.get("READING_TRAINER_DB")
            or os.environ.get("READING_TRAINER_DB"),
            "READING_TRAINER_DB_PATH",
            root / DB_FILENAME,
        )
        if self.db_path.name.lower() == "resumes.db":
            raise ValueError("Reading Trainer requires a separate database; resumes.db is not allowed")
        self.legacy_state_path = _default_path(
            legacy_state_path
            or app_config.get("READING_TRAINER_STATE_PATH")
            or app_config.get("READING_TRAINER_LEGACY_STATE_PATH")
            or os.environ.get("READING_TRAINER_LEGACY_STATE_PATH"),
            "READING_TRAINER_STATE_PATH",
            root / LEGACY_FILENAME,
        )
        self.session_ttl = int(
            app_config.get("READING_TRAINER_SESSION_TTL", os.environ.get("READING_TRAINER_SESSION_TTL", 30 * 86400))
        )
        self._initialized = False

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.db_path), timeout=20)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return {"initialized": True, "legacy_imported": bool(self.meta_get("legacy_state_imported"))}
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    owner_id TEXT NOT NULL,
                    section TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (owner_id, section)
                );
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'admin')),
                    password_hash TEXT NOT NULL DEFAULT '',
                    created_by TEXT,
                    class_id TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE (username COLLATE NOCASE, role)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
                CREATE TABLE IF NOT EXISTS invites (
                    code TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    teacher_id TEXT,
                    class_id TEXT,
                    data_json TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS classes (
                    id TEXT PRIMARY KEY,
                    teacher_id TEXT,
                    data_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS private_config (
                    name TEXT PRIMARY KEY,
                    data_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                """
            )
        imported = False
        with self.connect() as connection:
            marker = connection.execute(
                "SELECT value FROM meta WHERE key = 'legacy_state_imported'"
            ).fetchone()
        if marker is None and bool(self._config_value("READING_TRAINER_AUTO_IMPORT_LEGACY", True)):
            raw = self._read_legacy_file()
            if isinstance(raw, Mapping):
                summary = import_legacy_state(self, raw)
                imported = bool(summary.get("changed"))
                self._import_private_legacy_config(raw)
            self.meta_set("legacy_state_imported", str(_now()))
        self._bootstrap_admin()
        self._initialized = True
        return {"initialized": True, "legacy_imported": imported}

    def _import_private_legacy_config(self, raw: Mapping[str, Any]) -> None:
        state = _unwrap_legacy_state(raw)
        ai = state.get("ai")
        if isinstance(ai, Mapping):
            existing = self.get_private_config("ai")
            if not existing:
                self.put_private_config(
                    "ai",
                    {
                        "provider": ai.get("provider"),
                        "endpoint": ai.get("endpoint"),
                        "model": ai.get("model"),
                        "enabled": bool(ai.get("enabled")),
                        "api_key": ai.get("api_key") or ai.get("apiKey") or ai.get("key"),
                    },
                )
        feishu = state.get("feishu")
        if isinstance(feishu, Mapping) and not self.get_private_config("feishu"):
            self.put_private_config("feishu", {"enabled": bool(feishu.get("enabled"))})

    def _config_value(self, key: str, default: Any = None) -> Any:
        config = getattr(self.app, "config", {}) if self.app is not None else {}
        if key in config:
            return config[key]
        return default

    def _read_legacy_file(self) -> Mapping[str, Any] | None:
        try:
            with self.legacy_state_path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, Mapping) else None
        except (OSError, ValueError, TypeError):
            return None

    def _bootstrap_admin(self) -> None:
        configured_username = self._config_value(
            "READING_TRAINER_ADMIN_USERNAME",
            os.environ.get("READING_TRAINER_ADMIN_USERNAME")
            or os.environ.get("READING_TRAINER_ADMIN_USER"),
        )
        configured_password = self._config_value(
            "READING_TRAINER_ADMIN_PASSWORD",
            os.environ.get("READING_TRAINER_ADMIN_PASSWORD")
            or os.environ.get("READING_TRAINER_ADMIN_PASS"),
        )
        if not configured_username or not configured_password:
            return
        if self.find_user(str(configured_username), "admin") is None:
            self.upsert_user(
                {
                    "id": "admin_" + uuid.uuid4().hex,
                    "username": str(configured_username),
                    "role": "admin",
                    "password_hash": hash_password(str(configured_password)),
                    "created_at": _now(),
                }
            )

    def meta_get(self, key: str) -> str | None:
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None

    def meta_set(self, key: str, value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )

    def get_private_config(self, name: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT data_json FROM private_config WHERE name = ?", (str(name),)
            ).fetchone()
        if not row:
            return {}
        try:
            value = json.loads(row[0])
        except (TypeError, ValueError):
            return {}
        return dict(value) if isinstance(value, Mapping) else {}

    def put_private_config(self, name: str, data: Mapping[str, Any]) -> dict[str, Any]:
        allowed: dict[str, tuple[str, ...]] = {
            "ai": ("provider", "endpoint", "model", "enabled", "api_key"),
            "feishu": ("enabled",),
        }
        if name not in allowed:
            raise ValueError("unsupported private config")
        clean = {key: data.get(key) for key in allowed[name] if key in data}
        if name == "ai":
            old = self.get_private_config(name)
            if not clean.get("api_key") and old.get("api_key"):
                clean["api_key"] = old["api_key"]
            clean["endpoint"] = _safe_text(clean.get("endpoint"), 1000)
            clean["model"] = _safe_text(clean.get("model"), 200)
            clean["provider"] = _safe_text(clean.get("provider"), 80)
            clean["api_key"] = _safe_text(clean.get("api_key"), 4000)
            clean["enabled"] = bool(clean.get("enabled"))
        elif name == "feishu":
            clean["enabled"] = bool(clean.get("enabled"))
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO private_config(name, data_json, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (name, _json_dumps(clean), _now()),
            )
        return clean

    def get_document(self, owner_id: str, section: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT data_json FROM documents WHERE owner_id = ? AND section = ?",
                (owner_id, section),
            ).fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except (TypeError, ValueError):
            return default

    def put_document(self, owner_id: str, section: str, data: Any) -> Any:
        clean = sanitize_json(data)
        serialized = _json_dumps(clean)
        if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
            raise ValueError("document is too large")
        now = _now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (owner_id, section, serialized, now),
            )
        return clean

    def list_documents(self, sections: Iterable[str] | None = None) -> list[dict[str, Any]]:
        values = tuple(sections or ())
        with self.connect() as connection:
            if values:
                placeholders = ",".join("?" for _ in values)
                rows = connection.execute(
                    f"SELECT owner_id, section, data_json, updated_at FROM documents WHERE section IN ({placeholders})",
                    values,
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT owner_id, section, data_json, updated_at FROM documents"
                ).fetchall()
        result = []
        for row in rows:
            try:
                data = json.loads(row[2])
            except (TypeError, ValueError):
                data = None
            result.append(
                {
                    "owner_id": row[0],
                    "section": row[1],
                    "data": sanitize_json(data),
                    "updated_at": row[3],
                }
            )
        return result

    def find_user(self, username: str, role: str | None = None) -> dict[str, Any] | None:
        with self.connect() as connection:
            if role:
                row = connection.execute(
                    "SELECT * FROM users WHERE username = ? COLLATE NOCASE AND role = ?",
                    (username, role),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                    (username,),
                ).fetchone()
        return dict(row) if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

    def list_users(self, role: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if role:
                rows = connection.execute("SELECT * FROM users WHERE role = ? ORDER BY created_at", (role,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM users ORDER BY created_at").fetchall()
        return [dict(row) for row in rows]

    def replace_public_users(self, items: Iterable[Mapping[str, Any]]) -> None:
        incoming: set[str] = set()
        for item in items:
            user_id = _safe_text(item.get("id"), 200)
            role = _safe_text(item.get("role"), 20).lower()
            current = self.get_user(user_id) if user_id else None
            if not current or current.get("role") == "admin" or role not in ("student", "teacher"):
                continue
            incoming.add(user_id)
            self.upsert_user(
                {
                    "id": user_id,
                    "username": item.get("username") or current.get("username"),
                    "role": role,
                    "password_hash": current.get("password_hash"),
                    "created_by": item.get("created_by") or item.get("createdBy"),
                    "class_id": item.get("class_id") or item.get("classId"),
                    "created_at": current.get("created_at"),
                }
            )
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT id FROM users WHERE role IN ('student','teacher')"
            ).fetchall()
            for row in existing:
                user_id = str(row[0])
                if user_id not in incoming:
                    connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                    connection.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def upsert_user(self, user: Mapping[str, Any]) -> dict[str, Any]:
        user_id = _safe_text(user.get("id"), 200) or uuid.uuid4().hex
        username = _safe_text(user.get("username"), 120)
        role = _safe_text(user.get("role"), 20).lower()
        if not username or role not in ROLES:
            raise ValueError("invalid user")
        now = _now()
        password_hash = str(user.get("password_hash") or "")
        if password_hash and not password_hash.startswith(("pbkdf2_sha256$", "legacy_sha256$")):
            password_hash = ""
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO users(id, username, role, password_hash, created_by, class_id, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET username = excluded.username, role = excluded.role, "
                "password_hash = CASE WHEN excluded.password_hash <> '' THEN excluded.password_hash ELSE users.password_hash END, "
                "created_by = excluded.created_by, class_id = excluded.class_id, updated_at = excluded.updated_at",
                (
                    user_id,
                    username,
                    role,
                    password_hash,
                    _safe_text(user.get("created_by"), 200) or None,
                    _safe_text(user.get("class_id"), 200) or None,
                    int(user.get("created_at") or now),
                    now,
                ),
            )
        return self.get_user(user_id) or {}

    def create_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = _now()
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            connection.execute(
                "INSERT INTO sessions(token_hash, user_id, created_at, expires_at, last_seen) VALUES (?, ?, ?, ?, ?)",
                (token_hash, user_id, now, now + self.session_ttl, now),
            )
        return token

    def session_user(self, token: str | None) -> dict[str, Any] | None:
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = _now()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT user_id, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not row:
                return None
            if int(row[1]) <= now:
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            connection.execute(
                "UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, token_hash)
            )
        return self.get_user(str(row[0]))

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))

    def list_classes(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM classes ORDER BY updated_at").fetchall()
        result = []
        for row in rows:
            try:
                data = json.loads(row[2])
            except (TypeError, ValueError):
                data = {}
            data = sanitize_json(data) if isinstance(data, Mapping) else {}
            data.setdefault("id", row[0])
            if row[1]:
                data.setdefault("teacherId", row[1])
            result.append(data)
        return result

    def upsert_class(self, item: Mapping[str, Any]) -> None:
        class_id = _safe_text(item.get("id") or item.get("classId"), 200)
        if not class_id:
            return
        teacher_id = _safe_text(item.get("teacherId") or item.get("teacher_id"), 200) or None
        clean = sanitize_json(dict(item))
        clean["id"] = class_id
        now = _now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO classes(id, teacher_id, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET teacher_id = excluded.teacher_id, data_json = excluded.data_json, updated_at = excluded.updated_at",
                (class_id, teacher_id, _json_dumps(clean), now),
            )

    def replace_classes(self, items: Iterable[Mapping[str, Any]]) -> None:
        incoming: set[str] = set()
        for item in items:
            class_id = _safe_text(item.get("id") or item.get("classId"), 200)
            if class_id:
                incoming.add(class_id)
                self.upsert_class(item)
        with self.connect() as connection:
            rows = connection.execute("SELECT id FROM classes").fetchall()
            for row in rows:
                if str(row[0]) not in incoming:
                    connection.execute("DELETE FROM classes WHERE id = ?", (str(row[0]),))

    def find_invite(self, code: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM invites WHERE code = ? COLLATE NOCASE", (code,)
            ).fetchone()
        if not row:
            return None
        try:
            data = json.loads(row[4])
        except (TypeError, ValueError):
            data = {}
        data = sanitize_json(data) if isinstance(data, Mapping) else {}
        data.update(
            {
                "code": row[0],
                "role": row[1],
                "teacherId": row[2],
                "classId": row[3],
                "used": bool(row[5]),
            }
        )
        return data

    def list_invites(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT code FROM invites ORDER BY updated_at").fetchall()
        return [item for row in rows if (item := self.find_invite(str(row[0]))) is not None]

    def upsert_invite(self, item: Mapping[str, Any]) -> None:
        code = _safe_text(item.get("code"), 120).upper()
        role = _safe_text(item.get("role"), 20).lower()
        if not code or role not in ("student", "teacher"):
            return
        teacher_id = _safe_text(item.get("teacherId") or item.get("createdBy"), 200) or None
        class_id = _safe_text(item.get("classId"), 200) or None
        clean = sanitize_json(dict(item))
        clean["code"] = code
        now = _now()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO invites(code, role, teacher_id, class_id, data_json, used, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(code) DO UPDATE SET role = excluded.role, teacher_id = excluded.teacher_id, class_id = excluded.class_id, "
                "data_json = excluded.data_json, used = excluded.used, updated_at = excluded.updated_at",
                (code, role, teacher_id, class_id, _json_dumps(clean), int(bool(item.get("used"))), now),
            )

    def replace_invites(self, items: Iterable[Mapping[str, Any]]) -> None:
        incoming: set[str] = set()
        for item in items:
            code = _safe_text(item.get("code"), 120).upper()
            if code:
                incoming.add(code)
                self.upsert_invite(item)
        with self.connect() as connection:
            rows = connection.execute("SELECT code FROM invites").fetchall()
            for row in rows:
                if str(row[0]).upper() not in incoming:
                    connection.execute("DELETE FROM invites WHERE code = ?", (str(row[0]),))

    def consume_invite(self, code: str, account_id: str) -> dict[str, Any] | None:
        code = _safe_text(code, 120).upper()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM invites WHERE code = ? COLLATE NOCASE", (code,)
            ).fetchone()
            if not row or int(row[5]):
                return None
            try:
                data = json.loads(row[4])
            except (TypeError, ValueError):
                data = {}
            data = dict(data) if isinstance(data, Mapping) else {}
            data.update({"used": True, "usedBy": account_id, "usedAt": _now()})
            connection.execute(
                "UPDATE invites SET data_json = ?, used = 1, updated_at = ? WHERE code = ?",
                (_json_dumps(sanitize_json(data)), _now(), code),
            )
            return {"code": row[0], "role": row[1], "teacherId": row[2], "classId": row[3], **data}

    def teacher_can_access(self, teacher_id: str, owner_id: str) -> bool:
        if teacher_id == owner_id:
            return True
        owner = self.get_user(owner_id)
        if not owner:
            return False
        if owner.get("role") != "student":
            return False
        if owner.get("created_by") == teacher_id:
            return True
        class_id = owner.get("class_id")
        if class_id:
            for item in self.list_classes():
                if str(item.get("id")) == str(class_id) and str(
                    item.get("teacherId") or item.get("teacher_id") or ""
                ) == str(teacher_id):
                    return True
        return False

    def clear_expired_sessions(self) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (_now(),))


def _unwrap_legacy_state(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Accept both the old app.py object and localStorage-style snapshots."""

    result = dict(raw)
    for wrapper in ("state", "localStorage", "snapshot"):
        nested = raw.get(wrapper)
        if isinstance(nested, Mapping):
            merged = dict(nested)
            merged.update({key: value for key, value in raw.items() if key != wrapper})
            result = merged
            break
    return result


def _section_name(value: Any) -> str | None:
    name = str(value).strip().lower().replace("-", "_")
    if name.startswith("itr_"):
        name = name[4:]
    return _SECTION_ALIASES.get(name)


def _owner_map(value: Any) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    return all(isinstance(item, (list, Mapping)) for item in value.values())


def _append_document(documents: list[dict[str, Any]], section: str, owner: Any, data: Any) -> None:
    owner_id = _safe_text(owner, 200) or GLOBAL_OWNER_ID
    documents.append(
        {
            "owner_id": owner_id,
            "section": section,
            "data": sanitize_json(data),
        }
    )


def _collect_legacy_records(raw_state: Mapping[str, Any]) -> dict[str, Any]:
    state = _unwrap_legacy_state(raw_state)
    users: list[dict[str, Any]] = []
    invites: list[dict[str, Any]] = []
    classes: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []

    raw_accounts = state.get("accounts", state.get("users", state.get("itr_accounts", [])))
    if isinstance(raw_accounts, Mapping):
        raw_accounts = list(raw_accounts.values())
    if isinstance(raw_accounts, list):
        for raw in raw_accounts[:5000]:
            if not isinstance(raw, Mapping):
                continue
            role = _safe_text(raw.get("role"), 20).lower()
            if role not in ("student", "teacher", "admin"):
                continue
            username = _safe_text(raw.get("username"), 120)
            if not username:
                continue
            users.append(
                {
                    "id": _safe_text(raw.get("id"), 200) or f"{role}_{uuid.uuid4().hex}",
                    "username": username,
                    "role": role,
                    "password_hash": _legacy_password_hash(raw),
                    "created_by": raw.get("created_by") or raw.get("createdBy"),
                    "class_id": raw.get("class_id") or raw.get("classId"),
                    "created_at": raw.get("created_at") or raw.get("createdAt") or _now(),
                }
            )

    admin = state.get("admin") or state.get("itr_admin")
    if isinstance(admin, Mapping) and _safe_text(admin.get("username"), 120):
        users.append(
            {
                "id": _safe_text(admin.get("id"), 200) or "admin_" + uuid.uuid4().hex,
                "username": _safe_text(admin.get("username"), 120),
                "role": "admin",
                "password_hash": _legacy_password_hash(admin),
                "created_by": None,
                "class_id": None,
                "created_at": admin.get("createdAt") or _now(),
            }
        )

    raw_invites = state.get("invites", state.get("itr_invites", []))
    if isinstance(raw_invites, Mapping):
        raw_invites = list(raw_invites.values())
    if isinstance(raw_invites, list):
        invites = [dict(item) for item in raw_invites[:10000] if isinstance(item, Mapping)]

    raw_classes = state.get("classes", state.get("itr_classes", []))
    if isinstance(raw_classes, Mapping):
        raw_classes = list(raw_classes.values())
    if isinstance(raw_classes, list):
        classes = [dict(item) for item in raw_classes[:5000] if isinstance(item, Mapping)]

    # Old remote app.py used ai/feishu, while the HTML used itr_* keys.  AI
    # configuration is intentionally not imported as a document because its
    # key is a credential; ordinary settings remain importable.
    for key, value in state.items():
        section = _section_name(key)
        if not section:
            continue
        if section in ("vbook", "wbook", "grades", "library", "favorites") and _owner_map(value):
            for owner, owner_data in value.items():
                _append_document(documents, section, owner, owner_data)
        else:
            _append_document(documents, section, GLOBAL_OWNER_ID, value)

    prefix_re = re.compile(r"^(?:itr_)?(settings|favs|favorites|vbook|wbook|grades|library)_(.+)$", re.IGNORECASE)
    for key, value in state.items():
        match = prefix_re.match(str(key))
        if match:
            section = _section_name(match.group(1))
            if section:
                _append_document(documents, section, match.group(2), value)

    # A document table snapshot may already be present in an exported state.
    raw_documents = state.get("documents") or state.get("state_documents")
    if isinstance(raw_documents, list):
        for item in raw_documents:
            if not isinstance(item, Mapping):
                continue
            section = _section_name(item.get("section"))
            if section:
                _append_document(documents, section, item.get("owner_id"), item.get("data"))
    elif isinstance(raw_documents, Mapping):
        for owner, owner_docs in raw_documents.items():
            if not isinstance(owner_docs, Mapping):
                continue
            for section_key, data in owner_docs.items():
                section = _section_name(section_key)
                if section:
                    _append_document(documents, section, owner, data)

    # The previous server-side JSON shape kept administrator AI/Feishu
    # settings beside accounts.  Retain their non-sensitive switches and
    # display metadata in the global settings document, while deliberately
    # dropping provider keys and OAuth credentials.
    compatibility_settings: dict[str, Any] = {}
    for item in documents:
        if item["owner_id"] == GLOBAL_OWNER_ID and item["section"] == "settings" and isinstance(item["data"], Mapping):
            compatibility_settings.update(item["data"])
    for legacy_key in ("ai", "feishu"):
        if isinstance(state.get(legacy_key), Mapping):
            compatibility_settings[legacy_key] = sanitize_json(state[legacy_key])
    if compatibility_settings:
        documents = [
            item
            for item in documents
            if not (item["owner_id"] == GLOBAL_OWNER_ID and item["section"] == "settings")
        ]
        _append_document(documents, "settings", GLOBAL_OWNER_ID, compatibility_settings)

    # De-duplicate documents by the last occurrence, preserving the source's
    # natural order for deterministic migration previews.
    unique_documents: dict[tuple[str, str], dict[str, Any]] = {}
    for item in documents:
        unique_documents[(item["owner_id"], item["section"])] = item
    documents = list(unique_documents.values())
    return {"users": users, "invites": invites, "classes": classes, "documents": documents}


def _public_legacy_plan(records: Mapping[str, Any]) -> dict[str, Any]:
    users = [
        {
            "id": item.get("id"),
            "username": item.get("username"),
            "role": item.get("role"),
            "created_by": item.get("created_by"),
            "class_id": item.get("class_id"),
            "has_credential": bool(item.get("password_hash")),
        }
        for item in records.get("users", [])
    ]
    documents = [
        {
            "owner_id": item.get("owner_id"),
            "section": item.get("section"),
            "data": sanitize_json(item.get("data")),
        }
        for item in records.get("documents", [])
    ]
    return {
        "users": users,
        "invites": sanitize_json(records.get("invites", [])),
        "classes": sanitize_json(records.get("classes", [])),
        "documents": documents,
        "counts": {
            "users": len(users),
            "invites": len(records.get("invites", [])),
            "classes": len(records.get("classes", [])),
            "documents": len(documents),
        },
    }


def plan_legacy_migration(legacy: Mapping[str, Any]) -> dict[str, Any]:
    """Return a redacted, side-effect-free migration plan."""

    if not isinstance(legacy, Mapping):
        return {"users": [], "invites": [], "classes": [], "documents": [], "counts": {}}
    return _public_legacy_plan(_collect_legacy_records(legacy))


def import_legacy_state(store: ReadingTrainerStore, legacy: Mapping[str, Any]) -> dict[str, Any]:
    """Idempotently import a legacy snapshot without changing its source file."""

    records = _collect_legacy_records(legacy)
    changed = False
    imported_counts = {"users": 0, "invites": 0, "classes": 0, "documents": 0}
    for user in records["users"]:
        try:
            store.upsert_user(user)
            imported_counts["users"] += 1
            changed = True
        except (sqlite3.IntegrityError, ValueError):
            continue
    for item in records["invites"]:
        before = store.find_invite(_safe_text(item.get("code"), 120).upper()) if item.get("code") else None
        store.upsert_invite(item)
        if not before:
            imported_counts["invites"] += 1
        changed = True
    for item in records["classes"]:
        store.upsert_class(item)
        imported_counts["classes"] += 1
        changed = True
    for item in records["documents"]:
        store.put_document(item["owner_id"], item["section"], item["data"])
        imported_counts["documents"] += 1
        changed = True
    return {
        "changed": changed,
        "imported_counts": imported_counts,
        "counts": _public_legacy_plan(records)["counts"],
    }


def _feishu_env(name: str, *aliases: str) -> str:
    for key in (name,) + aliases:
        value = os.environ.get(key)
        if value:
            return value.strip()
    return ""


def _feishu_token_path(app: Any | None = None) -> Path:
    config = getattr(app, "config", {}) if app is not None else {}
    root = Path(__file__).resolve().parent.parent
    return Path(
        config.get("READING_TRAINER_FEISHU_TOKEN_FILE")
        or _feishu_env("FEISHU_TOKEN_FILE")
        or root / ".feishu_oauth_tokens.json"
    ).expanduser().resolve()


def _feishu_token_file(app: Any | None = None) -> dict[str, Any]:
    path = _feishu_token_path(app)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(value, Mapping):
        return {}
    nested = value.get("data") if isinstance(value.get("data"), Mapping) else value
    return dict(nested) if isinstance(nested, Mapping) else {}


def _write_feishu_token_file(app: Any, value: Mapping[str, Any]) -> None:
    path = _feishu_token_path(app)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with _FEISHU_TOKEN_LOCK:
        temp.write_text(_json_dumps(dict(value)), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, path)


def feishu_config(app: Any | None = None) -> dict[str, Any]:
    config = getattr(app, "config", {}) if app is not None else {}
    token_file = _feishu_token_file(app)
    tables = dict(FEISHU_TABLES)
    configured_tables = config.get("READING_TRAINER_FEISHU_TABLES")
    if isinstance(configured_tables, Mapping):
        tables.update({str(key): str(value) for key, value in configured_tables.items() if value})
    for name in list(tables):
        env_name = "FEISHU_TABLE_" + name.upper()
        value = _feishu_env(env_name, "FEISHU_" + name.upper() + "_TABLE_ID")
        if value:
            tables[name] = value
    # The existing remote app has no dedicated favorites table.  Favorites
    # therefore share the documented library table unless a deployment
    # supplies FEISHU_TABLE_FAVORITES explicitly.
    tables["favorites"] = _feishu_env("FEISHU_TABLE_FAVORITES", "FEISHU_FAVORITES_TABLE_ID") or tables["library"]
    base_token = str(
        config.get("READING_TRAINER_FEISHU_BASE_TOKEN")
        or _feishu_env("FEISHU_BASE_TOKEN", "FEISHU_APP_TOKEN", "FEISHU_BITABLE_APP_TOKEN")
        or FEISHU_BASE_TOKEN
    ).strip()
    app_id = str(config.get("READING_TRAINER_FEISHU_APP_ID") or _feishu_env("FEISHU_APP_ID") or FEISHU_APP_ID).strip()
    access_token = str(
        config.get("READING_TRAINER_FEISHU_ACCESS_TOKEN")
        or _feishu_env("FEISHU_ACCESS_TOKEN", "FEISHU_USER_ACCESS_TOKEN")
        or token_file.get("access_token")
        or token_file.get("user_access_token")
        or token_file.get("tenant_access_token")
    ).strip()
    app_secret = str(config.get("READING_TRAINER_FEISHU_APP_SECRET") or _feishu_env("FEISHU_APP_SECRET")).strip()
    redirect_uri = str(
        config.get("READING_TRAINER_FEISHU_REDIRECT_URI")
        or _feishu_env("FEISHU_REDIRECT_URI")
        or "https://www.kimdu.site/reading-trainer/feishu/oauth/callback"
    ).strip()
    store = (getattr(app, "extensions", {}) or {}).get("reading_trainer_v2", {}).get("store") if app is not None else None
    saved = store.get_private_config("feishu") if store is not None else {}
    enabled = bool(saved.get("enabled", config.get("READING_TRAINER_FEISHU_ENABLED", _feishu_env("FEISHU_ENABLED").lower() in {"1", "true", "yes"})))
    return {
        "base_token": base_token,
        "app_id": app_id,
        "access_token": access_token,
        "app_secret": app_secret,
        "redirect_uri": redirect_uri,
        "enabled": enabled,
        "tables": tables,
    }


def _stable_business_key(section: str, owner_id: str, value: Any, index: int = 0) -> str:
    if isinstance(value, Mapping):
        if section == "settings":
            return f"settings:{owner_id}"
        if section == "accounts" and value.get("id") not in (None, ""):
            return f"accounts:{value.get('id')}"
        if section == "classes" and value.get("id") not in (None, ""):
            return f"classes:{value.get('id')}"
        if section == "invites" and value.get("code") not in (None, ""):
            return f"invites:{value.get('code')}"
        for candidate in ("business_key", "businessKey", "id", "uid", "key", "code"):
            if value.get(candidate) not in (None, ""):
                return f"{section}:{owner_id}:{_safe_text(value[candidate], 200)}"
        if section in ("vbook", "wbook"):
            word = value.get("word") or value.get("term") or ""
            if word:
                return f"{section}:{owner_id}:{str(word).strip().lower()}"
        if section == "grades" and value.get("ts") is not None:
            return f"{section}:{owner_id}:{value.get('ts')}"
        if section == "library" and value.get("title"):
            return f"{section}:{owner_id}:{value.get('title')}"
    encoded = _json_dumps(sanitize_json(value))
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]
    return f"{section}:{owner_id}:{digest}:{index}"


def _feishu_fields(section: str, owner_id: str, value: Any, business_key: str) -> dict[str, Any]:
    data = value if isinstance(value, Mapping) else {"value": value}
    if section == "accounts":
        role = data.get("role", "")
        fields = {
            "账号ID": data.get("id", owner_id),
            "用户名": data.get("username", ""),
            "角色": "学生" if role == "student" else ("教师" if role == "teacher" else ""),
            "班级ID": data.get("class_id") or data.get("classId") or "",
            "创建者": data.get("created_by") or data.get("createdBy") or "",
        }
    elif section == "classes":
        fields = {
            "班级ID": data.get("id", ""),
            "班级名称": data.get("name", ""),
            "学员ID列表": ", ".join(map(str, data.get("students", []))) if isinstance(data.get("students"), list) else data.get("students", ""),
            "创建者": data.get("teacherId") or data.get("teacher_id") or data.get("created_by") or "",
        }
    elif section == "invites":
        role = data.get("role", "")
        fields = {
            "邀请码": data.get("code", ""),
            "类型": "教师" if role == "teacher" else "学生",
            "创建者": data.get("teacherId") or data.get("createdBy") or "",
        }
    elif section == "settings":
        fields = {"键": owner_id, "值": _json_dumps(data)}
    elif section == "vbook":
        fields = {
            "学员ID": owner_id,
            "单词": data.get("word") or data.get("term") or "",
            "释义": data.get("meaning") or data.get("def") or data.get("zh") or "",
        }
    elif section == "wbook":
        fields = {
            "学员ID": owner_id,
            "单词": data.get("word") or data.get("term") or "",
            "释义": data.get("meaning") or data.get("def") or data.get("zh") or "",
            "来源": data.get("source") or data.get("from") or data.get("article") or "",
        }
    elif section == "grades":
        fields = {
            "学员ID": owner_id,
            "文章标题": data.get("title") or data.get("article") or "",
            "题型": data.get("type") or data.get("exam") or "",
            "正确数": data.get("correct", data.get("right", 0)),
            "总题数": data.get("total", 0),
            "正确率": data.get("rate", data.get("pct", 0)),
        }
    else:  # library and favorites use the documented library table shape.
        fields = {
            "学员ID": owner_id,
            "题目标题": data.get("title") or data.get("name") or "",
            "题目内容": str(data.get("question") or data.get("content") or "")[:1000],
            "答案": str(data.get("answer") or "")[:500],
        }
    # A stable application key is additive metadata; it never contains any
    # credential and lets a sync distinguish two otherwise identical items.
    fields["业务键"] = business_key
    fields["数据类型"] = "收藏" if section == "favorites" else section
    fields["数据JSON"] = _json_dumps(sanitize_json(value))[:90000]
    return sanitize_json(fields)


def _local_feishu_records(store: ReadingTrainerStore) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in (*FEISHU_TABLES, "favorites")}
    for user in store.list_users():
        if user.get("role") == "admin":
            continue
        clean = {
            "id": user.get("id"),
            "username": user.get("username"),
            "role": user.get("role"),
            "created_by": user.get("created_by"),
            "class_id": user.get("class_id"),
        }
        grouped["accounts"].append({"owner_id": user.get("id"), "value": clean})
    for item in store.list_classes():
        grouped["classes"].append({"owner_id": item.get("teacherId") or GLOBAL_OWNER_ID, "value": item})
    with store.connect() as connection:
        rows = connection.execute("SELECT data_json, code, role, teacher_id, class_id, used FROM invites").fetchall()
    for row in rows:
        try:
            item = json.loads(row[0])
        except (TypeError, ValueError):
            item = {}
        item = dict(item) if isinstance(item, Mapping) else {}
        item.update({"code": row[1], "role": row[2], "teacherId": row[3], "classId": row[4], "used": bool(row[5])})
        grouped["invites"].append({"owner_id": row[3] or GLOBAL_OWNER_ID, "value": item})
    for document in store.list_documents(BUSINESS_SECTIONS):
        section = document["section"]
        data = document["data"]
        values = data if isinstance(data, list) else [data]
        for index, item in enumerate(values):
            grouped.setdefault(section, []).append(
                {"owner_id": document["owner_id"], "value": item, "index": index}
            )
    return grouped


def _remote_key(section: str, record: Mapping[str, Any]) -> str | None:
    fields = record.get("fields") if isinstance(record.get("fields"), Mapping) else record
    if not isinstance(fields, Mapping):
        return None
    for name in ("业务键", "_rt_key", "business_key", "businessKey"):
        if fields.get(name) not in (None, ""):
            return str(fields[name])
    if section == "accounts" and fields.get("账号ID"):
        return f"accounts:{fields.get('账号ID')}"
    if section == "classes" and fields.get("班级ID"):
        return f"classes:{fields.get('班级ID')}"
    if section == "invites" and fields.get("邀请码"):
        return f"invites:{fields.get('邀请码')}"
    owner = fields.get("学员ID") or fields.get("owner_id") or fields.get("ownerId") or GLOBAL_OWNER_ID
    if section in ("vbook", "wbook") and fields.get("单词"):
        return f"{section}:{owner}:{str(fields.get('单词')).strip().lower()}"
    if section == "settings" and fields.get("键") is not None:
        return f"settings:{fields.get('键')}"
    if section in ("library", "favorites") and fields.get("题目标题"):
        return f"{section}:{owner}:{fields.get('题目标题')}"
    record_id = record.get("record_id")
    if record_id:
        # Unknown remote shapes remain visible in the plan and are never
        # mistaken for a delete candidate.
        return f"remote:{section}:{record_id}"
    return None


def _feishu_value_equal(remote_value: Any, local_value: Any) -> bool:
    if local_value in (None, "") and remote_value in (None, ""):
        return True
    if isinstance(local_value, (int, float)) and isinstance(remote_value, (int, float)):
        return float(local_value) == float(remote_value)
    return remote_value == local_value


def build_feishu_sync_plan(
    store: ReadingTrainerStore,
    remote_records: Mapping[str, Iterable[Mapping[str, Any]]] | None = None,
    *,
    app: Any | None = None,
) -> dict[str, Any]:
    """Build an idempotent Feishu upsert plan without performing network I/O.

    The plan has only creates, updates, and ``remote_only`` records.  There is
    intentionally no delete action, so remote data that is absent locally is
    preserved.
    """

    cfg = feishu_config(app or store.app)
    local = _local_feishu_records(store)
    remote = remote_records or {}
    tables: dict[str, dict[str, Any]] = {}
    for section, local_items in local.items():
        if section not in cfg["tables"]:
            continue
        local_by_key: dict[str, dict[str, Any]] = {}
        for item in local_items:
            value = sanitize_json(item.get("value"))
            key = _stable_business_key(section, str(item.get("owner_id") or GLOBAL_OWNER_ID), value, int(item.get("index", 0)))
            fields = _feishu_fields(section, str(item.get("owner_id") or GLOBAL_OWNER_ID), value, key)
            local_by_key[key] = {"key": key, "fields": fields}
        remote_by_key: dict[str, Mapping[str, Any]] = {}
        remote_items = remote.get(section)
        if remote_items is None:
            remote_items = remote.get(cfg["tables"].get(section), [])
        for record in remote_items or []:
            if isinstance(record, Mapping):
                key = _remote_key(section, record)
                if key:
                    remote_by_key.setdefault(key, record)
        creates: list[dict[str, Any]] = []
        updates: list[dict[str, Any]] = []
        for key, local_record in local_by_key.items():
            old = remote_by_key.get(key)
            if not old:
                creates.append({"business_key": key, "fields": local_record["fields"]})
                continue
            old_fields = old.get("fields") if isinstance(old.get("fields"), Mapping) else {}
            comparable = sanitize_json(dict(old_fields))
            if any(not _feishu_value_equal(comparable.get(name), value) for name, value in local_record["fields"].items()):
                updates.append(
                    {
                        "record_id": old.get("record_id"),
                        "business_key": key,
                        "fields": local_record["fields"],
                    }
                )
        remote_only = [
            {"record_id": item.get("record_id"), "business_key": key, "fields": sanitize_json(item.get("fields", {}))}
            for key, item in remote_by_key.items()
            if key not in local_by_key
        ]
        tables[section] = {
            "table_id": cfg["tables"].get(section),
            "creates": creates,
            "updates": updates,
            "remote_only": remote_only,
            "deletes": [],
        }
    return {
        "tables": tables,
        "totals": {
            "creates": sum(len(item["creates"]) for item in tables.values()),
            "updates": sum(len(item["updates"]) for item in tables.values()),
            "remote_only": sum(len(item["remote_only"]) for item in tables.values()),
            "deletes": 0,
        },
    }


def _redacted_feishu_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    # sanitize_json is applied once more at the HTTP boundary.
    return sanitize_json(plan)


def _safe_user(user: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not user:
        return None
    result = {
        key: user.get(key)
        for key in ("id", "username", "role", "created_by", "class_id", "created_at")
        if user.get(key) is not None
    }
    if user.get("class_id") is not None:
        result["classId"] = user.get("class_id")
    if user.get("created_at") is not None:
        result["createdAt"] = int(user.get("created_at") or 0) * 1000
    return result


def _error(message: str, status: int, code: str = "request_error"):
    return jsonify({"error": {"code": code, "message": message}}), status


def _json_body() -> Any:
    if request is None:
        return {}
    return request.get_json(silent=True)


def _token_from_request() -> str | None:
    if request is None:
        return None
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    cookie_name = current_app.config.get("READING_TRAINER_SESSION_COOKIE", "reading_trainer_session")
    return request.cookies.get(cookie_name)


def _principal(store: ReadingTrainerStore) -> dict[str, Any] | None:
    cached = getattr(g, "reading_trainer_principal", None)
    if cached is not None:
        return cached
    user = store.session_user(_token_from_request())
    g.reading_trainer_principal = user
    return user


def _authorized_owner(store: ReadingTrainerStore, principal: Mapping[str, Any], owner_id: str) -> bool:
    role = principal.get("role")
    if role == "admin":
        return True
    if role == "student":
        return str(principal.get("id")) == str(owner_id)
    if role == "teacher":
        return store.teacher_can_access(str(principal.get("id")), owner_id)
    return False


def _set_session_cookie(response: Any, store: ReadingTrainerStore, token: str) -> Any:
    cookie_name = current_app.config.get("READING_TRAINER_SESSION_COOKIE", "reading_trainer_session")
    response.set_cookie(
        cookie_name,
        token,
        max_age=store.session_ttl,
        httponly=True,
        secure=bool(current_app.config.get("READING_TRAINER_SESSION_SECURE", False)),
        samesite="Lax",
        path="/",
    )
    return response


def _clear_session_cookie(response: Any) -> Any:
    cookie_name = current_app.config.get("READING_TRAINER_SESSION_COOKIE", "reading_trainer_session")
    response.delete_cookie(cookie_name, path="/")
    return response


def _auth_required(store: ReadingTrainerStore, roles: Iterable[str] | None = None):
    user = _principal(store)
    if not user:
        return None, _error("authentication required", 401, "authentication_required")
    if roles and user.get("role") not in tuple(roles):
        return None, _error("insufficient permissions", 403, "forbidden")
    return user, None


def _http_request(client: Any, method: str, url: str, **kwargs: Any) -> Any:
    if client is None:
        if requests is None:
            raise RuntimeError("HTTP client is unavailable")
        client = requests
    if callable(client) and not hasattr(client, "request"):
        return client(method, url, **kwargs)
    if hasattr(client, "request"):
        return client.request(method, url, **kwargs)
    method_fn = getattr(client, method.lower(), None)
    if method_fn is None:
        raise RuntimeError("HTTP client is invalid")
    return method_fn(url, **kwargs)


def _http_json(response: Any) -> Mapping[str, Any]:
    value = response if isinstance(response, Mapping) else response.json()
    if not isinstance(value, Mapping) or value.get("code", 0) not in (0, None):
        raise RuntimeError("upstream request failed")
    return value


def _ai_upstream_failure(response: Any | None = None, exc: Exception | None = None):
    """Return a useful admin-safe AI error without reflecting upstream bodies."""

    try:
        status = int(getattr(response, "status_code", 0) or getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    failures = {
        400: ("AI 服务商拒绝了请求，请核对模型名称。", "ai_request_invalid"),
        401: ("AI API Key 无效或已撤销，请更换 Key 后重新保存。", "ai_key_invalid"),
        402: ("AI 服务商账户余额不足，请充值后重试。", "ai_balance_insufficient"),
        403: ("当前 AI API Key 没有访问该模型的权限。", "ai_model_forbidden"),
        404: ("AI 接口地址或模型不存在，请核对配置。", "ai_endpoint_not_found"),
        429: ("AI 服务商请求过于频繁，请稍后重试。", "ai_rate_limited"),
    }
    if status in failures:
        message, code = failures[status]
        return _error(message, 502, code)
    if status >= 500:
        return _error("AI 服务商暂时不可用，请稍后重试。", 502, "ai_provider_unavailable")
    if exc is not None and "timeout" in type(exc).__name__.lower():
        return _error("连接 AI 服务商超时，请稍后重试。", 504, "ai_upstream_timeout")
    return _error("AI 服务商连接失败，请检查 Key、余额和接口配置。", 502, "ai_upstream_error")


def _ai_timeout_seconds(app: Any) -> float:
    """Read and safely bound the AI upstream timeout.

    ``READING_TRAINER_AI_TIMEOUT`` is the documented setting.  The
    ``*_SECONDS`` spelling is accepted as a compatibility alias for
    deployments that prefer explicit units.  Invalid, non-finite, or missing
    values fall back to the 110 second default.
    """

    config = getattr(app, "config", {})
    raw = config.get(
        "READING_TRAINER_AI_TIMEOUT",
        config.get(
            "READING_TRAINER_AI_TIMEOUT_SECONDS",
            os.environ.get(
                "READING_TRAINER_AI_TIMEOUT",
                os.environ.get("READING_TRAINER_AI_TIMEOUT_SECONDS"),
            ),
        ),
    )
    try:
        value = float(raw)
    except (TypeError, ValueError):
        value = float(AI_TIMEOUT_DEFAULT_SECONDS)
    if not math.isfinite(value):
        value = float(AI_TIMEOUT_DEFAULT_SECONDS)
    return max(float(AI_TIMEOUT_MIN_SECONDS), min(float(AI_TIMEOUT_MAX_SECONDS), value))


def _safe_ai_max_tokens(value: Any) -> int | None:
    """Return a bounded client token budget, or ``None`` when not supplied.

    The proxy owns the model, endpoint, and credentials.  ``max_tokens`` is
    the only generation control accepted from the browser, and even that is
    bounded to keep an accidentally huge request from exhausting resources.
    """

    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return max(AI_MAX_TOKENS_MIN, min(AI_MAX_TOKENS_MAX, number))


def _valid_feishu_access_token(app: Any, client: Any = None) -> str:
    cfg = feishu_config(app)
    tokens = _feishu_token_file(app)
    access_token = str(tokens.get("access_token") or cfg.get("access_token") or "").strip()
    expires_at = int(tokens.get("expires_at") or 0)
    if access_token and (not expires_at or expires_at > _now() + 120):
        return access_token
    refresh_token = str(tokens.get("refresh_token") or "").strip()
    refresh_expires_at = int(tokens.get("refresh_expires_at") or 0)
    if not refresh_token or (refresh_expires_at and refresh_expires_at <= _now()):
        raise RuntimeError("Feishu authorization expired")
    if not cfg.get("app_id") or not cfg.get("app_secret"):
        raise RuntimeError("Feishu OAuth is not configured")
    refreshed = _http_request(
        client,
        "POST",
        "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": cfg["app_id"],
            "client_secret": cfg["app_secret"],
            "refresh_token": refresh_token,
        },
        timeout=20,
    )
    payload = _http_json(refreshed)
    new_access = str(payload.get("access_token") or "").strip()
    if not new_access:
        raise RuntimeError("Feishu refresh failed")
    now = _now()
    stored = {
        "access_token": new_access,
        "expires_at": now + int(payload.get("expires_in") or 0),
        "refresh_token": payload.get("refresh_token") or refresh_token,
        "refresh_expires_at": now + int(payload.get("refresh_token_expires_in") or 0)
        if payload.get("refresh_token_expires_in")
        else refresh_expires_at,
        "scope": payload.get("scope") or tokens.get("scope") or "",
        "updated_at": now,
    }
    _write_feishu_token_file(app, stored)
    return new_access


def _ensure_feishu_metadata_fields(client: Any, table_base_url: str, headers: Mapping[str, str]) -> None:
    response = _http_request(client, "GET", table_base_url + "/fields", headers=headers, params={"page_size": 100}, timeout=30)
    result = _http_json(response)
    data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
    items = data.get("items") if isinstance(data.get("items"), list) else []
    existing = {
        str(item.get("field_name"))
        for item in items
        if isinstance(item, Mapping) and item.get("field_name")
    }
    for name in ("业务键", "数据类型", "数据JSON"):
        if name in existing:
            continue
        created = _http_request(
            client,
            "POST",
            table_base_url + "/fields",
            headers=headers,
            json={"field_name": name, "type": 1},
            timeout=30,
        )
        _http_json(created)


def _valid_https_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return host not in {"localhost", "127.0.0.1", "::1"} and not host.endswith(".local")


def _ai_config(store: ReadingTrainerStore, app: Any) -> dict[str, Any]:
    config = getattr(app, "config", {})
    saved = store.get_private_config("ai")
    endpoint = str(
        saved.get("endpoint")
        or config.get("READING_TRAINER_AI_ENDPOINT")
        or os.environ.get("READING_TRAINER_AI_ENDPOINT")
        or os.environ.get("OPENAI_BASE_URL", "")
    ).strip()
    key = str(
        saved.get("api_key")
        or config.get("READING_TRAINER_AI_API_KEY")
        or os.environ.get("READING_TRAINER_AI_API_KEY")
        or os.environ.get("OPENAI_API_KEY", "")
    ).strip()
    model = str(saved.get("model") or config.get("READING_TRAINER_AI_MODEL") or os.environ.get("READING_TRAINER_AI_MODEL", "gpt-4o-mini")).strip()
    return {
        "provider": _safe_text(saved.get("provider"), 80),
        "endpoint": endpoint,
        "api_key": key,
        "model": model,
        "enabled": bool(saved.get("enabled", True)),
    }


def _public_ai_config(store: ReadingTrainerStore, app: Any) -> dict[str, Any]:
    cfg = _ai_config(store, app)
    return {
        "provider": cfg.get("provider", ""),
        "endpoint": cfg.get("endpoint", ""),
        "model": cfg.get("model", ""),
        "enabled": bool(cfg.get("enabled")),
        "hasKey": bool(cfg.get("api_key")),
    }


def _public_feishu_config(store: ReadingTrainerStore, app: Any) -> dict[str, Any]:
    cfg = feishu_config(app)
    tokens = _feishu_token_file(app)
    return {
        "enabled": bool(cfg.get("enabled")),
        "configured": bool(cfg.get("app_id") and cfg.get("app_secret") and cfg.get("base_token")),
        "authorized": bool(cfg.get("access_token") or tokens.get("refresh_token")),
    }


def _state_snapshot(store: ReadingTrainerStore, principal: Mapping[str, Any] | None, app: Any) -> dict[str, Any]:
    role = principal.get("role") if principal else None
    principal_id = str(principal.get("id")) if principal else ""
    all_public_users = [item for item in store.list_users() if item.get("role") != "admin"]
    if role == "admin":
        visible_users = all_public_users
    elif role == "teacher":
        visible_users = [
            item for item in all_public_users
            if str(item.get("id")) == principal_id or store.teacher_can_access(principal_id, str(item.get("id")))
        ]
    elif role == "student":
        visible_users = [item for item in all_public_users if str(item.get("id")) == principal_id]
    else:
        visible_users = []
    accounts = [_safe_user(item) for item in visible_users]

    all_classes = store.list_classes()
    if role == "admin":
        classes = all_classes
        invites = store.list_invites()
    elif role == "teacher":
        classes = [item for item in all_classes if str(item.get("teacherId") or "") == principal_id]
        invites = [item for item in store.list_invites() if str(item.get("teacherId") or "") == principal_id]
    elif role == "student":
        class_id = principal.get("class_id") if principal else None
        classes = [item for item in all_classes if class_id and str(item.get("id")) == str(class_id)]
        invites = []
    else:
        classes = []
        invites = []

    owner_ids = {str(item.get("id")) for item in visible_users if item and item.get("id")}
    if principal_id:
        owner_ids.add(principal_id)
    user_data: dict[str, dict[str, Any]] = {}
    for owner_id in owner_ids:
        data: dict[str, Any] = {}
        for section_name in BUSINESS_SECTIONS:
            default: Any = {} if section_name == "settings" else []
            value = store.get_document(owner_id, section_name, None)
            if value is None and section_name == "settings":
                value = store.get_document(GLOBAL_OWNER_ID, section_name, default)
            data[section_name] = value if value is not None else default
        user_data[owner_id] = sanitize_json(data)
    return {
        "accounts": accounts,
        "invites": sanitize_json(invites),
        "classes": sanitize_json(classes),
        "ai": _public_ai_config(store, app),
        "feishu": _public_feishu_config(store, app),
        "userData": user_data,
    }


def _create_blueprint(store: ReadingTrainerStore):
    if Blueprint is None:  # pragma: no cover
        raise RuntimeError("Flask is required to register the Reading Trainer backend")
    bp = Blueprint("reading_trainer_v2", __name__, url_prefix=API_PREFIX)

    @bp.get("/bootstrap")
    def bootstrap():
        user = _principal(store)
        state = _state_snapshot(store, user, current_app)
        return jsonify(
            {
                "success": True,
                "api_version": 2,
                "authenticated": bool(user),
                "user": _safe_user(user),
                "roles": list(ROLES),
                "sections": list(BUSINESS_SECTIONS),
                "admin_configured": bool(store.list_users("admin")),
                "legacy_state_imported": bool(store.meta_get("legacy_state_imported")),
                "admin": bool(user and user.get("role") == "admin"),
                "state": state,
            }
        )

    def _login(payload: Any, admin_only: bool = False):
        payload = payload if isinstance(payload, Mapping) else {}
        username = _safe_text(payload.get("username"), 120)
        password = str(payload.get("password") or "")
        role = "admin" if admin_only else _safe_text(payload.get("role"), 20).lower()
        if not username or not password:
            return _error("invalid credentials", 400, "invalid_credentials")
        user = store.find_user(username, role or None)
        if not user or (admin_only and user.get("role") != "admin") or not verify_password(password, user.get("password_hash", "")):
            return _error("invalid credentials", 401, "invalid_credentials")
        token = store.create_session(str(user["id"]))
        if session is not None and current_app.secret_key:
            session["reading_trainer_admin"] = bool(user.get("role") == "admin")
            session["rt_admin"] = bool(user.get("role") == "admin")
            session["reading_trainer_user_id"] = str(user.get("id"))
        response = make_response(
            jsonify(
                {
                    "success": True,
                    "user": _safe_user(user),
                    "admin": bool(user.get("role") == "admin"),
                    "state": _state_snapshot(store, user, current_app),
                }
            ),
            200,
        )
        return _set_session_cookie(response, store, token)

    @bp.post("/auth/login")
    def user_login():
        return _login(_json_body(), admin_only=False)

    @bp.post("/admin/login")
    @bp.post("/auth/admin/login")
    def admin_login():
        return _login(_json_body(), admin_only=True)

    @bp.post("/auth/register")
    def user_register():
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        username = _safe_text(payload.get("username"), 120)
        password = str(payload.get("password") or "")
        role = _safe_text(payload.get("role"), 20).lower()
        invite_code = _safe_text(payload.get("invite_code") or payload.get("code"), 120).upper()
        if len(username) < 2 or len(password) < 6:
            return _error("username or password is invalid", 400, "invalid_registration")
        if role not in ("student", "teacher"):
            return _error("only student or teacher registration is allowed", 400, "invalid_role")
        if store.find_user(username, role):
            return _error("username is already registered", 409, "duplicate_user")
        require_invite = bool(current_app.config.get("READING_TRAINER_REQUIRE_INVITE", False))
        invite = store.find_invite(invite_code) if invite_code else None
        if invite_code and (not invite or invite.get("used") or invite.get("role") != role):
            return _error("invite code is invalid", 400, "invalid_invite")
        if require_invite and not invite:
            return _error("invite code is required", 400, "invite_required")
        account_id = f"{'tch' if role == 'teacher' else 'stu'}_{uuid.uuid4().hex}"
        created_by = invite.get("teacherId") if invite else None
        class_id = invite.get("classId") if invite else None
        user = store.upsert_user(
            {
                "id": account_id,
                "username": username,
                "role": role,
                "password_hash": hash_password(password),
                "created_by": created_by,
                "class_id": class_id,
                "created_at": _now(),
            }
        )
        if role == "teacher":
            # teacherId is represented by the user id in the database.
            pass
        if invite:
            store.consume_invite(invite_code, account_id)
        token = store.create_session(account_id)
        if session is not None and current_app.secret_key:
            session["reading_trainer_admin"] = False
            session["rt_admin"] = False
            session["reading_trainer_user_id"] = account_id
        response = make_response(
            jsonify(
                {
                    "success": True,
                    "user": _safe_user(user),
                    "admin": False,
                    "state": _state_snapshot(store, user, current_app),
                }
            ),
            201,
        )
        return _set_session_cookie(response, store, token)

    @bp.get("/auth/session")
    @bp.get("/session")
    @bp.get("/auth/me")
    @bp.get("/admin/session")
    @bp.get("/auth/admin/session")
    def auth_session():
        user = _principal(store)
        return jsonify({"authenticated": bool(user), "user": _safe_user(user)})

    @bp.post("/auth/logout")
    @bp.post("/admin/logout")
    def logout():
        store.delete_session(_token_from_request())
        if session is not None and current_app.secret_key:
            for key in ("reading_trainer_admin", "rt_admin", "reading_trainer_user_id"):
                session.pop(key, None)
        response = make_response(jsonify({"ok": True}), 200)
        return _clear_session_cookie(response)

    @bp.get("/data")
    def list_data():
        user, error = _auth_required(store)
        if error:
            return error
        owner_id = str(request.args.get("owner_id") or user["id"])
        if not _authorized_owner(store, user, owner_id):
            return _error("insufficient permissions", 403, "forbidden")
        result = {}
        for section in BUSINESS_SECTIONS:
            value = store.get_document(owner_id, section, None)
            if value is None and section == "settings":
                value = store.get_document(GLOBAL_OWNER_ID, section, {})
            result[section] = value if value is not None else []
        return jsonify({"owner_id": owner_id, "data": sanitize_json(result)})

    def _data_route(section: str, explicit_owner: str | None = None):
        if section not in BUSINESS_SECTIONS:
            return _error("unsupported data section", 404, "unknown_section")
        user, error = _auth_required(store)
        if error:
            return error
        payload = _json_body()
        payload_mapping = payload if isinstance(payload, Mapping) else {}
        owner_id = explicit_owner or request.args.get("owner_id") or payload_mapping.get("owner_id") or user["id"]
        owner_id = _safe_text(owner_id, 200)
        if not owner_id or not _authorized_owner(store, user, owner_id):
            return _error("insufficient permissions", 403, "forbidden")
        if request.method == "GET":
            default = {} if section == "settings" else []
            value = store.get_document(owner_id, section, None)
            # The old browser app had one global settings object.  Keep that
            # configuration visible to a newly migrated user until that user
            # saves an owner-scoped override; books and grades never fall back
            # across owners.
            if value is None and section == "settings":
                value = store.get_document(GLOBAL_OWNER_ID, section, default)
            return jsonify(
                {
                    "owner_id": owner_id,
                    "section": section,
                    "data": sanitize_json(value if value is not None else default),
                }
            )
        data = payload_mapping.get("data", payload_mapping.get("value")) if isinstance(payload, Mapping) else payload
        if data is None and isinstance(payload, Mapping) and "data" not in payload and "value" not in payload:
            data = payload
        try:
            saved = store.put_document(owner_id, section, data)
        except (TypeError, ValueError):
            return _error("data is not valid JSON or is too large", 400, "invalid_data")
        return jsonify(
            {
                "ok": True,
                "owner_id": owner_id,
                "section": section,
                "data": sanitize_json(saved),
                "state": _state_snapshot(store, user, current_app),
            }
        )

    @bp.route("/data/<section>", methods=["GET", "POST", "PUT", "PATCH"])
    @bp.route("/business/<section>", methods=["GET", "POST", "PUT", "PATCH"])
    def data(section: str):
        return _data_route(section)

    @bp.route("/data/<section>/<owner_id>", methods=["GET", "POST", "PUT", "PATCH"])
    def data_for_owner(section: str, owner_id: str):
        return _data_route(section, owner_id)

    @bp.route("/state/<section>", methods=["GET", "POST", "PUT", "PATCH"])
    def state_alias(section: str):
        if section in BUSINESS_SECTIONS:
            return _data_route(section)
        user, error = _auth_required(store, ("admin",))
        if error:
            return error
        if request.method == "GET":
            return jsonify({"state": _state_snapshot(store, user, current_app)})
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        value = payload.get("value", payload.get("data"))
        try:
            if section == "accounts" and isinstance(value, list):
                store.replace_public_users(item for item in value if isinstance(item, Mapping))
            elif section == "classes" and isinstance(value, list):
                store.replace_classes(item for item in value if isinstance(item, Mapping))
            elif section == "invites" and isinstance(value, list):
                store.replace_invites(item for item in value if isinstance(item, Mapping))
            elif section == "ai" and isinstance(value, Mapping):
                store.put_private_config(
                    "ai",
                    {
                        "provider": value.get("provider"),
                        "endpoint": value.get("endpoint"),
                        "model": value.get("model"),
                        "enabled": bool(value.get("enabled")),
                        "api_key": value.get("api_key") or value.get("apiKey") or value.get("key"),
                    },
                )
            elif section == "feishu" and isinstance(value, Mapping):
                store.put_private_config("feishu", {"enabled": bool(value.get("enabled"))})
            else:
                return _error("unsupported state section", 404, "unknown_section")
        except (TypeError, ValueError, sqlite3.IntegrityError):
            return _error("state update is invalid", 400, "invalid_state")
        return jsonify({"ok": True, "state": _state_snapshot(store, user, current_app)})

    @bp.route("/migration/legacy", methods=["GET", "POST"])
    @bp.route("/migration/legacy/dry-run", methods=["GET", "POST"])
    @bp.route("/migration/legacy/import", methods=["GET", "POST"])
    @bp.route("/migration/dry-run", methods=["GET", "POST"])
    @bp.route("/migration/import", methods=["GET", "POST"])
    def legacy_migration():
        user, error = _auth_required(store, ("admin",))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        path_name = request.path.rsplit("/", 1)[-1]
        if path_name in ("dry-run",):
            dry_run = True
        elif path_name in ("import",):
            dry_run = False
        else:
            dry_run = bool(payload.get("dry_run", request.args.get("dry_run", "true").lower() not in {"0", "false", "no"}))
        supplied = payload.get("state")
        legacy = supplied if isinstance(supplied, Mapping) else store._read_legacy_file()
        if not isinstance(legacy, Mapping):
            return _error("legacy state was not found", 404, "legacy_not_found")
        if dry_run:
            return jsonify({"dry_run": True, "imported": False, "plan": plan_legacy_migration(legacy)})
        summary = import_legacy_state(store, legacy)
        store._import_private_legacy_config(legacy)
        return jsonify(
            {
                "dry_run": False,
                "imported": bool(summary.get("changed")),
                "summary": summary,
                "state": _state_snapshot(store, user, current_app),
            }
        )

    @bp.post("/ai/proxy")
    @bp.post("/ai/chat")
    def ai_proxy():
        user, error = _auth_required(store)
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages or len(messages) > 20:
            return _error("AI messages are invalid", 400, "invalid_ai_request")
        clean_messages = []
        for item in messages:
            if not isinstance(item, Mapping) or item.get("role") not in ("system", "user", "assistant"):
                continue
            clean_messages.append({"role": item.get("role"), "content": str(item.get("content") or "")[:60000]})
        if not clean_messages:
            return _error("AI messages are empty", 400, "invalid_ai_request")
        cfg = _ai_config(store, current_app)
        if not cfg["enabled"] or not cfg["endpoint"] or not cfg["api_key"] or not _valid_https_url(cfg["endpoint"]):
            return _error("AI proxy is not configured", 503, "ai_unavailable")
        try:
            temperature = max(0.0, min(float(payload.get("temperature", 0.4)), 2.0))
        except (TypeError, ValueError):
            return _error("AI temperature is invalid", 400, "invalid_ai_request")
        upstream = {"messages": clean_messages, "model": cfg["model"], "temperature": temperature}
        max_tokens = _safe_ai_max_tokens(payload.get("max_tokens"))
        if max_tokens is not None:
            upstream["max_tokens"] = max_tokens
        if isinstance(payload.get("response_format"), Mapping):
            upstream["response_format"] = sanitize_json(payload["response_format"])
        client = current_app.extensions.get("reading_trainer_v2", {}).get("http_client")
        try:
            response = _http_request(
                client,
                "POST",
                cfg["endpoint"],
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
                json=upstream,
                timeout=_ai_timeout_seconds(current_app),
            )
            if not getattr(response, "ok", True):
                return _ai_upstream_failure(response)
            try:
                result = response.json()
            except Exception as exc:
                # A successful response that is not JSON is still an upstream
                # failure, but its body must never be reflected to the caller.
                return _ai_upstream_failure(exc=exc)
            return jsonify({"data": sanitize_json(result)})
        except Exception as exc:
            # Do not reflect upstream response bodies or exception text: they
            # may contain provider keys, URLs, or internal paths.
            return _ai_upstream_failure(exc=exc)

    @bp.post("/ai/test")
    def ai_test():
        user, error = _auth_required(store, ("admin",))
        if error:
            return error
        cfg = _ai_config(store, current_app)
        if not cfg["endpoint"] or not cfg["api_key"] or not _valid_https_url(cfg["endpoint"]):
            return _error("AI proxy is not configured", 503, "ai_unavailable")
        client = current_app.extensions.get("reading_trainer_v2", {}).get("http_client")
        try:
            response = _http_request(
                client,
                "POST",
                cfg["endpoint"],
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
                json={
                    "model": cfg["model"],
                    "messages": [{"role": "user", "content": "Reply with OK."}],
                    "temperature": 0,
                    "max_tokens": 8,
                },
                timeout=30,
            )
            if not getattr(response, "ok", True):
                return _ai_upstream_failure(response)
            return jsonify({"ok": True})
        except Exception as exc:
            return _ai_upstream_failure(exc=exc)

    @bp.get("/feishu/oauth/status")
    @bp.get("/feishu/status")
    def feishu_oauth_status():
        user, error = _auth_required(store, ("admin",))
        if error:
            return error
        cfg = feishu_config(current_app)
        return jsonify(
            {
                "enabled": bool(cfg["enabled"]),
                "oauth_configured": bool(cfg["app_id"] and cfg["app_secret"] and cfg["redirect_uri"]),
                "access_token_configured": bool(cfg["access_token"]),
                "base_configured": bool(cfg["base_token"]),
                "tables": sorted(cfg["tables"].keys()),
            }
        )

    @bp.post("/feishu/sync")
    def feishu_sync():
        user, error = _auth_required(store)
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        supplied_remote = payload.get("remote_records") if isinstance(payload.get("remote_records"), Mapping) else None
        dry_run = bool(payload.get("dry_run", True))
        if (dry_run or supplied_remote is not None) and user.get("role") != "admin":
            return _error("insufficient permissions", 403, "forbidden")
        remote = supplied_remote or {}
        if dry_run:
            plan = build_feishu_sync_plan(store, remote, app=current_app)
            return jsonify({"dry_run": True, "plan": _redacted_feishu_plan(plan)})
        cfg = feishu_config(current_app)
        tokens = _feishu_token_file(current_app)
        if not cfg["enabled"] or not (cfg["access_token"] or tokens.get("refresh_token")):
            return _error("Feishu sync is not configured", 503, "feishu_unavailable")
        client = current_app.extensions.get("reading_trainer_v2", {}).get("http_client")
        base_url = "https://open.feishu.cn/open-apis/bitable/v1/apps/{}/tables".format(cfg["base_token"])
        try:
            access_token = _valid_feishu_access_token(current_app, client)
            if supplied_remote is None:
                remote = {}
                for section, table_id in cfg["tables"].items():
                    if section not in BUSINESS_SECTIONS and section not in ("accounts", "classes", "invites"):
                        continue
                    table_url = base_url + "/" + str(table_id) + "/records"
                    items: list[Mapping[str, Any]] = []
                    page_token = None
                    while True:
                        params = {"page_size": 500}
                        if page_token:
                            params["page_token"] = page_token
                        fetched = _http_request(
                            client,
                            "GET",
                            table_url,
                            headers={"Authorization": "Bearer " + access_token},
                            params=params,
                            timeout=30,
                        )
                        result = fetched if isinstance(fetched, Mapping) else fetched.json()
                        if not isinstance(result, Mapping) or result.get("code", 0) not in (0, None):
                            raise RuntimeError("Feishu list failed")
                        data = result.get("data") if isinstance(result.get("data"), Mapping) else {}
                        page_items = data.get("items") if isinstance(data.get("items"), list) else []
                        items.extend(item for item in page_items if isinstance(item, Mapping))
                        if not data.get("has_more"):
                            break
                        page_token = data.get("page_token")
                        if not page_token:
                            break
                    remote[section] = items
            plan = build_feishu_sync_plan(store, remote, app=current_app)
            executed = {"creates": 0, "updates": 0, "remote_only": plan["totals"]["remote_only"], "deletes": 0}
            prepared_tables: set[str] = set()
            for table in plan["tables"].values():
                table_url = base_url + "/" + str(table["table_id"]) + "/records"
                headers = {"Authorization": "Bearer " + access_token, "Content-Type": "application/json"}
                table_base_url = base_url + "/" + str(table["table_id"])
                if str(table["table_id"]) not in prepared_tables:
                    _ensure_feishu_metadata_fields(client, table_base_url, headers)
                    prepared_tables.add(str(table["table_id"]))
                for offset in range(0, len(table["creates"]), 500):
                    batch = table["creates"][offset : offset + 500]
                    records = [{"fields": item["fields"]} for item in batch]
                    created = _http_request(client, "POST", table_url + "/batch_create", headers=headers, json={"records": records}, timeout=30)
                    _http_json(created)
                    executed["creates"] += len(records)
                for item in table["updates"]:
                    if not item.get("record_id"):
                        continue
                    updated = _http_request(client, "PUT", table_url + "/" + str(item["record_id"]), headers=headers, json={"fields": item["fields"]}, timeout=30)
                    _http_json(updated)
                    executed["updates"] += 1
            return jsonify({"dry_run": False, "executed": executed})
        except Exception:
            return _error("Feishu sync failed", 502, "feishu_upstream_error")

    return bp


def register_reading_trainer_v2(app: Any):
    """Initialize the isolated backend and mount its v2 Blueprint on ``app``."""

    if Blueprint is None:  # pragma: no cover
        raise RuntimeError("Flask is required to register the Reading Trainer backend")
    extension = app.extensions.get("reading_trainer_v2")
    if extension:
        return extension["blueprint"]
    store = ReadingTrainerStore(app)
    store.initialize()
    blueprint = _create_blueprint(store)
    app.extensions["reading_trainer_v2"] = {"store": store, "blueprint": blueprint}
    app.register_blueprint(blueprint)
    return blueprint


__all__ = [
    "API_PREFIX",
    "BUSINESS_SECTIONS",
    "FEISHU_BASE_TOKEN",
    "FEISHU_TABLES",
    "GLOBAL_OWNER_ID",
    "ReadingTrainerStore",
    "build_feishu_sync_plan",
    "feishu_config",
    "hash_password",
    "import_legacy_state",
    "plan_legacy_migration",
    "register_reading_trainer_v2",
    "sanitize_json",
    "verify_password",
]
