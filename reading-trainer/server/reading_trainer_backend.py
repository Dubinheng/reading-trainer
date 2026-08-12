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
from datetime import datetime, timezone
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
    # Assignments were added after the original Feishu schema.  Deployments
    # can opt in by setting FEISHU_TABLE_ASSIGNMENTS (or the equivalent app
    # config); keeping the key here makes the sync planner extensible without
    # inventing a table ID or changing the primary SQLite data source.
    "assignments": "",
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
                CREATE TABLE IF NOT EXISTS usage_events (
                    event_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    event_type TEXT NOT NULL,
                    event_date TEXT NOT NULL,
                    duration_ms INTEGER,
                    meta_json TEXT NOT NULL DEFAULT '{}',
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_usage_events_created ON usage_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_usage_events_type_date ON usage_events(event_type, event_date);
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
                CREATE TABLE IF NOT EXISTS assignments (
                    id TEXT PRIMARY KEY,
                    teacher_id TEXT NOT NULL,
                    title TEXT NOT NULL DEFAULT '',
                    instructions TEXT NOT NULL DEFAULT '',
                    questions_json TEXT NOT NULL DEFAULT '[]',
                    sections_json TEXT NOT NULL DEFAULT '[]',
                    settings_json TEXT NOT NULL DEFAULT '{}',
                    assignment_type TEXT NOT NULL DEFAULT 'question_card',
                    review_items_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'draft',
                    due_at INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_assignments_teacher
                    ON assignments(teacher_id, updated_at);
                CREATE TABLE IF NOT EXISTS assignment_recipients (
                    assignment_id TEXT NOT NULL,
                    student_id TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'unread',
                    unread INTEGER NOT NULL DEFAULT 1,
                    opened_at INTEGER,
                    submitted_at INTEGER,
                    answers_json TEXT,
                    result_json TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (assignment_id, student_id),
                    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_assignment_recipients_student
                    ON assignment_recipients(student_id, updated_at);
                CREATE TABLE IF NOT EXISTS assignment_question_checks (
                    assignment_id TEXT NOT NULL,
                    student_id TEXT NOT NULL,
                    question_id TEXT NOT NULL,
                    answer_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    checked_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (assignment_id, student_id, question_id),
                    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_assignment_question_checks_student
                    ON assignment_question_checks(student_id, updated_at);
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
            # The table was introduced after the first production schema.  A
            # guarded additive migration keeps an existing database usable.
            try:
                connection.execute("ALTER TABLE assignments ADD COLUMN due_at INTEGER")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
            # Review assignments were added after the original question-card
            # schema.  These migrations are additive and deliberately retain
            # every existing assignment as a question_card.
            for column, definition in (
                ("assignment_type", "TEXT NOT NULL DEFAULT 'question_card'"),
                ("review_items_json", "TEXT NOT NULL DEFAULT '[]'"),
            ):
                try:
                    connection.execute(f"ALTER TABLE assignments ADD COLUMN {column} {definition}")
                except sqlite3.OperationalError as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise
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
            value = json.loads(row[0])
        except (TypeError, ValueError):
            return default
        # Legacy wrong-book JSON predates the server-owned progress metadata.
        # Add the fields on read while preserving every original renderer
        # field.  The normalized value is also written back so subsequent
        # callers observe a stable item id even before the next review.
        if section == "wbook" and isinstance(value, list):
            normalized = _normalize_wbook_items(value)
            if normalized != value:
                try:
                    self.put_document(owner_id, section, normalized)
                except (TypeError, ValueError):
                    # A read must never fail just because a legacy document is
                    # too large to rewrite; return the lossless projection.
                    pass
            value = normalized
        return value

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

    def upsert_vbook_item(self, owner_id: str, item: Mapping[str, Any]) -> dict[str, Any]:
        """Append one vocabulary item atomically and de-duplicate by word.

        The browser historically replaced the whole ``vbook`` document.  A
        dedicated item write prevents two tabs (or an assignment and the
        practice page) from losing each other's additions while preserving the
        existing document/Feishu storage shape.
        """

        owner_id = _safe_text(owner_id, 200)
        if not owner_id:
            raise ValueError("owner id is required")
        word = _safe_text(item.get("word") or item.get("term"), 200).strip()
        if not word:
            raise ValueError("word is required")
        clean_item = sanitize_json(dict(item))
        if not isinstance(clean_item, Mapping):
            raise ValueError("vocabulary item is invalid")
        clean_item = dict(clean_item)
        clean_item["word"] = word
        clean_item.setdefault("box", 1)
        clean_item.setdefault("ts", int(time.time() * 1000))
        word_key = word.casefold()

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data_json FROM documents WHERE owner_id = ? AND section = ?",
                (owner_id, "vbook"),
            ).fetchone()
            try:
                book = json.loads(row[0]) if row else []
            except (TypeError, ValueError):
                book = []
            if not isinstance(book, list):
                book = []

            for existing in book:
                if not isinstance(existing, Mapping):
                    continue
                existing_word = _safe_text(existing.get("word") or existing.get("term"), 200).strip()
                if existing_word.casefold() == word_key:
                    return {
                        "created": False,
                        "item": sanitize_json(dict(existing)),
                        "data": sanitize_json(book),
                    }

            updated = [clean_item, *book]
            serialized = _json_dumps(updated)
            if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("document is too large")
            now = _now()
            connection.execute(
                "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (owner_id, "vbook", serialized, now),
            )
            return {
                "created": True,
                "item": sanitize_json(clean_item),
                "data": sanitize_json(updated),
            }

    @staticmethod
    def _wbook_item_identity(item: Mapping[str, Any]) -> tuple[str, ...]:
        """Return a stable identity for one wrong-book item.

        Assignment items have an explicit server-owned key.  Legacy/practice
        records do not always carry one, so fall back to an explicit id and
        finally a deterministic question fingerprint.  The fallback keeps a
        retry of the active endpoint idempotent without changing old records.
        """

        assignment_id = _safe_text(item.get("assignmentId") or item.get("assignment_id"), 200)
        question_id = _safe_text(item.get("questionId") or item.get("question_id"), 200)
        if not question_id and isinstance(item.get("q"), Mapping):
            question = item.get("q")
            question_id = _safe_text(
                question.get("questionId") or question.get("id") or question.get("key"), 200
            )
        if assignment_id and question_id:
            return ("assignment", assignment_id, question_id)
        question = item.get("q") if isinstance(item.get("q"), Mapping) else item
        # Question content is the durable identity for ordinary practice.  A
        # per-card question number is not globally unique (every generated
        # practice starts again at Q1), so hash the full question snapshot.
        # A generated/stable wrong-item ``id`` is intentionally ignored here
        # so a legacy row that gains metadata still matches a retry.
        if isinstance(question, Mapping) and question:
            try:
                fingerprint = hashlib.sha256(_json_dumps(sanitize_json(question)).encode("utf-8")).hexdigest()
            except (TypeError, ValueError):
                fingerprint = hashlib.sha256(str(question).encode("utf-8")).hexdigest()
            return ("question", fingerprint)
        explicit_id = _safe_text(item.get("id") or item.get("wrongId") or item.get("wrong_id"), 200)
        if explicit_id:
            return ("id", explicit_id)
        try:
            fingerprint = hashlib.sha256(_json_dumps(sanitize_json(question)).encode("utf-8")).hexdigest()
        except (TypeError, ValueError):
            fingerprint = hashlib.sha256(str(question).encode("utf-8")).hexdigest()
        return ("question", fingerprint)

    def upsert_wbook_item(self, owner_id: str, item: Mapping[str, Any]) -> dict[str, Any]:
        """Append one wrong-book item atomically and de-duplicate retries.

        The SQLite ``documents`` row remains the single source of truth.  A
        single ``BEGIN IMMEDIATE`` transaction makes two browser retries safe,
        while the returned shape mirrors ``upsert_vbook_item`` for the active
        wrong-book API.
        """

        owner_id = _safe_text(owner_id, 200)
        if not owner_id:
            raise ValueError("owner id is required")
        if not isinstance(item, Mapping):
            raise ValueError("wrong-book item is invalid")
        incoming = dict(sanitize_json(dict(item)))

        question_raw = incoming.get("q")
        if not isinstance(question_raw, Mapping):
            question_raw = incoming.get("question")
        if not isinstance(question_raw, Mapping):
            # Accept the compact active-client shape where question fields are
            # posted alongside metadata instead of nested under ``q``.
            metadata_keys = {
                "ownerId", "owner_id", "sourceType", "source_type", "assignmentId", "assignment_id",
                "assignmentTitle", "assignment_title", "questionId", "question_id", "userAnswer",
                "user_answer", "user", "article", "articleIndex", "article_index", "sectionIndex",
                "section_index", "section", "box", "ts", "id", "wrongId", "wrong_id",
                "articleGroupId", "article_group_id", "articleTitle", "article_title",
                "articleExcerpt", "article_excerpt",
            }
            question_raw = {key: value for key, value in incoming.items() if key not in metadata_keys}
        if not isinstance(question_raw, Mapping) or not question_raw:
            raise ValueError("question is required")
        question = dict(sanitize_json(dict(question_raw)))

        assignment_id = _safe_text(incoming.get("assignmentId") or incoming.get("assignment_id"), 200)
        question_id = _safe_text(
            incoming.get("questionId")
            or incoming.get("question_id")
            or question.get("questionId")
            or question.get("id")
            or question.get("key"),
            200,
        )
        if question_id:
            incoming["questionId"] = question_id
            question.setdefault("questionId", question_id)
            question.setdefault("id", question_id)
        if assignment_id:
            incoming["assignmentId"] = assignment_id
        source_type = _safe_text(incoming.get("sourceType") or incoming.get("source_type"), 50).lower()
        if source_type:
            incoming["sourceType"] = source_type
        incoming.pop("ownerId", None)
        incoming.pop("owner_id", None)
        incoming.pop("question", None)
        # Article grouping is server-derived.  A browser may supply the
        # source article, but it cannot choose the group id or summary fields.
        for key in (
            "articleGroupId", "article_group_id", "articleTitle", "article_title",
            "articleExcerpt", "article_excerpt",
        ):
            incoming.pop(key, None)
        incoming["q"] = question
        if "userAnswer" not in incoming:
            for alias in ("user_answer", "user"):
                if alias in incoming:
                    incoming["userAnswer"] = incoming.get(alias)
                    break
        incoming.setdefault("box", 1)
        incoming.setdefault("ts", int(time.time() * 1000))
        attempt_id = _safe_text(incoming.get("attemptId") or incoming.get("attempt_id"), 200)
        if not attempt_id and assignment_id and question_id:
            # Adding a checked assignment question is one learning event.
            # Browser retries must not increase error counters.
            attempt_id = f"assignment:{assignment_id}:{question_id}"
        if attempt_id:
            incoming["attemptId"] = attempt_id
            incoming.pop("attempt_id", None)
        incoming.update(_wbook_article_metadata(incoming))
        identity = self._wbook_item_identity(incoming)
        # IDs are generated by the server when absent.  They are derived from
        # the durable identity and therefore remain stable across retries and
        # old JSON migrations.
        incoming.setdefault("id", _wbook_stable_id(identity))
        # The practice UI uses a localized display label for an empty answer.
        # Prefer its explicit boolean so "（未作答）" is not counted as an
        # answered error merely because the label itself is non-empty.
        if isinstance(incoming.get("answered"), bool):
            answered = bool(incoming.get("answered"))
        else:
            answered = _is_answered(incoming.get("userAnswer"))

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data_json FROM documents WHERE owner_id = ? AND section = ?",
                (owner_id, "wbook"),
            ).fetchone()
            try:
                book = json.loads(row[0]) if row else []
            except (TypeError, ValueError):
                book = []
            if not isinstance(book, list):
                book = []

            normalized_book = _normalize_wbook_items(book)
            for index, existing in enumerate(normalized_book):
                if not isinstance(existing, Mapping):
                    continue
                if self._wbook_item_identity(existing) == identity:
                    if attempt_id and _safe_text(existing.get("lastAttemptId"), 200) == attempt_id:
                        return {
                            "created": False,
                            "item": sanitize_json(dict(existing)),
                            "data": sanitize_json(normalized_book),
                        }
                    updated_item = dict(existing)
                    # Keep the trusted question/context while accepting the
                    # latest answer and display metadata from this attempt.
                    for key, value in incoming.items():
                        if key not in {
                            "id", "status", "errorCount", "unansweredCount",
                            "masteryStreak", "lastReviewedAt",
                        }:
                            updated_item[key] = value
                    updated_item["id"] = str(existing.get("id") or incoming["id"])
                    updated_item["status"] = "pending"
                    updated_item["masteryStreak"] = 0
                    updated_item["errorCount"] = int(existing.get("errorCount") or 0) + (1 if answered else 0)
                    updated_item["unansweredCount"] = int(existing.get("unansweredCount") or 0) + (0 if answered else 1)
                    updated_item["lastReviewedAt"] = int(time.time() * 1000)
                    if attempt_id:
                        updated_item["lastAttemptId"] = attempt_id
                    normalized_book = [
                        sanitize_json(updated_item),
                        *normalized_book[:index],
                        *normalized_book[index + 1 :],
                    ][:150]
                    serialized = _json_dumps(normalized_book)
                    if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
                        raise ValueError("document is too large")
                    now = _now()
                    connection.execute(
                        "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                        (owner_id, "wbook", serialized, now),
                    )
                    return {
                        "created": False,
                        "item": sanitize_json(updated_item),
                        "data": sanitize_json(normalized_book),
                    }

            incoming["status"] = "pending"
            incoming["masteryStreak"] = 0
            incoming["errorCount"] = int(incoming.get("errorCount") or 0) + (1 if answered else 0)
            incoming["unansweredCount"] = int(incoming.get("unansweredCount") or 0) + (0 if answered else 1)
            incoming["lastReviewedAt"] = int(time.time() * 1000)
            if attempt_id:
                incoming["lastAttemptId"] = attempt_id
            updated = [sanitize_json(incoming), *normalized_book][:150]
            serialized = _json_dumps(updated)
            if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("document is too large")
            now = _now()
            connection.execute(
                "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (owner_id, "wbook", serialized, now),
            )
            return {
                "created": True,
                "item": sanitize_json(incoming),
                "data": sanitize_json(updated),
            }

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

    def review_wbook_item(self, owner_id: str, item_id: str, answer: Any) -> dict[str, Any] | None:
        """Grade and advance one wrong-book item in a single SQLite transaction."""

        owner_id = _safe_text(owner_id, 200)
        item_id = _safe_text(item_id, 200)
        if not owner_id or not item_id:
            return None
        now_ms = int(time.time() * 1000)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data_json FROM documents WHERE owner_id = ? AND section = ?",
                (owner_id, "wbook"),
            ).fetchone()
            try:
                book_raw = json.loads(row[0]) if row else []
            except (TypeError, ValueError):
                book_raw = []
            book = _normalize_wbook_items(book_raw)
            selected_index = -1
            for index, candidate in enumerate(book):
                if isinstance(candidate, Mapping) and str(candidate.get("id") or "") == item_id:
                    selected_index = index
                    break
            if selected_index < 0:
                return None
            selected = dict(book[selected_index])
            question = selected.get("q") if isinstance(selected.get("q"), Mapping) else selected
            has_key, correct_answer = _assignment_answer_key(question if isinstance(question, Mapping) else {})
            answered = _is_answered(answer)
            correct = bool(has_key and answered and _answers_equal(answer, correct_answer))
            if correct:
                streak = _wbook_int(selected.get("masteryStreak")) + 1
                selected["masteryStreak"] = streak
                selected["status"] = "mastered" if streak >= 3 else "pending"
            else:
                selected["masteryStreak"] = 0
                selected["status"] = "pending"
                if answered:
                    selected["errorCount"] = _wbook_int(selected.get("errorCount")) + 1
                else:
                    selected["unansweredCount"] = _wbook_int(selected.get("unansweredCount")) + 1
            selected["lastReviewedAt"] = now_ms
            selected["userAnswer"] = sanitize_json(answer)
            book[selected_index] = sanitize_json(selected)
            serialized = _json_dumps(book)
            if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("document is too large")
            now = _now()
            connection.execute(
                "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (owner_id, "wbook", serialized, now),
            )
            return {
                "item": sanitize_json(selected),
                "correct": correct,
                "answered": answered,
                "correctAnswer": sanitize_json(correct_answer) if has_key else None,
                "data": sanitize_json(book),
            }

    def sync_review_outcomes(
        self,
        student_id: str,
        assignment: Mapping[str, Any],
        result: Mapping[str, Any],
    ) -> dict[str, int]:
        """Apply a review assignment's question outcomes to the student's book."""

        student_id = _safe_text(student_id, 200)
        assignment_id = _safe_text(assignment.get("id") or assignment.get("assignmentId"), 200)
        if not student_id or not assignment_id:
            return {"created": 0, "updated": 0}
        items = assignment.get("reviewItems")
        items = items if isinstance(items, list) else []
        records = result.get("records") if isinstance(result, Mapping) else []
        records_by_id = {
            str(record.get("questionId") or record.get("id")): record
            for record in records
            if isinstance(record, Mapping) and record.get("kind", "question") == "question"
        }
        now_ms = int(time.time() * 1000)
        created = updated = 0
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT data_json FROM documents WHERE owner_id = ? AND section = ?",
                (student_id, "wbook"),
            ).fetchone()
            try:
                book_raw = json.loads(row[0]) if row else []
            except (TypeError, ValueError):
                book_raw = []
            book = _normalize_wbook_items(book_raw)
            by_id = {
                str(item.get("id")): index
                for index, item in enumerate(book)
                if isinstance(item, Mapping) and item.get("id")
            }
            for review_item in items:
                if not isinstance(review_item, Mapping) or str(review_item.get("kind")) != "question":
                    continue
                review_id = _safe_text(review_item.get("id"), 200)
                record = records_by_id.get(review_id)
                if not review_id or not isinstance(record, Mapping):
                    continue
                source_id = _safe_text(review_item.get("_sourceItemId"), 200) or review_id
                index = by_id.get(source_id)
                if index is None:
                    # Legacy rows may have a generated id; fall back to the
                    # question identity before creating a new record.
                    candidate = review_item.get("q") if isinstance(review_item.get("q"), Mapping) else review_item
                    identity = ReadingTrainerStore._wbook_item_identity({"q": candidate})
                    for candidate_index, candidate_item in enumerate(book):
                        if ReadingTrainerStore._wbook_item_identity(candidate_item) == identity:
                            index = candidate_index
                            break
                is_correct = bool(record.get("correct"))
                answered = bool(record.get("answered"))
                if index is None:
                    if is_correct:
                        continue
                    question = review_item.get("q") if isinstance(review_item.get("q"), Mapping) else {}
                    new_item: dict[str, Any] = {
                        "id": source_id,
                        "questionId": source_id,
                        "sourceType": "assignment",
                        "assignmentId": assignment_id,
                        "assignmentTitle": _safe_text(assignment.get("title"), 500),
                        "q": sanitize_json(dict(question)),
                        "userAnswer": sanitize_json(record.get("userAnswer")),
                        "status": "pending",
                        "errorCount": 1 if answered else 0,
                        "unansweredCount": 0 if answered else 1,
                        "masteryStreak": 0,
                        "lastReviewedAt": now_ms,
                        "ts": now_ms,
                        "box": 1,
                    }
                    book.insert(0, sanitize_json(new_item))
                    by_id[source_id] = 0
                    by_id = {str(item.get("id")): i for i, item in enumerate(book) if isinstance(item, Mapping) and item.get("id")}
                    created += 1
                    continue
                current = dict(book[index])
                current["status"] = "pending"
                current["lastReviewedAt"] = now_ms
                current["masteryStreak"] = 0
                current["userAnswer"] = sanitize_json(record.get("userAnswer"))
                if is_correct:
                    streak = _wbook_int(current.get("masteryStreak")) + 1
                    # A review answer is correct; preserve the existing streak
                    # before resetting only on wrong/unanswered outcomes.
                    streak = _wbook_int(book[index].get("masteryStreak")) + 1
                    current["masteryStreak"] = streak
                    current["status"] = "mastered" if streak >= 3 else "pending"
                elif answered:
                    current["errorCount"] = _wbook_int(current.get("errorCount")) + 1
                else:
                    current["unansweredCount"] = _wbook_int(current.get("unansweredCount")) + 1
                book[index] = sanitize_json(current)
                updated += 1
            # The capacity rule applies to writes, including review-created
            # entries.  Existing legacy rows were not truncated on read.
            book = book[:150]
            serialized = _json_dumps(book)
            if len(serialized.encode("utf-8")) > 5 * 1024 * 1024:
                raise ValueError("document is too large")
            connection.execute(
                "INSERT INTO documents(owner_id, section, data_json, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(owner_id, section) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at",
                (student_id, "wbook", serialized, _now()),
            )
        return {"created": created, "updated": updated}

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

    def record_usage_event(
        self,
        user_id: str | None,
        event_type: str,
        metadata: Mapping[str, Any] | None = None,
        duration_ms: int | None = None,
    ) -> None:
        """Persist a privacy-safe product-usage event for the admin dashboard.

        Only aggregate-safe metadata is accepted; request bodies, answer text,
        prompts and credentials are deliberately not recorded.
        """
        event_type = re.sub(r"[^a-z0-9_.-]", "_", str(event_type or "event").lower())[:80] or "event"
        clean_meta: dict[str, Any] = {}
        if isinstance(metadata, Mapping):
            for key, value in metadata.items():
                key_text = re.sub(r"[^a-zA-Z0-9_.-]", "_", str(key))[:50]
                if not key_text or _is_sensitive_key(key_text):
                    continue
                if isinstance(value, bool):
                    clean_meta[key_text] = value
                elif isinstance(value, (int, float)) and math.isfinite(float(value)):
                    clean_meta[key_text] = int(value)
                elif isinstance(value, str) and len(value) <= 120:
                    clean_meta[key_text] = value
        now = _now()
        event_date = datetime.fromtimestamp(now, timezone.utc).date().isoformat()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO usage_events(event_id,user_id,event_type,event_date,duration_ms,meta_json,created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    "ue_" + uuid.uuid4().hex,
                    _safe_text(user_id, 200) or None,
                    event_type,
                    event_date,
                    max(0, int(duration_ms)) if duration_ms is not None else None,
                    _json_dumps(clean_meta),
                    now,
                ),
            )

    def usage_summary(self, days: int = 30) -> dict[str, Any]:
        """Return aggregate platform usage without exposing user content."""
        days = max(7, min(int(days or 30), 365))
        now = _now()
        cutoff = now - days * 86400
        with self.connect() as connection:
            event_rows = connection.execute(
                "SELECT event_type, COUNT(*) AS n, COUNT(DISTINCT user_id) AS users, "
                "AVG(duration_ms) AS avg_duration FROM usage_events WHERE created_at >= ? GROUP BY event_type",
                (cutoff,),
            ).fetchall()
            daily_rows = connection.execute(
                "SELECT event_date, COUNT(*) AS events, COUNT(DISTINCT user_id) AS active_users "
                "FROM usage_events WHERE created_at >= ? GROUP BY event_date ORDER BY event_date",
                (cutoff,),
            ).fetchall()
            event_meta_rows = connection.execute(
                "SELECT event_type, meta_json FROM usage_events WHERE created_at >= ?",
                (cutoff,),
            ).fetchall()
            user_rows = connection.execute("SELECT role, COUNT(*) AS n FROM users GROUP BY role").fetchall()
            assignment_total = connection.execute("SELECT COUNT(*) FROM assignments").fetchone()[0]
            recipient_total = connection.execute("SELECT COUNT(*) FROM assignment_recipients").fetchone()[0]
            recipient_submitted = connection.execute(
                "SELECT COUNT(*) FROM assignment_recipients WHERE status = 'submitted'"
            ).fetchone()[0]
            recipient_opened = connection.execute(
                "SELECT COUNT(*) FROM assignment_recipients WHERE opened_at IS NOT NULL"
            ).fetchone()[0]
            class_event_rows = connection.execute(
                "SELECT u.class_id, COUNT(e.event_id) AS events, COUNT(DISTINCT e.user_id) AS active_users "
                "FROM users u LEFT JOIN usage_events e ON e.user_id = u.id AND e.created_at >= ? "
                "WHERE u.role = 'student' AND u.class_id IS NOT NULL GROUP BY u.class_id",
                (cutoff,),
            ).fetchall()
        event_map = {str(row[0]): int(row[1] or 0) for row in event_rows}
        event_users = {str(row[0]): int(row[2] or 0) for row in event_rows}
        avg_duration = {str(row[0]): round(float(row[3] or 0)) for row in event_rows}
        meta_totals: dict[str, int] = {}
        daily: dict[str, dict[str, int]] = {
            str(row[0]): {"date": str(row[0]), "events": int(row[1] or 0), "activeUsers": int(row[2] or 0), "practice": 0, "assignmentSubmits": 0}
            for row in daily_rows
        }
        for row in event_meta_rows:
            event_type = str(row[0])
            try:
                meta = json.loads(row[1]) if row[1] else {}
            except (TypeError, ValueError):
                meta = {}
            if isinstance(meta, Mapping):
                for key in ("questionCount", "count"):
                    if isinstance(meta.get(key), (int, float)):
                        meta_totals[key] = meta_totals.get(key, 0) + int(meta[key])
            # The event date is intentionally derived from the record itself
            # in a second lightweight query only when daily chart is needed.
        with self.connect() as connection:
            typed_days = connection.execute(
                "SELECT event_date, event_type, COUNT(*) FROM usage_events WHERE created_at >= ? GROUP BY event_date,event_type",
                (cutoff,),
            ).fetchall()
        for row in typed_days:
            day = daily.setdefault(str(row[0]), {"date": str(row[0]), "events": 0, "activeUsers": 0, "practice": 0, "assignmentSubmits": 0})
            if row[1] in ("practice_submit", "practice_complete"):
                day["practice"] += int(row[2] or 0)
            if row[1] in ("assignment_submit", "assignment_complete"):
                day["assignmentSubmits"] += int(row[2] or 0)
        role_counts = {str(row[0]): int(row[1] or 0) for row in user_rows}
        with self.connect() as connection:
            active_users = int(connection.execute(
                "SELECT COUNT(DISTINCT user_id) FROM usage_events WHERE created_at >= ? AND user_id IS NOT NULL",
                (cutoff,),
            ).fetchone()[0] or 0)
        class_event_map = {str(row[0]): {"events": int(row[1] or 0), "activeStudents": int(row[2] or 0)} for row in class_event_rows}
        all_students = self.list_users("student")
        classes = []
        for item in self.list_classes():
            class_id = str(item.get("id") or "")
            classes.append({
                "id": class_id,
                "name": _safe_text(item.get("name") or item.get("className") or class_id, 120),
                "students": sum(1 for student in all_students if str(student.get("class_id") or "") == class_id),
                **class_event_map.get(class_id, {"events": 0, "activeStudents": 0}),
            })
        return {
            "periodDays": days,
            "since": cutoff * 1000,
            "generatedAt": now * 1000,
            "users": {
                "students": role_counts.get("student", 0),
                "teachers": role_counts.get("teacher", 0),
                "admins": role_counts.get("admin", 0),
                "active": active_users,
                "activeStudents": event_users.get("practice_submit", 0) + event_users.get("assignment_submit", 0),
                "activeTeachers": event_users.get("assignment_create", 0),
            },
            "learning": {
                "practiceSubmissions": event_map.get("practice_submit", 0),
                "assignmentOpens": event_map.get("assignment_open", 0),
                "assignmentSubmissions": event_map.get("assignment_submit", 0),
                "wrongReviews": event_map.get("wrong_review", 0),
                "vocabReviews": event_map.get("vocab_review", 0),
                "questions": meta_totals.get("questionCount", 0),
            },
            "assignments": {
                "total": int(assignment_total or 0),
                "recipients": int(recipient_total or 0),
                "opened": int(recipient_opened or 0),
                "submitted": int(recipient_submitted or 0),
                "submissionRate": round((recipient_submitted / recipient_total) * 100, 1) if recipient_total else 0,
            },
            "ai": {
                "requests": event_map.get("ai_request", 0),
                "success": event_map.get("ai_success", 0),
                "failure": event_map.get("ai_failure", 0),
                "avgDurationMs": avg_duration.get("ai_success", 0),
            },
            "classes": classes,
            "daily": [daily[key] for key in sorted(daily)],
        }

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
        # A class assignment is the current source of truth.  A student can
        # retain the historical ``created_by`` field after being moved to a
        # different class; that old teacher must not continue to read or write
        # the student's business data.  Only use created_by for students that
        # have not been assigned to a class yet.
        class_id = owner.get("class_id")
        if class_id:
            for item in self.list_classes():
                if str(item.get("id")) == str(class_id) and str(
                    item.get("teacherId") or item.get("teacher_id") or ""
                ) == str(teacher_id):
                    return True
            return False
        return owner.get("created_by") == teacher_id

    # ------------------------------------------------------------------
    # Assignment persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_json(raw: Any, default: Any) -> Any:
        try:
            value = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            return default
        return value

    @staticmethod
    def _due_timestamp(value: Any) -> int | None:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            numeric = int(value)
            return numeric // 1000 if numeric > 10_000_000_000 else numeric
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.timestamp())
        except (TypeError, ValueError, OverflowError):
            return None

    @classmethod
    def _assignment_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        """Decode one assignment row into the stable API shape.

        The snake_case aliases are intentionally retained for server-side
        callers while camelCase fields match the browser API contract.
        """

        def value(name: str, default: Any = None) -> Any:
            try:
                return row[name]  # type: ignore[index]
            except (KeyError, IndexError, TypeError):
                return default

        assignment_id = str(value("id") or "")
        teacher_id = str(value("teacher_id") or "")
        created_at = int(value("created_at") or 0)
        updated_at = int(value("updated_at") or created_at or 0)
        questions = cls._decode_json(value("questions_json"), [])
        sections = cls._decode_json(value("sections_json"), [])
        settings = cls._decode_json(value("settings_json"), {})
        assignment_type = _safe_text(value("assignment_type") or "question_card", 40).lower()
        if assignment_type not in {"question_card", "review"}:
            assignment_type = "question_card"
        review_items = cls._decode_json(value("review_items_json"), [])
        if not isinstance(review_items, list):
            review_items = []
        source_student_id = ""
        if isinstance(settings, Mapping):
            source_student_id = _safe_text(settings.get("sourceStudentId") or settings.get("source_student_id"), 200)
        due_at = value("due_at")
        due_ms = int(due_at or 0) * 1000 if due_at else None
        return {
            "id": assignment_id,
            "assignmentId": assignment_id,
            "teacherId": teacher_id,
            "teacher_id": teacher_id,
            "title": str(value("title") or ""),
            "instructions": str(value("instructions") or ""),
            "questions": sanitize_json(questions if isinstance(questions, list) else []),
            "sections": sanitize_json(sections if isinstance(sections, list) else []),
            "settings": sanitize_json(settings if isinstance(settings, Mapping) else {}),
            "generationSettings": sanitize_json(settings if isinstance(settings, Mapping) else {}),
            "assignmentType": assignment_type,
            "assignment_type": assignment_type,
            "reviewItems": sanitize_json(review_items),
            "sourceStudentId": source_student_id or None,
            "status": str(value("status") or "draft"),
            "dueAt": due_ms,
            "deadline": due_ms,
            "createdAt": created_at * 1000,
            "updatedAt": updated_at * 1000,
            "created_at": created_at,
            "updated_at": updated_at,
            "studentIds": [],
            "recipients": [],
        }

    @classmethod
    def _recipient_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        def value(name: str, default: Any = None) -> Any:
            try:
                return row[name]  # type: ignore[index]
            except (KeyError, IndexError, TypeError):
                return default

        assignment_id = str(value("assignment_id") or "")
        student_id = str(value("student_id") or "")
        status = str(value("status") or "unread")
        unread = bool(int(value("unread") or 0))
        answers = cls._decode_json(value("answers_json"), None)
        result = cls._decode_json(value("result_json"), None)
        created_at = int(value("created_at") or 0)
        updated_at = int(value("updated_at") or created_at or 0)
        opened_at = value("opened_at")
        submitted_at = value("submitted_at")
        item: dict[str, Any] = {
            "assignmentId": assignment_id,
            "studentId": student_id,
            "status": status,
            "unread": unread,
            "read": not unread,
            "openedAt": int(opened_at or 0) * 1000 if opened_at else None,
            "submittedAt": int(submitted_at or 0) * 1000 if submitted_at else None,
            "createdAt": created_at * 1000,
            "updatedAt": updated_at * 1000,
            "result": sanitize_json(result) if isinstance(result, (Mapping, list)) else result,
        }
        if answers is not None:
            item["answers"] = sanitize_json(answers)
        return item

    def _assignment_recipients(self, assignment_id: str, student_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM assignment_recipients WHERE assignment_id = ?"
        params: list[Any] = [assignment_id]
        if student_id is not None:
            query += " AND student_id = ?"
            params.append(student_id)
        query += " ORDER BY student_id"
        with self.connect() as connection:
            rows = connection.execute(query, tuple(params)).fetchall()
        return [self._recipient_row(row) for row in rows]

    def create_assignment(
        self,
        teacher_id: str,
        payload: Mapping[str, Any],
        student_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Create or idempotently update an assignment and its recipients.

        ``id`` is accepted from trusted callers to make retries stable; when
        omitted a server-generated ``asgn_`` identifier is used.  Existing
        recipients are never deleted or reset, so a retry cannot erase a
        student's submitted answers.
        """

        data = payload if isinstance(payload, Mapping) else {}
        assignment_id = _safe_text(data.get("id") or data.get("assignmentId"), 200)
        if not assignment_id:
            assignment_id = "asgn_" + uuid.uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", assignment_id):
            raise ValueError("invalid assignment id")
        title = _safe_text(data.get("title") or data.get("name"), 500)
        instructions = _safe_text(data.get("instructions") or data.get("description"), 10000)
        questions = data.get("questions") if isinstance(data.get("questions"), list) else []
        sections = data.get("sections") if isinstance(data.get("sections"), list) else []
        settings_raw = data.get("settings", data.get("generationSettings", {}))
        settings = settings_raw if isinstance(settings_raw, Mapping) else {}
        assignment_type = _safe_text(
            data.get("assignmentType") or data.get("assignment_type") or "question_card", 40
        ).lower()
        if assignment_type not in {"question_card", "review"}:
            assignment_type = "question_card"
        review_items = data.get("reviewItems") if isinstance(data.get("reviewItems"), list) else []
        due_at = self._due_timestamp(data.get("dueAt", data.get("due_at", data.get("deadline"))))
        recipient_values: list[str] = []
        if student_ids is None:
            student_ids = data.get("studentIds") or data.get("student_ids") or data.get("students") or []
        if isinstance(student_ids, str):
            student_ids = [student_ids]
        for item in student_ids or []:
            candidate = item.get("id") if isinstance(item, Mapping) else item
            candidate = _safe_text(candidate, 200)
            if candidate and candidate not in recipient_values:
                recipient_values.append(candidate)
        status = _safe_text(data.get("status"), 30).lower()
        if status not in {"draft", "sent", "published", "archived"}:
            status = "sent" if recipient_values else "draft"
        now = _now()
        encoded_questions = _json_dumps(sanitize_json(questions))
        encoded_sections = _json_dumps(sanitize_json(sections))
        encoded_settings = _json_dumps(sanitize_json(settings))
        encoded_review_items = _json_dumps(sanitize_json(review_items))
        if sum(len(item.encode("utf-8")) for item in (encoded_questions, encoded_sections, encoded_settings, encoded_review_items)) > 8 * 1024 * 1024:
            raise ValueError("assignment is too large")
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT teacher_id, created_at FROM assignments WHERE id = ?", (assignment_id,)
            ).fetchone()
            if existing and str(existing[0]) != str(teacher_id):
                raise PermissionError("assignment belongs to another teacher")
            created_at = int(existing[1]) if existing else now
            connection.execute(
                "INSERT INTO assignments(id, teacher_id, title, instructions, questions_json, sections_json, settings_json, assignment_type, review_items_json, status, due_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET title = excluded.title, instructions = excluded.instructions, "
                "questions_json = excluded.questions_json, sections_json = excluded.sections_json, settings_json = excluded.settings_json, "
                "assignment_type = excluded.assignment_type, review_items_json = excluded.review_items_json, "
                "status = excluded.status, due_at = excluded.due_at, updated_at = excluded.updated_at",
                (
                    assignment_id,
                    str(teacher_id),
                    title,
                    instructions,
                    encoded_questions,
                    encoded_sections,
                    encoded_settings,
                    assignment_type,
                    encoded_review_items,
                    status,
                    due_at,
                    created_at,
                    now,
                ),
            )
            for student_id in recipient_values:
                connection.execute(
                    "INSERT OR IGNORE INTO assignment_recipients(assignment_id, student_id, status, unread, created_at, updated_at) "
                    "VALUES (?, ?, 'unread', 1, ?, ?)",
                    (assignment_id, student_id, now, now),
                )
        return self.get_assignment(assignment_id, teacher_id=str(teacher_id)) or {}

    def get_assignment(
        self,
        assignment_id: str,
        *,
        teacher_id: str | None = None,
        student_id: str | None = None,
    ) -> dict[str, Any] | None:
        assignment_id = _safe_text(assignment_id, 200)
        if not assignment_id:
            return None
        query = "SELECT * FROM assignments WHERE id = ?"
        params: list[Any] = [assignment_id]
        if teacher_id is not None:
            query += " AND teacher_id = ?"
            params.append(str(teacher_id))
        with self.connect() as connection:
            row = connection.execute(query, tuple(params)).fetchone()
        if not row:
            return None
        result = self._assignment_row(row)
        recipients = self._assignment_recipients(assignment_id, student_id)
        if student_id is not None and not recipients:
            # A student filter is an authorization boundary, not merely a
            # projection.  Never return an assignment shell to a non-recipient.
            return None
        result["recipients"] = recipients
        result["studentIds"] = [item["studentId"] for item in recipients]
        return result

    def list_assignments(
        self,
        *,
        teacher_id: str | None = None,
        student_id: str | None = None,
    ) -> list[dict[str, Any]]:
        if teacher_id is None and student_id is None:
            query = "SELECT * FROM assignments ORDER BY updated_at DESC, id DESC"
            params: tuple[Any, ...] = ()
        elif teacher_id is not None:
            query = "SELECT * FROM assignments WHERE teacher_id = ? ORDER BY updated_at DESC, id DESC"
            params = (str(teacher_id),)
        else:
            query = (
                "SELECT a.* FROM assignments a JOIN assignment_recipients r ON r.assignment_id = a.id "
                "WHERE r.student_id = ? ORDER BY a.updated_at DESC, a.id DESC"
            )
            params = (str(student_id),)
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        results = []
        for row in rows:
            item = self._assignment_row(row)
            recipients = self._assignment_recipients(str(row["id"]), student_id)
            item["recipients"] = recipients
            item["studentIds"] = [recipient["studentId"] for recipient in recipients]
            results.append(item)
        return results

    def mark_assignment_open(self, assignment_id: str, student_id: str) -> dict[str, Any] | None:
        assignment_id = _safe_text(assignment_id, 200)
        student_id = _safe_text(student_id, 200)
        if not assignment_id or not student_id:
            return None
        now = _now()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT status, opened_at FROM assignment_recipients WHERE assignment_id = ? AND student_id = ?",
                (assignment_id, student_id),
            ).fetchone()
            if not row:
                return None
            if str(row[0]) != "submitted":
                connection.execute(
                    "UPDATE assignment_recipients SET status = 'read', unread = 0, opened_at = COALESCE(opened_at, ?), updated_at = ? "
                    "WHERE assignment_id = ? AND student_id = ?",
                    (now, now, assignment_id, student_id),
                )
        return self.get_assignment(assignment_id, student_id=student_id)

    @classmethod
    def _question_check_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
        """Decode one first-attempt question check without exposing storage details."""

        def value(name: str, default: Any = None) -> Any:
            try:
                return row[name]  # type: ignore[index]
            except (KeyError, IndexError, TypeError):
                return default

        answer = cls._decode_json(value("answer_json"), None)
        result = cls._decode_json(value("result_json"), {})
        return {
            "assignmentId": str(value("assignment_id") or ""),
            "studentId": str(value("student_id") or ""),
            "questionId": str(value("question_id") or ""),
            "answer": sanitize_json(answer),
            "result": sanitize_json(result) if isinstance(result, Mapping) else {},
            "checkedAt": int(value("checked_at") or 0) * 1000 if value("checked_at") else None,
            "updatedAt": int(value("updated_at") or 0) * 1000 if value("updated_at") else None,
        }

    def get_assignment_question_check(
        self, assignment_id: str, student_id: str, question_id: str
    ) -> dict[str, Any] | None:
        assignment_id = _safe_text(assignment_id, 200)
        student_id = _safe_text(student_id, 200)
        question_id = _safe_text(question_id, 200)
        if not assignment_id or not student_id or not question_id:
            return None
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM assignment_question_checks "
                "WHERE assignment_id = ? AND student_id = ? AND question_id = ?",
                (assignment_id, student_id, question_id),
            ).fetchone()
        return self._question_check_row(row) if row else None

    def list_assignment_question_checks(
        self, assignment_id: str, student_id: str
    ) -> dict[str, dict[str, Any]]:
        assignment_id = _safe_text(assignment_id, 200)
        student_id = _safe_text(student_id, 200)
        if not assignment_id or not student_id:
            return {}
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assignment_question_checks "
                "WHERE assignment_id = ? AND student_id = ? ORDER BY question_id",
                (assignment_id, student_id),
            ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            item = self._question_check_row(row)
            result[str(item["questionId"])] = item
        return result

    def save_assignment_question_check(
        self,
        assignment_id: str,
        student_id: str,
        question_id: str,
        answer: Any,
        result: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Save a student's first score for a question.

        ``INSERT OR IGNORE`` makes this operation safe under concurrent browser
        retries.  A later request always receives the original answer/result;
        it can never replace the first scored attempt.
        """

        assignment_id = _safe_text(assignment_id, 200)
        student_id = _safe_text(student_id, 200)
        question_id = _safe_text(question_id, 200)
        if not assignment_id or not student_id or not question_id:
            return None, False
        now = _now()
        encoded_answer = _json_dumps(sanitize_json(answer))
        encoded_result = _json_dumps(sanitize_json(dict(result)))
        with self.connect() as connection:
            before = connection.execute(
                "SELECT 1 FROM assignment_question_checks "
                "WHERE assignment_id = ? AND student_id = ? AND question_id = ?",
                (assignment_id, student_id, question_id),
            ).fetchone()
            connection.execute(
                "INSERT OR IGNORE INTO assignment_question_checks "
                "(assignment_id, student_id, question_id, answer_json, result_json, checked_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (assignment_id, student_id, question_id, encoded_answer, encoded_result, now, now),
            )
            row = connection.execute(
                "SELECT * FROM assignment_question_checks "
                "WHERE assignment_id = ? AND student_id = ? AND question_id = ?",
                (assignment_id, student_id, question_id),
            ).fetchone()
        return (self._question_check_row(row) if row else None), bool(before)

    def record_assignment_outcomes(
        self,
        student_id: str,
        assignment_id: str,
        result: Mapping[str, Any],
        assignment: Mapping[str, Any] | None = None,
        *,
        include_wrong: bool = True,
    ) -> dict[str, int]:
        """Write a first submission to the student's existing grade/wrong books.

        The assignment recipient row is the idempotency source of truth.  This
        helper additionally de-duplicates by assignment/question id so a
        recovery retry cannot append duplicate local records.
        """

        student_id = _safe_text(student_id, 200)
        assignment_id = _safe_text(assignment_id, 200)
        if not student_id or not assignment_id:
            return {"grades": 0, "wrong": 0}
        clean_result = sanitize_json(dict(result))
        if not isinstance(clean_result, Mapping):
            clean_result = {}
        assignment_data: Mapping[str, Any] | None = assignment if isinstance(assignment, Mapping) else None
        if assignment_data is None:
            assignment_data = self.get_assignment(assignment_id, student_id=student_id)
        assignment_title = _safe_text(
            (assignment_data.get("title") or assignment_data.get("name")) if assignment_data else "",
            500,
        )
        grades = self.get_document(student_id, "grades", [])
        grades = list(grades) if isinstance(grades, list) else []
        grade_exists = any(
            isinstance(item, Mapping)
            and str(item.get("assignmentId") or item.get("assignment_id") or "") == assignment_id
            for item in grades
        )
        grade_written = 0
        if not grade_exists:
            grades.append(
                {
                    "id": f"assignment:{assignment_id}",
                    "assignmentId": assignment_id,
                    "source": "assignment",
                    "assignmentTitle": assignment_title,
                    "title": assignment_title,
                    "ts": clean_result.get("submittedAt") or _now() * 1000,
                    "pct": clean_result.get("pct", 0),
                    "right": clean_result.get("right", clean_result.get("correct", 0)),
                    "total": clean_result.get("total", 0),
                    "wrongCount": clean_result.get("wrongCount", 0),
                    "unanswered": clean_result.get("unanswered", 0),
                    "byType": clean_result.get("byType", {}),
                    "byExam": clean_result.get("byExam", {}),
                }
            )
            self.put_document(student_id, "grades", grades)
            grade_written = 1

        wrong_items = clean_result.get("wrong", []) if isinstance(clean_result, Mapping) else []
        if not include_wrong:
            wrong_items = []
        if assignment_data and str(assignment_data.get("assignmentType") or assignment_data.get("assignment_type") or "").lower() == "review":
            # Review submissions are synchronized by sync_review_outcomes,
            # which has the authoritative source item linkage and streak
            # semantics.  Avoid creating a second synthetic wrong-book row.
            wrong_items = []
        wrong_book = self.get_document(student_id, "wbook", [])
        wrong_book = _normalize_wbook_items(wrong_book)
        wrong_written = 0
        if isinstance(wrong_items, list):
            # Reuse the same identity helper as the active API.  In
            # particular, this handles legacy rows whose question id is only
            # present inside ``q`` and avoids conditional-expression
            # precedence bugs when ``q`` is not a mapping.
            existing_keys = {
                self._wbook_item_identity(item)
                for item in wrong_book
                if isinstance(item, Mapping)
            }
            for item in wrong_items:
                if not isinstance(item, Mapping):
                    continue
                question_id = _safe_text(
                    item.get("questionId") or item.get("question_id") or item.get("id"), 200
                )
                question_value = item.get("q")
                if not question_id and isinstance(question_value, Mapping):
                    question_id = _safe_text(
                        question_value.get("questionId") or question_value.get("id") or question_value.get("key"),
                        200,
                    )
                key = ("assignment", assignment_id, question_id)
                if not question_id or key in existing_keys:
                    continue
                snapshot = (
                    _assignment_question_snapshot(assignment_data, question_id, fallback=item)
                    if assignment_data
                    else None
                )
                if not isinstance(snapshot, Mapping):
                    fallback_question = item.get("q") if isinstance(item.get("q"), Mapping) else {}
                    snapshot = {
                        "q": sanitize_json(dict(fallback_question)),
                        "article": item.get("article", ""),
                        "articleIndex": item.get("articleIndex"),
                        "sectionIndex": item.get("sectionIndex"),
                        "sectionTitle": item.get("sectionTitle", ""),
                        "sectionId": item.get("sectionId", ""),
                        "section": item.get("section"),
                    }
                question_snapshot = snapshot.get("q") if isinstance(snapshot.get("q"), Mapping) else {}
                question_snapshot = dict(question_snapshot)
                # Preserve the trusted grading answer/explanation even when a
                # legacy assignment question omitted those aliases.
                if "answer" not in question_snapshot and item.get("correctAnswer") is not None:
                    question_snapshot["answer"] = item.get("correctAnswer")
                if not question_snapshot.get("explanation") and item.get("explanation") is not None:
                    question_snapshot["explanation"] = item.get("explanation")
                question_snapshot.setdefault("id", question_id)
                question_snapshot.setdefault("questionId", question_id)
                article = snapshot.get("article") or item.get("article", "")
                wrong_entry = {
                    "id": _wbook_stable_id(key),
                    "assignmentId": assignment_id,
                    "questionId": question_id,
                    "sourceType": "assignment",
                    "assignmentTitle": assignment_title,
                    "q": sanitize_json(question_snapshot),
                    "userAnswer": item.get("userAnswer"),
                    "article": article,
                    "articleIndex": snapshot.get("articleIndex"),
                    "sectionIndex": snapshot.get("sectionIndex"),
                    "sectionTitle": snapshot.get("sectionTitle", ""),
                    "sectionId": snapshot.get("sectionId", ""),
                    "section": snapshot.get("section"),
                    "box": 1,
                    "status": "pending",
                    "errorCount": 0 if not _is_answered(item.get("userAnswer")) else 1,
                    "unansweredCount": 1 if not _is_answered(item.get("userAnswer")) else 0,
                    "masteryStreak": 0,
                    "lastReviewedAt": clean_result.get("submittedAt") or _now() * 1000,
                    "ts": clean_result.get("submittedAt") or _now() * 1000,
                }
                wrong_book.insert(
                    0,
                    wrong_entry,
                )
                existing_keys.add(key)
                wrong_written += 1
            if wrong_written:
                self.put_document(student_id, "wbook", wrong_book[:150])
        return {"grades": grade_written, "wrong": wrong_written}

    def submit_assignment(
        self,
        assignment_id: str,
        student_id: str,
        answers: Any,
        result: Mapping[str, Any],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Persist a submission and return ``(assignment, idempotent)``.

        A previously submitted recipient is never overwritten, even when a
        retried request carries a different answer payload.
        """

        assignment_id = _safe_text(assignment_id, 200)
        student_id = _safe_text(student_id, 200)
        if not assignment_id or not student_id:
            return None, False
        now = _now()
        encoded_answers = _json_dumps(sanitize_json(answers))
        encoded_result = _json_dumps(sanitize_json(dict(result)))
        with self.connect() as connection:
            row = connection.execute(
                "SELECT status FROM assignment_recipients WHERE assignment_id = ? AND student_id = ?",
                (assignment_id, student_id),
            ).fetchone()
            if not row:
                return None, False
            if str(row[0]) == "submitted":
                return self.get_assignment(assignment_id, student_id=student_id), True
            connection.execute(
                "UPDATE assignment_recipients SET status = 'submitted', unread = 0, opened_at = COALESCE(opened_at, ?), "
                "submitted_at = ?, answers_json = ?, result_json = ?, updated_at = ? "
                "WHERE assignment_id = ? AND student_id = ? AND status <> 'submitted'",
                (now, now, encoded_answers, encoded_result, now, assignment_id, student_id),
            )
        return self.get_assignment(assignment_id, student_id=student_id), False

    def clear_expired_sessions(self) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (_now(),))


def _wbook_stable_id(identity: tuple[str, ...]) -> str:
    """Derive a compact, deterministic wrong-book item identifier."""

    digest = hashlib.sha256("\x1f".join(identity).encode("utf-8")).hexdigest()
    return "wbi_" + digest[:32]


def _wbook_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return default


def _wbook_article_text(item: Mapping[str, Any]) -> str:
    """Return the best available article snapshot for one wrong-book row."""

    for value in (
        item.get("article"),
        item.get("passage"),
        item.get("context"),
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    section = item.get("section")
    if isinstance(section, Mapping):
        context = _context_text(section)
        if context:
            return context.strip()
    question = item.get("q")
    if isinstance(question, Mapping):
        context = _context_text(question)
        if context:
            return context.strip()
    return ""


def _wbook_article_metadata(value: Mapping[str, Any]) -> dict[str, str]:
    """Derive a stable article group and compact display metadata.

    Exact article content is the primary key so the same passage can merge
    across ordinary practice and assignments.  Source identifiers are used
    only when a historical row no longer contains its article snapshot.
    """

    item = value if isinstance(value, Mapping) else {}
    question = item.get("q") if isinstance(item.get("q"), Mapping) else {}
    article = _wbook_article_text(item)
    normalized_article = re.sub(r"\s+", " ", article).strip().casefold()
    if normalized_article:
        identity = "content\x1f" + normalized_article
    else:
        source_id = _safe_text(
            item.get("articleId")
            or item.get("article_id")
            or item.get("resourceId")
            or item.get("resource_id")
            or item.get("libraryId")
            or item.get("library_id")
            or question.get("articleId")
            or question.get("article_id"),
            300,
        )
        assignment_id = _safe_text(item.get("assignmentId") or item.get("assignment_id"), 200)
        section_id = _safe_text(item.get("sectionId") or item.get("section_id"), 200)
        article_index = item.get("articleIndex", item.get("article_index", item.get("sectionIndex")))
        if source_id:
            identity = "source\x1f" + source_id
        elif assignment_id and (section_id or article_index not in (None, "")):
            identity = "assignment-section\x1f{}\x1f{}".format(
                assignment_id, section_id or str(article_index)
            )
        elif assignment_id:
            identity = "assignment\x1f" + assignment_id
        else:
            # Legacy rows without any passage cannot be safely merged merely
            # because their titles match.  Keep the question identity as a
            # deterministic one-item article group.
            identity = "question\x1f" + "\x1f".join(ReadingTrainerStore._wbook_item_identity(item))
    group_id = "wba_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]

    explicit_title = _safe_text(
        item.get("articleTitle")
        or item.get("article_title")
        or item.get("sectionTitle")
        or item.get("section_title")
        or question.get("articleTitle")
        or question.get("article_title"),
        160,
    )
    first_line = ""
    if article:
        first_line = next((line.strip() for line in article.splitlines() if line.strip()), "")
        if len(first_line) > 120:
            first_line = ""
    assignment_title = _safe_text(
        item.get("assignmentTitle") or item.get("assignment_title"), 160
    )
    title = explicit_title or first_line or assignment_title or "未命名文章"
    excerpt_source = re.sub(r"\s+", " ", article).strip()
    excerpt = excerpt_source[:180] + ("…" if len(excerpt_source) > 180 else "")
    if not excerpt:
        prompt = _safe_text(question.get("prompt") or question.get("question"), 180)
        excerpt = prompt or "该历史错题未保存原文快照"
    return {
        "articleGroupId": group_id,
        "articleTitle": title,
        "articleExcerpt": excerpt,
    }


def _normalize_wbook_item(value: Any) -> dict[str, Any] | None:
    """Fill server-owned metadata on a legacy item without dropping fields."""

    if not isinstance(value, Mapping):
        return None
    item = dict(sanitize_json(dict(value)))
    identity = ReadingTrainerStore._wbook_item_identity(item)
    if not _safe_text(item.get("id"), 200):
        item["id"] = _wbook_stable_id(identity)
    status = str(item.get("status") or "pending").strip().lower()
    item["status"] = "mastered" if status == "mastered" else "pending"
    item["errorCount"] = _wbook_int(item.get("errorCount"), 0)
    item["unansweredCount"] = _wbook_int(item.get("unansweredCount"), 0)
    item["masteryStreak"] = _wbook_int(item.get("masteryStreak"), 0)
    reviewed = item.get("lastReviewedAt")
    item["lastReviewedAt"] = _wbook_int(reviewed, 0) if reviewed not in (None, "") else None
    item.update(_wbook_article_metadata(item))
    return item


def _normalize_wbook_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        normalized = _normalize_wbook_item(item)
        if normalized is not None:
            result.append(normalized)
        else:
            # Preserve malformed legacy entries verbatim; they are not
            # eligible for server review but migration must remain lossless.
            if isinstance(item, Mapping):
                result.append(dict(item))
    return result


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
        if section == "assignments":
            assignment_id = value.get("assignment_id") or value.get("assignmentId") or value.get("id")
            student_id = value.get("student_id") or value.get("studentId")
            if assignment_id not in (None, "") and student_id not in (None, ""):
                return f"assignments:{assignment_id}:{student_id}"
            if assignment_id not in (None, ""):
                return f"assignments:{assignment_id}"
        if section == "wbook":
            assignment_id = value.get("assignment_id") or value.get("assignmentId")
            question_id = value.get("question_id") or value.get("questionId")
            if not question_id and isinstance(value.get("q"), Mapping):
                question = value.get("q")
                question_id = question.get("questionId") or question.get("id") or question.get("key")
            if assignment_id not in (None, "") and question_id not in (None, ""):
                return f"wbook:{owner_id}:{assignment_id}:{question_id}"
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
    elif section == "assignments":
        assignment_id = data.get("assignment_id") or data.get("assignmentId") or data.get("id") or ""
        student_id = data.get("student_id") or data.get("studentId") or ""
        fields = {
            "作业ID": assignment_id,
            "学生ID": student_id,
            "教师ID": data.get("teacher_id") or data.get("teacherId") or owner_id,
            "标题": data.get("title") or "",
            "状态": data.get("status") or "",
            "未读": bool(data.get("unread")),
            "提交时间": data.get("submittedAt") or data.get("submitted_at") or "",
            "结果JSON": _json_dumps(data.get("result")) if data.get("result") is not None else "",
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
    # Assignments are a separate syncable entity.  One row per
    # assignment/student recipient gives Feishu a stable key even when one
    # teacher sends the same card to multiple students; submitted answers and
    # result JSON remain server-derived data, never browser storage.
    with store.connect() as connection:
        rows = connection.execute(
            "SELECT a.id, a.teacher_id, a.title, a.instructions, a.questions_json, a.sections_json, a.settings_json, a.status, "
            "a.created_at, a.updated_at, r.student_id, r.status AS recipient_status, r.unread, r.opened_at, r.submitted_at, "
            "r.answers_json, r.result_json FROM assignments a LEFT JOIN assignment_recipients r ON r.assignment_id = a.id "
            "ORDER BY a.updated_at, a.id, r.student_id"
        ).fetchall()
    for row in rows:
        try:
            result_value = json.loads(row[16]) if row[16] else None
            answers_value = json.loads(row[15]) if row[15] else None
        except (TypeError, ValueError):
            result_value = answers_value = None
        value = {
            "assignmentId": row[0],
            "assignment_id": row[0],
            "studentId": row[10] or "",
            "student_id": row[10] or "",
            "teacherId": row[1],
            "teacher_id": row[1],
            "title": row[2],
            "instructions": row[3],
            "questions": ReadingTrainerStore._decode_json(row[4], []),
            "sections": ReadingTrainerStore._decode_json(row[5], []),
            "settings": ReadingTrainerStore._decode_json(row[6], {}),
            "status": row[11] or row[7],
            "unread": bool(row[12]) if row[10] else False,
            "openedAt": int(row[13] or 0) * 1000 if row[13] else None,
            "submittedAt": int(row[14] or 0) * 1000 if row[14] else None,
            "answers": answers_value,
            "result": result_value,
            "createdAt": int(row[8] or 0) * 1000,
            "updatedAt": int(row[9] or 0) * 1000,
        }
        grouped["assignments"].append({"owner_id": row[1] or GLOBAL_OWNER_ID, "value": value})
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
    if section == "assignments" and fields.get("作业ID"):
        if fields.get("学生ID") not in (None, ""):
            return f"assignments:{fields.get('作业ID')}:{fields.get('学生ID')}"
        return f"assignments:{fields.get('作业ID')}"
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
        # Assignments have no baked-in Feishu table ID.  They become part of
        # the plan as soon as a deployment configures one, while ordinary
        # syncs continue to work unchanged when that table is absent.
        if section not in cfg["tables"] or not cfg["tables"].get(section):
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


_ANSWER_KEY_NAMES = {
    "answer",
    "answers",
    "answerkey",
    "answerkeys",
    "correctanswer",
    "correctanswers",
    "rightanswer",
    "rightanswers",
    "correctoption",
    "correctoptions",
    "correctchoice",
    "correctchoices",
    "correct",
    "iscorrect",
    "correctness",
    "solution",
    "solutions",
    "explanation",
    "explanations",
}


def _is_answer_key_name(name: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(name).strip().lower())
    return normalized in _ANSWER_KEY_NAMES or normalized.startswith("answerkey") or normalized.startswith("correctanswer")


def _strip_answer_keys(value: Any) -> Any:
    """Remove answer keys recursively from a student-visible question card."""

    if isinstance(value, Mapping):
        return {
            str(key): _strip_answer_keys(item)
            for key, item in value.items()
            if not _is_answer_key_name(key)
        }
    if isinstance(value, (list, tuple)):
        return [_strip_answer_keys(item) for item in value]
    return value


def _assignment_question_list(assignment: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten either ``sections[].questions`` or a top-level questions list."""

    sections = assignment.get("sections")
    flattened: list[dict[str, Any]] = []
    if isinstance(sections, list):
        for section_index, section in enumerate(sections):
            if not isinstance(section, Mapping):
                continue
            questions = section.get("questions")
            if not isinstance(questions, list):
                continue
            for question_index, question in enumerate(questions):
                if isinstance(question, Mapping):
                    item = dict(question)
                    item.setdefault("_section_index", section_index)
                    item.setdefault("_question_index", question_index)
                    if section.get("exam") is not None:
                        item.setdefault("_section_exam", section.get("exam"))
                    flattened.append(item)
    if flattened:
        return flattened
    questions = assignment.get("questions")
    if isinstance(questions, list):
        for index, question in enumerate(questions):
            if isinstance(question, Mapping):
                item = dict(question)
                item.setdefault("_question_index", index)
                flattened.append(item)
    return flattened


def _review_item_list(assignment: Mapping[str, Any]) -> list[dict[str, Any]]:
    value = assignment.get("reviewItems")
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            continue
        clean = dict(item)
        clean.setdefault("id", str(index + 1))
        kind = _safe_text(clean.get("kind"), 30).lower()
        clean["kind"] = "vocab" if kind == "vocab" else "question"
        result.append(clean)
    return result


def _strip_internal_fields(value: Any) -> Any:
    """Remove server-only review linkage fields from API projections."""

    if isinstance(value, Mapping):
        return {
            str(key): _strip_internal_fields(item)
            for key, item in value.items()
            if not str(key).startswith("_")
        }
    if isinstance(value, (list, tuple)):
        return [_strip_internal_fields(item) for item in value]
    return value


def _context_text(value: Any) -> str:
    """Extract an article/passage string from a section-like mapping."""

    if not isinstance(value, Mapping):
        return ""
    for key in ("article", "passage", "text", "content", "source", "context"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return ""


def _assignment_question_snapshot(
    assignment: Mapping[str, Any],
    question_id: Any,
    *,
    fallback: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a complete, answer-bearing question snapshot plus source context.

    Assignment detail responses intentionally redact answer keys before a
    student submits.  Wrong-book persistence runs on the trusted server-side
    assignment and therefore uses the original question object, retaining all
    renderer fields (options/items/headings/steps/beginnings/endings) and the
    answer/explanation.  Section/article metadata is copied alongside the
    question so a later wrong-book review does not depend on a mutable article
    library entry.
    """

    requested_id = _safe_text(question_id, 200)
    if not requested_id:
        return None
    questions = _assignment_question_list(assignment)
    selected: Mapping[str, Any] | None = None
    selected_index = -1
    for index, candidate in enumerate(questions):
        if _assignment_question_id(candidate, index) == requested_id:
            selected = candidate
            selected_index = index
            break
    if selected is None:
        if isinstance(fallback, Mapping):
            selected = fallback
        else:
            return None

    question = dict(sanitize_json(dict(selected)))
    question.pop("_section_index", None)
    question.pop("_question_index", None)
    question.pop("_section_exam", None)
    question["id"] = requested_id
    question.setdefault("questionId", requested_id)
    # Normalize alternate answer-key aliases for the browser's shared
    # ``renderQuestion``/``checkQuestion`` path while retaining every original
    # field in the snapshot.
    if "answer" not in question:
        has_key, answer = _assignment_answer_key(selected)
        if has_key:
            question["answer"] = sanitize_json(answer)

    sections = assignment.get("sections")
    section_index: int | None = None
    section: Mapping[str, Any] | None = None
    if isinstance(selected, Mapping) and selected.get("_section_index") is not None:
        try:
            section_index = int(selected.get("_section_index"))
        except (TypeError, ValueError):
            section_index = None
    if section_index is not None and isinstance(sections, list) and 0 <= section_index < len(sections):
        candidate_section = sections[section_index]
        if isinstance(candidate_section, Mapping):
            section = candidate_section

    article = _context_text(section)
    if not article:
        article = _context_text(assignment)
    if not article:
        article = _context_text(selected)
    section_title = ""
    section_id = ""
    if section:
        section_title = _safe_text(
            section.get("title") or section.get("name") or section.get("heading") or section.get("label"),
            500,
        )
        section_id = _safe_text(section.get("id") or section.get("sectionId") or section.get("key"), 200)

    # Keep useful section metadata but avoid duplicating every question in the
    # wrong-book item; the complete selected question is already persisted in
    # ``q`` above.
    section_context: dict[str, Any] | None = None
    if section is not None:
        section_context = {
            str(key): value
            for key, value in section.items()
            if str(key) not in {"questions", "items"}
        }
        section_context = sanitize_json(section_context)

    result: dict[str, Any] = {
        "q": question,
        "article": article,
        "articleIndex": section_index,
        "sectionIndex": section_index,
        "sectionTitle": section_title,
        "sectionId": section_id,
        "section": section_context,
        "questionIndex": selected_index if selected_index >= 0 else None,
    }
    return sanitize_json(result)


def _assignment_question_id(question: Mapping[str, Any], index: int) -> str:
    value = question.get("id") or question.get("questionId") or question.get("key")
    return _safe_text(value, 200) or str(index + 1)


def _assignment_answer_key(question: Mapping[str, Any]) -> tuple[bool, Any]:
    question_type = str(question.get("type") or question.get("questionType") or "").strip().lower()
    # Historical title/matching cards often put a human-readable summary in
    # ``answer`` (for example ``Paragraph 1 -> ii``) while the actual select
    # values live on each item.  Prefer the per-row values whenever they are
    # available so both that legacy shape and the newer answer-array shape
    # grade identically.
    if question_type in {"matching", "title-matching", "title_matching", "heading"} and isinstance(
        question.get("items"), list
    ):
        item_answers: list[Any] = []
        usable_items = True
        option_keys = ("heading", "answer", "value", "selected", "choice", "label", "text")
        for item in question.get("items", []):
            if isinstance(item, Mapping):
                if not any(key in item for key in option_keys):
                    usable_items = False
                    break
                item_answers.append(_option_value(item, option_keys))
            else:
                item_answers.append(item)
        if usable_items and item_answers and all(item not in (None, "") for item in item_answers):
            return True, item_answers
    for key in (
        "answer",
        "correctAnswer",
        "correct_answer",
        "answerKey",
        "answer_key",
        "solution",
        "correct",
        "rightAnswer",
        "right_answer",
    ):
        if key in question:
            return True, question.get(key)
    # These two generated question shapes keep their answer per row rather
    # than in a top-level ``answer`` field.  Mirror the existing browser
    # grader so assignments produce the same result as ordinary practice.
    if question_type == "matching" and isinstance(question.get("items"), list):
        answers = [
            _option_value(item, ("heading", "answer", "value", "selected", "choice", "label", "text"))
            if isinstance(item, Mapping)
            else item
            for item in question.get("items", [])
        ]
        return True, answers
    if question_type == "diagram" and isinstance(question.get("steps"), list):
        answers = [
            _option_value(item, ("answer", "value", "label", "text")) if isinstance(item, Mapping) else item
            for item in question.get("steps", [])
        ]
        return True, answers
    return False, None


def _option_value(value: Mapping[str, Any], keys: Iterable[str]) -> Any:
    """Read an option represented as either a primitive or an option object."""

    for key in keys:
        if key in value and value.get(key) is not None:
            return value.get(key)
    return value


def _extract_answer_value(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return value
    # Answers posted by the browser may wrap a primitive in ``answer`` or
    # ``value``.  An option object (e.g. {id: "H1", text: "Heading"}) has no
    # wrapper key and must remain intact for object/string compatibility.
    return _option_value(
        value,
        ("answer", "value", "selected", "choice", "response", "option"),
    )


def _assignment_answers_mapping(answers: Any) -> dict[str, Any]:
    if isinstance(answers, Mapping):
        result: dict[str, Any] = {}
        for key, value in answers.items():
            result[str(key)] = _extract_answer_value(value)
        return result
    if not isinstance(answers, list):
        return {}
    mapped: dict[str, Any] = {}
    for index, value in enumerate(answers):
        if isinstance(value, Mapping):
            key = value.get("id") or value.get("questionId") or value.get("question_id")
            if key is not None:
                mapped[str(key)] = _extract_answer_value(value)
                continue
        mapped[str(index + 1)] = value
    return mapped


def _normalize_answer(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key).strip().lower(), _normalize_answer(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_normalize_answer(item) for item in value)
    if value is None:
        return ""
    text = str(value).strip().casefold()
    text = re.sub(r"\s+", " ", text)
    return text


def _option_candidates(value: Any) -> list[Any]:
    """Return primitive aliases for string and object option shapes."""

    if not isinstance(value, Mapping):
        return [value]
    candidates: list[Any] = []
    for key in (
        "answer",
        "value",
        "selected",
        "choice",
        "response",
        "option",
        "id",
        "key",
        "label",
        "heading",
        "text",
        "title",
        "name",
    ):
        if key in value and value.get(key) not in (None, ""):
            candidate = value.get(key)
            if not isinstance(candidate, (Mapping, list, tuple)):
                candidates.append(candidate)
    if not candidates:
        candidates.append(value)
    return candidates


def _answers_equal(left: Any, right: Any) -> bool:
    """Compare answers while accepting primitive and option-object variants."""

    if isinstance(left, Mapping) and isinstance(right, Mapping):
        left_keys = {str(key) for key in left}
        right_keys = {str(key) for key in right}
        # A sentence-end answer is a mapping of row id -> option.  Compare
        # those rows structurally before trying option aliases.
        if left_keys == right_keys and not left_keys.intersection(
            {"id", "value", "label", "text", "heading", "title", "name"}
        ):
            return all(_answers_equal(left.get(key), right.get(key)) for key in left)
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        if not isinstance(left, (list, tuple)) or not isinstance(right, (list, tuple)):
            return False
        return len(left) == len(right) and all(_answers_equal(a, b) for a, b in zip(left, right))
    left_values = _option_candidates(left)
    right_values = _option_candidates(right)
    return any(_normalize_answer(a) == _normalize_answer(b) for a in left_values for b in right_values)


def _is_answered(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (list, tuple)):
        return bool(value) and any(_is_answered(item) for item in value)
    if isinstance(value, Mapping):
        return bool(value) and any(_is_answered(item) for item in value.values())
    return True


def _question_type(question: Mapping[str, Any]) -> str:
    return _safe_text(question.get("type") or question.get("questionType") or "unknown", 100) or "unknown"


def _question_exam(question: Mapping[str, Any], assignment: Mapping[str, Any] | None = None) -> str:
    value = (
        question.get("exam")
        or question.get("examType")
        or question.get("sourceExam")
        or question.get("_section_exam")
    )
    if value is None and assignment:
        value = assignment.get("exam") or assignment.get("examType")
        if value is None and isinstance(assignment.get("settings"), Mapping):
            settings = assignment.get("settings")
            value = settings.get("exam") or settings.get("examType")
    text = _safe_text(value, 100)
    if not text:
        return "—"
    lowered = text.casefold()
    if "ielts" in lowered:
        return "IELTS"
    if "toefl" in lowered:
        return "TOEFL"
    return text


_TYPE_ADVICE = {
    "multiple-choice": "先定位题干关键词回原文，再逐项排除偷换概念和过度推断。",
    "vocabulary": "结合上下文猜词义，并积累学术高频词与近义词辨析。",
    "true-false-notgiven": "区分原文明确支持、明确矛盾和未提及，避免用常识脑补。",
    "fill-blank": "检查同义替换、词性、单复数、时态与拼写。",
    "matching": "先抓段落主旨句，再将概括性标题与段落配对。",
    "headings": "先通读段落找主旨，警惕只对应细节的干扰标题。",
    "diagram": "理清流程或因果，回原文核对词性和单复数。",
    "sentence-end": "关注因果、转折和代词指代，确认句尾与前半的逻辑衔接。",
}


def _grade_assignment_question(
    assignment: Mapping[str, Any], question: Mapping[str, Any], index: int, submitted: Any
) -> dict[str, Any]:
    question_id = _assignment_question_id(question, index)
    has_key, correct_answer = _assignment_answer_key(question)
    answered = _is_answered(submitted)
    is_correct = bool(has_key and answered and _answers_equal(submitted, correct_answer))
    question_type = _question_type(question)
    exam = _question_exam(question, assignment)
    return {
        "id": question_id,
        "questionId": question_id,
        "type": question_type,
        "exam": exam,
        "prompt": question.get("prompt") or question.get("question") or "",
        "correct": is_correct,
        "answered": answered,
        "userAnswer": sanitize_json(submitted),
        "correctAnswer": sanitize_json(correct_answer) if has_key else None,
        "explanation": question.get("explanation") if has_key else None,
    }


def _grade_assignment(
    assignment: Mapping[str, Any],
    answers: Any,
    first_checks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    answer_map = _assignment_answers_mapping(answers)
    questions = _assignment_question_list(assignment)
    records: list[dict[str, Any]] = []
    wrong: list[dict[str, Any]] = []
    unanswered_questions: list[dict[str, Any]] = []
    right = 0
    unanswered = 0
    for index, question in enumerate(questions):
        question_id = _assignment_question_id(question, index)
        submitted = answer_map.get(question_id)
        if submitted is None and str(index + 1) in answer_map:
            submitted = answer_map.get(str(index + 1))
        if first_checks and question_id in first_checks:
            saved = first_checks.get(question_id)
            if isinstance(saved, Mapping) and "answer" in saved:
                submitted = saved.get("answer")
        record = _grade_assignment_question(assignment, question, index, submitted)
        if not record["answered"]:
            unanswered += 1
            unanswered_questions.append(record)
        if record["correct"]:
            right += 1
        records.append(record)
        if not record["correct"]:
            wrong.append(sanitize_json(record))
    total = len(questions)
    pct = round((right / total) * 100, 2) if total else 0
    by_type: dict[str, dict[str, Any]] = {}
    by_exam: dict[str, dict[str, Any]] = {}
    for record in records:
        for grouping, key in ((by_type, str(record.get("type") or "unknown")), (by_exam, str(record.get("exam") or "—"))):
            bucket = grouping.setdefault(
                key,
                {"right": 0, "correct": 0, "total": 0, "wrong": 0, "unanswered": 0, "pct": 0},
            )
            bucket["total"] += 1
            if record["correct"]:
                bucket["right"] += 1
                bucket["correct"] += 1
            elif not record["answered"]:
                bucket["unanswered"] += 1
            else:
                bucket["wrong"] += 1
    for grouping in (by_type, by_exam):
        for bucket in grouping.values():
            bucket["pct"] = round(bucket["right"] / bucket["total"] * 100, 2) if bucket["total"] else 0
    weak = sorted(
        ((key, value) for key, value in by_type.items() if value.get("pct", 0) < 100),
        key=lambda item: item[1].get("pct", 0),
    )
    advice: list[str] = []
    if pct >= 90:
        advice.append("整体表现优秀，可尝试提高难度或缩短做题时间以贴近考试节奏。")
    elif pct >= 60:
        advice.append("整体达标，建议优先巩固下方正确率较低的题型。")
    else:
        advice.append("基础仍需加强，建议先稳固基础并进行薄弱题型专项训练。")
    for type_name, bucket in weak[:3]:
        advice.append(
            f"{type_name} 正确率 {bucket.get('pct', 0)}%：{_TYPE_ADVICE.get(type_name, '回顾原文定位与同义替换。')}"
        )
    if unanswered:
        advice.append(f"有 {unanswered} 题未作答，考试中应先填写答案以避免白丢分。")
    answered_wrong = sum(1 for record in records if not record["correct"] and record["answered"])
    return {
        "score": pct,
        "pct": pct,
        "percentage": pct,
        "correct": right,
        "correctCount": right,
        "right": right,
        "total": total,
        "totalCount": total,
        "unanswered": unanswered,
        "unansweredCount": unanswered,
        "wrongCount": answered_wrong,
        "answeredWrongCount": answered_wrong,
        "wrong": wrong,
        "wrongAnswers": wrong,
        "unansweredQuestions": sanitize_json(unanswered_questions),
        "records": records,
        "byType": by_type,
        "byExam": by_exam,
        "advice": advice,
        "adviceText": " ".join(advice),
        "submittedAt": _now() * 1000,
    }


def _grade_review_assignment(
    assignment: Mapping[str, Any],
    answers: Any,
    viewed_vocab_ids: Any = None,
    first_checks: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Grade a server-authored wrong-book review card."""

    answer_map = _assignment_answers_mapping(answers)
    if first_checks:
        for checked_id, checked in first_checks.items():
            if isinstance(checked, Mapping) and "answer" in checked:
                answer_map[str(checked_id)] = checked.get("answer")
    viewed_values = viewed_vocab_ids if isinstance(viewed_vocab_ids, list) else []
    viewed = {str(value) for value in viewed_values if value not in (None, "")}
    records: list[dict[str, Any]] = []
    wrong: list[dict[str, Any]] = []
    unanswered_questions: list[dict[str, Any]] = []
    right = unanswered = 0
    question_total = 0
    by_type: dict[str, dict[str, Any]] = {}
    vocabulary_records: list[dict[str, Any]] = []
    for index, item in enumerate(_review_item_list(assignment)):
        item_id = _safe_text(item.get("id"), 200) or str(index + 1)
        kind = _safe_text(item.get("kind"), 30).lower() or "question"
        if kind == "vocab":
            # A vocabulary card is considered reviewed only when its stable id
            # (or word alias for older clients) is explicitly reported.
            word = _safe_text(item.get("word") or item.get("term"), 200)
            is_viewed = item_id in viewed or (word and word in viewed)
            vocabulary_records.append(
                {"id": item_id, "word": word, "viewed": bool(is_viewed), "kind": "vocab"}
            )
            continue
        question_total += 1
        question = item.get("q") if isinstance(item.get("q"), Mapping) else item
        submitted = answer_map.get(item_id)
        if submitted is None and str(index + 1) in answer_map:
            submitted = answer_map.get(str(index + 1))
        record = _grade_assignment_question(assignment, question if isinstance(question, Mapping) else {}, index, submitted)
        record["id"] = item_id
        record["questionId"] = item_id
        record["kind"] = "question"
        record["sourceItemId"] = _safe_text(item.get("_sourceItemId"), 200) or item_id
        records.append(record)
        if record["correct"]:
            right += 1
        elif not record["answered"]:
            unanswered += 1
            unanswered_questions.append(record)
        wrong.append(sanitize_json(record)) if not record["correct"] else None
        type_key = str(record.get("type") or "unknown")
        bucket = by_type.setdefault(
            type_key,
            {"right": 0, "correct": 0, "total": 0, "wrong": 0, "unanswered": 0, "pct": 0},
        )
        bucket["total"] += 1
        if record["correct"]:
            bucket["right"] += 1
            bucket["correct"] += 1
        elif record["answered"]:
            bucket["wrong"] += 1
        else:
            bucket["unanswered"] += 1
    for bucket in by_type.values():
        bucket["pct"] = round(bucket["right"] / bucket["total"] * 100, 2) if bucket["total"] else 0
    pct = round((right / question_total) * 100, 2) if question_total else 0
    vocabulary = {
        "total": len(vocabulary_records),
        "viewed": sum(1 for item in vocabulary_records if item["viewed"]),
        "unviewed": sum(1 for item in vocabulary_records if not item["viewed"]),
        "viewedIds": [item["id"] for item in vocabulary_records if item["viewed"]],
        "unviewedIds": [item["id"] for item in vocabulary_records if not item["viewed"]],
        "items": vocabulary_records,
    }
    advice = [
        "整体表现优秀，可继续巩固错题并保持复习节奏。"
        if pct >= 90
        else "建议优先复习本次未答或答错的题目。"
    ]
    if unanswered:
        advice.append(f"有 {unanswered} 题未作答，建议先完成所有题目。")
    return {
        "score": pct,
        "pct": pct,
        "percentage": pct,
        "correct": right,
        "correctCount": right,
        "right": right,
        "total": question_total,
        "totalCount": question_total,
        "unanswered": unanswered,
        "unansweredCount": unanswered,
        "wrongCount": sum(1 for item in records if item.get("kind") == "question" and not item.get("correct") and item.get("answered")),
        "wrong": wrong,
        "wrongAnswers": wrong,
        "unansweredQuestions": sanitize_json(unanswered_questions),
        "records": sanitize_json(records),
        "byType": by_type,
        "byExam": {},
        "vocabulary": sanitize_json(vocabulary),
        "advice": advice,
        "adviceText": " ".join(advice),
        "submittedAt": _now() * 1000,
    }


def _membership_for_user(store: ReadingTrainerStore, user: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not user or user.get("role") != "student":
        return None
    class_id = _safe_text(user.get("class_id") or user.get("classId"), 200)
    default = {
        "assigned": False,
        "classId": None,
        "className": "暂未分配",
        "teacherId": None,
        "teacherName": "暂未分配",
    }
    if not class_id:
        # Students registered from a teacher invite may have a teacher
        # relationship before an administrator places them in a class.
        teacher_id = _safe_text(user.get("created_by") or user.get("createdBy"), 200) or None
        teacher = store.get_user(teacher_id) if teacher_id else None
        if teacher:
            default["teacherId"] = teacher_id
            default["teacherName"] = _safe_text(teacher.get("username"), 120) or "暂未分配"
            default["assigned"] = True
        return default
    class_item = next((item for item in store.list_classes() if str(item.get("id")) == class_id), None)
    if not class_item:
        # Do not fall back to the historical created_by teacher when a class
        # id exists.  The same rule is used by teacher_can_access().
        default["classId"] = class_id
        return default
    teacher_id = _safe_text(
        class_item.get("teacherId") or class_item.get("teacher_id") or class_item.get("created_by"), 200
    ) or None
    teacher = store.get_user(teacher_id) if teacher_id else None
    class_name = _safe_text(class_item.get("name") or class_item.get("className") or class_item.get("title"), 300)
    return {
        "assigned": bool(class_name or teacher_id),
        "classId": class_id,
        "className": class_name or "暂未分配",
        "teacherId": teacher_id,
        "teacherName": _safe_text(teacher.get("username"), 120) if teacher else ("暂未分配" if not teacher_id else ""),
    }


def _assignment_view(
    store: ReadingTrainerStore,
    assignment: Mapping[str, Any],
    principal: Mapping[str, Any],
    *,
    detail: bool = False,
) -> dict[str, Any]:
    """Build a role-scoped assignment response with answer-key redaction."""

    role = principal.get("role")
    result = dict(assignment)
    recipients = [dict(item) for item in assignment.get("recipients", []) if isinstance(item, Mapping)]
    if role == "student":
        own_id = str(principal.get("id"))
        own = next((item for item in recipients if str(item.get("studentId")) == own_id), None)
        if own is None:
            own = {"assignmentId": result.get("id"), "studentId": own_id, "status": "unread", "unread": True, "result": None}
        result["recipients"] = [own]
        result["studentIds"] = [own_id]
        result["status"] = own.get("status", result.get("status"))
        result["unread"] = bool(own.get("unread", False))
        result["read"] = not result["unread"]
        result["result"] = own.get("result")
        if result.get("assignmentType") == "review":
            # Source identity is teacher-facing routing metadata.  Do not
            # expose it to a student recipient, while retaining the complete
            # settings object for teacher/admin projections.
            settings = result.get("settings")
            if isinstance(settings, Mapping):
                settings = dict(settings)
                settings.pop("sourceStudentId", None)
                settings.pop("source_student_id", None)
                result["settings"] = settings
            result.pop("sourceStudentId", None)
        if own.get("status") != "submitted":
            result["questions"] = _strip_answer_keys(result.get("questions", []))
            result["sections"] = _strip_answer_keys(result.get("sections", []))
            result["reviewItems"] = _strip_internal_fields(_strip_answer_keys(result.get("reviewItems", [])))
            # The recipient's submitted answers are absent until submission.
            own.pop("answers", None)
        elif not detail:
            # Summary rows do not need to carry the potentially large card.
            result["questions"] = []
            result["sections"] = []
            result["reviewItems"] = []
        teacher = store.get_user(str(result.get("teacherId") or ""))
        result["teacher"] = _safe_user(teacher)
        result["reviewItems"] = _strip_internal_fields(result.get("reviewItems", []))
        if not detail:
            result["questions"] = []
            result["sections"] = []
            result["reviewItems"] = []
    else:
        result["recipients"] = recipients
        result["studentIds"] = [item.get("studentId") for item in recipients if item.get("studentId")]
        if not detail:
            result["questions"] = []
            result["sections"] = []
        for recipient in result["recipients"]:
            recipient["student"] = _safe_user(store.get_user(str(recipient.get("studentId") or "")))
    return sanitize_json(result)


def _review_item_clean_source(item: Mapping[str, Any], *, kind: str, source_id: str) -> dict[str, Any]:
    """Copy one source-book row while removing student-specific history."""

    history_keys = {
        "ownerId", "owner_id", "studentId", "student_id", "userAnswer", "user_answer", "user",
        "status", "errorCount", "unansweredCount", "masteryStreak", "lastReviewedAt", "ts", "box",
        "sourceStudentId", "source_student_id", "createdBy", "created_by", "student", "studentName",
        "username", "userId", "user_id", "owner", "identity",
    }
    source = {
        str(key): value
        for key, value in item.items()
        if str(key) not in history_keys
    }
    review_id = _safe_text(source.get("id"), 200) or source_id
    if kind == "question":
        question = source.get("q") if isinstance(source.get("q"), Mapping) else source
        question = {
            str(key): value
            for key, value in (question.items() if isinstance(question, Mapping) else [])
            if str(key) not in history_keys
        }
        question.setdefault("id", review_id)
        question.setdefault("questionId", review_id)
        return {
            "id": review_id,
            "kind": "question",
            "questionId": review_id,
            "q": sanitize_json(question),
            "prompt": question.get("prompt") or question.get("question") or "",
            "type": _question_type(question),
            "article": source.get("article", ""),
            "_sourceItemId": source_id,
        }
    return {
        "id": review_id,
        "kind": "vocab",
        "word": source.get("word") or source.get("term") or "",
        "term": source.get("term") or source.get("word") or "",
        "definition": source.get("definition") or source.get("meaning") or source.get("zh") or source.get("explanation") or "",
        "zh": source.get("zh") or source.get("definition") or source.get("meaning") or "",
        "pos": source.get("pos") or source.get("partOfSpeech") or "",
        "ctx": source.get("ctx") or source.get("context") or "",
        "example": source.get("example") or source.get("sentence") or source.get("ctx") or "",
        "_sourceItemId": source_id,
    }


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


def _authorized_write_owner(principal: Mapping[str, Any], owner_id: str) -> bool:
    """Business documents are self-write; admin-only cross-owner repair."""

    role = str(principal.get("role") or "")
    if role == "admin":
        return True
    return role in {"student", "teacher"} and str(principal.get("id")) == str(owner_id)


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


def _ai_response_content(result: Any) -> Any:
    """Extract the first chat choice's message content safely.

    Providers can return a successful JSON envelope without a usable answer.
    Treat a missing choice/message/content the same as an empty content so the
    proxy never turns that malformed success into a misleading HTTP 200.
    """

    if not isinstance(result, Mapping):
        return None
    choices = result.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, Mapping):
        return None
    message = first.get("message")
    if not isinstance(message, Mapping):
        return None
    return message.get("content")


def _ai_response_content_empty(result: Any) -> bool:
    """Return whether an upstream chat response has no usable content."""

    content = _ai_response_content(result)
    return not isinstance(content, str) or not content.strip()


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
        "membership": _membership_for_user(store, principal),
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
        membership = _membership_for_user(store, user)
        public_user = _safe_user(user)
        if public_user is not None and membership is not None:
            public_user["membership"] = membership
        return jsonify(
            {
                "success": True,
                "api_version": 2,
                "authenticated": bool(user),
                "user": public_user,
                "membership": membership,
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
        store.record_usage_event(str(user["id"]), "login", {"role": user.get("role")})
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
        store.record_usage_event(account_id, "register", {"role": role})
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

    @bp.get("/admin/usage")
    def admin_usage():
        user, error = _auth_required(store, ("admin",))
        if error:
            return error
        try:
            days = int(request.args.get("days", 30))
        except (TypeError, ValueError):
            days = 30
        return jsonify({"ok": True, "usage": store.usage_summary(days)})

    @bp.get("/reports/students/<student_id>")
    def student_report(student_id: str):
        user, error = _auth_required(store, ("student", "teacher", "admin"))
        if error:
            return error
        student = store.get_user(_safe_text(student_id, 200))
        if not student or student.get("role") != "student":
            return _error("student not found", 404, "student_not_found")
        role = str(user.get("role") or "")
        if role == "student" and str(user.get("id")) != str(student.get("id")):
            return _error("insufficient permissions", 403, "forbidden")
        if role == "teacher" and not store.teacher_can_access(str(user.get("id")), str(student.get("id"))):
            return _error("insufficient permissions", 403, "forbidden")
        class_item = None
        class_id = student.get("class_id")
        if class_id:
            class_item = next((item for item in store.list_classes() if str(item.get("id")) == str(class_id)), None)
        teacher = store.get_user(str(class_item.get("teacherId"))) if class_item and class_item.get("teacherId") else None
        grades = store.get_document(str(student["id"]), "grades", [])
        wrong = store.get_document(str(student["id"]), "wbook", [])
        vocab = store.get_document(str(student["id"]), "vbook", [])
        grades = grades if isinstance(grades, list) else []
        wrong = wrong if isinstance(wrong, list) else []
        vocab = vocab if isinstance(vocab, list) else []
        return jsonify({
            "ok": True,
            "report": {
                "student": _safe_user(student),
                "class": sanitize_json(class_item or {"id": class_id, "name": "暂未分配"}),
                "teacher": _safe_user(teacher),
                "grades": sanitize_json(grades[-200:]),
                "wrongCount": len(wrong),
                "vocabCount": len(vocab),
                "generatedAt": _now() * 1000,
            },
        })

    @bp.post("/auth/logout")
    @bp.post("/admin/logout")
    def logout():
        store.delete_session(_token_from_request())
        if session is not None and current_app.secret_key:
            for key in ("reading_trainer_admin", "rt_admin", "reading_trainer_user_id"):
                session.pop(key, None)
        response = make_response(jsonify({"ok": True}), 200)
        return _clear_session_cookie(response)

    @bp.post("/vbook/items")
    def vocabulary_item_create():
        """Append one server-confirmed, idempotent vocabulary item."""

        user, error = _auth_required(store, ("student", "teacher", "admin"))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        owner_id = _safe_text(payload.get("ownerId") or payload.get("owner_id") or user.get("id"), 200)
        if not owner_id or not _authorized_write_owner(user, owner_id):
            if _safe_text(payload.get("sourceType") or payload.get("source_type"), 50).lower() == "assignment":
                return _error("assignment owner must be a student recipient", 403, "forbidden_assignment")
            return _error("insufficient permissions", 403, "forbidden")
        item = dict(payload)
        item.pop("ownerId", None)
        item.pop("owner_id", None)
        source_type = _safe_text(item.get("sourceType") or item.get("source_type"), 50).lower()
        assignment_id = _safe_text(item.get("assignmentId") or item.get("assignment_id"), 200)
        if source_type == "assignment" and not assignment_id:
            return _error("assignment id is required", 400, "invalid_assignment_source")
        if source_type == "assignment":
            owner = store.get_user(owner_id)
            if owner and owner.get("role") == "student":
                assignment = store.get_assignment(assignment_id, student_id=owner_id)
            elif owner and owner.get("role") == "teacher":
                assignment = store.get_assignment(assignment_id, teacher_id=owner_id)
            else:
                assignment = None
            if assignment is None:
                return _error("assignment is not visible to this student", 403, "forbidden_assignment")
        try:
            saved = store.upsert_vbook_item(owner_id, item)
        except (TypeError, ValueError):
            return _error("vocabulary item is invalid", 400, "invalid_vocabulary")
        return jsonify(
            {
                "ok": True,
                "created": bool(saved.get("created")),
                "owner_id": owner_id,
                "section": "vbook",
                "item": saved.get("item"),
                "data": saved.get("data", []),
                "state": _state_snapshot(store, user, current_app),
            }
        )

    @bp.post("/wbook/items")
    def wrongbook_item_create():
        """Append a server-confirmed, idempotent wrong-book item.

        Assignment-origin items are checked against the authoritative SQLite
        assignment and recipient rows.  The browser cannot manufacture a
        question snapshot or write a different student's wrong book by merely
        posting an ``assignmentId``.
        """

        user, error = _auth_required(store, ("student", "teacher", "admin"))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        owner_id = _safe_text(payload.get("ownerId") or payload.get("owner_id") or user.get("id"), 200)
        if not owner_id or not _authorized_write_owner(user, owner_id):
            if _safe_text(payload.get("sourceType") or payload.get("source_type"), 50).lower() == "assignment":
                return _error("assignment owner must be a student recipient", 403, "forbidden_assignment")
            return _error("insufficient permissions", 403, "forbidden")

        item = dict(payload)
        item.pop("ownerId", None)
        item.pop("owner_id", None)
        source_type = _safe_text(item.get("sourceType") or item.get("source_type"), 50).lower()
        assignment_id = _safe_text(item.get("assignmentId") or item.get("assignment_id"), 200)
        question_source = item.get("q")
        if not isinstance(question_source, Mapping):
            question_source = item.get("question")
        question_id = _safe_text(item.get("questionId") or item.get("question_id"), 200)
        if not question_id and isinstance(question_source, Mapping):
            question_id = _safe_text(
                question_source.get("questionId") or question_source.get("id") or question_source.get("key"),
                200,
            )
        assignment_data: Mapping[str, Any] | None = None
        if source_type == "assignment":
            if not assignment_id or not question_id:
                return _error("assignment id and question id are required", 400, "invalid_assignment_source")
            owner = store.get_user(owner_id)
            # An assignment is addressed to a student recipient.  Teachers
            # may write a student's book only for non-assignment/admin flows;
            # they cannot claim an assignment question for themselves.
            if not owner or owner.get("role") != "student":
                return _error("assignment owner must be a student recipient", 403, "forbidden_assignment")
            assignment_data = store.get_assignment(assignment_id, student_id=owner_id)
            if assignment_data is None:
                return _error("assignment is not visible to this student", 403, "forbidden_assignment")
            snapshot = _assignment_question_snapshot(assignment_data, question_id)
            if snapshot is None:
                return _error("question is not part of this assignment", 404, "question_not_found")
            # Active insertion is only allowed after the server has recorded
            # this student's first check for the question.  The stored answer
            # is authoritative, so a client cannot replace it with a forged
            # value while adding a wrong-book item.
            checked = store.get_assignment_question_check(assignment_id, owner_id, question_id)
            if checked is None:
                return _error("question must be checked before adding it", 409, "question_not_checked")
            checked_result = checked.get("result") if isinstance(checked.get("result"), Mapping) else {}
            if bool(checked_result.get("correct")):
                return _error("a correct question cannot be added to the wrong book", 409, "question_not_wrong")
            # Replace any client-provided q/options/answers with the trusted
            # assignment snapshot and first-check answer.
            item["q"] = snapshot.get("q")
            item["questionId"] = question_id
            item["assignmentId"] = assignment_id
            item["sourceType"] = "assignment"
            item["userAnswer"] = sanitize_json(checked.get("answer"))
            item.setdefault("article", snapshot.get("article", ""))
            item.setdefault("articleIndex", snapshot.get("articleIndex"))
            item.setdefault("sectionIndex", snapshot.get("sectionIndex"))
            item.setdefault("sectionTitle", snapshot.get("sectionTitle", ""))
            item.setdefault("sectionId", snapshot.get("sectionId", ""))
            item.setdefault("section", snapshot.get("section"))
            item.setdefault("assignmentTitle", assignment_data.get("title") or assignment_data.get("name", ""))
        elif assignment_id:
            # A non-assignment item carrying an assignment id would otherwise
            # create an ambiguous identity; require the explicit source tag.
            return _error("source type is invalid for assignment item", 400, "invalid_assignment_source")
        try:
            saved = store.upsert_wbook_item(owner_id, item)
        except (TypeError, ValueError):
            return _error("wrong-book item is invalid", 400, "invalid_wrongbook_item")
        return jsonify(
            {
                "ok": True,
                "created": bool(saved.get("created")),
                "owner_id": owner_id,
                "section": "wbook",
                "item": saved.get("item"),
                "data": saved.get("data", []),
                "state": _state_snapshot(store, user, current_app),
            }
        )

    @bp.post("/wbook/items/<item_id>/review")
    def wrongbook_item_review(item_id: str):
        """Grade one wrong-book item using the trusted stored answer key."""

        user, error = _auth_required(store, ("student",))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        owner_id = _safe_text(payload.get("ownerId") or payload.get("owner_id") or user.get("id"), 200)
        if not owner_id or str(owner_id) != str(user.get("id")):
            return _error("insufficient permissions", 403, "forbidden")
        if "answer" in payload:
            answer = payload.get("answer")
        elif "value" in payload:
            answer = payload.get("value")
        else:
            answer = payload.get("response", payload.get("selected"))
        try:
            reviewed = store.review_wbook_item(owner_id, item_id, answer)
        except (TypeError, ValueError):
            return _error("wrong-book item is invalid", 400, "invalid_wrongbook_item")
        if reviewed is None:
            return _error("wrong-book item not found", 404, "wrongbook_item_not_found")
        return jsonify(
            {
                "ok": True,
                "item": reviewed.get("item"),
                "correct": bool(reviewed.get("correct")),
                "answered": bool(reviewed.get("answered")),
                "correctAnswer": reviewed.get("correctAnswer"),
                "data": reviewed.get("data", []),
                "state": _state_snapshot(store, user, current_app),
            }
        )

    # ------------------------------------------------------------------
    # Teacher/student assignments
    # ------------------------------------------------------------------

    def _assignment_not_found_or_forbidden(assignment_id: str, user: Mapping[str, Any]):
        existing = store.get_assignment(assignment_id)
        if existing is not None:
            return _error("insufficient permissions", 403, "forbidden")
        return _error("assignment not found", 404, "assignment_not_found")

    @bp.get("/assignments")
    def assignment_list():
        user, error = _auth_required(store, ("student", "teacher", "admin"))
        if error:
            return error
        role = str(user.get("role"))
        if role == "student":
            records = store.list_assignments(student_id=str(user["id"]))
        elif role == "teacher":
            records = store.list_assignments(teacher_id=str(user["id"]))
        else:
            records = store.list_assignments()
        summary = request.args.get("summary", "0").lower() in {"1", "true", "yes"}
        # Summary is currently the default card shape as well; the explicit
        # flag is accepted for the browser contract and future pagination.
        visible = [_assignment_view(store, item, user, detail=False) for item in records]
        return jsonify({"assignments": visible, "data": visible, "items": visible})

    @bp.post("/assignments")
    def assignment_create():
        user, error = _auth_required(store, ("teacher", "admin"))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        raw_student_ids = payload.get("studentIds") or payload.get("student_ids") or payload.get("students") or []
        if isinstance(raw_student_ids, str):
            raw_student_ids = [raw_student_ids]
        student_ids: list[str] = []
        for item in raw_student_ids if isinstance(raw_student_ids, list) else []:
            candidate = item.get("id") if isinstance(item, Mapping) else item
            candidate = _safe_text(candidate, 200)
            if candidate and candidate not in student_ids:
                student_ids.append(candidate)
        if str(user.get("role")) == "teacher":
            for student_id in student_ids:
                student = store.get_user(student_id)
                if not student or student.get("role") != "student" or not store.teacher_can_access(str(user["id"]), student_id):
                    return _error("teacher can only assign work to current students", 403, "forbidden_student")
        else:
            for student_id in student_ids:
                student = store.get_user(student_id)
                if not student or student.get("role") != "student":
                    return _error("student does not exist", 400, "invalid_student")
        try:
            assignment = store.create_assignment(str(user["id"]), payload, student_ids)
        except PermissionError:
            return _error("assignment belongs to another teacher", 403, "forbidden")
        except (TypeError, ValueError, sqlite3.IntegrityError):
            return _error("assignment payload is invalid", 400, "invalid_assignment")
        visible = _assignment_view(store, assignment, user, detail=True)
        return jsonify({"ok": True, "assignment": visible, "data": visible, **visible}), 201

    @bp.post("/assignments/review")
    def review_assignment_create():
        """Create a review card from a student's authoritative books."""

        user, error = _auth_required(store, ("teacher", "admin"))
        if error:
            return error
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        source_id = _safe_text(payload.get("sourceStudentId") or payload.get("source_student_id"), 200)
        source = store.get_user(source_id) if source_id else None
        if not source or source.get("role") != "student":
            return _error("source student does not exist", 400, "invalid_source_student")
        teacher_id = str(user.get("id"))
        if str(user.get("role")) == "teacher" and not store.teacher_can_access(teacher_id, source_id):
            return _error("teacher can only review current students", 403, "forbidden_source_student")

        raw_student_ids = payload.get("studentIds") or payload.get("student_ids")
        if raw_student_ids is None:
            raw_student_ids = [source_id]
        if isinstance(raw_student_ids, str):
            raw_student_ids = [raw_student_ids]
        recipient_ids: list[str] = []
        for candidate in raw_student_ids if isinstance(raw_student_ids, list) else []:
            candidate = candidate.get("id") if isinstance(candidate, Mapping) else candidate
            candidate = _safe_text(candidate, 200)
            if candidate and candidate not in recipient_ids:
                recipient_ids.append(candidate)
        if not recipient_ids:
            recipient_ids = [source_id]

        source_class_id = _safe_text(source.get("class_id") or source.get("classId"), 200)
        source_class = None
        if source_class_id:
            source_class = next(
                (item for item in store.list_classes() if str(item.get("id")) == source_class_id), None
            )
            if str(user.get("role")) == "teacher" and (
                not source_class
                or str(source_class.get("teacherId") or source_class.get("teacher_id") or "") != teacher_id
            ):
                return _error("teacher cannot access source class", 403, "forbidden_source_student")
        # A student without a class is only reviewable for that student.  Once
        # assigned, every recipient must be in the same teacher-owned class.
        for recipient_id in recipient_ids:
            recipient = store.get_user(recipient_id)
            if not recipient or recipient.get("role") != "student":
                return _error("student does not exist", 400, "invalid_student")
            if str(user.get("role")) == "admin":
                continue
            if not source_class_id:
                if recipient_id != source_id:
                    return _error("unassigned source can only target itself", 403, "forbidden_student")
            else:
                recipient_class_id = _safe_text(recipient.get("class_id") or recipient.get("classId"), 200)
                if recipient_class_id != source_class_id or not store.teacher_can_access(teacher_id, recipient_id):
                    return _error("teacher can only target students in the current class", 403, "forbidden_student")

        def _requested_ids(value: Any) -> list[str]:
            if value is None:
                return []
            values = value if isinstance(value, list) else [value]
            result: list[str] = []
            for candidate in values:
                candidate = candidate.get("id") if isinstance(candidate, Mapping) else candidate
                candidate = _safe_text(candidate, 200)
                if candidate and candidate not in result:
                    result.append(candidate)
            return result

        wrong_book = store.get_document(source_id, "wbook", [])
        vocab_book = store.get_document(source_id, "vbook", [])
        wrong_book = wrong_book if isinstance(wrong_book, list) else []
        vocab_book = vocab_book if isinstance(vocab_book, list) else []
        wrong_raw = payload.get("wrongItemIds") if "wrongItemIds" in payload else payload.get("wrong_item_ids")
        vocab_raw = payload.get("vocabItemIds") if "vocabItemIds" in payload else payload.get("vocab_item_ids")
        if wrong_raw is None and vocab_raw is None:
            return _error("selected review item ids are required", 400, "invalid_review_items")
        wrong_ids = _requested_ids(wrong_raw)
        vocab_ids = _requested_ids(vocab_raw)
        review_items: list[dict[str, Any]] = []
        for source_item in wrong_book:
            if not isinstance(source_item, Mapping):
                continue
            source_item_id = _safe_text(source_item.get("id"), 200)
            if source_item_id and source_item_id in wrong_ids:
                review_items.append(_review_item_clean_source(source_item, kind="question", source_id=source_item_id))
        for source_item in vocab_book:
            if not isinstance(source_item, Mapping):
                continue
            source_item_id = _safe_text(source_item.get("id"), 200) or _safe_text(source_item.get("word") or source_item.get("term"), 200)
            if source_item_id and source_item_id in vocab_ids:
                review_items.append(_review_item_clean_source(source_item, kind="vocab", source_id=source_item_id))
        if not review_items:
            return _error("review items are required", 400, "invalid_review_items")
        review_payload = {
            "id": payload.get("id") or payload.get("assignmentId"),
            "assignmentType": "review",
            "reviewItems": review_items,
            "title": payload.get("title") or "错题复习",
            "instructions": payload.get("instructions") or payload.get("description") or "",
            "dueAt": payload.get("dueAt") or payload.get("due_at"),
            "status": payload.get("status") or "sent",
            "settings": {"sourceStudentId": source_id},
        }
        try:
            assignment = store.create_assignment(teacher_id, review_payload, recipient_ids)
        except PermissionError:
            return _error("assignment belongs to another teacher", 403, "forbidden")
        except (TypeError, ValueError, sqlite3.IntegrityError):
            return _error("review assignment payload is invalid", 400, "invalid_assignment")
        visible = _assignment_view(store, assignment, user, detail=True)
        return jsonify({"ok": True, "assignment": visible, "data": visible, **visible}), 201

    @bp.get("/assignments/<assignment_id>")
    def assignment_detail(assignment_id: str):
        user, error = _auth_required(store, ("student", "teacher", "admin"))
        if error:
            return error
        role = str(user.get("role"))
        if role == "student":
            assignment = store.get_assignment(assignment_id, student_id=str(user["id"]))
        elif role == "teacher":
            assignment = store.get_assignment(assignment_id, teacher_id=str(user["id"]))
        else:
            assignment = store.get_assignment(assignment_id)
        if assignment is None:
            return _assignment_not_found_or_forbidden(assignment_id, user)
        visible = _assignment_view(store, assignment, user, detail=True)
        return jsonify({"assignment": visible, "data": visible, **visible})

    @bp.post("/assignments/<assignment_id>/open")
    def assignment_open(assignment_id: str):
        user, error = _auth_required(store, ("student",))
        if error:
            return error
        assignment = store.mark_assignment_open(assignment_id, str(user["id"]))
        if assignment is None:
            return _assignment_not_found_or_forbidden(assignment_id, user)
        store.record_usage_event(str(user["id"]), "assignment_open", {"assignmentType": assignment.get("assignmentType")})
        visible = _assignment_view(store, assignment, user, detail=True)
        return jsonify({"ok": True, "assignment": visible, "data": visible, **visible})

    @bp.post("/assignments/<assignment_id>/questions/<question_id>/check")
    def assignment_question_check(assignment_id: str, question_id: str):
        """Check exactly one question and retain the first scored attempt.

        The assignment detail endpoint deliberately strips answer keys.  This
        endpoint is the only student-visible path that reveals the selected
        question's key, and it never includes another question's answer.
        """

        user, error = _auth_required(store, ("student",))
        if error:
            return error
        assignment = store.get_assignment(assignment_id, student_id=str(user["id"]))
        if assignment is None:
            return _assignment_not_found_or_forbidden(assignment_id, user)
        requested_id = _safe_text(question_id, 200)
        question: Mapping[str, Any] | None = None
        question_index = -1
        assignment_type = _safe_text(assignment.get("assignmentType") or assignment.get("assignment_type"), 40).lower()
        candidates = _assignment_question_list(assignment)
        if assignment_type == "review":
            for index, candidate in enumerate(_review_item_list(assignment)):
                if str(candidate.get("kind")) != "question":
                    continue
                if _safe_text(candidate.get("id"), 200) == requested_id:
                    raw_question = candidate.get("q") if isinstance(candidate.get("q"), Mapping) else candidate
                    question = raw_question if isinstance(raw_question, Mapping) else None
                    question_index = index
                    break
        else:
            for index, candidate in enumerate(candidates):
                if _assignment_question_id(candidate, index) == requested_id:
                    question = candidate
                    question_index = index
                    break
        if question is None:
            return _error("question not found", 404, "question_not_found")
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        if "answer" in payload:
            answer = payload.get("answer")
        elif "value" in payload:
            answer = payload.get("value")
        else:
            answer = payload.get("response", payload.get("selected"))
        existing = store.get_assignment_question_check(assignment_id, str(user["id"]), requested_id)
        if existing is not None:
            result = existing.get("result") if isinstance(existing.get("result"), Mapping) else {}
            return jsonify(
                {
                    "ok": True,
                    "idempotent": True,
                    "questionId": requested_id,
                    "correct": bool(result.get("correct")),
                    "answered": bool(result.get("answered")),
                    "userAnswer": sanitize_json(existing.get("answer")),
                    "correctAnswer": sanitize_json(result.get("correctAnswer")),
                    "explanation": result.get("explanation"),
                    "result": sanitize_json(result),
                }
            )
        record = _grade_assignment_question(assignment, question, question_index, answer)
        persisted, idempotent = store.save_assignment_question_check(
            assignment_id,
            str(user["id"]),
            requested_id,
            answer,
            record,
        )
        if persisted is not None:
            saved_result = persisted.get("result") if isinstance(persisted.get("result"), Mapping) else record
            saved_answer = persisted.get("answer")
        else:
            saved_result = record
            saved_answer = answer
        return jsonify(
            {
                "ok": True,
                "idempotent": bool(idempotent),
                "questionId": requested_id,
                "correct": bool(saved_result.get("correct")),
                "answered": bool(saved_result.get("answered")),
                "userAnswer": sanitize_json(saved_answer),
                "correctAnswer": sanitize_json(saved_result.get("correctAnswer")),
                "explanation": saved_result.get("explanation"),
                "result": sanitize_json(saved_result),
            }
        )

    @bp.post("/assignments/<assignment_id>/submit")
    def assignment_submit(assignment_id: str):
        user, error = _auth_required(store, ("student",))
        if error:
            return error
        assignment = store.get_assignment(assignment_id, student_id=str(user["id"]))
        if assignment is None:
            return _assignment_not_found_or_forbidden(assignment_id, user)
        payload = _json_body()
        payload = payload if isinstance(payload, Mapping) else {}
        answers = payload.get("answers", payload.get("responses", payload.get("data", {})))
        if answers is None:
            answers = {}
        assignment_type = _safe_text(assignment.get("assignmentType") or assignment.get("assignment_type"), 40).lower()
        viewed_vocab_ids = payload.get("viewedVocabIds", payload.get("viewed_vocab_ids", []))
        if assignment_type == "review":
            # Review cards are graded from the immutable server snapshot.  No
            # answer key is trusted from the browser payload.
            first_checks = store.list_assignment_question_checks(assignment_id, str(user["id"]))
            result = _grade_review_assignment(assignment, answers, viewed_vocab_ids, first_checks)
            for record in result.get("records", []):
                if not isinstance(record, Mapping) or record.get("kind") != "question":
                    continue
                store.save_assignment_question_check(
                    assignment_id,
                    str(user["id"]),
                    str(record.get("questionId") or record.get("id") or ""),
                    record.get("userAnswer"),
                    record,
                )
            saved, idempotent = store.submit_assignment(assignment_id, str(user["id"]), answers, result)
            if saved is None:
                return _assignment_not_found_or_forbidden(assignment_id, user)
            if not idempotent:
                store.record_usage_event(str(user["id"]), "assignment_submit", {"questionCount": int(result.get("total") or 0)})
                store.sync_review_outcomes(str(user["id"]), assignment, result)
                if int(result.get("total") or 0) > 0:
                    store.record_assignment_outcomes(
                        str(user["id"]), assignment_id, result, assignment=assignment, include_wrong=False
                    )
            visible = _assignment_view(store, saved, user, detail=True)
            persisted_result = visible.get("result") or result
            return jsonify(
                {
                    "ok": True,
                    "idempotent": bool(idempotent),
                    "result": persisted_result,
                    "assignment": visible,
                    "data": visible,
                    "state": _state_snapshot(store, user, current_app),
                    **visible,
                }
            )
        # A question that was already checked is immutable: a later submit
        # cannot silently replace the first scored answer.  Unchecked rows are
        # scored from the submit payload and become first checks themselves.
        first_checks = store.list_assignment_question_checks(assignment_id, str(user["id"]))
        effective_answers = _assignment_answers_mapping(answers)
        for checked_id, checked in first_checks.items():
            if isinstance(checked, Mapping) and "answer" in checked:
                effective_answers[checked_id] = checked.get("answer")
        result = _grade_assignment(assignment, effective_answers, first_checks)
        for record in result.get("records", []):
            if not isinstance(record, Mapping):
                continue
            store.save_assignment_question_check(
                assignment_id,
                str(user["id"]),
                str(record.get("questionId") or record.get("id") or ""),
                record.get("userAnswer"),
                record,
            )
        saved, idempotent = store.submit_assignment(assignment_id, str(user["id"]), effective_answers, result)
        if saved is None:
            return _assignment_not_found_or_forbidden(assignment_id, user)
        if not idempotent:
            store.record_usage_event(str(user["id"]), "assignment_submit", {"questionCount": int(result.get("total") or 0)})
            store.record_assignment_outcomes(str(user["id"]), assignment_id, result, assignment=assignment)
        visible = _assignment_view(store, saved, user, detail=True)
        persisted_result = visible.get("result") or result
        return jsonify(
            {
                "ok": True,
                "idempotent": bool(idempotent),
                "result": persisted_result,
                "assignment": visible,
                "data": visible,
                "state": _state_snapshot(store, user, current_app),
                **visible,
            }
        )

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
        if not _authorized_write_owner(user, owner_id):
            return _error("insufficient permissions", 403, "forbidden")
        data = payload_mapping.get("data", payload_mapping.get("value")) if isinstance(payload, Mapping) else payload
        if data is None and isinstance(payload, Mapping) and "data" not in payload and "value" not in payload:
            data = payload
        try:
            saved = store.put_document(owner_id, section, data)
        except (TypeError, ValueError):
            return _error("data is not valid JSON or is too large", 400, "invalid_data")
        if section == "grades" and isinstance(data, list):
            store.record_usage_event(
                str(owner_id),
                "practice_submit",
                {"questionCount": sum(
                    int(item.get("total") or 0)
                    for item in data[-1:]
                    if isinstance(item, Mapping) and str(item.get("total") or "0").lstrip("-").isdigit()
                )},
            )
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
        ai_started = time.monotonic()
        store.record_usage_event(str(user["id"]), "ai_request")
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
        response_format_requested = isinstance(payload.get("response_format"), Mapping)
        if response_format_requested:
            upstream["response_format"] = sanitize_json(payload["response_format"])
        is_deepseek_json = cfg.get("provider", "").lower() == "deepseek" and response_format_requested
        if is_deepseek_json:
            # DeepSeek V4 enables thinking by default. Structured question
            # generation does not need hidden chain-of-thought, and disabling
            # it preserves the output budget for the actual JSON response.
            upstream["thinking"] = {"type": "disabled"}
        client = current_app.extensions.get("reading_trainer_v2", {}).get("http_client")
        timeout_seconds = _ai_timeout_seconds(current_app)
        deadline = time.monotonic() + timeout_seconds

        def remaining_timeout() -> float:
            return deadline - time.monotonic()

        try:
            remaining = remaining_timeout()
            if remaining <= 0:
                return _ai_upstream_failure(exc=TimeoutError("AI request deadline exceeded"))
            response = _http_request(
                client,
                "POST",
                cfg["endpoint"],
                headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
                json=upstream,
                timeout=remaining,
            )
            if not getattr(response, "ok", True):
                return _ai_upstream_failure(response)
            try:
                result = response.json()
            except Exception as exc:
                # A successful response that is not JSON is still an upstream
                # failure, but its body must never be reflected to the caller.
                return _ai_upstream_failure(exc=exc)

            if _ai_response_content_empty(result):
                if is_deepseek_json:
                    remaining = remaining_timeout()
                    if remaining <= 0:
                        return _ai_upstream_failure(exc=TimeoutError("AI request deadline exceeded"))
                    retry_upstream = dict(upstream)
                    retry_upstream.pop("response_format", None)
                    retry_messages = [dict(item) for item in clean_messages]
                    for message in reversed(retry_messages):
                        if message.get("role") == "user":
                            suffix = "返回完整JSON且不可为空。"
                            content = str(message.get("content") or "")
                            message["content"] = (content.rstrip() + "\n" + suffix).strip()
                            break
                    retry_upstream["messages"] = retry_messages
                    response = _http_request(
                        client,
                        "POST",
                        cfg["endpoint"],
                        headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
                        json=retry_upstream,
                        timeout=remaining,
                    )
                    if not getattr(response, "ok", True):
                        return _ai_upstream_failure(response)
                    try:
                        result = response.json()
                    except Exception as exc:
                        return _ai_upstream_failure(exc=exc)

                if _ai_response_content_empty(result):
                    return _error("AI 服务商返回了空内容，请稍后重试。", 502, "ai_empty_response")
            store.record_usage_event(str(user["id"]), "ai_success", duration_ms=int((time.monotonic() - ai_started) * 1000))
            return jsonify({"data": sanitize_json(result)})
        except Exception as exc:
            # Do not reflect upstream response bodies or exception text: they
            # may contain provider keys, URLs, or internal paths.
            store.record_usage_event(str(user["id"]), "ai_failure", duration_ms=int((time.monotonic() - ai_started) * 1000))
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
                    # Optional mirrors (currently assignments) deliberately
                    # use an empty table id until production configures a
                    # destination.  Skipping them keeps the remaining Feishu
                    # tables syncable instead of requesting ``tables//records``.
                    if not table_id:
                        continue
                    if section not in BUSINESS_SECTIONS and section not in ("accounts", "classes", "invites", "assignments"):
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
