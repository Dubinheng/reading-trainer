import json
import os

from flask import Flask

from server.reading_trainer_backend import (
    BUSINESS_SECTIONS,
    ReadingTrainerStore,
    _safe_ai_max_tokens,
    _valid_feishu_access_token,
    build_feishu_sync_plan,
    register_reading_trainer_v2,
)


def make_app(tmp_path, legacy=None):
    state_path = tmp_path / ".reading_trainer_state.json"
    if legacy is not None:
        state_path.write_text(json.dumps(legacy), encoding="utf-8")
    app = Flask("reading-trainer-tests")
    app.config.update(
        TESTING=True,
        READING_TRAINER_DB_PATH=str(tmp_path / "reading_trainer.db"),
        READING_TRAINER_STATE_PATH=str(state_path),
        READING_TRAINER_ADMIN_USERNAME="admin",
        READING_TRAINER_ADMIN_PASSWORD="admin-password",
        READING_TRAINER_REQUIRE_INVITE=False,
    )
    register_reading_trainer_v2(app)
    return app


def register(client, username, role="student", password="student-password"):
    response = client.post(
        "/reading-trainer/api/v2/auth/register",
        json={"username": username, "password": password, "role": role},
    )
    assert response.status_code == 201
    return response


def login(client, username, role, password):
    response = client.post(
        "/reading-trainer/api/v2/auth/login",
        json={"username": username, "role": role, "password": password},
    )
    assert response.status_code == 200
    return response


def admin_login(client):
    response = client.post(
        "/reading-trainer/api/v2/admin/login",
        json={"username": "admin", "password": "admin-password"},
    )
    assert response.status_code == 200
    return response


def test_first_init_migrates_legacy_json_without_deleting_it(tmp_path):
    legacy = {
        "accounts": [
            {
                "id": "stu_legacy",
                "username": "legacy-user",
                "role": "student",
                "pass": "legacy-password",
            }
        ],
        "itr_settings": {
            "theme": "dark",
            "apiKey": "do-not-store-this-key",
            "nested": {"accessToken": "do-not-store-this-token"},
        },
        "itr_vbook_stu_legacy": [{"word": "migration"}],
        "itr_session": {"token": "do-not-import-this-session"},
    }
    source = tmp_path / ".reading_trainer_state.json"
    source.write_text(json.dumps(legacy), encoding="utf-8")
    original_source = source.read_bytes()
    resumes_db = tmp_path / "resumes.db"
    resumes_db.write_bytes(b"existing resume database")

    app = make_app(tmp_path, legacy=None)
    client = app.test_client()
    bootstrap = client.get("/reading-trainer/api/v2/bootstrap")
    assert bootstrap.status_code == 200
    assert bootstrap.get_json()["legacy_state_imported"] is True
    assert source.read_bytes() == original_source

    login(client, "legacy-user", "student", "legacy-password")
    response = client.get("/reading-trainer/api/v2/data/vbook")
    assert response.get_json()["data"] == [{"word": "migration"}]
    settings = client.get("/reading-trainer/api/v2/data/settings").get_json()["data"]
    assert settings == {"theme": "dark", "nested": {}}
    assert b"legacy-password" not in (tmp_path / "reading_trainer.db").read_bytes()
    assert resumes_db.read_bytes() == b"existing resume database"

    store = app.extensions["reading_trainer_v2"]["store"]
    imported = store.get_user("stu_legacy")
    assert imported["password_hash"].startswith(("pbkdf2_sha256$", "legacy_sha256$"))


def test_register_login_session_and_logout_do_not_return_session_or_hash(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()

    registration = register(client, "new-user")
    body = registration.get_json()
    assert "password_hash" not in body
    assert "token" not in body
    assert "Set-Cookie" in registration.headers
    assert "HttpOnly" in registration.headers["Set-Cookie"]
    assert client.get("/reading-trainer/api/v2/auth/session").get_json()["authenticated"] is True

    assert client.post("/reading-trainer/api/v2/auth/logout").status_code == 200
    assert client.get("/reading-trainer/api/v2/auth/session").get_json() == {
        "authenticated": False,
        "user": None,
    }

    admin_client = app.test_client()
    response = admin_login(admin_client)
    assert "password_hash" not in response.get_json()
    assert admin_client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["role"] == "admin"


def test_authorization_isolation_and_teacher_student_scope(tmp_path):
    app = make_app(tmp_path)
    alice_client = app.test_client()
    bob_client = app.test_client()
    teacher_client = app.test_client()
    register(alice_client, "alice")
    alice_id = alice_client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    register(bob_client, "bob")
    bob_id = bob_client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    register(teacher_client, "teacher", role="teacher", password="teacher-password")
    teacher_id = teacher_client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]

    store = app.extensions["reading_trainer_v2"]["store"]
    store.upsert_user(
        {
            "id": bob_id,
            "username": "bob",
            "role": "student",
            "created_by": teacher_id,
            "password_hash": store.get_user(bob_id)["password_hash"],
        }
    )
    alice_client.put(
        "/reading-trainer/api/v2/data/vbook",
        json={"data": [{"word": "alice-only"}]},
    )
    assert alice_client.get(f"/reading-trainer/api/v2/data/vbook/{bob_id}").status_code == 403
    assert bob_client.get(f"/reading-trainer/api/v2/data/vbook/{alice_id}").status_code == 403
    assert teacher_client.get(f"/reading-trainer/api/v2/data/vbook/{bob_id}").status_code == 200

    unauthenticated = app.test_client().get("/reading-trainer/api/v2/data/vbook")
    assert unauthenticated.status_code == 401
    assert BUSINESS_SECTIONS == ("settings", "favorites", "vbook", "wbook", "grades", "library")


def test_business_data_is_per_owner_and_survives_new_app_instance(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "persistent-user")
    user_id = client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    saved = client.put(
        "/reading-trainer/api/v2/data/grades",
        json={"data": [{"id": "grade-1", "pct": 88}]},
    )
    assert saved.status_code == 200
    client.put(
        "/reading-trainer/api/v2/data/settings",
        json={"data": {"theme": "dark", "api_key": "never-return", "language": "en"}},
    )

    app2 = make_app(tmp_path)
    client2 = app2.test_client()
    login(client2, "persistent-user", "student", "student-password")
    assert client2.get("/reading-trainer/api/v2/data/grades").get_json()["data"] == [
        {"id": "grade-1", "pct": 88}
    ]
    assert client2.get("/reading-trainer/api/v2/data/settings").get_json()["data"] == {
        "theme": "dark",
        "language": "en",
    }
    assert user_id == client2.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]


def test_legacy_migration_dry_run_and_import_redact_sensitive_fields(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    admin_login(client)
    legacy = {
        "accounts": [{"id": "migrated", "username": "migrated", "role": "student", "pass": "one-time-pass"}],
        "settings": {"theme": "light", "api_key": "secret-api-key", "feishu": {"accessToken": "secret-token"}},
        "vbook_migrated": [{"word": "safe-word", "secret": "remove"}],
    }
    dry_run = client.post(
        "/reading-trainer/api/v2/migration/legacy/dry-run", json={"state": legacy}
    )
    assert dry_run.status_code == 200
    dry_text = json.dumps(dry_run.get_json(), ensure_ascii=False)
    assert "one-time-pass" not in dry_text
    assert "secret-api-key" not in dry_text
    assert "secret-token" not in dry_text
    assert "password_hash" not in dry_text
    assert dry_run.get_json()["imported"] is False

    imported = client.post(
        "/reading-trainer/api/v2/migration/legacy/import", json={"state": legacy}
    )
    assert imported.status_code == 200
    assert imported.get_json()["imported"] is True
    migrated_login = app.test_client()
    login(migrated_login, "migrated", "student", "one-time-pass")
    assert migrated_login.get("/reading-trainer/api/v2/data/vbook").get_json()["data"] == [
        {"word": "safe-word"}
    ]


def test_feishu_plan_is_sanitized_idempotent_and_never_deletes_remote_only(tmp_path):
    app = make_app(tmp_path)
    admin_client = app.test_client()
    admin_login(admin_client)
    user_client = app.test_client()
    register(user_client, "sync-user")
    user_client.put(
        "/reading-trainer/api/v2/data/vbook",
        json={"data": [{"id": "v-1", "word": "stable", "apiKey": "not-a-field"}]},
    )
    store = app.extensions["reading_trainer_v2"]["store"]
    first = build_feishu_sync_plan(store)
    vbook = first["tables"]["vbook"]
    assert vbook["creates"]
    payload_text = json.dumps(first, ensure_ascii=False)
    assert "not-a-field" not in payload_text
    assert "password_hash" not in payload_text
    assert first["totals"]["deletes"] == 0

    matching = vbook["creates"][0]
    remote = {
        "vbook": [
            {"record_id": "remote-match", "fields": matching["fields"]},
            {"record_id": "remote-only", "fields": {"学员ID": "other", "单词": "remote"}},
        ]
    }
    second = build_feishu_sync_plan(store, remote)
    assert second["tables"]["vbook"]["creates"] == []
    assert second["tables"]["vbook"]["updates"] == []
    assert second["tables"]["vbook"]["remote_only"]
    assert second["totals"]["deletes"] == 0

    # The endpoint defaults to a dry-run; an HTTP client that would fail proves
    # the test did not make a real Feishu write.
    def forbidden_http(*args, **kwargs):
        raise AssertionError("network must not be called by the dry-run")

    app.extensions["reading_trainer_v2"]["http_client"] = forbidden_http
    response = admin_client.post(
        "/reading-trainer/api/v2/feishu/sync",
        json={"dry_run": True, "remote_records": remote},
    )
    assert response.status_code == 200
    assert response.get_json()["plan"]["totals"]["deletes"] == 0


def test_store_rejects_resume_database_path(tmp_path):
    app = Flask("path-test")
    try:
        ReadingTrainerStore(app, db_path=tmp_path / "resumes.db")
    except ValueError as exc:
        assert "separate database" in str(exc)
    else:
        raise AssertionError("resumes.db must never be used by this backend")


def test_frontend_contract_returns_snapshot_and_admin_private_settings(tmp_path):
    app = make_app(tmp_path)
    student = app.test_client()
    registration = register(student, "contract-user")
    registered = registration.get_json()
    user_id = registered["user"]["id"]
    assert registered["state"]["accounts"][0]["id"] == user_id
    assert registered["state"]["userData"][user_id]["vbook"] == []

    saved = student.put(
        "/reading-trainer/api/v2/data/vbook",
        json={"value": [{"word": "server-first"}]},
    ).get_json()
    assert saved["state"]["userData"][user_id]["vbook"] == [{"word": "server-first"}]

    admin = app.test_client()
    admin_login(admin)
    ai = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "provider": "test",
                "endpoint": "https://example.com/v1/chat/completions",
                "model": "test-model",
                "key": "private-provider-key",
                "enabled": True,
            }
        },
    )
    assert ai.status_code == 200
    body = ai.get_json()
    assert body["state"]["ai"]["hasKey"] is True
    assert "private-provider-key" not in json.dumps(body)
    assert all(item["role"] != "admin" for item in body["state"]["accounts"])
    assert os.stat(tmp_path / "reading_trainer.db").st_mode & 0o777 == 0o600


def test_admin_global_state_updates_are_server_backed(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    invite = {"code": "NC-TEST01", "role": "student", "used": False}
    klass = {"id": "class-1", "name": "Class One", "teacherId": None}
    assert admin.put("/reading-trainer/api/v2/state/invites", json={"value": [invite]}).status_code == 200
    response = admin.put("/reading-trainer/api/v2/state/classes", json={"value": [klass]})
    assert response.status_code == 200
    state = response.get_json()["state"]
    assert state["invites"][0]["code"] == "NC-TEST01"
    assert state["classes"][0]["id"] == "class-1"


def test_feishu_rows_contain_stable_key_full_json_and_no_admin_account(tmp_path):
    app = make_app(tmp_path)
    user = app.test_client()
    register(user, "feishu-user")
    user_id = user.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    user.put(
        "/reading-trainer/api/v2/data/favorites",
        json={"value": [{"id": "fav-1", "title": "Saved", "text": "Full article"}]},
    )
    store = app.extensions["reading_trainer_v2"]["store"]
    plan = build_feishu_sync_plan(store)
    account_rows = plan["tables"]["accounts"]["creates"]
    assert all(row["fields"]["角色"] != "admin" for row in account_rows)
    favorite = plan["tables"]["favorites"]["creates"][0]["fields"]
    assert favorite["业务键"].startswith(f"favorites:{user_id}:")
    assert favorite["数据类型"] == "收藏"
    assert json.loads(favorite["数据JSON"])["text"] == "Full article"


def test_expired_feishu_access_token_is_refreshed_only_on_server(tmp_path):
    app = make_app(tmp_path)
    token_path = tmp_path / ".feishu_oauth_tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "access_token": "expired-access",
                "expires_at": 1,
                "refresh_token": "server-refresh",
                "refresh_expires_at": 9999999999,
            }
        ),
        encoding="utf-8",
    )
    app.config.update(
        READING_TRAINER_FEISHU_TOKEN_FILE=str(token_path),
        READING_TRAINER_FEISHU_APP_ID="app-id",
        READING_TRAINER_FEISHU_APP_SECRET="app-secret",
    )

    def fake_http(method, url, **kwargs):
        assert kwargs["json"]["grant_type"] == "refresh_token"
        assert kwargs["json"]["refresh_token"] == "server-refresh"
        return {
            "code": 0,
            "access_token": "new-access",
            "expires_in": 7200,
            "refresh_token": "new-refresh",
            "refresh_token_expires_in": 604800,
        }

    assert _valid_feishu_access_token(app, fake_http) == "new-access"
    stored = json.loads(token_path.read_text(encoding="utf-8"))
    assert stored["access_token"] == "new-access"
    assert stored["refresh_token"] == "new-refresh"
    assert os.stat(token_path).st_mode & 0o777 == 0o600


def test_ai_test_returns_safe_actionable_upstream_error(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    response = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "provider": "deepseek",
                "endpoint": "https://api.deepseek.com/v1/chat/completions",
                "model": "deepseek-v4-flash",
                "key": "invalid-secret-key",
                "enabled": True,
            }
        },
    )
    assert response.status_code == 200

    class InvalidKeyResponse:
        ok = False
        status_code = 401

        def json(self):
            return {"error": {"message": "upstream body must not be reflected", "secret": "do-not-leak"}}

    app.extensions["reading_trainer_v2"]["http_client"] = lambda *args, **kwargs: InvalidKeyResponse()
    tested = admin.post("/reading-trainer/api/v2/ai/test", json={})
    assert tested.status_code == 502
    body = tested.get_json()
    assert body["error"]["code"] == "ai_key_invalid"
    assert "Key" in body["error"]["message"]
    assert "upstream body" not in json.dumps(body)
    assert "do-not-leak" not in json.dumps(body)


def test_ai_chat_bounds_max_tokens_and_uses_configured_timeout(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    configured = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "provider": "deepseek",
                "endpoint": "https://api.deepseek.com/v1/chat/completions",
                "model": "server-model",
                "key": "server-secret",
                "enabled": True,
            }
        },
    )
    assert configured.status_code == 200
    app.config["READING_TRAINER_AI_TIMEOUT"] = 112
    calls = []

    class SuccessResponse:
        ok = True
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": "{}"}}]}

    def fake_http(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return SuccessResponse()

    app.extensions["reading_trainer_v2"]["http_client"] = fake_http
    response = admin.post(
        "/reading-trainer/api/v2/ai/chat",
        json={
            "model": "client-model-must-be-ignored",
            "endpoint": "https://client.example.invalid/override",
            "key": "client-key-must-be-ignored",
            "messages": [{"role": "user", "content": "Reply with JSON."}],
            "max_tokens": 999999,
        },
    )
    assert response.status_code == 200
    assert len(calls) == 1
    kwargs = calls[0][2]
    assert 0 < kwargs["timeout"] <= 112
    assert kwargs["json"]["model"] == "server-model"
    assert kwargs["json"]["max_tokens"] == 8192
    assert kwargs["headers"]["Authorization"] == "Bearer server-secret"
    assert _safe_ai_max_tokens(-100) == 256
    assert _safe_ai_max_tokens("not-a-number") is None


def test_ai_chat_deepseek_empty_json_retries_without_response_format(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    configured = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "provider": "deepseek",
                "endpoint": "https://api.deepseek.com/v1/chat/completions",
                "model": "server-model",
                "key": "server-secret",
                "enabled": True,
            }
        },
    )
    assert configured.status_code == 200
    app.config["READING_TRAINER_AI_TIMEOUT"] = 112
    calls = []

    class DeepSeekResponse:
        ok = True
        status_code = 200

        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    responses = iter(
        [
            {"choices": [{"message": {"content": "   ", "reasoning_content": "private reasoning"}}]},
            {"choices": [{"message": {"content": "{\"answer\":1}"}}]},
        ]
    )

    def fake_http(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return DeepSeekResponse(next(responses))

    app.extensions["reading_trainer_v2"]["http_client"] = fake_http
    response = admin.post(
        "/reading-trainer/api/v2/ai/chat",
        json={
            "messages": [{"role": "user", "content": "Reply with JSON."}],
            "response_format": {"type": "json_object"},
        },
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["choices"][0]["message"]["content"] == '{"answer":1}'
    assert len(calls) == 2
    assert calls[0][2]["json"]["response_format"] == {"type": "json_object"}
    assert calls[0][2]["json"]["thinking"] == {"type": "disabled"}
    assert "response_format" not in calls[1][2]["json"]
    assert calls[1][2]["json"]["thinking"] == {"type": "disabled"}
    assert calls[1][2]["json"]["model"] == "server-model"
    assert "返回完整JSON且不可为空" in calls[1][2]["json"]["messages"][-1]["content"]
    assert calls[0][2]["headers"]["Authorization"] == calls[1][2]["headers"]["Authorization"] == "Bearer server-secret"
    assert 0 < calls[0][2]["timeout"] <= 112
    assert 0 < calls[1][2]["timeout"] <= calls[0][2]["timeout"]


def test_ai_chat_empty_json_returns_safe_502_after_deepseek_retry(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    configured = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "provider": "deepseek",
                "endpoint": "https://api.deepseek.com/v1/chat/completions",
                "model": "server-model",
                "key": "server-secret",
                "enabled": True,
            }
        },
    )
    assert configured.status_code == 200
    calls = []

    class EmptyResponse:
        ok = True
        status_code = 200

        def json(self):
            return {"choices": [{"message": {"content": "", "reasoning_content": "secret reasoning"}}]}

    def fake_http(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return EmptyResponse()

    app.extensions["reading_trainer_v2"]["http_client"] = fake_http
    response = admin.post(
        "/reading-trainer/api/v2/ai/chat",
        json={
            "messages": [{"role": "user", "content": "Reply with JSON."}],
            "response_format": {"type": "json_object"},
        },
    )
    assert response.status_code == 502
    body = response.get_json()
    assert body["error"]["code"] == "ai_empty_response"
    assert "secret reasoning" not in json.dumps(body)
    assert len(calls) == 2
    assert "response_format" not in calls[1][2]["json"]


def test_ai_chat_non_json_non_2xx_maps_status_without_parsing_body(tmp_path):
    app = make_app(tmp_path)
    admin = app.test_client()
    admin_login(admin)
    configured = admin.put(
        "/reading-trainer/api/v2/state/ai",
        json={
            "value": {
                "endpoint": "https://api.example.com/v1/chat/completions",
                "model": "example-model",
                "key": "example-secret",
                "enabled": True,
            }
        },
    )
    assert configured.status_code == 200

    class HtmlErrorResponse:
        ok = False
        status_code = 502

        def json(self):
            raise AssertionError("HTML error body must not be parsed")

    app.extensions["reading_trainer_v2"]["http_client"] = lambda *args, **kwargs: HtmlErrorResponse()
    response = admin.post(
        "/reading-trainer/api/v2/ai/chat",
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 502
    body = response.get_json()
    assert body["error"]["code"] == "ai_provider_unavailable"
    assert "HTML" not in json.dumps(body)
