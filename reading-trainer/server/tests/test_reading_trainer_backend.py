import json
import os

from flask import Flask

from server.reading_trainer_backend import (
    BUSINESS_SECTIONS,
    ReadingTrainerStore,
    _grade_assignment,
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


def test_live_feishu_sync_skips_unconfigured_optional_table(tmp_path):
    app = make_app(tmp_path)
    app.config.update(
        READING_TRAINER_FEISHU_ENABLED=True,
        READING_TRAINER_FEISHU_ACCESS_TOKEN="test-access-token",
        READING_TRAINER_FEISHU_TOKEN_FILE=str(tmp_path / "missing-feishu-token.json"),
    )
    admin_client = app.test_client()
    admin_login(admin_client)
    requested_urls = []

    def fake_http(method, url, **kwargs):
        requested_urls.append(url)
        if url.endswith("/records"):
            return {"code": 0, "data": {"items": [], "has_more": False}}
        if url.endswith("/fields"):
            return {
                "code": 0,
                "data": {
                    "items": [
                        {"field_name": "业务键"},
                        {"field_name": "数据类型"},
                        {"field_name": "数据JSON"},
                    ]
                },
            }
        raise AssertionError(f"unexpected Feishu request: {method} {url}")

    app.extensions["reading_trainer_v2"]["http_client"] = fake_http
    response = admin_client.post(
        "/reading-trainer/api/v2/feishu/sync",
        json={"dry_run": False},
    )

    assert response.status_code == 200
    assert response.get_json()["executed"]["deletes"] == 0
    assert requested_urls
    assert all("/tables//" not in url for url in requested_urls)


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


def test_assignment_vocabulary_item_is_confirmed_idempotent_and_persistent(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    student = app.test_client()
    other_student = app.test_client()
    register(teacher, "vocab-teacher", role="teacher", password="teacher-password")
    register(student, "vocab-student")
    register(other_student, "vocab-other")
    store = app.extensions["reading_trainer_v2"]["store"]
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    existing = store.get_user(student_id)
    store.upsert_user(
        {
            "id": student_id,
            "username": "vocab-student",
            "role": "student",
            "password_hash": existing["password_hash"],
            "created_by": teacher_id,
            "created_at": existing["created_at"],
        }
    )
    created_assignment = teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={
            "id": "assignment-vocab-1",
            "title": "Vocabulary source",
            "studentIds": [student_id],
            "sections": [{"article": "Reliable systems preserve every vocabulary item.", "questions": []}],
        },
    )
    assert created_assignment.status_code == 201

    payload = {
        "word": "Reliable",
        "pos": "adj.",
        "zh": "可靠的",
        "ctx": "Reliable systems preserve every vocabulary item.",
        "sourceType": "assignment",
        "assignmentId": "assignment-vocab-1",
        "assignmentTitle": "Vocabulary source",
        "articleIndex": 0,
    }
    first = student.post("/reading-trainer/api/v2/vbook/items", json=payload)
    assert first.status_code == 200
    assert first.get_json()["ok"] is True
    assert first.get_json()["created"] is True
    assert len(first.get_json()["data"]) == 1
    duplicate = student.post("/reading-trainer/api/v2/vbook/items", json={**payload, "word": "reliable"})
    assert duplicate.status_code == 200
    assert duplicate.get_json()["created"] is False
    assert len(duplicate.get_json()["data"]) == 1

    forbidden = other_student.post("/reading-trainer/api/v2/vbook/items", json=payload)
    assert forbidden.status_code == 403
    assert forbidden.get_json()["error"]["code"] == "forbidden_assignment"

    app2 = make_app(tmp_path)
    refreshed = app2.test_client()
    login(refreshed, "vocab-student", "student", "student-password")
    saved = refreshed.get("/reading-trainer/api/v2/data/vbook").get_json()["data"]
    assert len(saved) == 1
    assert saved[0]["word"] == "Reliable"
    assert saved[0]["assignmentId"] == "assignment-vocab-1"
    assert saved[0]["sourceType"] == "assignment"


def test_assignments_permissions_visibility_read_submit_idempotency_and_transfer(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    other_teacher = app.test_client()
    student = app.test_client()
    other_student = app.test_client()
    register(teacher, "assignment-teacher", role="teacher", password="teacher-password")
    register(other_teacher, "assignment-other", role="teacher", password="teacher-password")
    register(student, "assignment-student")
    register(other_student, "assignment-other-student")
    store = app.extensions["reading_trainer_v2"]["store"]
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    other_teacher_id = other_teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    other_student_id = other_student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    for student_id_value, username in ((student_id, "assignment-student"), (other_student_id, "assignment-other-student")):
        existing = store.get_user(student_id_value)
        store.upsert_user(
            {
                "id": student_id_value,
                "username": username,
                "role": "student",
                "password_hash": existing["password_hash"],
                "created_by": teacher_id,
                "created_at": existing["created_at"],
            }
        )

    pre_class_membership = student.get("/reading-trainer/api/v2/bootstrap").get_json()["membership"]
    assert pre_class_membership["className"] == "暂未分配"
    assert pre_class_membership["teacherId"] == teacher_id
    assert pre_class_membership["teacherName"] == "assignment-teacher"

    created = teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={
            "id": "assignment-contract-1",
            "title": "Reading card",
            "instructions": "Complete this card",
            "studentIds": [student_id],
            "questions": [{"id": 1, "prompt": "Choose", "answer": "B", "explanation": "Because"}],
            "settings": {"level": "B2"},
            "dueAt": "2030-01-02T03:04:05Z",
        },
    )
    assert created.status_code == 201
    assignment_id = created.get_json()["id"]
    assert assignment_id == "assignment-contract-1"
    assert created.get_json()["dueAt"] == 1893553445000
    app.config["READING_TRAINER_FEISHU_TABLES"] = {"assignments": "tbl-assignment-test"}
    assignment_plan = build_feishu_sync_plan(store)
    assignment_rows = assignment_plan["tables"]["assignments"]["creates"]
    assert any(row["business_key"] == f"assignments:{assignment_id}:{student_id}" for row in assignment_rows)
    assert all("password" not in json.dumps(row["fields"]).lower() for row in assignment_rows)
    assert other_teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={"title": "forbidden", "studentIds": [student_id], "questions": []},
    ).status_code == 403

    listing = student.get("/reading-trainer/api/v2/assignments?summary=1")
    assert listing.status_code == 200
    assert listing.get_json()["assignments"][0]["id"] == assignment_id
    detail = student.get(f"/reading-trainer/api/v2/assignments/{assignment_id}")
    assert detail.status_code == 200
    assert '"answer"' not in json.dumps(detail.get_json(), ensure_ascii=False)
    assert detail.get_json()["unread"] is True
    opened = student.post(f"/reading-trainer/api/v2/assignments/{assignment_id}/open")
    assert opened.status_code == 200
    assert opened.get_json()["unread"] is False
    assert opened.get_json()["status"] == "read"
    assert other_student.get(f"/reading-trainer/api/v2/assignments/{assignment_id}").status_code == 403

    first_submit = student.post(
        f"/reading-trainer/api/v2/assignments/{assignment_id}/submit", json={"answers": {"1": "A"}}
    )
    assert first_submit.status_code == 200
    first_result = first_submit.get_json()["result"]
    assert first_result["correct"] == 0
    second_submit = student.post(
        f"/reading-trainer/api/v2/assignments/{assignment_id}/submit", json={"answers": {"1": "B"}}
    )
    assert second_submit.status_code == 200
    assert second_submit.get_json()["idempotent"] is True
    assert second_submit.get_json()["result"] == first_result
    teacher_detail = teacher.get(f"/reading-trainer/api/v2/assignments/{assignment_id}")
    assert teacher_detail.status_code == 200
    assert teacher_detail.get_json()["questions"][0]["answer"] == "B"

    # A class move revokes the old created_by teacher's access and grants the
    # current class teacher access, while persisted assignment state survives
    # a fresh app instance.
    store.upsert_class({"id": "class-current", "name": "Current class", "teacherId": other_teacher_id})
    existing_student = store.get_user(student_id)
    store.upsert_user(
        {
            "id": student_id,
            "username": "assignment-student",
            "role": "student",
            "password_hash": existing_student["password_hash"],
            "created_by": teacher_id,
            "class_id": "class-current",
            "created_at": existing_student["created_at"],
        }
    )
    assert teacher.get(f"/reading-trainer/api/v2/data/vbook/{student_id}").status_code == 403
    assert other_teacher.get(f"/reading-trainer/api/v2/data/vbook/{student_id}").status_code == 200

    app2 = make_app(tmp_path)
    refreshed = app2.test_client()
    login(refreshed, "assignment-student", "student", "student-password")
    refreshed_assignment = refreshed.get(f"/reading-trainer/api/v2/assignments/{assignment_id}")
    assert refreshed_assignment.status_code == 200
    assert refreshed_assignment.get_json()["status"] == "submitted"
    bootstrap = refreshed.get("/reading-trainer/api/v2/bootstrap").get_json()
    assert bootstrap["membership"] == {
        "assigned": True,
        "classId": "class-current",
        "className": "Current class",
        "teacherId": other_teacher_id,
        "teacherName": "assignment-other",
    }


def test_assignment_grader_supports_embedded_matching_and_diagram_answers():
    assignment = {
        "sections": [
            {
                "questions": [
                    {
                        "id": "match-1",
                        "type": "matching",
                        "prompt": "Match",
                        "items": [{"para": "A", "heading": "H1"}],
                    },
                    {
                        "id": "diagram-1",
                        "type": "diagram",
                        "prompt": "Complete",
                        "steps": [{"text": "Step", "answer": "water"}],
                    },
                ]
            }
        ]
    }
    result = _grade_assignment(assignment, {"match-1": ["H1"], "diagram-1": ["water"]})
    assert result["correct"] == 2
    assert result["wrongCount"] == 0


def test_assignment_question_check_is_scoped_and_first_attempt_is_immutable(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    student = app.test_client()
    other = app.test_client()
    register(teacher, "check-teacher", role="teacher", password="teacher-password")
    register(student, "check-student")
    register(other, "check-other")
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    store = app.extensions["reading_trainer_v2"]["store"]
    current = store.get_user(student_id)
    store.upsert_user(
        {
            "id": student_id,
            "username": "check-student",
            "role": "student",
            "password_hash": current["password_hash"],
            "created_by": teacher_id,
            "created_at": current["created_at"],
        }
    )
    created = teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={
            "id": "check-contract",
            "studentIds": [student_id],
            "questions": [
                {"id": "q1", "type": "multiple-choice", "prompt": "One", "answer": "B", "explanation": "B is stated."},
                {"id": "q2", "type": "fill-blank", "prompt": "Two", "answer": "water", "explanation": "Use the noun."},
            ],
        },
    )
    assert created.status_code == 201
    assignment_id = "check-contract"
    detail = student.get(f"/reading-trainer/api/v2/assignments/{assignment_id}")
    assert detail.status_code == 200
    assert '"answer"' not in json.dumps(detail.get_json(), ensure_ascii=False)
    assert other.post(
        f"/reading-trainer/api/v2/assignments/{assignment_id}/questions/q1/check", json={"answer": "A"}
    ).status_code == 403

    first = student.post(
        f"/reading-trainer/api/v2/assignments/{assignment_id}/questions/q1/check", json={"answer": "A"}
    )
    assert first.status_code == 200
    assert first.get_json()["questionId"] == "q1"
    assert first.get_json()["correct"] is False
    assert first.get_json()["userAnswer"] == "A"
    assert first.get_json()["correctAnswer"] == "B"
    assert "water" not in json.dumps(first.get_json(), ensure_ascii=False)

    retry = student.post(
        f"/reading-trainer/api/v2/assignments/{assignment_id}/questions/q1/check", json={"answer": "B"}
    )
    assert retry.status_code == 200
    assert retry.get_json()["idempotent"] is True
    assert retry.get_json()["correct"] is False
    assert retry.get_json()["userAnswer"] == "A"
    saved = store.get_assignment_question_check(assignment_id, student_id, "q1")
    assert saved["answer"] == "A"


def test_assignment_submit_returns_aggregate_report_and_persists_once(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    student = app.test_client()
    register(teacher, "report-teacher", role="teacher", password="teacher-password")
    register(student, "report-student")
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    store = app.extensions["reading_trainer_v2"]["store"]
    current = store.get_user(student_id)
    store.upsert_user(
        {
            "id": student_id,
            "username": "report-student",
            "role": "student",
            "password_hash": current["password_hash"],
            "created_by": teacher_id,
            "created_at": current["created_at"],
        }
    )
    response = teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={
            "id": "report-contract",
            "title": "Aggregate",
            "studentIds": [student_id],
            "questions": [
                {"id": "ielts-right", "type": "headings", "exam": "ielts", "prompt": "Heading", "answer": "A"},
                {"id": "toefl-wrong", "type": "fill-blank", "exam": "TOEFL", "prompt": "Blank", "answer": "water", "explanation": "Read the sentence."},
                {"id": "ielts-empty", "type": "matching", "exam": "IELTS", "prompt": "Match", "answer": ["H1"]},
            ],
        },
    )
    assert response.status_code == 201
    # First scoring wins even if submit retries with a different answer.
    assert student.post(
        "/reading-trainer/api/v2/assignments/report-contract/questions/ielts-right/check", json={"answer": "A"}
    ).get_json()["correct"] is True
    submitted = student.post(
        "/reading-trainer/api/v2/assignments/report-contract/submit",
        json={"answers": {"ielts-right": "B", "toefl-wrong": "sand"}},
    )
    assert submitted.status_code == 200
    result = submitted.get_json()["result"]
    assert result["pct"] == 33.33
    assert result["right"] == 1
    assert result["total"] == 3
    assert result["unanswered"] == 1
    assert result["wrongCount"] == 1
    assert result["byType"]["headings"]["right"] == 1
    assert result["byExam"]["IELTS"]["right"] == 1
    assert result["byExam"]["TOEFL"]["wrong"] == 1
    assert result["advice"]
    assert {item["questionId"] for item in result["wrong"]} == {"toefl-wrong", "ielts-empty"}
    grades = student.get("/reading-trainer/api/v2/data/grades").get_json()["data"]
    wrong_book = student.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]
    assert len(grades) == 1
    assert len(wrong_book) == 2

    retry = student.post(
        "/reading-trainer/api/v2/assignments/report-contract/submit",
        json={"answers": {"ielts-right": "B", "toefl-wrong": "water"}},
    )
    assert retry.status_code == 200
    assert retry.get_json()["idempotent"] is True
    assert retry.get_json()["result"] == result
    assert len(student.get("/reading-trainer/api/v2/data/grades").get_json()["data"]) == 1
    assert len(student.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]) == 2


def test_assignment_grader_accepts_object_and_string_heading_options():
    assignment = {
        "questions": [
            {
                "id": "title-1",
                "type": "headings",
                "exam": "IELTS Academic",
                "prompt": "Choose a heading",
                "answer": [{"id": "H1", "text": "Origins"}],
            },
            {
                "id": "title-2",
                "type": "matching",
                "items": [{"heading": {"value": "H2", "label": "Methods"}}],
            },
        ]
    }
    result = _grade_assignment(
        assignment,
        {"title-1": ["H1"], "title-2": [{"id": "H2", "text": "Methods"}]},
    )
    assert result["right"] == 2
    assert result["byExam"]["IELTS"]["pct"] == 100

    legacy_title = {
        "questions": [
            {
                "id": "legacy-title",
                "type": "matching",
                "prompt": "Match titles",
                "answer": "Paragraph 1 -> H1",
                "items": [{"para": "Paragraph 1", "heading": "H1"}],
            }
        ]
    }
    assert _grade_assignment(legacy_title, {"legacy-title": ["H1"]})["right"] == 1

    headings_with_topics = {
        "questions": [
            {
                "id": "headings-topics",
                "type": "headings",
                "items": [{"para": "Paragraph 1", "topic": "Origins"}],
                "answer": ["H1"],
            }
        ]
    }
    assert _grade_assignment(headings_with_topics, {"headings-topics": ["H1"]})["right"] == 1


def test_assignment_wrongbook_keeps_complete_question_snapshots_and_state(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    student = app.test_client()
    register(teacher, "snapshot-teacher", role="teacher", password="teacher-password")
    register(student, "snapshot-student")
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    store = app.extensions["reading_trainer_v2"]["store"]
    current = store.get_user(student_id)
    store.upsert_user(
        {
            "id": student_id,
            "username": "snapshot-student",
            "role": "student",
            "password_hash": current["password_hash"],
            "created_by": teacher_id,
            "created_at": current["created_at"],
        }
    )
    assignment = {
        "id": "snapshot-assignment",
        "title": "Complete card",
        "studentIds": [student_id],
        "sections": [
            {
                "id": "passage-1",
                "title": "Passage One",
                "article": "The article used by every question in this section.",
                "questions": [
                    {
                        "id": "choice",
                        "type": "multiple-choice",
                        "prompt": "Choose one",
                        "options": ["A", "B"],
                        "answer": "A",
                        "explanation": "A is stated.",
                    },
                    {
                        "id": "heading",
                        "type": "headings",
                        "prompt": "Choose headings",
                        "options": ["H1", "H2", "H3"],
                        "items": [{"para": "Paragraph 1", "topic": "Main idea"}],
                        "answer": ["H1"],
                        "explanation": "H1 summarizes the paragraph.",
                    },
                    {
                        "id": "matching",
                        "type": "matching",
                        "prompt": "Match paragraphs",
                        "options": ["H1", "H2"],
                        "items": [{"para": "Paragraph 2", "heading": "H1"}],
                        "answer": ["H1"],
                        "explanation": "Match the main idea.",
                    },
                    {
                        "id": "sentence",
                        "type": "sentence-end",
                        "prompt": "Match sentence endings",
                        "beginnings": [{"id": "i", "text": "The study"}],
                        "endings": [{"id": "A", "text": "was replicated"}, {"id": "B", "text": "was abandoned"}],
                        "answer": {"i": "A"},
                        "explanation": "The final clause follows the evidence.",
                    },
                    {
                        "id": "diagram",
                        "type": "diagram",
                        "prompt": "Complete the flow",
                        "steps": [{"text": "Plants absorb ____.", "answer": "water"}],
                        "answer": ["water"],
                        "explanation": "The passage names water.",
                    },
                ],
            }
        ],
    }
    created = teacher.post("/reading-trainer/api/v2/assignments", json=assignment)
    assert created.status_code == 201
    submitted = student.post(
        "/reading-trainer/api/v2/assignments/snapshot-assignment/submit",
        json={
            "answers": {
                "choice": "B",
                "heading": ["H2"],
                "matching": ["H2"],
                "sentence": {"i": "B"},
                "diagram": ["soil"],
            }
        },
    )
    assert submitted.status_code == 200
    body = submitted.get_json()
    assert body["state"]["userData"][student_id]["wbook"] == student.get(
        "/reading-trainer/api/v2/data/wbook"
    ).get_json()["data"]
    wrong_book = body["state"]["userData"][student_id]["wbook"]
    assert {item["questionId"] for item in wrong_book} == {"choice", "heading", "matching", "sentence", "diagram"}
    by_id = {item["questionId"]: item for item in wrong_book}
    assert by_id["choice"]["q"]["options"] == ["A", "B"]
    assert by_id["heading"]["q"]["items"][0]["topic"] == "Main idea"
    assert by_id["matching"]["q"]["items"][0]["heading"] == "H1"
    assert by_id["sentence"]["q"]["beginnings"][0]["id"] == "i"
    assert by_id["sentence"]["q"]["endings"][1]["id"] == "B"
    assert by_id["diagram"]["q"]["steps"][0]["answer"] == "water"
    assert all(item["article"] == "The article used by every question in this section." for item in wrong_book)
    assert all(item["sectionIndex"] == 0 and item["sectionId"] == "passage-1" for item in wrong_book)
    assert wrong_book[0]["assignmentTitle"] == "Complete card"
    grades = student.get("/reading-trainer/api/v2/data/grades").get_json()["data"]
    assert grades[0]["source"] == "assignment"
    assert grades[0]["assignmentTitle"] == "Complete card"
    assert grades[0]["title"] == "Complete card"
    assert "byType" in grades[0] and "byExam" in grades[0]


def test_wrongbook_item_api_is_server_confirmed_idempotent_and_scoped(tmp_path):
    app = make_app(tmp_path)
    teacher = app.test_client()
    student = app.test_client()
    other = app.test_client()
    register(teacher, "wbook-teacher", role="teacher", password="teacher-password")
    register(student, "wbook-student")
    register(other, "wbook-other")
    store = app.extensions["reading_trainer_v2"]["store"]
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    student_id = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    other_id = other.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    for student_id_value, username in ((student_id, "wbook-student"), (other_id, "wbook-other")):
        current = store.get_user(student_id_value)
        store.upsert_user(
            {
                "id": student_id_value,
                "username": username,
                "role": "student",
                "password_hash": current["password_hash"],
                "created_by": teacher_id,
                "created_at": current["created_at"],
            }
        )
    created = teacher.post(
        "/reading-trainer/api/v2/assignments",
        json={
            "id": "wbook-assignment",
            "title": "Source card",
            "studentIds": [student_id],
            "sections": [
                {
                    "article": "Authoritative passage",
                    "questions": [
                        {
                            "id": "q1",
                            "type": "headings",
                            "prompt": "Pick a heading",
                            "options": ["H1", "H2"],
                            "items": [{"para": "P1", "topic": "Topic"}],
                            "answer": ["H1"],
                            "explanation": "The topic is H1.",
                        },
                        {
                            "id": "q2",
                            "type": "multiple-choice",
                            "prompt": "A second question",
                            "options": ["A", "B"],
                            "answer": "A",
                            "explanation": "A is correct.",
                        },
                        {
                            "id": "q3",
                            "type": "multiple-choice",
                            "prompt": "A third question",
                            "options": ["A", "B"],
                            "answer": "A",
                            "explanation": "A is correct.",
                        },
                    ],
                }
            ],
        },
    )
    assert created.status_code == 201
    payload = {
        "sourceType": "assignment",
        "assignmentId": "wbook-assignment",
        "questionId": "q1",
        "q": {"id": "q1", "type": "headings", "prompt": "tampered", "options": ["bad"]},
        "userAnswer": ["forged"],
    }
    # The active wrong-book API requires a server-recorded first check.  The
    # answer stored in that check, not the request payload, is authoritative.
    unchecked = student.post(
        "/reading-trainer/api/v2/wbook/items",
        json={**payload, "questionId": "q2"},
    )
    assert unchecked.status_code == 409
    assert unchecked.get_json()["error"]["code"] == "question_not_checked"
    checked_wrong = student.post(
        "/reading-trainer/api/v2/assignments/wbook-assignment/questions/q1/check",
        json={"answer": ["H2"]},
    )
    assert checked_wrong.status_code == 200
    assert checked_wrong.get_json()["correct"] is False
    first = student.post("/reading-trainer/api/v2/wbook/items", json=payload)
    assert first.status_code == 200
    first_body = first.get_json()
    assert first_body["ok"] is True and first_body["created"] is True
    assert first_body["item"]["q"]["options"] == ["H1", "H2"]
    assert first_body["item"]["q"]["prompt"] == "Pick a heading"
    assert first_body["item"]["article"] == "Authoritative passage"
    assert first_body["item"]["assignmentTitle"] == "Source card"
    assert first_body["item"]["userAnswer"] == ["H2"]
    assert first_body["item"]["userAnswer"] != ["forged"]
    retry = student.post("/reading-trainer/api/v2/wbook/items", json=payload)
    assert retry.status_code == 200
    assert retry.get_json()["created"] is False
    assert len(retry.get_json()["data"]) == 1
    assert retry.get_json()["item"]["errorCount"] == 1
    assert retry.get_json()["state"]["userData"][student_id]["wbook"] == retry.get_json()["data"]

    # Recipient validation happens even when the caller is authenticated.
    forbidden = other.post("/reading-trainer/api/v2/wbook/items", json=payload)
    assert forbidden.status_code == 403
    assert forbidden.get_json()["error"]["code"] == "forbidden_assignment"
    teacher_forbidden = teacher.post(
        "/reading-trainer/api/v2/wbook/items",
        json={**payload, "ownerId": other_id},
    )
    assert teacher_forbidden.status_code == 403
    assert teacher_forbidden.get_json()["error"]["code"] == "forbidden_assignment"
    checked_right = student.post(
        "/reading-trainer/api/v2/assignments/wbook-assignment/questions/q3/check",
        json={"answer": "A"},
    )
    assert checked_right.status_code == 200
    assert checked_right.get_json()["correct"] is True
    correct = student.post(
        "/reading-trainer/api/v2/wbook/items",
        json={**payload, "questionId": "q3"},
    )
    assert correct.status_code == 409
    assert correct.get_json()["error"]["code"] == "question_not_wrong"
    missing_question = student.post(
        "/reading-trainer/api/v2/wbook/items",
        json={**payload, "questionId": "not-in-assignment"},
    )
    assert missing_question.status_code == 404
    assert missing_question.get_json()["error"]["code"] == "question_not_found"

    # Feishu is only a sanitized idempotent replica: changing review metadata
    # must keep the assignment/question business key stable and never delete a
    # remote-only record.
    app.config["READING_TRAINER_FEISHU_TABLES"] = {"wbook": "tbl-wbook-test"}
    plan_before = build_feishu_sync_plan(store)
    wbook_rows = plan_before["tables"]["wbook"]["creates"]
    assert len(wbook_rows) == 1
    assert wbook_rows[0]["business_key"] == f"wbook:{student_id}:wbook-assignment:q1"
    remote = {"wbook": [{"record_id": "remote-wbook", "fields": wbook_rows[0]["fields"]}]}
    store.put_document(student_id, "wbook", [{**first_body["item"], "box": 2, "ts": 999}])
    replay = build_feishu_sync_plan(store, remote)
    assert replay["tables"]["wbook"]["creates"] == []
    assert replay["tables"]["wbook"]["updates"][0]["business_key"] == wbook_rows[0]["business_key"]
    assert replay["totals"]["deletes"] == 0


def test_legacy_wbook_read_fills_metadata_without_dropping_fields(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "legacy-wbook")
    user_id = client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    store = app.extensions["reading_trainer_v2"]["store"]
    legacy = [{"q": {"id": "legacy-q", "prompt": "keep me", "answer": "A"}, "custom": {"x": 1}, "userAnswer": "B"}]
    store.put_document(user_id, "wbook", legacy)
    loaded = store.get_document(user_id, "wbook", [])
    assert loaded[0]["q"]["prompt"] == "keep me"
    assert loaded[0]["custom"] == {"x": 1}
    assert loaded[0]["userAnswer"] == "B"
    assert loaded[0]["id"]
    assert loaded[0]["status"] == "pending"
    assert loaded[0]["errorCount"] == 0
    assert loaded[0]["unansweredCount"] == 0
    assert loaded[0]["masteryStreak"] == 0
    persisted = client.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]
    assert persisted[0]["id"] == loaded[0]["id"]


def test_wbook_attempt_idempotency_streak_reset_and_teacher_review_forbidden(tmp_path):
    app = make_app(tmp_path)
    student = app.test_client()
    teacher = app.test_client()
    register(student, "progress-student")
    register(teacher, "progress-teacher", role="teacher", password="teacher-password")
    question = {"id": "progress-q", "type": "multiple-choice", "prompt": "p", "answer": "A"}
    first = student.post("/reading-trainer/api/v2/wbook/items", json={"q": question, "userAnswer": "B", "attemptId": "a1"})
    assert first.status_code == 200
    assert first.get_json()["item"]["errorCount"] == 1
    retry = student.post("/reading-trainer/api/v2/wbook/items", json={"q": question, "userAnswer": "B", "attemptId": "a1"})
    assert retry.get_json()["item"]["errorCount"] == 1
    second = student.post("/reading-trainer/api/v2/wbook/items", json={"q": question, "userAnswer": "B", "attemptId": "a2"})
    assert second.get_json()["item"]["errorCount"] == 2
    # Generated practices restart numbering at Q1. Distinct question content
    # with the same display number must remain two independent wrong items.
    other_question = {"id": "progress-q", "type": "multiple-choice", "prompt": "different", "answer": "B"}
    other = student.post(
        "/reading-trainer/api/v2/wbook/items",
        json={"q": other_question, "userAnswer": "A", "attemptId": "other-1"},
    )
    assert other.status_code == 200 and len(other.get_json()["data"]) == 2
    unanswered = student.post(
        "/reading-trainer/api/v2/wbook/items",
        json={"q": question, "userAnswer": "（未作答）", "answered": False, "attemptId": "a3"},
    )
    assert unanswered.get_json()["item"]["unansweredCount"] == 1
    assert unanswered.get_json()["item"]["errorCount"] == 2
    item_id = unanswered.get_json()["item"]["id"]
    for _ in range(3):
        reviewed = student.post(f"/reading-trainer/api/v2/wbook/items/{item_id}/review", json={"answer": "A"})
        assert reviewed.status_code == 200
    mastered = reviewed.get_json()["item"]
    assert mastered["status"] == "mastered" and mastered["masteryStreak"] == 3
    re_error = student.post("/reading-trainer/api/v2/wbook/items", json={"q": question, "userAnswer": "B", "attemptId": "a4"})
    assert re_error.get_json()["item"]["status"] == "pending"
    assert re_error.get_json()["item"]["masteryStreak"] == 0
    assert teacher.post(f"/reading-trainer/api/v2/wbook/items/{item_id}/review", json={"answer": "A"}).status_code == 403


def test_wbook_capacity_keeps_latest_150(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    register(client, "capacity-student")
    for index in range(151):
        response = client.post(
            "/reading-trainer/api/v2/wbook/items",
            json={"q": {"id": f"capacity-{index}", "prompt": str(index), "answer": "A"}, "userAnswer": "B", "attemptId": str(index)},
        )
        assert response.status_code == 200
    items = client.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]
    assert len(items) == 150
    ids = {item["q"]["id"] for item in items}
    assert "capacity-150" in ids and "capacity-0" not in ids


def _seed_review_class(app, teacher, source, peer, cross):
    store = app.extensions["reading_trainer_v2"]["store"]
    teacher_id = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    ids = {
        name: client.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
        for name, client in (("source", source), ("peer", peer), ("cross", cross))
    }
    for name, username in (("source", "review-source"), ("peer", "review-peer"), ("cross", "review-cross")):
        current = store.get_user(ids[name])
        store.upsert_user({**current, "created_by": teacher_id, "class_id": "class-a" if name != "cross" else "class-b"})
    store.upsert_class({"id": "class-a", "teacherId": teacher_id, "name": "A"})
    other_teacher_id = "teacher-other"
    store.upsert_class({"id": "class-b", "teacherId": other_teacher_id, "name": "B"})
    return store, teacher_id, ids


def test_review_assignment_selection_privacy_classes_and_source_metadata(tmp_path):
    app = make_app(tmp_path)
    teacher, source, peer, cross = (app.test_client() for _ in range(4))
    register(teacher, "review-teacher", role="teacher", password="teacher-password")
    register(source, "review-source")
    register(peer, "review-peer")
    register(cross, "review-cross")
    store, teacher_id, ids = _seed_review_class(app, teacher, source, peer, cross)
    source.post("/reading-trainer/api/v2/wbook/items", json={"q": {"id": "rq", "prompt": "prompt", "answer": "A"}, "userAnswer": "B", "attemptId": "src"})
    source.post("/reading-trainer/api/v2/vbook/items", json={"id": "rv", "word": "term", "zh": "中文", "pos": "n.", "ctx": "context"})
    item = source.get("/reading-trainer/api/v2/data/wbook").get_json()["data"][0]
    vocab = source.get("/reading-trainer/api/v2/data/vbook").get_json()["data"][0]
    assert teacher.post("/reading-trainer/api/v2/assignments/review", json={"sourceStudentId": ids["source"], "studentIds": [ids["source"]]}).status_code == 400
    created = teacher.post(
        "/reading-trainer/api/v2/assignments/review",
        json={"sourceStudentId": ids["source"], "wrongItemIds": [item["id"]], "vocabItemIds": [vocab["id"]], "studentIds": [ids["source"], ids["peer"]], "title": "Review"},
    )
    assert created.status_code == 201
    assignment = created.get_json()["assignment"]
    assert assignment["assignmentType"] == "review"
    assert assignment["sourceStudentId"] == ids["source"]
    assert assignment["settings"]["sourceStudentId"] == ids["source"]
    question_item, vocab_item = assignment["reviewItems"]
    assert "userAnswer" not in question_item and "errorCount" not in question_item
    assert vocab_item["zh"] == "中文" and vocab_item["pos"] == "n." and vocab_item["ctx"] == "context"
    assignment_id = assignment["id"]
    student_view = source.get(f"/reading-trainer/api/v2/assignments/{assignment_id}").get_json()["assignment"]
    assert "sourceStudentId" not in student_view.get("settings", {})
    assert teacher.post(
        "/reading-trainer/api/v2/assignments/review",
        json={"sourceStudentId": ids["source"], "wrongItemIds": [item["id"]], "vocabItemIds": [], "studentIds": [ids["source"], ids["cross"]]},
    ).status_code == 403
    # An unassigned source may only receive its own review.
    current = store.get_user(ids["source"])
    store.upsert_user({**current, "class_id": None})
    assert teacher.post(
        "/reading-trainer/api/v2/assignments/review",
        json={"sourceStudentId": ids["source"], "wrongItemIds": [item["id"]], "vocabItemIds": [], "studentIds": [ids["peer"]]},
    ).status_code == 403


def test_review_submit_report_vocab_linkage_and_repeat_is_idempotent(tmp_path):
    app = make_app(tmp_path)
    teacher, source = app.test_client(), app.test_client()
    register(teacher, "report-teacher", role="teacher", password="teacher-password")
    register(source, "report-source")
    store = app.extensions["reading_trainer_v2"]["store"]
    tid = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    sid = source.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    current = store.get_user(sid)
    store.upsert_user({**current, "created_by": tid, "class_id": "report-class"})
    store.upsert_class({"id": "report-class", "teacherId": tid, "name": "Report"})
    source.post("/reading-trainer/api/v2/wbook/items", json={"q": {"id": "report-q", "prompt": "p", "answer": "A", "type": "multiple-choice"}, "userAnswer": "B", "attemptId": "a"})
    source.post("/reading-trainer/api/v2/vbook/items", json={"id": "report-v", "word": "word", "zh": "中文"})
    q = source.get("/reading-trainer/api/v2/data/wbook").get_json()["data"][0]
    v = source.get("/reading-trainer/api/v2/data/vbook").get_json()["data"][0]
    created = teacher.post("/reading-trainer/api/v2/assignments/review", json={"sourceStudentId": sid, "wrongItemIds": [q["id"]], "vocabItemIds": [v["id"]], "studentIds": [sid]})
    aid = created.get_json()["assignment"]["id"]
    first = source.post(f"/reading-trainer/api/v2/assignments/{aid}/submit", json={"answers": {q["id"]: "B"}, "viewedVocabIds": []})
    assert first.status_code == 200
    report = first.get_json()["result"]
    assert report["wrongCount"] == 1 and report["unanswered"] == 0
    assert report["vocabulary"]["viewed"] == 0 and report["vocabulary"]["unviewed"] == 1
    assert len(source.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]) == 1
    second = source.post(f"/reading-trainer/api/v2/assignments/{aid}/submit", json={"answers": {q["id"]: "A"}, "viewedVocabIds": [v["id"]]})
    assert second.status_code == 200 and second.get_json()["idempotent"] is True
    assert len(source.get("/reading-trainer/api/v2/data/wbook").get_json()["data"]) == 1
    grades_before = source.get("/reading-trainer/api/v2/data/grades").get_json()["data"]
    vocab_only = teacher.post(
        "/reading-trainer/api/v2/assignments/review",
        json={"sourceStudentId": sid, "wrongItemIds": [], "vocabItemIds": [v["id"]], "studentIds": [sid]},
    ).get_json()["assignment"]
    vocab_submit = source.post(
        f"/reading-trainer/api/v2/assignments/{vocab_only['id']}/submit",
        json={"answers": {}, "viewedVocabIds": [v["id"]]},
    )
    assert vocab_submit.status_code == 200
    assert vocab_submit.get_json()["result"]["total"] == 0
    assert source.get("/reading-trainer/api/v2/data/grades").get_json()["data"] == grades_before


def test_review_question_check_uses_first_attempt_and_question_card_default(tmp_path):
    app = make_app(tmp_path)
    teacher, source = app.test_client(), app.test_client()
    register(teacher, "check-teacher", role="teacher", password="teacher-password")
    register(source, "check-source")
    store = app.extensions["reading_trainer_v2"]["store"]
    tid = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    sid = source.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    current = store.get_user(sid)
    store.upsert_user({**current, "created_by": tid, "class_id": "check-class"})
    store.upsert_class({"id": "check-class", "teacherId": tid, "name": "Check"})
    source.post("/reading-trainer/api/v2/wbook/items", json={"q": {"id": "check-q", "prompt": "p", "answer": "A"}, "userAnswer": "B", "attemptId": "a"})
    q = source.get("/reading-trainer/api/v2/data/wbook").get_json()["data"][0]
    assignment = teacher.post("/reading-trainer/api/v2/assignments/review", json={"sourceStudentId": sid, "wrongItemIds": [q["id"]], "studentIds": [sid]}).get_json()["assignment"]
    aid = assignment["id"]
    checked = source.post(f"/reading-trainer/api/v2/assignments/{aid}/questions/{q['id']}/check", json={"answer": "B"})
    assert checked.status_code == 200 and checked.get_json()["correct"] is False
    assert source.post(f"/reading-trainer/api/v2/assignments/{aid}/questions/{q['id']}/check", json={"answer": "A"}).get_json()["idempotent"] is True
    submitted = source.post(f"/reading-trainer/api/v2/assignments/{aid}/submit", json={"answers": {q["id"]: "A"}})
    assert submitted.get_json()["result"]["wrongCount"] == 1
    card = teacher.post("/reading-trainer/api/v2/assignments", json={"id": "old-card", "title": "Old", "questions": [{"id": "q", "answer": "A"}], "studentIds": [sid]})
    assert card.status_code == 201 and card.get_json()["assignment"]["assignmentType"] == "question_card"


def test_teacher_can_read_but_not_write_student_business_document(tmp_path):
    app = make_app(tmp_path)
    teacher, student = app.test_client(), app.test_client()
    register(teacher, "readonly-teacher", role="teacher", password="teacher-password")
    register(student, "readonly-student")
    store = app.extensions["reading_trainer_v2"]["store"]
    tid = teacher.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    sid = student.get("/reading-trainer/api/v2/auth/session").get_json()["user"]["id"]
    current = store.get_user(sid)
    store.upsert_user({**current, "created_by": tid})
    assert teacher.get(f"/reading-trainer/api/v2/data/vbook/{sid}").status_code == 200
    assert teacher.put(f"/reading-trainer/api/v2/data/vbook/{sid}", json={"data": [{"word": "blocked"}]}).status_code == 403
