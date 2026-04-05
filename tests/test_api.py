"""Tests for the Email Validator API."""

import os
import tempfile
import importlib
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Run every test against a fresh, temporary SQLite database."""
    db_file = str(tmp_path / "test.db")
    monkeypatch.setenv("EMAIL_VALIDATOR_DB", db_file)

    # Patch the DB_PATH constant used by database.py before importing main.
    import database
    monkeypatch.setattr(database, "DB_PATH", db_file)

    # Re-initialize the schema on the new file.
    database.init_db()
    yield


@pytest.fixture()
def client(isolated_db):
    from main import app
    return TestClient(app)


@pytest.fixture()
def api_key(isolated_db):
    """Return a freshly created API key."""
    import database
    return database.create_api_key("test_owner")


# ---------------------------------------------------------------------------
# /keys  – key creation
# ---------------------------------------------------------------------------


class TestCreateKey:
    def test_create_key_returns_201(self, client):
        resp = client.post("/keys", json={"owner": "alice"})
        assert resp.status_code == 201

    def test_create_key_response_shape(self, client):
        resp = client.post("/keys", json={"owner": "alice"})
        data = resp.json()
        assert "api_key" in data
        assert data["owner"] == "alice"
        assert data["limit_per_month"] == 100

    def test_create_key_is_unique(self, client):
        key1 = client.post("/keys", json={"owner": "bob"}).json()["api_key"]
        key2 = client.post("/keys", json={"owner": "bob"}).json()["api_key"]
        assert key1 != key2

    def test_missing_owner_returns_422(self, client):
        resp = client.post("/keys", json={})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /usage  – usage endpoint
# ---------------------------------------------------------------------------


class TestUsage:
    def test_usage_starts_at_zero(self, client, api_key):
        resp = client.get("/usage", params={"api_key": api_key})
        assert resp.status_code == 200
        data = resp.json()
        assert data["used_this_month"] == 0
        assert data["remaining"] == 100

    def test_usage_invalid_key(self, client):
        resp = client.get("/usage", params={"api_key": "bad-key"})
        assert resp.status_code == 401

    def test_usage_reflects_validate_calls(self, client, api_key):
        with patch("main._domain_exists", return_value=True):
            client.get("/validate", params={"email": "a@example.com", "api_key": api_key})
            client.get("/validate", params={"email": "b@example.com", "api_key": api_key})

        resp = client.get("/usage", params={"api_key": api_key})
        assert resp.json()["used_this_month"] == 2


# ---------------------------------------------------------------------------
# /validate  – authentication guards
# ---------------------------------------------------------------------------


class TestValidateAuth:
    def test_missing_api_key_returns_422(self, client):
        resp = client.get("/validate", params={"email": "test@example.com"})
        assert resp.status_code == 422

    def test_invalid_api_key_returns_401(self, client):
        resp = client.get(
            "/validate",
            params={"email": "test@example.com", "api_key": "totally-wrong"},
        )
        assert resp.status_code == 401
        assert resp.json()["detail"]["error"] == "invalid_api_key"

    def test_rate_limit_returns_429(self, client, api_key):
        import database
        # Exhaust the quota manually.
        database.increment_usage(api_key)
        # Override count directly via repeated increments.
        ym = database._current_year_month()
        with database.get_db() as conn:
            conn.execute(
                "UPDATE usage SET count = 100 WHERE key = ? AND year_month = ?",
                (api_key, ym),
            )

        with patch("main._domain_exists", return_value=True):
            resp = client.get(
                "/validate",
                params={"email": "test@example.com", "api_key": api_key},
            )
        assert resp.status_code == 429
        detail = resp.json()["detail"]
        assert detail["error"] == "rate_limit_exceeded"
        assert detail["used"] == 100


# ---------------------------------------------------------------------------
# /validate  – format validation
# ---------------------------------------------------------------------------


class TestValidateFormat:
    def test_valid_format_and_domain(self, client, api_key):
        with patch("main._domain_exists", return_value=True):
            resp = client.get(
                "/validate",
                params={"email": "user@example.com", "api_key": api_key},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid_format"] is True
        assert data["domain_exists"] is True
        assert data["status"] == "valid"

    def test_invalid_format(self, client, api_key):
        resp = client.get(
            "/validate",
            params={"email": "not-an-email", "api_key": api_key},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid_format"] is False
        assert data["domain_exists"] is False
        assert data["status"] == "invalid_format"

    def test_valid_format_domain_not_found(self, client, api_key):
        with patch("main._domain_exists", return_value=False):
            resp = client.get(
                "/validate",
                params={"email": "user@nonexistent-xyz-domain.com", "api_key": api_key},
            )
        data = resp.json()
        assert data["valid_format"] is True
        assert data["domain_exists"] is False
        assert data["status"] == "domain_not_found"

    def test_response_contains_email_field(self, client, api_key):
        with patch("main._domain_exists", return_value=True):
            resp = client.get(
                "/validate",
                params={"email": "hello@example.com", "api_key": api_key},
            )
        assert resp.json()["email"] == "hello@example.com"

    @pytest.mark.parametrize(
        "email",
        [
            "plainaddress",
            "@missinglocal.com",
            "missing@",
            "two@@at.com",
            "space in@email.com",
        ],
    )
    def test_invalid_formats(self, client, api_key, email):
        resp = client.get("/validate", params={"email": email, "api_key": api_key})
        assert resp.json()["valid_format"] is False

    @pytest.mark.parametrize(
        "email",
        [
            "simple@example.com",
            "user.name+tag@sub.domain.org",
            "x@y.co",
        ],
    )
    def test_valid_formats(self, client, api_key, email):
        with patch("main._domain_exists", return_value=True):
            resp = client.get("/validate", params={"email": email, "api_key": api_key})
        assert resp.json()["valid_format"] is True


# ---------------------------------------------------------------------------
# Swagger / OpenAPI docs availability
# ---------------------------------------------------------------------------


class TestDocs:
    def test_openapi_json_available(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        assert "paths" in resp.json()

    def test_swagger_ui_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_redoc_available(self, client):
        resp = client.get("/redoc")
        assert resp.status_code == 200
