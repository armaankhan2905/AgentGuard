from collections.abc import Iterator
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.session import get_db
from app.main import create_app


def test_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy", "application": "AgentGuard", "version": "0.1.0"
    }


def test_system_status_uses_real_database(client: TestClient) -> None:
    response = client.get("/api/system/status")
    assert response.status_code == 200
    assert response.json() == {
        "backend": {"available": True},
        "database": {"connected": True},
        "ai_provider": {"configured": False, "connection_verified": False},
        "version": "0.1.0",
    }


@pytest.mark.parametrize(
    ("provider", "model", "key", "expected"),
    [
        ("", "", "", False),
        ("provider", "model", "", False),
        ("", "model", "test-secret-value", False),
        ("provider", "", "test-secret-value", False),
        ("provider", "model", "  ", False),
        ("provider", "model", "test-secret-value", True),
    ],
)
def test_ai_status_only_reports_configuration(
    provider: str, model: str, key: str, expected: bool,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = Settings(
        database_url="sqlite:///:memory:", ai_provider=provider,
        ai_model=model, ai_api_key=key,
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/api/system/status")
        assert response.status_code == 200
        assert response.json()["ai_provider"] == {
            "configured": expected, "connection_verified": False
        }
        assert "test-secret-value" not in response.text
    output = capsys.readouterr()
    assert "test-secret-value" not in output.err + output.out + repr(settings)


def test_database_failure_is_reported_without_exception_payload(
    application: FastAPI, client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    db = Mock(spec=Session)
    db.execute.side_effect = OperationalError("SELECT 1", {}, Exception("sensitive-db-secret"))
    db.rollback.side_effect = OperationalError("ROLLBACK", {}, Exception("sensitive-db-secret"))

    def failing_db() -> Iterator[Session]:
        yield db

    application.dependency_overrides[get_db] = failing_db
    response = client.get("/api/system/status")
    assert response.status_code == 503
    assert response.json()["database"] == {"connected": False}
    assert response.json()["backend"] == {"available": True}
    output = capsys.readouterr()
    assert "sensitive-db-secret" not in response.text + output.err + output.out


def test_centralized_http_error(client: TestClient) -> None:
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {
        "error": {"code": "http_error", "message": "Resource not found."}
    }


def test_unhandled_errors_are_sanitized(
    application: FastAPI, capsys: pytest.CaptureFixture[str]
) -> None:
    @application.get("/test-error", include_in_schema=False)
    def raise_error() -> None:
        raise RuntimeError("sensitive-error-payload")

    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/test-error")
        assert response.status_code == 500
        assert response.json() == {"error": {
            "code": "internal_server_error", "message": "An internal error occurred."
        }}
    output = capsys.readouterr()
    assert "sensitive-error-payload" not in response.text + output.err + output.out


def test_validation_errors_do_not_echo_input(application: FastAPI) -> None:
    @application.get("/test-validation", include_in_schema=False)
    def validate_input(value: int) -> dict[str, int]:
        return {"value": value}

    with TestClient(application) as client:
        response = client.get("/test-validation", params={"value": "private-input-secret"})
        assert response.status_code == 422
        assert response.json() == {"error": {
            "code": "validation_error", "message": "Request validation failed."
        }}
        assert "private-input-secret" not in response.text


def test_local_frontend_cors(client: TestClient) -> None:
    response = client.options("/api/health", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"
    })
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_unknown_origins_are_not_allowed(client: TestClient) -> None:
    response = client.get("/api/health", headers={"Origin": "https://untrusted.example"})
    assert "access-control-allow-origin" not in response.headers
