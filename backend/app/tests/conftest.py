from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def application(tmp_path: Path) -> FastAPI:
    return create_app(Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}"))


@pytest.fixture
def client(application: FastAPI) -> Iterator[TestClient]:
    # Entering TestClient runs the real startup schema initialization.
    with TestClient(application) as test_client:
        yield test_client
