from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nozo_relay.bootstrap import bootstrap, credentials_path
from nozo_relay.clock import FakeClock
from nozo_relay.config import Settings
from nozo_relay.main import create_app

OWNER_PASSWORD = "correct horse battery staple"
BASE_URL = "http://127.0.0.1:8765"


@dataclass
class Env:
    settings: Settings
    clock: FakeClock
    creds: dict
    app: object

    def client(self) -> TestClient:
        return TestClient(self.app, base_url=BASE_URL)  # type: ignore[arg-type]


def make_settings(tmp_path: Path, **overrides) -> Settings:
    overrides.setdefault("insecure_dev_cookies", True)
    overrides.setdefault("watchdog_interval_seconds", 0)  # tests drive sweeps via the fake clock
    return Settings(_env_file=None, data_dir=tmp_path / "data", **overrides)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def env(settings: Settings, clock: FakeClock) -> Env:
    bootstrap(settings, owner_password=OWNER_PASSWORD, clock=clock)
    creds = json.loads(credentials_path(settings).read_text())
    app = create_app(settings, clock)
    return Env(settings=settings, clock=clock, creds=creds, app=app)


@pytest.fixture
def client(env: Env):
    with env.client() as c:
        yield c


def login(client: TestClient, password: str = OWNER_PASSWORD, username: str = "owner"):
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


@pytest.fixture
def api(env: Env):
    from api_helpers import Api

    return Api(env)
