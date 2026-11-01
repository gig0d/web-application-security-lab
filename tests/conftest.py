import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from apps.core.application import create_app
from apps.core.config import Settings
from apps.core.models import Base
from apps.core.security import SecurePolicy
from apps.core.seed import DEMO_PASSWORD, seed
from apps.vulnerable.policy import TrainingPolicy

EVIDENCE = []


@pytest.fixture(scope="session")
def seeded_database(tmp_path_factory):
    root = tmp_path_factory.mktemp("fixture")
    url = "sqlite:///" + str(root / "baseline.db")
    engine = create_engine(url)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        seed(db)
    engine.dispose()
    return root / "baseline.db"


@pytest.fixture
def app_factory(tmp_path, seeded_database):
    import shutil

    apps = []

    def build(variant="hardened"):
        path = tmp_path / f"{variant}-{len(apps)}.db"
        shutil.copyfile(seeded_database, path)
        app = create_app(
            TrainingPolicy() if variant == "vulnerable" else SecurePolicy(),
            Settings(
                database_url="sqlite:///" + str(path),
                origin=f"http://127.0.0.1:{18080 if variant == 'vulnerable' else 18081}",
            ),
        )
        client = TestClient(app, raise_server_exceptions=False)
        apps.append((app, client))
        return SimpleNamespace(app=app, client=client, variant=variant)

    yield build
    for app, client in apps:
        client.close()
        app.state.engine.dispose()


def authenticate(env, username="alice"):
    response = env.client.post("/api/login", json={"username": username, "password": DEMO_PASSWORD})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf"]}


@pytest.fixture
def secured(app_factory):
    env = app_factory()
    env.headers = authenticate(env)
    return env


@pytest.fixture
def evidence(request):
    observations = []

    def observe(lab_id, variant, **values):
        observations.append({"lab_id": lab_id, "variant": variant, "observations": values})

    yield observe
    EVIDENCE.extend(
        {
            **o,
            "test": request.node.nodeid,
            "test_passed": bool(getattr(request.node, "call_passed", False)),
        }
        for o in observations
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.when == "call":
        item.call_passed = report.passed


def pytest_sessionfinish(session, exitstatus):
    from datetime import UTC, datetime

    output = Path("artifacts/tests")
    output.mkdir(parents=True, exist_ok=True)
    (output / "evidence.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": datetime.now(UTC).isoformat(),
                "exit_status": int(exitstatus),
                "database": "SQLite unless an observation explicitly says PostgreSQL",
                "observations": EVIDENCE,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


@pytest.fixture
def postgres_app(tmp_path, monkeypatch):
    url = os.environ.get("AEGIS_TEST_DATABASE_URL")
    if not url:
        pytest.skip("AEGIS_TEST_DATABASE_URL is required for PostgreSQL evidence")
    from sqlalchemy.engine import make_url

    parsed = make_url(url)
    if (
        parsed.host not in {"127.0.0.1", "localhost"}
        or parsed.database != "aegis_test"
        or parsed.drivername != "postgresql+psycopg"
    ):
        pytest.fail("Only loopback PostgreSQL database aegis_test is authorized")
    monkeypatch.setenv("AEGIS_DATABASE_URL", url)
    command.upgrade(Config("alembic.ini"), "head")
    app = create_app(SecurePolicy(), Settings(database_url=url))
    with app.state.sessions() as db:
        seed(db)
    with TestClient(app) as client:
        yield SimpleNamespace(app=app, client=client, variant="hardened")
    # No DROP DATABASE or broad schema cleanup: transaction tests restore their data.
    app.state.engine.dispose()
