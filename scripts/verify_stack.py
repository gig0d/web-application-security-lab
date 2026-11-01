"""Exercise actual fixed Compose services and PostgreSQL containment assertions."""

import asyncio
import json
from datetime import UTC, datetime

import httpx

from apps.core.seed import DEMO_PASSWORD
from apps.lab_control.evaluation import check
from scripts.isolation import ROOT, compose, effective_runtime
from scripts.lab import check_config, check_local_docker

SCOPE = {"vulnerable": "http://127.0.0.1:18080", "hardened": "http://127.0.0.1:18081"}


async def verify_control_actions() -> None:
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:18082", timeout=15, trust_env=False
    ) as client:
        await client.get("/")
        token = client.cookies.get("aegis_control_csrf")
        headers = {"X-Aegis-Token": token or ""}
        reset = await client.post(
            "/api/reset-data",
            json={"selection": "isolated-pair", "confirmation": "RESET SYNTHETIC HARBORDESK"},
            headers=headers,
        )
        if reset.status_code != 200 or reset.json().get("outcomes") != {
            "vulnerable": "reset",
            "hardened": "reset",
        }:
            raise RuntimeError(
                f"Actual controller synthetic reset failed: status={reset.status_code}, outcomes={reset.json().get('outcomes')}"
            )
        evaluation = await client.post(
            "/api/evaluate/lab01", json={"selection": "isolated-pair"}, headers=headers
        )
        if evaluation.status_code != 200 or evaluation.json().get("status") != "passed":
            raise RuntimeError("Actual controller paired evaluation failed")


async def verify() -> list[dict[str, object]]:
    results = []
    for lab_id in (f"lab{n:02}" for n in range(1, 13) if n not in {5, 6}):
        for variant, base in SCOPE.items():
            async with httpx.AsyncClient(
                base_url=base, timeout=5, trust_env=False, follow_redirects=False
            ) as client:
                login = await client.post(
                    "/api/login", json={"username": "admin", "password": DEMO_PASSWORD}
                )
                if login.status_code != 200:
                    raise RuntimeError(
                        f"Fixture admin login failed: {lab_id}/{variant}: status={login.status_code}"
                    )
                reset = await client.post(
                    "/api/admin/reset",
                    json={"confirmation": "RESET SYNTHETIC HARBORDESK"},
                    headers={"X-CSRF-Token": login.json()["csrf"]},
                )
                if reset.status_code != 200:
                    raise RuntimeError(
                        f"Synthetic reset failed: {lab_id}/{variant}: status={reset.status_code}, request_id={reset.headers.get('x-request-id', 'unavailable')}"
                    )
                client.cookies.clear()
                result = await check(client, lab_id, variant)
                results.append({"lab_id": lab_id, **result})
                if not result["passed"]:
                    raise RuntimeError(
                        f"Actual Compose comparison failed: {lab_id}/{variant}: {result['observation']}"
                    )
    return results


async def persistence_probe() -> tuple[int, dict[str, object]]:
    async with httpx.AsyncClient(
        base_url=SCOPE["vulnerable"], timeout=5, trust_env=False
    ) as client:
        login = await client.post(
            "/api/login", json={"username": "alice", "password": DEMO_PASSWORD}
        )
        if login.status_code != 200:
            raise RuntimeError("Persistence fixture login failed")
        created = await client.post(
            "/api/tickets",
            json={
                "title": "Compose persistence probe",
                "description": "Harmless synthetic verification row",
            },
            headers={"X-CSRF-Token": login.json()["csrf"]},
        )
        if created.status_code != 201:
            raise RuntimeError("PostgreSQL-backed ticket creation failed")
        ticket_id = int(created.json()["id"])
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        await client.get("http://127.0.0.1:18082/")
        token = client.cookies.get("aegis_control_csrf")
        saved = await client.post(
            "http://127.0.0.1:18082/api/progress/lab12",
            json={"notes": "Synthetic restart persistence probe", "reviewed": False},
            headers={"X-Aegis-Token": token or ""},
        )
        if saved.status_code != 200:
            raise RuntimeError("Control-center persistence fixture could not be saved")
        progress = (await client.get("http://127.0.0.1:18082/api/state")).json()
    return ticket_id, progress


async def after_restart(ticket_id: int, progress: dict[str, object]) -> None:
    for variant, base in SCOPE.items():
        async with httpx.AsyncClient(base_url=base, timeout=5, trust_env=False) as client:
            login = await client.post(
                "/api/login", json={"username": "alice", "password": DEMO_PASSWORD}
            )
            if login.status_code != 200:
                raise RuntimeError("Post-restart login failed")
            response = await client.get(f"/api/tickets/{ticket_id}")
            if response.status_code != (200 if variant == "vulnerable" else 404):
                raise RuntimeError("Independent database state or restart persistence failed")
    async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
        observed = (await client.get("http://127.0.0.1:18082/api/state")).json()
    if observed != progress:
        raise RuntimeError("Independent control-center progress did not survive restart")


def main() -> None:
    check_local_docker()
    check_config()
    errors = effective_runtime()
    if errors:
        raise SystemExit("; ".join(errors))
    asyncio.run(verify_control_actions())
    results = asyncio.run(verify())
    ticket_id, progress = asyncio.run(persistence_probe())
    compose(["restart", "vulnerable", "hardened", "control"])
    compose(["up", "-d", "--wait", "--wait-timeout", "180"])
    asyncio.run(after_restart(ticket_id, progress))
    # Execute only fixed assertions inside the vulnerable container; no user code/arguments.
    code = """
from sqlalchemy import text
from sqlalchemy.orm import Session
from apps.core.config import Settings
from apps.core.database import make_engine
from apps.core.models import User
from apps.vulnerable.policy import TrainingPolicy
engine = make_engine(Settings().database_url)
with Session(engine) as db:
    assert db.scalar(text('SELECT current_user')) == 'aegis_app'
    assert not db.scalar(text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')"))
    assert not db.scalar(text("SELECT rolsuper OR rolcreatedb OR rolcreaterole FROM pg_roles WHERE rolname=current_user"))
    user = db.get(User, 1)
    db.rollback()
    user_id = 1
with Session(engine) as db:
    user = User(id=user_id, role='customer')
    rows = TrainingPolicy().search(db, user, "' OR 1=1 -- ")
    assert any(row['id'] == 2 for row in rows)
    assert db.scalar(text('SHOW transaction_read_only')) == 'on'
    try:
        db.execute(text('UPDATE tickets SET status=status WHERE id=1'))
    except Exception as exc:
        assert getattr(getattr(exc, 'orig', None), 'sqlstate', '') == '25006'
        db.rollback()
    else:
        db.rollback()
        raise AssertionError('Training search transaction accepted a write')
engine.dispose()
print('Restricted PostgreSQL role and actual read-only training transaction verified')
"""
    compose(["exec", "-T", "vulnerable", "python", "-c", code])
    output = ROOT / "artifacts/compose"
    output.mkdir(parents=True, exist_ok=True)
    (output / "verification.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": datetime.now(UTC).isoformat(),
                "transport": "Actual local Docker Compose with independent PostgreSQL and internal simulator",
                "checks": results,
                "restricted_role_and_read_only_transaction": True,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"Verified {len(results)} real Compose comparisons and restricted PostgreSQL transaction")


if __name__ == "__main__":
    main()
