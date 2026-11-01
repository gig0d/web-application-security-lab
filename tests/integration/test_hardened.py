import time

import pytest
from sqlalchemy import select

from apps.core.models import LoginSession, Ticket, User
from apps.core.security import digest
from apps.core.seed import DEMO_PASSWORD, seed
from tests.conftest import authenticate


def test_legitimate_workflow(secured):
    client, headers = secured.client, secured.headers
    created = client.post(
        "/api/tickets",
        headers=headers,
        json={"title": "Fictional request", "description": "Synthetic support request"},
    )
    assert created.status_code == 201
    ticket_id = created.json()["id"]
    assert client.get(f"/tickets/{ticket_id}").status_code == 200
    assert (
        client.post(
            f"/api/tickets/{ticket_id}/comments", headers=headers, json={"body": "Harmless update"}
        ).status_code
        == 201
    )
    assert (
        client.patch(
            f"/api/tickets/{ticket_id}", headers=headers, json={"status": "closed"}
        ).json()["status"]
        == "closed"
    )
    upload = client.post(
        f"/api/tickets/{ticket_id}/attachments",
        headers=headers,
        files={"file": ("notes.txt", b"Synthetic notes", "text/plain")},
    )
    assert upload.status_code == 201
    downloaded = client.get(f"/api/attachments/{upload.json()['id']}")
    assert downloaded.content == b"Synthetic notes"
    assert downloaded.headers["content-disposition"].startswith("attachment;")
    assert client.get("/portal").status_code == 200


def test_concurrent_users_keep_ticket_and_private_note_boundaries(app_factory):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from fastapi.testclient import TestClient

    env = app_factory()
    barrier = Barrier(3)
    with TestClient(env.app) as alice, TestClient(env.app) as bob, TestClient(env.app) as staff:

        def login(client, username):
            response = client.post(
                "/api/login", json={"username": username, "password": DEMO_PASSWORD}
            )
            assert response.status_code == 200
            return {"X-CSRF-Token": response.json()["csrf"]}

        alice_token, bob_token, staff_token = (
            login(alice, "alice"),
            login(bob, "bob"),
            login(staff, "sam"),
        )

        def perform(client, method, body, headers):
            barrier.wait(timeout=5)
            return client.request(
                method,
                "/api/tickets/1" if method == "PATCH" else "/api/tickets/1/comments",
                json=body,
                headers=headers,
            ).status_code

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [
                pool.submit(perform, alice, "PATCH", {"status": "closed"}, alice_token),
                pool.submit(
                    perform, bob, "POST", {"body": "Unauthorized concurrent write"}, bob_token
                ),
                pool.submit(
                    perform,
                    staff,
                    "POST",
                    {"body": "Private concurrent note", "private": True},
                    staff_token,
                ),
            ]
            assert [future.result(timeout=10) for future in futures] == [200, 404, 201]
        assert alice.get("/api/tickets/1").json()["status"] == "closed"
        assert "Private concurrent note" not in alice.get("/api/tickets/1/comments").text
        assert "Private concurrent note" in staff.get("/api/tickets/1/comments").text
        assert bob.get("/api/tickets/1").status_code == 404


@pytest.mark.parametrize(
    "path,method,body",
    [
        ("/api/tickets/2", "get", None),
        ("/tickets/2", "get", None),
        ("/api/tickets/2/comments", "get", None),
        ("/api/tickets/2/attachments", "get", None),
        ("/api/tickets/2/comments", "post", {"body": "forbidden"}),
        ("/api/tickets/2", "patch", {"status": "closed"}),
    ],
)
def test_every_object_route_checks_ownership(secured, path, method, body):
    response = secured.client.request(method, path, headers=secured.headers, json=body)
    assert response.status_code == 404
    assert "renewal" not in response.text.lower()


def test_download_checks_parent(secured):
    assert secured.client.get("/api/attachments/2").status_code == 404
    assert secured.client.get("/api/attachments/1").status_code == 200


def test_no_private_notes_to_customers(app_factory):
    env = app_factory()
    env.headers = authenticate(env, "bob")
    assert env.client.get("/api/tickets/2/comments").json() == []
    assert "approval pending" not in env.client.get("/tickets/2").text
    assert (
        env.client.post(
            "/api/tickets/2/comments", headers=env.headers, json={"body": "hidden", "private": True}
        ).status_code
        == 403
    )
    staff = app_factory()
    headers = authenticate(staff, "sam")
    assert staff.client.get("/api/tickets/2/comments").json()[0]["private"] is True
    assert (
        staff.client.post(
            "/api/tickets/2/comments", headers=headers, json={"body": "Staff note", "private": True}
        ).status_code
        == 201
    )


def test_admin_assignment_and_role_invalidation(app_factory):
    env = app_factory()
    admin = env.client
    admin_headers = authenticate(env, "admin")
    assert (
        admin.post(
            "/api/admin/tickets/1/assign", headers=admin_headers, json={"assignee_id": 3}
        ).status_code
        == 200
    )
    assert (
        admin.post(
            "/api/admin/tickets/1/assign", headers=admin_headers, json={"assignee_id": 2}
        ).status_code
        == 422
    )
    from fastapi.testclient import TestClient

    with TestClient(env.app) as employee:
        assert (
            employee.post(
                "/api/login", json={"username": "sam", "password": DEMO_PASSWORD}
            ).status_code
            == 200
        )
        assert (
            admin.post(
                "/api/admin/users/3/role", headers=admin_headers, json={"role": "customer"}
            ).status_code
            == 200
        )
        assert employee.get("/api/session").status_code == 401


def test_csrf_and_origin(secured):
    body = {"display_name": "Changed"}
    assert secured.client.post("/api/profile", json=body).status_code == 403
    assert (
        secured.client.post(
            "/api/profile", json=body, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert (
        secured.client.post(
            "/api/profile",
            json=body,
            headers={**secured.headers, "Origin": "http://127.0.0.1:18082"},
        ).status_code
        == 403
    )
    assert secured.client.post("/api/profile", json=body, headers=secured.headers).json() == body


def test_expiration_rotation_logout_and_storage(app_factory):
    env = app_factory()
    headers = authenticate(env)
    old = env.client.cookies.get("aegis_hardened")
    with env.app.state.sessions() as db:
        assert db.get(LoginSession, digest(old)) is not None
        assert db.get(LoginSession, old) is None
    authenticate(env)
    new = env.client.cookies.get("aegis_hardened")
    assert old != new
    env.client.cookies.clear()
    env.client.cookies.set("aegis_hardened", old)
    assert env.client.get("/api/session").status_code == 401
    env.client.cookies.set("aegis_hardened", new)
    with env.app.state.sessions() as db:
        db.get(LoginSession, digest(new)).expires = time.time() - 1
        db.commit()
    assert env.client.get("/api/session").status_code == 401
    env.client.cookies.clear()
    headers = authenticate(env)
    token = env.client.cookies.get("aegis_hardened")
    assert env.client.post("/api/logout", headers=headers).status_code == 200
    env.client.cookies.set("aegis_hardened", token)
    assert env.client.get("/api/session").status_code == 401


@pytest.mark.parametrize("value", ["", "invalid", "a" * 500, "x.y.z"])
def test_invalid_sessions(app_factory, value):
    env = app_factory()
    env.client.cookies.set("aegis_hardened", value)
    assert env.client.get("/api/session").status_code == 401


def test_cookie_flags(app_factory):
    env = app_factory()
    response = env.client.post("/api/login", json={"username": "alice", "password": DEMO_PASSWORD})
    header = response.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=lax" in header and "max-age=1800" in header
    # Secure is deliberately absent for loopback HTTP; test the supported TLS option too.
    env.app.state.settings.secure_cookie = True
    response = env.client.post("/api/login", json={"username": "bob", "password": DEMO_PASSWORD})
    assert "secure" in response.headers["set-cookie"].lower()


def test_authentication_errors_and_rate_limit(app_factory):
    env = app_factory()
    known = env.client.post("/api/login", json={"username": "alice", "password": "wrong"})
    unknown = env.client.post("/api/login", json={"username": "absent", "password": "wrong"})
    assert known.status_code == unknown.status_code == 401 and known.json() == unknown.json()
    statuses = [
        env.client.post("/api/login", json={"username": "absent", "password": "wrong"}).status_code
        for _ in range(5)
    ]
    assert statuses[-1] == 429


def test_headers_and_safe_real_exception(secured):
    @secured.app.get("/test-exception")
    def failure():
        raise RuntimeError("NEVER-EXPOSE-THIS")

    response = secured.client.get("/test-exception")
    assert response.status_code == 500
    assert "NEVER-EXPOSE-THIS" not in response.text
    assert "content-security-policy" in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers
    assert (
        secured.client.options(
            "/api/profile", headers={"Origin": "http://127.0.0.1:18082"}
        ).status_code
        == 405
    )


@pytest.mark.parametrize(
    "filename,content",
    [
        ("../notes.txt", b"safe"),
        ("..\\notes.txt", b"safe"),
        ("notes.csv", b"safe"),
        ("notes.txt", b"\xff"),
        ("notes.txt", b"\x00"),
        ("notes.txt", b"a" * 65537),
        ("C:notes.txt", b"safe"),
        (".hidden.txt", b"safe"),
    ],
)
def test_unsafe_uploads_rejected(secured, filename, content):
    response = secured.client.post(
        "/api/tickets/1/attachments",
        headers=secured.headers,
        files={"file": (filename, content, "text/plain")},
    )
    assert response.status_code == 422


def test_body_limit_and_validation_redaction(secured):
    response = secured.client.post("/api/profile", headers=secured.headers, content=b"a" * 150001)
    assert response.status_code == 413
    response = secured.client.post(
        "/api/login", json={"username": "alice", "password": "SENSITIVE-FIXTURE", "extra": 1}
    )
    assert response.status_code == 422 and "SENSITIVE-FIXTURE" not in response.text
    assert (
        secured.client.post("/api/profile", headers=secured.headers, content="name=abc").status_code
        == 415
    )
    assert secured.client.delete("/api/tickets/1", headers=secured.headers).status_code == 405


def test_sql_input_remains_literal(secured):
    assert secured.client.get("/api/tickets", params={"q": "' OR 1=1 -- "}).json() == []
    assert secured.client.get("/api/tickets", params={"q": "%"}).json() == []
    normal = secured.client.get("/api/tickets", params={"q": "Workspace"}).json()
    assert len(normal) == 1 and normal[0]["owner_id"] == 1


def test_audit_redaction_and_denials(secured):
    secured.client.get("/api/tickets/2")
    secured.client.post("/api/profile", json={"display_name": "private-body"})
    assert secured.client.get("/api/admin/audit").status_code == 403
    authenticate(secured, "admin")
    response = secured.client.get("/api/admin/audit")
    assert response.status_code == 200
    text = response.text
    assert "authorization.ticket" in text and "csrf.validation" in text
    assert "private-body" not in text and DEMO_PASSWORD not in text and "token_hash" not in text


def test_reset_idempotent_and_sessions_invalidated(app_factory):
    env = app_factory()
    for _ in range(2):
        headers = authenticate(env, "admin")
        assert (
            env.client.post(
                "/api/admin/reset",
                headers=headers,
                json={"confirmation": "RESET SYNTHETIC HARBORDESK"},
            ).status_code
            == 200
        )
        assert env.client.get("/api/session").status_code == 401
        authenticate(env)
        assert env.client.get("/api/tickets/1").status_code == 200
    with env.app.state.sessions() as db:
        seed(db)
        assert len(list(db.scalars(select(User)))) == 4


@pytest.mark.postgres
def test_postgres_migration_and_transaction_rollback(postgres_app):
    authenticate(postgres_app)
    assert postgres_app.client.get("/api/tickets/1").status_code == 200
    with postgres_app.app.state.sessions() as db:
        ticket = db.get(Ticket, 1)
        original = ticket.title
        ticket.title = "Rolled back fixture"
        db.flush()
        db.rollback()
        assert db.get(Ticket, 1).title == original
    assert postgres_app.client.get("/api/tickets", params={"q": "' OR 1=1 -- "}).json() == []
