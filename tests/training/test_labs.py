"""Explicit expected-vulnerability suite. Never included by default discovery."""

import pytest

from tests.conftest import authenticate

pytestmark = pytest.mark.training


@pytest.fixture(params=["vulnerable", "hardened"])
def env(request, app_factory):
    instance = app_factory(request.param)
    instance.headers = authenticate(instance)
    instance.hard = request.param == "hardened"
    return instance


def test_lab01_objects(env, evidence):
    api = env.client.get("/api/tickets/2")
    ui = env.client.get("/tickets/2")
    update = env.client.patch("/api/tickets/2", headers=env.headers, json={"status": "closed"})
    own = env.client.get("/api/tickets/1")
    expected = 404 if env.hard else 200
    assert api.status_code == ui.status_code == update.status_code == expected
    assert own.status_code == 200
    evidence(
        "lab01",
        env.variant,
        foreign_api=api.status_code,
        foreign_ui=ui.status_code,
        foreign_update=update.status_code,
        own=own.status_code,
    )


def test_lab02_files(env, evidence):
    response = env.client.get("/api/attachments/2")
    assert response.status_code == (404 if env.hard else 200)
    if not env.hard:
        assert b"Bob's synthetic" in response.content
    assert env.client.get("/api/attachments/1").status_code == 200
    evidence("lab02", env.variant, foreign_download=response.status_code)


def test_lab03_roles(env, evidence):
    page = env.client.get("/tickets/1")
    assert 'id="assign"' not in page.text
    response = env.client.post(
        "/api/admin/tickets/1/assign", headers=env.headers, json={"assignee_id": 4}
    )
    assert response.status_code == (403 if env.hard else 200)
    assigned = env.client.get("/api/tickets/1").json()["assignee_id"]
    assert assigned == (3 if env.hard else 4)
    admin = authenticate(env, "admin")
    assert (
        env.client.post(
            "/api/admin/tickets/1/assign", headers=admin, json={"assignee_id": 3}
        ).status_code
        == 200
    )
    evidence(
        "lab03",
        env.variant,
        customer_assignment=response.status_code,
        assignee_after=assigned,
        hidden_form=True,
        legitimate_admin=200,
    )


def test_lab04_sql(env, evidence):
    response = env.client.get("/api/tickets", params={"q": "' OR 1=1 -- "})
    assert response.status_code == 200, response.text
    ids = [t["id"] for t in response.json()]
    if env.hard:
        assert ids == []
    else:
        assert 2 in ids
    assert env.client.get("/api/tickets", params={"q": "Workspace"}).json()[0]["id"] == 1
    evidence("lab04", env.variant, returned_ticket_ids=ids, database="SQLite")


def test_lab05_stored_rendering(env, evidence):
    payload = "<script>document.body.dataset.proof='stored'</script>"
    assert (
        env.client.post(
            "/api/tickets/1/comments", headers=env.headers, json={"body": payload}
        ).status_code
        == 201
    )
    response = env.client.get("/tickets/1")
    if env.hard:
        assert payload not in response.text and "&lt;script&gt;" in response.text
    else:
        assert payload in response.text
    evidence(
        "lab05",
        env.variant,
        raw_script_in_html=payload in response.text,
        browser_execution_verified=False,
    )


def test_lab06_reflected_rendering(env, evidence):
    payload = "<script>document.body.dataset.proof='reflected'</script>"
    response = env.client.get("/search", params={"q": payload})
    assert (payload in response.text) is not env.hard
    if env.hard:
        assert "&lt;script&gt;" in response.text
    evidence(
        "lab06",
        env.variant,
        raw_script_in_html=payload in response.text,
        browser_execution_verified=False,
    )


def test_lab07_csrf(env, evidence):
    response = env.client.post(
        "/api/profile",
        data={"display_name": "Forged Local Name"},
        headers={"Origin": "http://127.0.0.1:18082"},
    )
    assert response.status_code == (403 if env.hard else 200)
    value = env.client.get("/api/session").json()["display_name"]
    assert value == ("Alice Morgan" if env.hard else "Forged Local Name")
    assert (
        env.client.post(
            "/api/profile", headers=env.headers, json={"display_name": "Legitimate"}
        ).status_code
        == 200
    )
    evidence(
        "lab07",
        env.variant,
        forged_status=response.status_code,
        observed_name=value,
        browser_verified=False,
    )


def test_lab08_authentication(env, evidence):
    known = env.client.post("/api/login", json={"username": "alice", "password": "wrong"})
    unknown = env.client.post("/api/login", json={"username": "absent", "password": "wrong"})
    assert known.status_code == unknown.status_code == 401
    equal = known.json() == unknown.json()
    assert equal is env.hard
    statuses = [
        env.client.post("/api/login", json={"username": "absent", "password": "wrong"}).status_code
        for _ in range(5)
    ]
    assert statuses[-1] == (429 if env.hard else 401)
    evidence("lab08", env.variant, identical_errors=equal, bounded_statuses=statuses)


def test_lab09_sessions(env, evidence):
    cookie = env.client.cookies.get(f"aegis_{env.variant}")
    assert env.client.post("/api/logout", headers=env.headers).status_code == 200
    env.client.cookies.set(f"aegis_{env.variant}", cookie)
    response = env.client.get("/api/session")
    assert response.status_code == (401 if env.hard else 200)
    evidence("lab09", env.variant, stale_cookie_status=response.status_code)


def test_lab10_uploads(env, evidence):
    response = env.client.post(
        "/api/tickets/1/attachments",
        headers=env.headers,
        files={"file": ("../notes.csv", b"Harmless text", "text/plain")},
    )
    assert response.status_code == (422 if env.hard else 201)
    if not env.hard:
        assert response.json()["filename"] == "../notes.csv"
        download = env.client.get(f"/api/attachments/{response.json()['id']}")
        assert download.headers["content-type"].startswith("text/plain")
    valid = env.client.post(
        "/api/tickets/1/attachments",
        headers=env.headers,
        files={"file": ("notes.txt", b"Harmless text", "text/plain")},
    )
    assert valid.status_code == 201
    evidence(
        "lab10",
        env.variant,
        unsafe_filename_status=response.status_code,
        valid_upload=valid.status_code,
    )


def test_lab11_preview(env, evidence, monkeypatch):
    import httpx

    from apps.core import security

    real_client = httpx.AsyncClient
    destinations = []

    def simulated(request):
        destinations.append(str(request.url))
        return httpx.Response(
            200,
            text="SYNTHETIC-METADATA"
            if request.url.path.startswith("/private")
            else "Fictional handbook",
        )

    monkeypatch.setattr(
        security.httpx,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(simulated), **kw),
    )
    private = env.client.get("/api/preview", params={"source": "metadata"})
    public = env.client.get("/api/preview", params={"source": "handbook"})
    assert private.status_code == (403 if env.hard else 200)
    assert public.status_code == 200
    assert env.client.get(
        "/api/preview", params={"source": "http://169.254.169.254"}
    ).status_code == (403 if env.hard else 422)
    assert all(url.startswith("http://simulator:8080/") for url in destinations)
    evidence(
        "lab11",
        env.variant,
        private_status=private.status_code,
        destinations=destinations,
        transport="controlled fixture; not real Docker networking",
    )


def test_lab12_configuration(env, evidence):
    response = env.client.get("/api/diagnostics/error")
    assert response.status_code == 500
    csp = "content-security-policy" in response.headers
    assert csp is env.hard
    assert ("SYNTHETIC-NOT-A-SECRET" in response.text) is not env.hard
    if env.hard:
        assert response.json() == {"detail": "An internal error occurred"}
        assert "access-control-allow-origin" not in response.headers
    evidence(
        "lab12",
        env.variant,
        error_status=response.status_code,
        csp_present=csp,
        synthetic_debug_exposed="SYNTHETIC-NOT-A-SECRET" in response.text,
    )
