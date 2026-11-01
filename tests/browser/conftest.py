import os
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from playwright.sync_api import sync_playwright

from apps.core.seed import DEMO_PASSWORD


@pytest.fixture(scope="session")
def browser():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(Path(".runtime/browsers").resolve()))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def servers(app_factory):
    owned = []

    def start(app, port):
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            listener.close()
            pytest.fail(
                f"Required local lab port {port} is occupied; no existing process was touched"
            )
        config = uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error", access_log=False
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        deadline = time.monotonic() + 10
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not server.started:
            server.should_exit = True
            thread.join(5)
            listener.close()
            pytest.fail("Local test server did not become ready within 10 seconds")
        owned.append((server, thread, listener, app))
        return f"http://127.0.0.1:{port}"

    yield start
    for server, thread, listener, app in reversed(owned):
        server.should_exit = True
        thread.join(5)
        listener.close()
        if hasattr(app.state, "engine"):
            app.state.engine.dispose()


@pytest.fixture(params=["vulnerable", "hardened"])
def live(request, app_factory, servers, browser):
    hard = request.param == "hardened"
    if request.config.getoption("--compose"):
        env = SimpleNamespace(
            variant=request.param, hard=hard, base=f"http://127.0.0.1:{18081 if hard else 18080}"
        )
        with httpx.Client(base_url=env.base, timeout=5, trust_env=False) as client:
            login = client.post("/api/login", json={"username": "admin", "password": DEMO_PASSWORD})
            assert login.status_code == 200, "Explicit Compose fixture is not ready"
            restored = client.post(
                "/api/admin/reset",
                json={"confirmation": "RESET SYNTHETIC HARBORDESK"},
                headers={"X-CSRF-Token": login.json()["csrf"]},
            )
            assert restored.status_code == 200
        env.transport = "Real Docker Compose, PostgreSQL and loopback HTTP"
    else:
        env = app_factory(request.param)
        env.hard = hard
        env.base = servers(env.app, 18081 if env.hard else 18080)
        env.transport = "Test-owned loopback HTTP and disposable SQLite"
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    context.set_default_timeout(7000)
    env.context = context
    env.page = context.new_page()
    yield env
    context.close()


@pytest.fixture
def forgery_origin(servers):
    app = FastAPI()

    @app.get("/forge/{variant}", response_class=HTMLResponse)
    def forge(variant: str):
        assert variant in {"hardened", "vulnerable"}
        port = 18081 if variant == "hardened" else 18080
        return f"""<!doctype html><html lang="en"><title>Isolated CSRF fixture</title>
        <form action="http://127.0.0.1:{port}/api/profile" method="post">
        <input name="display_name" value="Forged Local Name"></form>
        <script>document.forms[0].submit()</script></html>"""

    return servers(app, 18083)
