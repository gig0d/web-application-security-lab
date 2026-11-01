import os
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from playwright.sync_api import sync_playwright


@pytest.fixture(scope="session")
def browser():
    os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(Path(".runtime/browsers").resolve()))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def servers():
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
        owned.append((server, thread, listener))
        return f"http://127.0.0.1:{port}"

    yield start
    for server, thread, listener in reversed(owned):
        server.should_exit = True
        thread.join(5)
        listener.close()


@pytest.fixture(params=["vulnerable", "hardened"])
def live(request, app_factory, servers, browser):
    env = app_factory(request.param)
    env.hard = request.param == "hardened"
    env.base = servers(env.app, 18081 if env.hard else 18080)
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

    return servers(app, 18082)
