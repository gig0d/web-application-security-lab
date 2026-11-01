from pathlib import Path
from urllib.parse import quote

import pytest
from playwright.sync_api import expect

from apps.core.seed import DEMO_PASSWORD

pytestmark = [pytest.mark.browser, pytest.mark.training]


def login(live):
    page = live.page
    page.goto(live.base)
    page.get_by_label("Username", exact=True).fill("alice")
    page.get_by_label("Password", exact=True).fill(DEMO_PASSWORD)
    page.get_by_role("button", name="Open workspace").click()
    page.wait_for_url("**/portal")
    expect(page.get_by_role("link", name="#1 Workspace access request")).to_be_visible()
    return live.context.request.get(live.base + "/api/session").json()["csrf"]


def capture(live, lab_id):
    folder = Path("artifacts/browser")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{lab_id}-{live.variant}.png"
    live.page.screenshot(path=str(path), full_page=True)
    return path.as_posix()


def test_stored_xss(live, evidence):
    token = login(live)
    payload = "<script>document.body.dataset.proof='stored'</script>"
    created = live.context.request.post(
        live.base + "/api/tickets/1/comments",
        data={"body": payload},
        headers={"X-CSRF-Token": token},
    )
    assert created.status == 201
    live.page.goto(live.base + "/tickets/1")
    marker = live.page.evaluate("document.body.dataset.proof || null")
    assert marker == (None if live.hard else "stored")
    if live.hard:
        expect(live.page.locator(".comment").last).to_contain_text(payload)
        assert live.page.locator(".comment script").count() == 0
    evidence(
        "lab05",
        live.variant,
        browser="Chromium",
        dom_marker=marker,
        browser_execution_verified=True,
        screenshot=capture(live, "lab05"),
    )


def test_reflected_xss(live, evidence):
    login(live)
    payload = "<script>document.body.dataset.proof='reflected'</script>"
    live.page.goto(live.base + "/search?q=" + quote(payload))
    marker = live.page.evaluate("document.body.dataset.proof || null")
    assert marker == (None if live.hard else "reflected")
    if live.hard:
        expect(live.page.locator("#search-echo")).to_contain_text(payload)
        assert live.page.locator("#search-echo script").count() == 0
    evidence(
        "lab06",
        live.variant,
        browser="Chromium",
        dom_marker=marker,
        browser_execution_verified=True,
        screenshot=capture(live, "lab06"),
    )


def test_cross_origin_form(live, forgery_origin, evidence):
    token = login(live)
    with live.page.expect_response(
        lambda response: response.url == live.base + "/api/profile"
    ) as observed:
        live.page.goto(forgery_origin + "/forge/" + live.variant)
    response = observed.value
    assert response.status == (403 if live.hard else 200)
    state = live.context.request.get(live.base + "/api/session").json()
    assert state["display_name"] == ("Alice Morgan" if live.hard else "Forged Local Name")
    legitimate = live.context.request.post(
        live.base + "/api/profile",
        data={"display_name": "Legitimate Browser Update"},
        headers={"X-CSRF-Token": token},
    )
    assert legitimate.status == 200
    evidence(
        "lab07",
        live.variant,
        browser="Chromium",
        browser_verified=True,
        forged_status=response.status,
        observed_name=state["display_name"],
    )


def test_object_authorization_in_browser(live, evidence):
    login(live)
    response = live.page.goto(live.base + "/tickets/2")
    assert response.status == (404 if live.hard else 200)
    if live.hard:
        assert "Confidential renewal" not in live.page.content()
    else:
        expect(
            live.page.get_by_role("heading", name="Confidential renewal estimate")
        ).to_be_visible()
    live.page.goto(live.base + "/tickets/1")
    expect(live.page.get_by_role("heading", name="Workspace access request")).to_be_visible()
    assert live.page.locator("#assign").count() == 0
    evidence(
        "lab01",
        live.variant,
        browser="Chromium",
        foreign_ui_status=response.status,
        own_ui_visible=True,
        screenshot=capture(live, "lab01"),
    )


def test_dashboard_notebook_and_responsive_layout(browser, servers, tmp_path):
    from apps.core.config import Settings
    from apps.lab_control.main import create_control

    base = servers(create_control(Settings(progress_path=tmp_path / "control.db")), 18082)
    with browser.new_context(viewport={"width": 1440, "height": 1000}) as context:
        page = context.new_page()
        page.goto(base)
        expect(
            page.get_by_role("heading", name="Understand the weakness. Prove the fix.")
        ).to_be_visible()
        assert page.locator(".lab-card").count() == 12
        page.locator("#lab-filter").fill("SQL")
        assert page.locator(".lab-card:visible").count() == 1
        page.locator("#lab-filter").fill("")
        folder = Path("artifacts/browser")
        folder.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(folder / "control-desktop.png"), full_page=True)
        page.goto(base + "/labs/lab01")
        page.get_by_label("Your observations").fill("Actual browser notebook persistence check.")
        page.get_by_label("I have reviewed this lesson").check()
        page.get_by_role("button", name="Save notes").click()
        expect(page.get_by_role("status")).to_contain_text("Notebook saved")
        page.reload()
        expect(page.get_by_label("Your observations")).to_have_value(
            "Actual browser notebook persistence check."
        )
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(base)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(folder / "control-mobile.png"), full_page=True)
