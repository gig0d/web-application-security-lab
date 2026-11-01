import asyncio
import secrets
from pathlib import Path
from typing import Any, cast

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from apps.core.application import BodyLimit
from apps.core.config import Settings
from apps.core.security import SecurePolicy
from apps.core.seed import DEMO_PASSWORD
from apps.lab_control.catalog import BY_ID, LABS
from apps.lab_control.evaluation import TARGETS, evaluate
from apps.lab_control.reporting import findings, markdown
from apps.lab_control.store import ProgressStore


class ProgressInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    notes: str = Field(default="", max_length=10000)
    reviewed: bool = False


class ScopeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selection: str = Field(pattern="^isolated-pair$")


class ResetInput(ScopeInput):
    confirmation: str = Field(pattern="^RESET SYNTHETIC HARBORDESK$")


def create_control(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title="Aegis Control Center", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = ProgressStore(settings.progress_path)
    app.state.execution = asyncio.Lock()
    templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
    app.mount(
        "/static", StaticFiles(directory=Path(__file__).parents[1] / "core/static"), name="static"
    )
    app.add_middleware(BodyLimit)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver", "control"]
    )

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers.update(SecurePolicy().headers())
        return response

    def mutation(request: Request) -> None:
        token = request.headers.get("x-aegis-token", "")
        cookie = request.cookies.get("aegis_control_csrf", "")
        if not token or not cookie or not secrets.compare_digest(token, cookie):
            raise HTTPException(403, "Control-center CSRF validation failed")
        if request.headers.get("origin", "http://127.0.0.1:18082") != "http://127.0.0.1:18082":
            raise HTTPException(403, "Origin rejected")

    def known(lab_id: str) -> None:
        if lab_id not in BY_ID:
            raise HTTPException(404, "Laboratory not found")

    def render(request: Request, name: str, **context: Any) -> HTMLResponse:
        token = secrets.token_urlsafe(32)
        response = templates.TemplateResponse(
            request=request, name=name, context={"csrf": token, **context}
        )
        response.set_cookie("aegis_control_csrf", token, httponly=True, samesite="strict")
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        app.state.store.state()
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request) -> HTMLResponse:
        return render(request, "index.html", labs=LABS, state=app.state.store.state())

    @app.get("/labs/{lab_id}", response_class=HTMLResponse)
    def detail(lab_id: str, request: Request) -> HTMLResponse:
        known(lab_id)
        return render(request, "lab.html", lab=BY_ID[lab_id], state=app.state.store.state())

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        return cast(dict[str, Any], app.state.store.state())

    @app.post("/api/progress/{lab_id}", dependencies=[Depends(mutation)])
    def save(lab_id: str, body: ProgressInput) -> dict[str, bool]:
        known(lab_id)
        app.state.store.save(lab_id, body.notes, body.reviewed)
        return {"saved": True}

    @app.delete("/api/progress/{lab_id}", dependencies=[Depends(mutation)])
    def reset_progress(lab_id: str) -> dict[str, bool]:
        known(lab_id)
        app.state.store.reset(lab_id)
        return {"reset": True}

    @app.post("/api/evaluate/{lab_id}", dependencies=[Depends(mutation)])
    async def run(lab_id: str, body: ScopeInput) -> dict[str, Any]:
        known(lab_id)
        if app.state.execution.locked():
            raise HTTPException(429, "A bounded lab execution is already running")
        async with app.state.execution:
            try:
                result = await asyncio.wait_for(evaluate(lab_id, body.selection), timeout=45)
            except TimeoutError:
                result = {
                    "status": "timeout",
                    "vulnerable_demonstrated": False,
                    "hardened_verified": False,
                    "checks": [],
                    "limitations": ["Execution exceeded 45 seconds; no success is claimed."],
                }
            app.state.store.result(lab_id, result)
            return result

    @app.post("/api/reset-data", dependencies=[Depends(mutation)])
    async def reset_data(body: ResetInput) -> dict[str, Any]:
        if app.state.execution.locked():
            raise HTTPException(429, "Wait for the current execution")
        outcomes = {}
        async with app.state.execution:
            for variant, base in TARGETS.items():
                try:
                    async with httpx.AsyncClient(
                        base_url=base, timeout=10, trust_env=False, follow_redirects=False
                    ) as client:
                        login = await client.post(
                            "/api/login", json={"username": "admin", "password": DEMO_PASSWORD}
                        )
                        if login.status_code != 200:
                            outcomes[variant] = "fixture-login-failed"
                            continue
                        response = await client.post(
                            "/api/admin/reset",
                            json={"confirmation": body.confirmation},
                            headers={"X-CSRF-Token": login.json()["csrf"]},
                        )
                        outcomes[variant] = "reset" if response.status_code == 200 else "failed"
                except httpx.HTTPError:
                    outcomes[variant] = "unavailable"
        return {"outcomes": outcomes, "progress_preserved": True}

    @app.get("/exports/findings.json")
    def export_json() -> JSONResponse:
        return JSONResponse(
            findings(app.state.store.state()),
            headers={"Content-Disposition": 'attachment; filename="aegis-findings.json"'},
        )

    @app.get("/exports/report.md")
    def export_markdown() -> Response:
        return Response(
            markdown(findings(app.state.store.state())),
            media_type="text/markdown",
            headers={"Content-Disposition": 'attachment; filename="aegis-assessment.md"'},
        )

    return app


app = create_control()
