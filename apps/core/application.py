import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from apps.core.audit import logger, record
from apps.core.config import Settings
from apps.core.database import make_engine
from apps.core.routes import router
from apps.core.security import SecurePolicy


class BodyLimit:
    """Bound every request, including chunked uploads, before multipart parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 150000:
                await JSONResponse({"detail": "Request exceeds safety ceiling"}, 413)(
                    scope,
                    receive,
                    send,
                )
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def bounded_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)


def create_app(policy: SecurePolicy, settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(title=f"HarborDesk ({policy.label})", docs_url=None, redoc_url=None)
    app.state.policy = policy
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.sessions = sessionmaker(app.state.engine, expire_on_commit=False)
    root = Path(__file__).parent
    app.state.templates = Jinja2Templates(directory=str(root / "templates"))
    app.mount("/static", StaticFiles(directory=root / "static"), name="static")
    app.add_middleware(BodyLimit)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[
            "127.0.0.1",
            "localhost",
            "testserver",
            "hardened",
            "vulnerable",
        ],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Any:
        request.state.request_id = secrets.token_hex(16)
        response = await call_next(request)
        if response.status_code in {400, 403, 404, 405, 413, 415, 422}:
            try:
                with app.state.sessions() as db:
                    record(
                        request, db, "http.rejected", "deny", resource=f"method:{request.method}"
                    )
                    db.commit()
            except SQLAlchemyError:
                logger.error(
                    '{"schema_version":1,"event":"audit.persistence_failed","outcome":"error"}'
                )
        response.headers.update(policy.headers())
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Pydantic error inputs may contain a password or payload: never return them.
        with app.state.sessions() as db:
            record(request, db, "input.validation", "deny")
            db.commit()
        return JSONResponse({"detail": "Request validation failed"}, status_code=422)

    @app.exception_handler(Exception)
    async def failure(request: Request, exc: Exception) -> JSONResponse:
        response = JSONResponse({"detail": "An internal error occurred"}, status_code=500)
        response.headers.update(policy.headers())
        response.headers["X-Request-ID"] = getattr(request.state, "request_id", "unknown")
        return response

    app.include_router(router)
    return app
