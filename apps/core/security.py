import hashlib
import secrets
import time
import unicodedata
from pathlib import PurePath
from threading import Lock

import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import HTTPException, Request
from markupsafe import Markup, escape
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from apps.core.audit import record
from apps.core.models import LoginAttempt, LoginSession, Ticket, User

PASSWORDS = PasswordHasher()
DUMMY_HASH = PASSWORDS.hash(secrets.token_urlsafe(32))
COOKIE = "aegis_session"
SIMULATOR_URLS = {
    "handbook": "http://simulator:8080/public/handbook",
    "metadata": "http://simulator:8080/private/metadata",
}


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def verify_password(encoded: str, password: str) -> bool:
    try:
        return PASSWORDS.verify(encoded, password)
    except VerificationError:
        return False


class SecurePolicy:
    label = "hardened"
    warning = "Hardened comparison environment · synthetic data only"

    def __init__(self) -> None:
        self._rate_lock = Lock()

    def ticket(self, user: User, ticket: Ticket) -> bool:
        return user.role in {"employee", "admin"} or ticket.owner_id == user.id

    def attachment(self, user: User, ticket: Ticket) -> bool:
        return self.ticket(user, ticket)

    def admin(self, user: User) -> bool:
        return user.role == "admin"

    def render(self, value: str) -> Markup:
        return escape(value)

    def search(self, db: Session, user: User, query: str) -> list[dict[str, object]]:
        statement = select(Ticket)
        if user.role == "customer":
            statement = statement.where(Ticket.owner_id == user.id)
        # Escaping wildcard characters keeps search literal as well as parameterized.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        statement = statement.where(Ticket.title.ilike(f"%{escaped}%", escape="\\"))
        return [ticket_dict(t) for t in db.scalars(statement.order_by(Ticket.id).limit(50))]

    def session_valid(self, session: LoginSession, user: User) -> bool:
        return session.expires > time.time() and session.user_version == user.session_version

    def revoke(self, db: Session, session: LoginSession) -> None:
        db.delete(session)

    def csrf(self, request: Request, session: LoginSession) -> None:
        origin = request.headers.get("origin")
        if origin and origin != request.app.state.settings.origin:
            raise HTTPException(403, "Origin rejected")
        token = request.headers.get("x-csrf-token", "")
        if not secrets.compare_digest(token, session.csrf):
            raise HTTPException(403, "CSRF validation failed")

    def login_error(self, exists: bool) -> str:
        return "Invalid username or password"

    def rate_limit(self, request: Request, db: Session, username: str) -> None:
        with self._rate_lock:
            self._rate_limit(request, db, username)

    def _rate_limit(self, request: Request, db: Session, username: str) -> None:
        # One Uvicorn worker in this lab; persisted buckets also survive restarts.
        # Per-account and per-client buckets bound attempts without logging identifiers.
        now = time.time()
        db.execute(delete(LoginAttempt).where(LoginAttempt.at < now - 60))
        client = request.client.host if request.client else "local"
        keys = (digest(f"account:{username.lower()}"), digest(f"client:{client}"))
        for key, maximum in zip(keys, (5, 20), strict=True):
            count = (
                db.scalar(
                    select(func.count())
                    .select_from(LoginAttempt)
                    .where(
                        LoginAttempt.key == key,
                        LoginAttempt.at >= now - 60,
                    )
                )
                or 0
            )
            if count >= maximum:
                record(request, db, "authentication.rate_limit", "deny")
                db.commit()
                raise HTTPException(429, "Too many attempts; wait 60 seconds")
        db.add_all([LoginAttempt(key=k, at=now) for k in keys])
        db.commit()  # Failed logins must retain attempts and evidence.

    def upload(self, filename: str, content: bytes, maximum: int) -> tuple[str, str]:
        name = unicodedata.normalize("NFKC", filename)
        if (
            not name
            or len(name) > 120
            or PurePath(name).name != name
            or any(c in name for c in "/\\:\x00\r\n")
            or name.startswith(".")
            or not name.lower().endswith(".txt")
            or len(content) > maximum
        ):
            raise HTTPException(422, "A safe .txt filename and at most 64 KiB are required")
        try:
            decoded = content.decode("utf-8")
        except UnicodeError as exc:
            raise HTTPException(422, "Only UTF-8 text documents are accepted") from exc
        if any(ord(c) < 32 and c not in "\r\n\t" for c in decoded):
            raise HTTPException(422, "Binary content is not accepted")
        return name, secrets.token_hex(24)

    async def preview(self, selector: str) -> str:
        if selector != "handbook":
            raise HTTPException(403, "Preview destination is not approved")
        return await fetch_simulation(selector)

    def error(self) -> dict[str, str]:
        return {"detail": "An internal error occurred"}

    def headers(self) -> dict[str, str]:
        return {
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
            "frame-ancestors 'none'; object-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        }


async def fetch_simulation(selector: str) -> str:
    # Fixed selectors, fixed host, no redirects/proxies or user-provided URL; even the
    # vulnerable exercise cannot access the host, Internet, or real cloud metadata.
    url = SIMULATOR_URLS.get(selector)
    if url is None:
        raise HTTPException(422, "Unknown internal simulation fixture")
    try:
        async with httpx.AsyncClient(timeout=2, follow_redirects=False, trust_env=False) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > 4096:
                        raise HTTPException(502, "Preview exceeded the fixture size limit")
                return body.decode("utf-8", errors="replace")
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Internal preview simulator unavailable") from exc


def ticket_dict(ticket: Ticket) -> dict[str, object]:
    return {
        "id": ticket.id,
        "owner_id": ticket.owner_id,
        "assignee_id": ticket.assignee_id,
        "title": ticket.title,
        "description": ticket.description,
        "status": ticket.status,
    }
