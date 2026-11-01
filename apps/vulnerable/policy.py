"""Intentional, bounded weaknesses. Never copy this package to the hardened image."""

from fastapi import HTTPException, Request
from markupsafe import Markup
from sqlalchemy import text
from sqlalchemy.orm import Session

from apps.core.models import LoginSession, Ticket, User
from apps.core.security import SecurePolicy, fetch_simulation


class TrainingPolicy(SecurePolicy):
    label = "vulnerable"
    warning = "INTENTIONALLY VULNERABLE · isolated local training only · synthetic data"

    def ticket(self, user: User, ticket: Ticket) -> bool:
        return True  # LAB01: no object ownership check.

    def attachment(self, user: User, ticket: Ticket) -> bool:
        return True  # LAB02: authentication alone does not authorize a document.

    def admin(self, user: User) -> bool:
        return True  # LAB03: UI visibility is the only supposed control.

    def render(self, value: str) -> Markup:
        return Markup(value)  # noqa: S704 - LAB05/06 intentional output-escaping bypass

    def search(self, db: Session, user: User, query: str) -> list[dict[str, object]]:
        # LAB04: only SELECT, single statement, bounded result, disposable data.
        # PostgreSQL read-only transaction prevents writes even through SQL injection.
        if db.bind is not None and db.bind.dialect.name == "postgresql":
            db.execute(text("SET TRANSACTION READ ONLY"))
        sql = (
            "SELECT id, owner_id, assignee_id, title, description, status FROM tickets "
            f"WHERE owner_id = {int(user.id)} AND title LIKE '%{query}%' LIMIT 50"
        )
        return [dict(row) for row in db.execute(text(sql)).mappings()]

    def csrf(self, request: Request, session: LoginSession) -> None:
        pass  # LAB07: cross-origin state change accepted without token.

    def login_error(self, exists: bool) -> str:
        return "Incorrect password" if exists else "Unknown username"  # LAB08

    def rate_limit(self, request: Request, db: Session, username: str) -> None:
        pass  # LAB08: intentionally no throttle; automated fixtures remain bounded.

    def revoke(self, db: Session, session: LoginSession) -> None:
        pass  # LAB09: deleting only the browser cookie leaves the server token valid.

    def upload(self, filename: str, content: bytes, maximum: int) -> tuple[str, str]:
        if len(content) > 131072:
            raise HTTPException(413, "Training safety ceiling exceeded")
        # LAB10: unsafe name is retained as metadata, never used as a filesystem path.
        # All downloads remain text/plain attachments; no executable uploads.
        import secrets

        return filename[:160], secrets.token_hex(24)

    async def preview(self, selector: str) -> str:
        return await fetch_simulation(selector)  # LAB11: private fixture also reachable.

    def error(self) -> dict[str, str]:
        return {
            "detail": "Synthetic PreviewError at /srv/harbordesk/preview.py:42",
            "debug": "training_database=harbordesk; fixture_key=SYNTHETIC-NOT-A-SECRET",
        }  # LAB12: fixed harmless debug exposure, never real exception/environment data.

    def headers(self) -> dict[str, str]:
        return {"Access-Control-Allow-Origin": "*", "Cache-Control": "no-store"}
