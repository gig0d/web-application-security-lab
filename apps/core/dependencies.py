import time
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from apps.core.audit import record
from apps.core.database import get_db
from apps.core.models import LoginSession, Ticket, User
from apps.core.security import SecurePolicy, digest


@dataclass
class Principal:
    user: User
    session: LoginSession


def principal(request: Request, db: Session = Depends(get_db, scope="function")) -> Principal:
    policy: SecurePolicy = request.app.state.policy
    token = request.cookies.get(f"aegis_{policy.label}", "")
    session = db.get(LoginSession, digest(token)) if token and len(token) < 200 else None
    user = db.get(User, session.user_id) if session else None
    if not session or not user or not policy.session_valid(session, user):
        raise HTTPException(401, "Authentication required")
    return Principal(user, session)


def change(
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> Principal:
    policy: SecurePolicy = request.app.state.policy
    try:
        policy.csrf(request, actor.session)
    except HTTPException:
        record(request, db, "csrf.validation", "deny", actor.user.id)
        db.commit()
        raise
    return actor


def authorized_ticket(request: Request, db: Session, user: User, ticket_id: int) -> Ticket:
    ticket = db.get(Ticket, ticket_id)
    policy: SecurePolicy = request.app.state.policy
    if not ticket or not policy.ticket(user, ticket):
        record(request, db, "authorization.ticket", "deny", user.id, f"ticket:{ticket_id}")
        db.commit()
        raise HTTPException(404, "Ticket not found")
    return ticket


def administrator(request: Request, db: Session, user: User) -> None:
    policy: SecurePolicy = request.app.state.policy
    if not policy.admin(user):
        record(request, db, "authorization.admin", "deny", user.id)
        db.commit()
        raise HTTPException(403, "Administrator role required")


def new_session(db: Session, user: User, seconds: int) -> tuple[str, LoginSession]:
    import secrets

    token = secrets.token_urlsafe(32)
    session = LoginSession(
        token_hash=digest(token),
        user_id=user.id,
        csrf=secrets.token_urlsafe(32),
        expires=time.time() + seconds,
        user_version=user.session_version,
    )
    db.add(session)
    return token, session
