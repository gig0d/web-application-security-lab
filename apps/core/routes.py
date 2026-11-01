import json
from typing import Any, cast
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from apps.core.audit import record
from apps.core.database import get_db
from apps.core.dependencies import (
    Principal,
    administrator,
    authorized_ticket,
    change,
    new_session,
    principal,
)
from apps.core.models import (
    Attachment,
    AuditEvent,
    Comment,
    LoginAttempt,
    LoginSession,
    Ticket,
    User,
)
from apps.core.schemas import (
    AssignmentInput,
    CommentInput,
    LoginInput,
    ProfileInput,
    ResetInput,
    RoleInput,
    StatusInput,
    TicketInput,
)
from apps.core.security import (
    DUMMY_HASH,
    PASSWORDS,
    SecurePolicy,
    digest,
    ticket_dict,
    verify_password,
)

router = APIRouter()


def policy_for(request: Request) -> SecurePolicy:
    policy: SecurePolicy = request.app.state.policy
    return policy


def page(request: Request, name: str, **context: Any) -> HTMLResponse:
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name=name,
            context={"policy": policy_for(request), **context},
        ),
    )


@router.get("/health")
def health(db: Session = Depends(get_db, scope="function")) -> dict[str, str]:
    db.execute(select(1))
    return {"status": "ok"}


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    return page(request, "login.html")


@router.post("/api/login")
def login(
    body: LoginInput,
    request: Request,
    response: Response,
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    policy = policy_for(request)
    origin = request.headers.get("origin")
    if policy.label == "hardened" and origin and origin != request.app.state.settings.origin:
        raise HTTPException(403, "Origin rejected")
    policy.rate_limit(request, db, body.username)
    user = db.scalar(select(User).where(User.username == body.username.lower()))
    valid = verify_password(user.password_hash if user else DUMMY_HASH, body.password)
    if not user or not valid:
        record(request, db, "authentication.login", "deny")
        db.commit()
        raise HTTPException(401, policy.login_error(user is not None))
    if PASSWORDS.check_needs_rehash(user.password_hash):
        user.password_hash = PASSWORDS.hash(body.password)
    cookie = f"aegis_{policy.label}"
    previous = request.cookies.get(cookie, "")
    if previous:
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(previous)))
    token, session = new_session(db, user, request.app.state.settings.session_seconds)
    response.set_cookie(
        cookie,
        token,
        httponly=True,
        secure=request.app.state.settings.secure_cookie,
        samesite="lax",
        max_age=request.app.state.settings.session_seconds,
        path="/",
    )
    record(request, db, "authentication.login", "allow", user.id)
    return {"id": user.id, "role": user.role, "csrf": session.csrf}


@router.get("/api/session")
def session_info(actor: Principal = Depends(principal)) -> dict[str, object]:
    return {
        "id": actor.user.id,
        "username": actor.user.username,
        "role": actor.user.role,
        "display_name": actor.user.display_name,
        "csrf": actor.session.csrf,
    }


@router.post("/api/logout")
def logout(
    request: Request,
    response: Response,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, bool]:
    policy = policy_for(request)
    policy.revoke(db, actor.session)
    response.delete_cookie(f"aegis_{policy.label}", path="/")
    record(request, db, "authentication.logout", "allow", actor.user.id)
    return {"logged_out": True}


@router.get("/api/tickets")
def tickets(
    request: Request,
    q: str = "",
    status: str = "",
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> list[dict[str, object]]:
    if len(q) > 200 or status not in {"", "open", "closed"}:
        raise HTTPException(422, "Invalid search")
    # Search needs its own read transaction for the training read-only SQL boundary.
    factory = request.app.state.sessions
    try:
        with factory() as search_db:
            results = policy_for(request).search(search_db, actor.user, q)
    except SQLAlchemyError as exc:
        raise HTTPException(400, "Search could not be processed") from exc
    return [r for r in results if not status or r["status"] == status]


@router.post("/api/tickets", status_code=201)
def create_ticket(
    body: TicketInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    ticket = Ticket(owner_id=actor.user.id, title=body.title, description=body.description)
    db.add(ticket)
    db.flush()
    record(request, db, "ticket.created", "allow", actor.user.id, f"ticket:{ticket.id}")
    return ticket_dict(ticket)


@router.get("/api/tickets/{ticket_id}")
def read_ticket(
    ticket_id: int,
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    ticket = authorized_ticket(request, db, actor.user, ticket_id)
    return ticket_dict(ticket)


@router.patch("/api/tickets/{ticket_id}")
def update_ticket(
    ticket_id: int,
    body: StatusInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    ticket = authorized_ticket(request, db, actor.user, ticket_id)
    ticket.status = body.status
    record(request, db, "ticket.status", "allow", actor.user.id, f"ticket:{ticket.id}")
    return ticket_dict(ticket)


@router.post("/api/admin/tickets/{ticket_id}/assign")
def assign(
    ticket_id: int,
    body: AssignmentInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    administrator(request, db, actor.user)
    ticket = authorized_ticket(request, db, actor.user, ticket_id)
    employee = db.get(User, body.assignee_id)
    if not employee or employee.role not in {"employee", "admin"}:
        raise HTTPException(422, "Select a support employee")
    ticket.assignee_id = employee.id
    record(request, db, "admin.ticket_assignment", "allow", actor.user.id, f"ticket:{ticket.id}")
    return ticket_dict(ticket)


@router.post("/api/admin/users/{user_id}/role")
def role_change(
    user_id: int,
    body: RoleInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, bool]:
    # Role changes always require real admin privileges, even in the bounded training app.
    if actor.user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.role = body.role
    user.session_version += 1
    record(request, db, "admin.role_change", "allow", actor.user.id, f"user:{user_id}")
    return {"sessions_invalidated": True}


@router.get("/api/tickets/{ticket_id}/comments")
def comments(
    ticket_id: int,
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> list[dict[str, object]]:
    authorized_ticket(request, db, actor.user, ticket_id)
    query = select(Comment).where(Comment.ticket_id == ticket_id).order_by(Comment.id)
    if actor.user.role == "customer":
        query = query.where(Comment.private.is_(False))
    return [{"id": c.id, "body": c.body, "private": c.private} for c in db.scalars(query)]


@router.post("/api/tickets/{ticket_id}/comments", status_code=201)
def add_comment(
    ticket_id: int,
    body: CommentInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, int]:
    authorized_ticket(request, db, actor.user, ticket_id)
    if body.private and actor.user.role == "customer":
        raise HTTPException(403, "Only employees can create private notes")
    comment = Comment(ticket_id=ticket_id, author_id=actor.user.id, **body.model_dump())
    db.add(comment)
    db.flush()
    record(request, db, "ticket.comment", "allow", actor.user.id, f"ticket:{ticket_id}")
    return {"id": comment.id}


@router.get("/api/tickets/{ticket_id}/attachments")
def attachments(
    ticket_id: int,
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> list[dict[str, object]]:
    authorized_ticket(request, db, actor.user, ticket_id)
    return [
        {"id": a.id, "filename": a.filename}
        for a in db.scalars(
            select(Attachment).where(Attachment.ticket_id == ticket_id).order_by(Attachment.id)
        )
    ]


@router.get("/api/attachments/{attachment_id}")
def download(
    attachment_id: int,
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> Response:
    attachment = db.get(Attachment, attachment_id)
    ticket = db.get(Ticket, attachment.ticket_id) if attachment else None
    if not attachment or not ticket or not policy_for(request).attachment(actor.user, ticket):
        record(request, db, "authorization.attachment", "deny", actor.user.id)
        db.commit()
        raise HTTPException(404, "Attachment not found")
    # Even training uploads cannot become executable browser content or response headers.
    filename = quote(attachment.filename, safe="")
    return Response(
        attachment.content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{filename}",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/api/tickets/{ticket_id}/attachments", status_code=201)
async def upload(
    ticket_id: int,
    file: UploadFile,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, object]:
    authorized_ticket(request, db, actor.user, ticket_id)
    content = await file.read(131073)
    filename, key = policy_for(request).upload(
        file.filename or "",
        content,
        request.app.state.settings.upload_limit,
    )
    attachment = Attachment(
        ticket_id=ticket_id, filename=filename, storage_key=key, content=content
    )
    db.add(attachment)
    db.flush()
    record(request, db, "attachment.upload", "allow", actor.user.id, f"ticket:{ticket_id}")
    return {"id": attachment.id, "filename": filename, "storage_key": key}


@router.post("/api/profile")
async def profile(
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, str]:
    kind = request.headers.get("content-type", "").split(";")[0]
    try:
        if kind == "application/json":
            body = ProfileInput.model_validate(await request.json())
        elif kind == "application/x-www-form-urlencoded":
            body = ProfileInput.model_validate(dict(await request.form()))
        else:
            raise HTTPException(415, "Unsupported content type")
    except (ValidationError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(422, "Invalid profile data") from exc
    actor.user.display_name = body.display_name
    record(request, db, "profile.updated", "allow", actor.user.id)
    return {"display_name": body.display_name}


@router.get("/api/preview")
async def preview(
    request: Request,
    source: str = "handbook",
    actor: Principal = Depends(principal),
) -> dict[str, str]:
    return {"preview": await policy_for(request).preview(source)}


@router.get("/api/diagnostics/error")
def diagnostic_error(request: Request, actor: Principal = Depends(principal)) -> JSONResponse:
    # A deterministic synthetic exception scenario, never a dump of real configuration.
    return JSONResponse(policy_for(request).error(), status_code=500)


@router.get("/api/admin/audit")
def audit_export(
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> list[dict[str, object]]:
    if actor.user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    return [
        {
            "schema_version": 1,
            "id": e.id,
            "at": e.at,
            "event": e.event,
            "outcome": e.outcome,
            "actor_id": e.actor_id,
            "resource": e.resource,
            "request_id": e.request_id,
        }
        for e in db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(500))
    ]


@router.post("/api/admin/reset")
def reset_business_data(
    body: ResetInput,
    request: Request,
    actor: Principal = Depends(change),
    db: Session = Depends(get_db, scope="function"),
) -> dict[str, bool]:
    from apps.core.seed import seed

    if actor.user.role != "admin":
        raise HTTPException(403, "Administrator role required")
    # Only the selected app database; schema, volumes and host resources are untouched.
    # Executed as one transaction; rollback restores the prior dataset on failure.
    for model in (Comment, Attachment, LoginSession, LoginAttempt, Ticket, User):
        db.execute(delete(model), execution_options={"synchronize_session": False})
    db.expunge_all()
    seed(db)
    record(request, db, "admin.synthetic_reset", "allow", 4)
    return {"reset": True, "sessions_invalidated": True}


@router.get("/portal", response_class=HTMLResponse)
def portal(request: Request, actor: Principal = Depends(principal)) -> HTMLResponse:
    return page(request, "portal.html", user=actor.user, csrf=actor.session.csrf)


@router.get("/tickets/{ticket_id}", response_class=HTMLResponse)
def ticket_page(
    ticket_id: int,
    request: Request,
    actor: Principal = Depends(principal),
    db: Session = Depends(get_db, scope="function"),
) -> HTMLResponse:
    ticket = authorized_ticket(request, db, actor.user, ticket_id)
    visible = comments(ticket_id, request, actor, db)
    rendered = [{**c, "rendered": policy_for(request).render(str(c["body"]))} for c in visible]
    return page(
        request,
        "ticket.html",
        user=actor.user,
        csrf=actor.session.csrf,
        ticket=ticket,
        comments=rendered,
    )


@router.get("/search", response_class=HTMLResponse)
def search_page(
    request: Request,
    q: str = "",
    actor: Principal = Depends(principal),
) -> HTMLResponse:
    if len(q) > 200:
        raise HTTPException(422, "Search too long")
    return page(
        request,
        "search.html",
        user=actor.user,
        csrf=actor.session.csrf,
        rendered_query=policy_for(request).render(q),
    )
