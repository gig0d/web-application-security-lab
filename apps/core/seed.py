from sqlalchemy import select
from sqlalchemy.orm import Session

from apps.core.models import Attachment, Comment, Ticket, User
from apps.core.security import PASSWORDS

# Public disposable fixture, not an operational credential.
DEMO_PASSWORD = "HarborDesk-Local-Only!42"  # noqa: S105  # nosec B105


def seed(db: Session) -> None:
    if db.scalar(select(User.id).limit(1)) is not None:
        return
    for uid, name, role, display in (
        (1, "alice", "customer", "Alice Morgan"),
        (2, "bob", "customer", "Bob Rivera"),
        (3, "sam", "employee", "Sam Chen"),
        (4, "admin", "admin", "Jordan Avery"),
    ):
        db.add(
            User(
                id=uid,
                username=name,
                role=role,
                display_name=display,
                password_hash=PASSWORDS.hash(DEMO_PASSWORD),
                session_version=1,
            )
        )
    db.flush()
    db.add_all(
        [
            Ticket(
                id=1,
                owner_id=1,
                assignee_id=3,
                title="Workspace access request",
                description="Please provision the fictional Northstar team workspace.",
            ),
            Ticket(
                id=2,
                owner_id=2,
                assignee_id=3,
                title="Confidential renewal estimate",
                description="Synthetic renewal budget: 1200 fictional credits.",
            ),
        ]
    )
    db.flush()
    db.add_all(
        [
            Comment(ticket_id=1, author_id=3, body="We are reviewing your request.", private=False),
            Comment(
                ticket_id=2, author_id=3, body="Internal: fictional approval pending.", private=True
            ),
            Attachment(
                id=1,
                ticket_id=1,
                filename="workspace.txt",
                storage_key="fixture-alice",
                content=b"Synthetic workspace checklist for Alice. No real data.",
            ),
            Attachment(
                id=2,
                ticket_id=2,
                filename="renewal.txt",
                storage_key="fixture-bob",
                content=b"Bob's synthetic private renewal: 1200 fictional credits.",
            ),
        ]
    )
    db.commit()
