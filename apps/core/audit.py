import json
import logging
import time

from fastapi import Request
from sqlalchemy.orm import Session

from apps.core.models import AuditEvent

logger = logging.getLogger("aegis.security")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())


def record(
    request: Request,
    db: Session,
    event: str,
    outcome: str,
    actor_id: int | None = None,
    resource: str = "",
) -> None:
    # Only server-defined categories and identifiers are accepted here; no request bodies or cookies.
    entry = AuditEvent(
        at=time.time(),
        event=event,
        outcome=outcome,
        actor_id=actor_id,
        resource=resource[:100],
        request_id=getattr(request.state, "request_id", "unknown"),
    )
    db.add(entry)
    logger.info(
        json.dumps(
            {
                "schema_version": 1,
                "at": entry.at,
                "event": event,
                "outcome": outcome,
                "actor_id": actor_id,
                "resource": entry.resource,
                "request_id": entry.request_id,
            }
        )
    )
