"""The security event log.

Two properties matter and both are deliberate:

1. Events are written in their **own transaction** (`session_scope`), so
   recording "we denied you" survives the rollback of the business transaction
   that did the denying.
2. The table is append-only at the database level (migration 0002), so an
   attacker who reaches the app role still cannot erase their own trail.
"""

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import session_scope
from app.domain.enums import SecurityEventType, Severity
from app.domain.models import SecurityEvent

logger = logging.getLogger("skylock.security")


def client_ip(request: Request | None) -> str | None:
    """The caller's IP.

    X-Forwarded-For is deliberately NOT trusted: this service does not know
    whether it sits behind a proxy it controls, and an attacker-supplied header
    would let anyone forge the identity that rate limits and velocity rules key
    on. Behind a real load balancer, terminate XFF there and pass a signed
    header, or run uvicorn with --proxy-headers and a trusted-hosts list.
    """
    if request is None or request.client is None:
        return None
    return request.client.host


def _request_fields(request: Request | None) -> dict[str, Any]:
    if request is None:
        return {}
    return {
        "ip": client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:400] or None,
        "method": request.method,
        "path": request.url.path[:200],
    }


async def record_security_event(
    session: AsyncSession,
    event_type: SecurityEventType,
    severity: Severity = Severity.INFO,
    *,
    request: Request | None = None,
    actor_user_id: Any = None,
    actor_email: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    decision: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Append an event using a caller-supplied session (caller commits)."""
    session.add(
        SecurityEvent(
            event_type=event_type,
            severity=severity,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            decision=decision,
            detail=detail or {},
            **_request_fields(request),
        )
    )
    logger.info(
        "security_event",
        extra={"event_type": str(event_type), "severity": str(severity), "detail": detail},
    )


async def record_security_event_bg(
    request: Request | None,
    event_type: SecurityEventType,
    severity: Severity = Severity.INFO,
    **kwargs: Any,
) -> None:
    """Append an event in an independent transaction.

    Use this from anywhere the surrounding transaction may roll back — denials,
    validation rejections, fraud blocks. Never let audit-logging failure take
    down the request it is describing.
    """
    try:
        async with session_scope() as session:
            await record_security_event(session, event_type, severity, request=request, **kwargs)
    except Exception:  # noqa: BLE001 - logging must not break the request path
        logger.exception("failed to record security event %s", event_type)
