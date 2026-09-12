"""Read-only operator dashboard.

Its job is to make invisible work visible: seat holds counting down, the
append-only audit trail, and the security feed lighting up during a simulated
card-testing attack. Watching state change live is far more convincing than a
script printing output.

Strictly read-only, by construction — this module defines no route that writes.
Booking logic lives in exactly one place, and this is not it.
"""

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app.config import settings
from app.deps import DbSession
from app.domain.enums import BookingState, SeatStatus
from app.domain.models import (
    Booking,
    BookingAudit,
    Flight,
    SeatInventory,
    SecurityEvent,
    User,
)

router = APIRouter(prefix="/dash", tags=["dashboard"], include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

_basic = HTTPBasic(auto_error=False)


async def dashboard_auth(
    credentials: Annotated[HTTPBasicCredentials | None, Depends(_basic)] = None,
) -> str:
    """HTTP Basic, compared in constant time.

    The dashboard exposes other people's booking history and the security feed,
    so it is not public even though it is read-only. Basic auth is proportionate
    for a single-operator local tool; a real deployment would put it behind the
    same SSO as the rest of the admin surface.
    """
    if not settings.dashboard_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dashboard is disabled")
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Dashboard login required",
            headers={"WWW-Authenticate": "Basic"},
        )
    ok_user = secrets.compare_digest(credentials.username, settings.dashboard_user)
    ok_pass = secrets.compare_digest(credentials.password, settings.dashboard_password)
    if not (ok_user and ok_pass):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid dashboard credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


DashboardUser = Annotated[str, Depends(dashboard_auth)]


async def _stats(db) -> dict:
    now = datetime.now(UTC)
    active_holds = int(
        await db.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(
                SeatInventory.status == SeatStatus.HELD,
                SeatInventory.hold_expires_at > func.now(),
            )
        )
        or 0
    )
    booked = int(
        await db.scalar(
            select(func.count())
            .select_from(SeatInventory)
            .where(SeatInventory.status == SeatStatus.BOOKED)
        )
        or 0
    )
    confirmed = int(
        await db.scalar(
            select(func.count()).select_from(Booking).where(Booking.state == BookingState.CONFIRMED)
        )
        or 0
    )
    needs_review = int(
        await db.scalar(
            select(func.count())
            .select_from(Booking)
            .where(Booking.state == BookingState.NEEDS_MANUAL_REVIEW)
        )
        or 0
    )
    high_sev = int(
        await db.scalar(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.severity.in_(["high", "critical"]))
        )
        or 0
    )
    flights = int(await db.scalar(select(func.count()).select_from(Flight)) or 0)
    return {
        "active_holds": active_holds,
        "seats_booked": booked,
        "bookings_confirmed": confirmed,
        "needs_review": needs_review,
        "high_severity_events": high_sev,
        "flights": flights,
        "generated_at": now,
    }


@router.get("")
async def index(request: Request, _: DashboardUser, db: DbSession):
    return templates.TemplateResponse(
        request, "dashboard/index.html", {"stats": await _stats(db), "tab": "overview"}
    )


# --- active holds -----------------------------------------------------------


async def _active_holds(db, limit: int = 100):
    rows = (
        await db.execute(
            select(SeatInventory, Flight, User.email)
            .join(Flight, Flight.id == SeatInventory.flight_id)
            .outerjoin(User, User.id == SeatInventory.held_by_user_id)
            .where(
                SeatInventory.status == SeatStatus.HELD,
                SeatInventory.hold_expires_at > func.now(),
            )
            .order_by(SeatInventory.hold_expires_at)
            .limit(limit)
        )
    ).all()
    now = datetime.now(UTC)
    return [
        {
            "seat_no": seat.seat_no,
            "flight_no": flight.flight_no,
            "route": f"{flight.src_iata}→{flight.dst_iata}",
            "email": email or "—",
            "expires_at": seat.hold_expires_at,
            "seconds_remaining": max(0, int((seat.hold_expires_at - now).total_seconds())),
            "attached_to_booking": seat.booking_id is not None,
        }
        for seat, flight, email in rows
    ]


@router.get("/holds")
async def holds_page(request: Request, _: DashboardUser, db: DbSession):
    return templates.TemplateResponse(
        request,
        "dashboard/holds.html",
        {"holds": await _active_holds(db), "tab": "holds", "stats": await _stats(db)},
    )


@router.get("/holds/rows")
async def holds_rows(request: Request, _: DashboardUser, db: DbSession):
    """HTMX fragment — polled so the countdowns tick without a page reload."""
    return templates.TemplateResponse(
        request, "dashboard/_holds_rows.html", {"holds": await _active_holds(db)}
    )


# --- audit trail ------------------------------------------------------------


@router.get("/audit")
async def audit_page(
    request: Request,
    _: DashboardUser,
    db: DbSession,
    limit: int = Query(100, ge=1, le=500),
):
    rows = (
        await db.execute(
            select(BookingAudit, Booking.ref, Booking.state)
            .join(Booking, Booking.id == BookingAudit.booking_id)
            .order_by(BookingAudit.id.desc())
            .limit(limit)
        )
    ).all()
    entries = [
        {
            "ref": ref,
            "booking_state": state,
            "seq": row.seq,
            "event_type": row.event_type,
            "from_state": row.from_state,
            "to_state": row.to_state,
            "actor_type": row.actor_type,
            "detail": row.detail,
            "occurred_at": row.occurred_at,
        }
        for row, ref, state in rows
    ]
    return templates.TemplateResponse(
        request,
        "dashboard/audit.html",
        {"entries": entries, "tab": "audit", "stats": await _stats(db)},
    )


# --- security feed ----------------------------------------------------------


async def _security_events(db, limit: int = 60, severity: str | None = None):
    stmt = select(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(limit)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    return list((await db.scalars(stmt)).all())


@router.get("/security")
async def security_page(
    request: Request,
    _: DashboardUser,
    db: DbSession,
    severity: str | None = Query(None, pattern=r"^(info|low|medium|high|critical)$"),
):
    return templates.TemplateResponse(
        request,
        "dashboard/security.html",
        {
            "events": await _security_events(db, severity=severity),
            "severity": severity,
            "tab": "security",
            "stats": await _stats(db),
        },
    )


@router.get("/security/rows")
async def security_rows(
    request: Request,
    _: DashboardUser,
    db: DbSession,
    severity: str | None = Query(None, pattern=r"^(info|low|medium|high|critical)$"),
):
    """HTMX fragment — this is the one that lights up during the carding demo."""
    return templates.TemplateResponse(
        request,
        "dashboard/_security_rows.html",
        {"events": await _security_events(db, severity=severity)},
    )
