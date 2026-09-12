import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.domain.enums import (
    BookingState,
    IdempotencyState,
    PaymentState,
    SeatStatus,
    Severity,
)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


TS = DateTime(timezone=True)
NOW = func.now()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(200))
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Brute-force lockout state.
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TS)

    # Reserved for the documented "future work" field-level PII encryption; the
    # column exists now so adding it later is not a migration of live data.
    mfa_secret_enc: Mapped[bytes | None] = mapped_column()

    created_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)

    # Emails are normalized to lowercase before they ever reach the database
    # (app/security/hashing.py::normalize_email), so the plain unique index on
    # `email` is genuinely case-insensitive.


class RefreshToken(Base):
    """One row per issued refresh token. Tokens form a *family*: rotation makes
    a child, and replaying any already-used token revokes the whole family.

    Only the SHA-256 of the token is stored — a database dump does not yield
    usable tokens.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    family_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )

    issued_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    #: The reuse sentinel. Non-null means this token has already been exchanged.
    used_at: Mapped[datetime | None] = mapped_column(TS)
    revoked_at: Mapped[datetime | None] = mapped_column(TS)
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(TS, nullable=False)

    user_agent: Mapped[str | None] = mapped_column(String(400))
    ip: Mapped[str | None] = mapped_column(INET)


# ---------------------------------------------------------------------------
# Reference data (seeded from OurAirports / OpenFlights, read-only at runtime)
# ---------------------------------------------------------------------------


class Airport(Base):
    __tablename__ = "airports"

    iata: Mapped[str] = mapped_column(String(3), primary_key=True)
    icao: Mapped[str | None] = mapped_column(String(4))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    city: Mapped[str | None] = mapped_column(String(120))
    country: Mapped[str | None] = mapped_column(String(2), index=True)
    latitude: Mapped[float | None] = mapped_column()
    longitude: Mapped[float | None] = mapped_column()
    timezone: Mapped[str | None] = mapped_column(String(64))


class Airline(Base):
    __tablename__ = "airlines"

    iata: Mapped[str] = mapped_column(String(2), primary_key=True)
    icao: Mapped[str | None] = mapped_column(String(3))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    country: Mapped[str | None] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class Route(Base):
    __tablename__ = "routes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    airline_iata: Mapped[str] = mapped_column(String(2), nullable=False, index=True)
    src_iata: Mapped[str] = mapped_column(String(3), nullable=False)
    dst_iata: Mapped[str] = mapped_column(String(3), nullable=False)
    equipment: Mapped[str | None] = mapped_column(String(120))

    __table_args__ = (
        UniqueConstraint("airline_iata", "src_iata", "dst_iata", name="uq_route"),
        Index("ix_routes_src_dst", "src_iata", "dst_iata"),
    )


# ---------------------------------------------------------------------------
# Generated inventory
# ---------------------------------------------------------------------------


class Flight(Base):
    __tablename__ = "flights"

    id: Mapped[uuid.UUID] = _uuid_pk()
    flight_no: Mapped[str] = mapped_column(String(8), nullable=False)
    airline_iata: Mapped[str] = mapped_column(
        ForeignKey("airlines.iata", ondelete="RESTRICT"), nullable=False
    )
    src_iata: Mapped[str] = mapped_column(
        ForeignKey("airports.iata", ondelete="RESTRICT"), nullable=False
    )
    dst_iata: Mapped[str] = mapped_column(
        ForeignKey("airports.iata", ondelete="RESTRICT"), nullable=False
    )
    depart_at: Mapped[datetime] = mapped_column(TS, nullable=False)
    arrive_at: Mapped[datetime] = mapped_column(TS, nullable=False)
    aircraft_type: Mapped[str] = mapped_column(String(8), nullable=False)
    base_fare: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False, default="CAD")

    airline: Mapped[Airline] = relationship(lazy="selectin")
    origin: Mapped[Airport] = relationship(foreign_keys="Flight.src_iata", lazy="selectin")
    destination: Mapped[Airport] = relationship(foreign_keys="Flight.dst_iata", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("airline_iata", "flight_no", "depart_at", name="uq_flight_instance"),
        # The search index: origin + destination + departure day.
        Index("ix_flights_search", "src_iata", "dst_iata", "depart_at"),
        CheckConstraint("arrive_at > depart_at", name="ck_flight_times"),
        CheckConstraint("base_fare >= 0", name="ck_flight_fare_nonneg"),
    )


class FareClass(Base):
    __tablename__ = "fare_classes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    flight_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("flights.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code: Mapped[str] = mapped_column(String(2), nullable=False)  # Y, W, J, F
    cabin: Mapped[str] = mapped_column(String(16), nullable=False)  # economy/premium/business
    multiplier: Mapped[Decimal] = mapped_column(Numeric(6, 3), nullable=False, default=1)
    seats_total: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (UniqueConstraint("flight_id", "code", name="uq_fare_class"),)


class SeatInventory(Base):
    """The contended row. Everything about seat state lives here and nowhere else.

    Expiry is evaluated *lazily*, in the WHERE clause of every query that asks
    "is this seat takeable?":

        status = 'available' OR (status = 'held' AND hold_expires_at < now())

    So an expired hold is already not a hold, whether or not the sweep job has
    run. The sweep is a janitor, not the mechanism. See docs/ADR-0001.
    """

    __tablename__ = "seat_inventory"

    id: Mapped[uuid.UUID] = _uuid_pk()
    flight_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("flights.id", ondelete="CASCADE"), nullable=False
    )
    seat_no: Mapped[str] = mapped_column(String(4), nullable=False)  # e.g. "14C"
    row_no: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    seat_letter: Mapped[str] = mapped_column(String(1), nullable=False)
    cabin: Mapped[str] = mapped_column(String(16), nullable=False)
    fare_class_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("fare_classes.id", ondelete="CASCADE"), nullable=False
    )
    is_exit_row: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    price: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    status: Mapped[str] = mapped_column(
        String(12), nullable=False, default=SeatStatus.AVAILABLE, server_default="available"
    )
    held_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    hold_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    hold_expires_at: Mapped[datetime | None] = mapped_column(TS)
    booking_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bookings.id", ondelete="SET NULL")
    )

    #: Kept even though the MVP locks pessimistically: it makes the optimistic
    #: alternative a one-line change and gives every write a cheap audit stamp.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    __table_args__ = (
        UniqueConstraint("flight_id", "seat_no", name="uq_seat_per_flight"),
        Index("ix_seat_flight_status", "flight_id", "status"),
        # Partial index for the sweep: only held rows can ever expire.
        Index(
            "ix_seat_hold_expiry",
            "hold_expires_at",
            postgresql_where=text("status = 'held'"),
        ),
        Index("ix_seat_hold_id", "hold_id", postgresql_where=text("hold_id IS NOT NULL")),
        Index("ix_seat_booking", "booking_id", postgresql_where=text("booking_id IS NOT NULL")),
        CheckConstraint("status IN ('available','held','booked')", name="ck_seat_status"),
        # A held seat must say who holds it and until when. This constraint has
        # caught more bugs than any test.
        CheckConstraint(
            "(status <> 'held') OR "
            "(held_by_user_id IS NOT NULL AND hold_expires_at IS NOT NULL AND hold_id IS NOT NULL)",
            name="ck_held_seat_has_holder",
        ),
        CheckConstraint(
            "(status <> 'booked') OR (booking_id IS NOT NULL)",
            name="ck_booked_seat_has_booking",
        ),
    )


# ---------------------------------------------------------------------------
# Bookings
# ---------------------------------------------------------------------------


class Booking(Base):
    __tablename__ = "bookings"

    id: Mapped[uuid.UUID] = _uuid_pk()
    ref: Mapped[str] = mapped_column(String(6), unique=True, nullable=False)  # the PNR
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    flight_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("flights.id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(24), nullable=False, default=BookingState.PENDING)
    total_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))

    created_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(
        TS, nullable=False, server_default=NOW, onupdate=NOW
    )

    flight: Mapped[Flight] = relationship(lazy="selectin")
    passengers: Mapped[list["BookingPassenger"]] = relationship(
        back_populates="booking", lazy="selectin", cascade="all, delete-orphan"
    )
    tickets: Mapped[list["Ticket"]] = relationship(back_populates="booking", lazy="selectin")

    __table_args__ = (
        Index("ix_bookings_user_created", "user_id", "created_at"),
        CheckConstraint("total_amount >= 0", name="ck_booking_total_nonneg"),
    )


class BookingPassenger(Base):
    __tablename__ = "booking_passengers"

    id: Mapped[uuid.UUID] = _uuid_pk()
    booking_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bookings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    given_name: Mapped[str] = mapped_column(String(100), nullable=False)
    family_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # PII kept deliberately narrow. The `_enc` columns are bytea and currently
    # hold plaintext-encoded values; swapping in envelope encryption is the
    # documented next step and needs no schema change. Only the last 4 of a
    # passport is ever returned by the API.
    dob_enc: Mapped[bytes | None] = mapped_column()
    passport_enc: Mapped[bytes | None] = mapped_column()
    passport_last4: Mapped[str | None] = mapped_column(String(4))

    seat_inventory_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("seat_inventory.id", ondelete="SET NULL")
    )

    booking: Mapped[Booking] = relationship(back_populates="passengers")
    seat: Mapped[SeatInventory | None] = relationship(lazy="selectin")


class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[uuid.UUID] = _uuid_pk()
    booking_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bookings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_ref: Mapped[str | None] = mapped_column(String(64))

    #: Never a card number. The gateway hands back an opaque token; we store the
    #: token plus a salted fingerprint so velocity rules can correlate cards
    #: across accounts without ever holding a PAN. (PCI-DSS scope reduction.)
    card_token: Mapped[str] = mapped_column(String(64), nullable=False)
    card_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    card_last4: Mapped[str | None] = mapped_column(String(4))

    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default=PaymentState.PENDING)
    failure_code: Mapped[str | None] = mapped_column(String(48))
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)

    created_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    updated_at: Mapped[datetime] = mapped_column(
        TS, nullable=False, server_default=NOW, onupdate=NOW
    )


class Ticket(Base):
    __tablename__ = "tickets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    booking_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bookings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    passenger_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("booking_passengers.id", ondelete="CASCADE"), nullable=False
    )
    seat_inventory_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("seat_inventory.id", ondelete="RESTRICT"), nullable=False
    )
    e_ticket_no: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    issued_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    #: A cancelled e-ticket is voided, not deleted. It really was issued, and the
    #: record of that is worth keeping — which is also what lets the seat be sold
    #: again without colliding with its own history.
    voided_at: Mapped[datetime | None] = mapped_column(TS)

    booking: Mapped[Booking] = relationship(back_populates="tickets")

    __table_args__ = (
        # A seat backs at most one *live* ticket. Belt and braces alongside the
        # row locking: even a logic bug cannot double-issue.
        #
        # Partial, on purpose. A plain UNIQUE(seat_inventory_id) looks right and
        # is wrong: once a booking is cancelled the seat returns to inventory,
        # but its old ticket still references the row, so the next customer to
        # buy that seat collides with a ticket that is no longer valid. Scoping
        # the constraint to un-voided tickets keeps the guarantee that matters
        # and drops the one that was never intended.
        Index(
            "uq_ticket_live_per_seat",
            "seat_inventory_id",
            unique=True,
            postgresql_where=text("voided_at IS NULL"),
        ),
        Index(
            "uq_ticket_live_per_passenger",
            "passenger_id",
            unique=True,
            postgresql_where=text("voided_at IS NULL"),
        ),
    )


class IdempotencyKey(Base):
    """Idempotency is a table, not a cache: the guarantee has to survive a
    Redis restart. See docs/ADR-0004.
    """

    __tablename__ = "idempotency_keys"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    endpoint: Mapped[str] = mapped_column(String(80), nullable=False)
    #: SHA-256 of the canonicalized request body. Same key + different body is a
    #: client bug, and we surface it as 422 rather than silently replaying.
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default=IdempotencyState.IN_PROGRESS
    )
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_body: Mapped[dict | None] = mapped_column(JSONB)
    booking_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("bookings.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    expires_at: Mapped[datetime] = mapped_column(TS, nullable=False)


# ---------------------------------------------------------------------------
# Append-only tables
#
# Migration 0002 attaches ON UPDATE / ON DELETE rules and REVOKEs UPDATE and
# DELETE from the application role, so immutability is a database property.
# ---------------------------------------------------------------------------


class BookingAudit(Base):
    __tablename__ = "booking_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    booking_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("bookings.id", ondelete="CASCADE"), nullable=False
    )
    #: Per-booking sequence, gap-free. A gap means a lost write.
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)  # user|system|job
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    from_state: Mapped[str | None] = mapped_column(String(24))
    to_state: Mapped[str | None] = mapped_column(String(24))
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    occurred_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)

    __table_args__ = (
        UniqueConstraint("booking_id", "seq", name="uq_audit_seq"),
        Index("ix_audit_booking_seq", "booking_id", "seq"),
        Index("ix_audit_occurred", "occurred_at"),
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(TS, nullable=False, server_default=NOW)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(10), nullable=False, default=Severity.INFO)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    actor_email: Mapped[str | None] = mapped_column(String(320))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(400))
    method: Mapped[str | None] = mapped_column(String(8))
    path: Mapped[str | None] = mapped_column(String(200))
    resource_type: Mapped[str | None] = mapped_column(String(32))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    decision: Mapped[str | None] = mapped_column(String(16))
    #: Rule hits, counts, and thresholds — enough for the dashboard to explain
    #: *why* something tripped, which is the difference between a log and a
    #: detection surface.
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        Index("ix_secevent_occurred_desc", text("occurred_at DESC")),
        Index("ix_secevent_type_occurred", "event_type", "occurred_at"),
    )
