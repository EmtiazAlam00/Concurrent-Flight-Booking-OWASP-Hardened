import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import admin, auth, bookings, dashboard, flights, holds
from app.config import settings
from app.db import get_engine
from app.errors import register_exception_handlers
from app.jobs.scheduler import start_scheduler, stop_scheduler
from app.redis_client import close_redis, get_redis
from app.security.context import AuthContextMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
)
logger = logging.getLogger("skylock")

DESCRIPTION = """
Airline seat booking under real concurrency, with security engineering as a
first-class concern.

**The engineering stories**

* *No overselling.* Acquiring a seat is one conditional `UPDATE`; the loser of a
  race gets zero rows back and a `409`. Try it: two `POST /holds` for the same
  seat at once.
* *Holds that expire correctly.* Expiry is evaluated in the `WHERE` clause of
  every availability query, so an expired hold is already not a hold. The
  background sweep only tidies rows — stop it and nothing oversells.
* *A saga that can be interrupted.* hold → charge → issue tickets → confirm,
  idempotent on `Idempotency-Key` and compensating when a step fails after the
  card was charged. Drive every branch with the demo card tokens below.
* *Object-level authorization.* Booking routes take an ownership-checked object,
  not a raw id, and answer `404` rather than `403` so they cannot be used to
  enumerate PNRs.

**Demo card tokens** — the last four characters select the behaviour:

| token | what happens |
|---|---|
| `tok_test_aaaa11110000` | approved |
| `tok_test_aaaa11110002` | declined (insufficient funds) — hold survives for a retry |
| `tok_test_aaaa11119995` | charge succeeds, ticketing fails → compensation |
| `tok_test_aaaa11110119` | gateway times out, then succeeds on retry (same key, one charge) |
| `tok_test_aaaa11115309` | compensation itself fails → `NEEDS_MANUAL_REVIEW` |

The read-only operator dashboard is at `/dash`.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await get_redis().ping()
    logger.info("datastores reachable")

    start_scheduler()
    try:
        yield
    finally:
        stop_scheduler()
        await close_redis()
        await engine.dispose()


app = FastAPI(
    title="SkyLock — Secure Flight Booking API",
    version="0.1.0",
    description=DESCRIPTION,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "auth", "description": "Registration, login, refresh rotation."},
        {"name": "flights", "description": "Search and seat maps."},
        {"name": "holds", "description": "Seat holds with TTL — the contended write."},
        {"name": "bookings", "description": "The booking saga and reservation management."},
        {"name": "admin", "description": "Security event log (admin scope)."},
    ],
)

app.add_middleware(AuthContextMiddleware)
register_exception_handlers(app)

app.include_router(auth.router)
app.include_router(flights.router)
app.include_router(holds.router)
app.include_router(bookings.router)
app.include_router(admin.router)
if settings.dashboard_enabled:
    app.include_router(dashboard.router)
    app.mount(
        "/static",
        StaticFiles(directory=str(Path(__file__).resolve().parent / "static")),
        name="static",
    )


@app.get("/health", tags=["ops"])
async def health() -> dict:
    """Liveness + datastore reachability."""
    checks = {"database": "unknown", "redis": "unknown"}
    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {type(exc).__name__}"
    try:
        await get_redis().ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        # Redis being down degrades rate limiting and fraud detection but does
        # not stop bookings — the service reports degraded, not dead.
        checks["redis"] = f"error: {type(exc).__name__}"

    healthy = checks["database"] == "ok"
    return {
        "status": "ok" if healthy and checks["redis"] == "ok" else "degraded",
        "checks": checks,
        "environment": settings.env,
    }
