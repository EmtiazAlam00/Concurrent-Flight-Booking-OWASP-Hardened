"""The one background job: release seat holds nobody paid for.

Worth being precise about what this job is *not*. It is not what makes an
expired hold stop counting — every availability query already treats
`hold_expires_at < now()` as free (app/services/holds.py::takeable). This job
only normalizes the rows so the data matches the semantics: the dashboard shows
clean state, indexes stay small, and `status` means what it says.

The practical consequence: if the sweep stops running, nothing oversells and no
booking breaks. Availability is unaffected. That property is the reason holds
are not stored as Redis TTL keys — see docs/ADR-0001.

The UPDATE is conditional on the row still being expired-and-held, so it can
never take a seat away from a booking that is mid-flight: the saga holds the row
lock, the sweep waits, and when it gets the lock the WHERE no longer matches.
"""

import logging

from sqlalchemy import func, update

from app.db import rows_affected, session_scope
from app.domain.enums import SeatStatus
from app.domain.models import SeatInventory

logger = logging.getLogger("skylock.sweep")


async def sweep_expired_holds() -> int:
    """Return expired holds to inventory. Returns the number of seats released."""
    async with session_scope() as session:
        result = await session.execute(
            update(SeatInventory)
            .where(
                SeatInventory.status == SeatStatus.HELD,
                SeatInventory.hold_expires_at < func.now(),
                # A seat attached to a live booking is the saga's business, not
                # ours; it will be released by compensation if that fails.
                SeatInventory.booking_id.is_(None),
            )
            .values(
                status=SeatStatus.AVAILABLE,
                held_by_user_id=None,
                hold_id=None,
                hold_expires_at=None,
                version=SeatInventory.version + 1,
            )
            .execution_options(synchronize_session=False)
        )
        released = rows_affected(result)

    if released:
        logger.info("sweep released %d expired seat hold(s)", released)
    return released
