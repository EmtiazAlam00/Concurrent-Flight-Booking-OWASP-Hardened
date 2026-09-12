"""Card-testing detection.

The rules are tested directly against the engine (fast, and lets us assert on
scores and rule names), plus one end-to-end test proving a blocked payment
actually stops the saga before the gateway is called.
"""

import uuid
from decimal import Decimal

import pytest
from sqlalchemy import select

from app.domain.enums import Decision, SecurityEventType
from app.domain.models import Booking, SecurityEvent
from app.security import carding
from app.security.carding import (
    SCORE_BLOCK,
    T_DECLINE_BURST,
    T_DISTINCT_CARDS,
    Assessment,
)
from app.services.payments import get_gateway
from tests.conftest import DECLINE_TOKEN, book, hold_seat

pytestmark = [pytest.mark.security, pytest.mark.integration]


def _card(n: int) -> str:
    return f"fingerprint-{n:04d}"


async def _assess(user_id, fingerprint, amount=Decimal("250.00"), ip="203.0.113.10"):
    return await carding.assess_payment_attempt(
        user_id=user_id, ip=ip, card_fingerprint=fingerprint, amount=amount
    )


class TestRuleDistinctCards:
    async def test_one_account_cycling_through_cards_is_flagged(self):
        user_id = uuid.uuid4()
        for n in range(T_DISTINCT_CARDS - 1):
            assessment = await _assess(user_id, _card(n))
            assert "distinct_cards_per_account" not in [h.rule for h in assessment.hits]

        assessment = await _assess(user_id, _card(T_DISTINCT_CARDS))
        assert "distinct_cards_per_account" in [h.rule for h in assessment.hits]

    async def test_the_same_card_repeatedly_is_not_flagged(self):
        """A customer retrying their own card must not look like carding."""
        user_id = uuid.uuid4()
        for _ in range(10):
            assessment = await _assess(user_id, _card(1))
        assert assessment.decision is Decision.ALLOW
        assert "distinct_cards_per_account" not in [h.rule for h in assessment.hits]


class TestRuleDeclineVolume:
    async def test_repeated_declines_raise_the_score(self):
        user_id = uuid.uuid4()
        for _ in range(6):
            await carding.record_outcome(
                user_id=user_id, ip="203.0.113.11", card_fingerprint=_card(1), approved=False
            )
        assessment = await _assess(user_id, _card(1))
        assert "declines_per_account" in [h.rule for h in assessment.hits]

    async def test_declines_from_one_address_across_accounts(self):
        ip = "198.51.100.7"
        for _ in range(9):
            await carding.record_outcome(
                user_id=uuid.uuid4(), ip=ip, card_fingerprint=_card(2), approved=False
            )
        assessment = await _assess(uuid.uuid4(), _card(99), ip=ip)
        assert "declines_per_ip" in [h.rule for h in assessment.hits]


class TestRuleCardAcrossAccounts:
    async def test_one_card_on_several_accounts_is_flagged(self):
        """A stolen-card list being worked through, not a shared family card."""
        fingerprint = _card(42)
        for _ in range(2):
            await _assess(uuid.uuid4(), fingerprint)
        assessment = await _assess(uuid.uuid4(), fingerprint)
        assert "card_across_accounts" in [h.rule for h in assessment.hits]


class TestRuleDeclineBurstThenSuccess:
    async def test_a_validated_card_flags_the_account_for_next_time(self):
        """The signal that can only be seen after the fact.

        Decline, decline, decline, approve is what a successful card validation
        looks like. We cannot block the attempt that just succeeded, so it raises
        a risk flag that makes the *next* attempt score on its own.
        """
        user_id = uuid.uuid4()
        for _ in range(T_DECLINE_BURST):
            await carding.record_outcome(
                user_id=user_id, ip="203.0.113.12", card_fingerprint=_card(3), approved=False
            )
        await carding.record_outcome(
            user_id=user_id, ip="203.0.113.12", card_fingerprint=_card(4), approved=True
        )

        assessment = await _assess(user_id, _card(5))
        assert "recent_card_validation" in [h.rule for h in assessment.hits]

    async def test_an_ordinary_success_does_not_flag_anything(self):
        user_id = uuid.uuid4()
        await carding.record_outcome(
            user_id=user_id, ip="203.0.113.13", card_fingerprint=_card(6), approved=True
        )
        assessment = await _assess(user_id, _card(6))
        assert "recent_card_validation" not in [h.rule for h in assessment.hits]


class TestScoringAndDecisions:
    def test_bands(self):
        assert Assessment(score=0).decision is Decision.ALLOW
        assert Assessment(score=29).decision is Decision.ALLOW
        assert Assessment(score=30).decision is Decision.CHALLENGE
        assert Assessment(score=SCORE_BLOCK).decision is Decision.BLOCK

    def test_severity_tracks_the_decision(self):
        assert Assessment(score=0).severity == "info"
        assert Assessment(score=35).severity == "medium"
        assert Assessment(score=80).severity == "high"

    async def test_a_clean_first_payment_is_allowed(self):
        assessment = await _assess(uuid.uuid4(), _card(7))
        assert assessment.decision is Decision.ALLOW
        assert assessment.score == 0
        assert assessment.hits == []


class TestDetectionIsExplainable:
    async def test_the_event_carries_the_rules_and_the_counts(self, db):
        """A feed that says "blocked" and nothing else is not a detection surface."""
        user_id = uuid.uuid4()
        for n in range(T_DISTINCT_CARDS + 1):
            await _assess(user_id, _card(100 + n))

        event = await db.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.actor_user_id == user_id)
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.event_type in {
            SecurityEventType.CARDING_SUSPECTED,
            SecurityEventType.CARDING_BLOCKED,
        }
        assert "distinct_cards_per_account" in event.detail["rules_hit"]

        hit = next(h for h in event.detail["hits"] if h["rule"] == "distinct_cards_per_account")
        assert hit["observed"] >= hit["threshold"]
        assert hit["window_seconds"] > 0
        assert hit["note"]


class TestEndToEndBlocking:
    async def test_a_blocked_payment_never_reaches_the_gateway(self, client, user, make_flight, db):
        """Score high enough to block, then confirm the charge is not attempted."""
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        # Push this account over the block threshold: many distinct cards (40)
        # plus a decline burst (35) is 75, comfortably past 60.
        for n in range(T_DISTINCT_CARDS + 1):
            await _assess(user.id, _card(200 + n), ip=None)
        for _ in range(6):
            await carding.record_outcome(
                user_id=user.id, ip=None, card_fingerprint=_card(201), approved=False
            )

        before = get_gateway().authorization_count()
        response = await book(client, user, [hold])

        assert response.status_code == 403
        assert response.json()["code"] == "payment_blocked"
        assert response.json()["risk_score"] >= SCORE_BLOCK
        assert get_gateway().authorization_count() == before, "the card was not charged"

        booking = await db.scalar(select(Booking).where(Booking.user_id == user.id))
        assert booking.state == "PAYMENT_FAILED"

    async def test_a_declined_booking_feeds_the_windows(self, client, user, make_flight, db):
        """The saga must actually report outcomes back to the detector."""
        flight = await make_flight(seats=4)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        assert (await book(client, user, [hold], card_token=DECLINE_TOKEN)).status_code == 402

        event = await db.scalar(
            select(SecurityEvent)
            .where(
                SecurityEvent.event_type == SecurityEventType.PAYMENT_DECLINED,
                SecurityEvent.actor_user_id == user.id,
            )
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.detail["failure_code"] == "insufficient_funds"

    async def test_detection_failing_open_does_not_break_booking(
        self, client, user, make_flight, monkeypatch
    ):
        """Redis being down degrades detection; it must not stop revenue."""
        flight = await make_flight(seats=2)
        hold = await hold_seat(client, user, flight.id, flight.seat_numbers[0])

        async def exploding_touch(*args, **kwargs):
            raise ConnectionError("redis is down")

        monkeypatch.setattr(carding, "_touch", exploding_touch)
        monkeypatch.setattr(carding, "_count", exploding_touch)

        response = await book(client, user, [hold])
        assert response.status_code == 201
