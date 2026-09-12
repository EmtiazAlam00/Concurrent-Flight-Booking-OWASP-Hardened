"""Pure-logic tests. No datastores, so these run anywhere."""

from decimal import Decimal

import pytest

from app.domain.enums import BookingState
from app.domain.money import money, total
from app.domain.pnr import PNR_ALPHABET, PNR_LENGTH, generate_eticket_number, generate_pnr
from app.domain.states import IllegalTransition, assert_can_transition, require_state
from app.errors import InvalidStateTransition
from app.security.hashing import (
    card_fingerprint,
    hash_password,
    needs_rehash,
    normalize_email,
    verify_password,
)
from app.services.demo_triggers import Trigger, trigger_for
from app.services.idempotency import request_hash


class TestMoney:
    def test_quantizes_to_cents(self):
        assert money(Decimal("10.005")) == Decimal("10.01")
        assert money("3.1") == Decimal("3.10")
        assert str(money(7)) == "7.00"

    def test_half_up_not_bankers_rounding(self):
        # Python's default for Decimal is ROUND_HALF_EVEN, which would give 2.22.
        # Money conventions expect half-up, and a silent difference here is the
        # kind of bug that shows up as a one-cent reconciliation gap.
        assert money(Decimal("2.225")) == Decimal("2.23")

    def test_total_sums_exactly(self):
        amounts = [Decimal("0.10")] * 10
        assert total(amounts) == Decimal("1.00")

    def test_no_float_drift(self):
        # The float version of this sum is 0.9999999999999999.
        assert total([Decimal("0.1")] * 3 + [Decimal("0.7")]) == Decimal("1.00")


class TestPnr:
    def test_shape(self):
        pnr = generate_pnr()
        assert len(pnr) == PNR_LENGTH
        assert set(pnr) <= set(PNR_ALPHABET)

    def test_excludes_ambiguous_characters(self):
        # 0/O and 1/I get misread when a PNR is read aloud or handwritten.
        assert not (set("01IO") & set(PNR_ALPHABET))

    def test_reasonably_collision_free(self):
        assert len({generate_pnr() for _ in range(2000)}) > 1990

    def test_eticket_shape(self):
        number = generate_eticket_number()
        assert len(number) == 13 and number.isdigit()


class TestStateMachine:
    def test_happy_path_is_legal(self):
        assert_can_transition(BookingState.PENDING, BookingState.PAYMENT_AUTHORIZED)
        assert_can_transition(BookingState.PAYMENT_AUTHORIZED, BookingState.TICKETED)
        assert_can_transition(BookingState.TICKETED, BookingState.CONFIRMED)

    def test_cannot_skip_payment(self):
        with pytest.raises(IllegalTransition):
            assert_can_transition(BookingState.PENDING, BookingState.CONFIRMED)

    def test_cannot_resurrect_a_terminal_booking(self):
        for terminal in (
            BookingState.PAYMENT_FAILED,
            BookingState.VOIDED,
            BookingState.CANCELLED,
        ):
            with pytest.raises(IllegalTransition):
                assert_can_transition(terminal, BookingState.CONFIRMED)

    def test_compensation_can_reach_manual_review(self):
        assert_can_transition(BookingState.COMPENSATING, BookingState.NEEDS_MANUAL_REVIEW)

    def test_require_state_is_caller_facing(self):
        # Distinct from IllegalTransition: this one is a 409 for the client.
        with pytest.raises(InvalidStateTransition):
            require_state(BookingState.PAYMENT_FAILED, BookingState.CONFIRMED)


class TestIdempotencyHash:
    def test_field_order_does_not_matter(self):
        assert request_hash({"a": 1, "b": 2}) == request_hash({"b": 2, "a": 1})

    def test_different_body_different_hash(self):
        assert request_hash({"seat": "14C"}) != request_hash({"seat": "14D"})

    def test_nested_structures_are_stable(self):
        left = {"passengers": [{"name": "Ada", "dob": "1990-01-01"}]}
        right = {"passengers": [{"dob": "1990-01-01", "name": "Ada"}]}
        assert request_hash(left) == request_hash(right)


class TestDemoTriggers:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("tok_test_aaaa11110000", Trigger.APPROVE),
            ("tok_test_aaaa11110002", Trigger.DECLINE_INSUFFICIENT_FUNDS),
            ("tok_test_aaaa11110069", Trigger.DECLINE_DO_NOT_HONOR),
            ("tok_test_aaaa11119995", Trigger.TICKETING_FAILURE),
            ("tok_test_aaaa11110119", Trigger.GATEWAY_TIMEOUT_THEN_OK),
            ("tok_test_aaaa11115309", Trigger.REFUND_FAILURE),
            ("tok_test_unknownsuffix", Trigger.APPROVE),
        ],
    )
    def test_suffix_selects_behaviour(self, token, expected):
        assert trigger_for(token) is expected


class TestPasswordHashing:
    def test_round_trip(self):
        digest = hash_password("a-long-enough-password")
        assert digest != "a-long-enough-password"
        assert verify_password("a-long-enough-password", digest)
        assert not verify_password("a-long-enough-passwore", digest)

    def test_salted(self):
        assert hash_password("same-password-twice") != hash_password("same-password-twice")

    def test_uses_argon2id(self):
        assert hash_password("x" * 20).startswith("$argon2id$")

    def test_missing_hash_is_false_not_an_error(self):
        # The no-such-user path must not raise, or login becomes an oracle.
        assert verify_password("anything", None) is False

    def test_garbage_hash_is_flagged_for_rehash(self):
        assert needs_rehash("not-a-hash") is True

    def test_email_normalization(self):
        assert normalize_email("  Ada@Example.COM ") == "ada@example.com"


class TestCardFingerprint:
    def test_stable_and_opaque(self):
        token = "tok_test_aaaa11110000"
        assert card_fingerprint(token) == card_fingerprint(token)
        assert token not in card_fingerprint(token)

    def test_distinguishes_cards(self):
        assert card_fingerprint("tok_test_aaaa11110000") != card_fingerprint(
            "tok_test_aaaa11110002"
        )
