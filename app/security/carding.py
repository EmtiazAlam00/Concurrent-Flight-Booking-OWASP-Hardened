"""Card-testing (carding) detection.

Airlines are a favourite target for validating stolen cards: tickets are high
value, instantly fungible, and a booking flow gives an attacker a cheap
authorize/void oracle. So the signal we're looking for is not "one bad payment",
it's *shape over time*: many cards on one account, bursts of declines, and the
tell-tale decline-decline-decline-approve sequence that means a card was just
validated.

Windows live in Redis sorted sets (same structure as the rate limiter). Redis is
derived state here: losing it loses recent history, which degrades detection but
cannot corrupt a booking. Every assessment writes a SecurityEvent row to
Postgres carrying the rule hits, so the dashboard can explain *why* something
tripped — the difference between a log and a detection surface.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from fastapi import Request

from app.domain.enums import Decision, SecurityEventType, Severity
from app.redis_client import get_redis
from app.security.events import record_security_event_bg

logger = logging.getLogger("skylock.carding")

# --- windows ----------------------------------------------------------------

W_DISTINCT_CARDS = 3600  # 1h
W_CARD_ACROSS_ACCOUNTS = 86400  # 24h
W_DECLINES = 600  # 10m
W_OUTCOME_SEQUENCE = 900  # 15m
W_RAPID_BOOKINGS = 120  # 2m
W_SMALL_AMOUNTS = 3600  # 1h
W_RISK_FLAG = 1800  # 30m — how long a confirmed validation keeps an account hot

# --- thresholds -------------------------------------------------------------

T_DISTINCT_CARDS = 4
T_DECLINES_PER_ACCOUNT = 5
T_DECLINES_PER_IP = 8
T_DECLINE_BURST = 3
T_CARD_ACCOUNTS = 3
T_RAPID_BOOKINGS = 3
T_SMALL_AMOUNTS = 5
SMALL_AMOUNT_CEILING = Decimal("40.00")

# --- scoring ----------------------------------------------------------------

SCORE_BLOCK = 60
SCORE_CHALLENGE = 30


@dataclass(frozen=True)
class RuleHit:
    rule: str
    score: int
    observed: int
    threshold: int
    window_seconds: int
    note: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "score": self.score,
            "observed": self.observed,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "note": self.note,
        }


@dataclass
class Assessment:
    score: int = 0
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def decision(self) -> Decision:
        if self.score >= SCORE_BLOCK:
            return Decision.BLOCK
        if self.score >= SCORE_CHALLENGE:
            return Decision.CHALLENGE
        return Decision.ALLOW

    @property
    def severity(self) -> Severity:
        if self.score >= SCORE_BLOCK:
            return Severity.HIGH
        if self.score >= SCORE_CHALLENGE:
            return Severity.MEDIUM
        return Severity.INFO

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "decision": str(self.decision),
            "rules_hit": [h.rule for h in self.hits],
            "hits": [h.as_dict() for h in self.hits],
        }


# --- redis window helpers ---------------------------------------------------


def _now_ms() -> int:
    return int(time.time() * 1000)


async def _touch(key: str, member: str, window_seconds: int) -> int:
    """Add `member` to a time-ordered set and return the distinct count in window.

    Using the member value itself (a card fingerprint, a user id) makes the set
    naturally de-duplicating, which is what "distinct cards" needs. Callers that
    want an event *count* instead pass a unique member.
    """
    now = _now_ms()
    redis = get_redis()
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, now - window_seconds * 1000)
    pipe.zadd(key, {member: now})
    pipe.zcard(key)
    pipe.expire(key, window_seconds + 1)
    results = await pipe.execute()
    return int(results[2])


async def _count(key: str, window_seconds: int) -> int:
    now = _now_ms()
    redis = get_redis()
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, now - window_seconds * 1000)
    pipe.zcard(key)
    results = await pipe.execute()
    return int(results[1])


async def _members(key: str, window_seconds: int) -> list[str]:
    now = _now_ms()
    redis = get_redis()
    await redis.zremrangebyscore(key, 0, now - window_seconds * 1000)
    # decode_responses=True is set on the pool, so members come back as str.
    return [str(member) for member in await redis.zrange(key, 0, -1)]


# --- key layout -------------------------------------------------------------


def _k_distinct_cards(user_id: Any) -> str:
    return f"cd:cards:u:{user_id}"


def _k_card_accounts(fingerprint: str) -> str:
    return f"cd:accts:fp:{fingerprint}"


def _k_declines_user(user_id: Any) -> str:
    return f"cd:dec:u:{user_id}"


def _k_declines_ip(ip: str) -> str:
    return f"cd:dec:ip:{ip}"


def _k_outcomes(user_id: Any) -> str:
    return f"cd:out:u:{user_id}"


def _k_bookings(user_id: Any) -> str:
    return f"cd:bk:u:{user_id}"


def _k_small(user_id: Any) -> str:
    return f"cd:small:u:{user_id}"


def _k_risk(user_id: Any) -> str:
    return f"cd:risk:u:{user_id}"


# --- the rules --------------------------------------------------------------


async def assess_payment_attempt(
    *,
    user_id: Any,
    ip: str | None,
    card_fingerprint: str,
    amount: Decimal,
    request: Request | None = None,
) -> Assessment:
    """Evaluate an about-to-happen payment. Called before the gateway is hit."""
    assessment = Assessment()

    try:
        distinct_cards = await _touch(
            _k_distinct_cards(user_id), card_fingerprint, W_DISTINCT_CARDS
        )
        card_accounts = await _touch(
            _k_card_accounts(card_fingerprint), str(user_id), W_CARD_ACROSS_ACCOUNTS
        )
        rapid_bookings = await _touch(_k_bookings(user_id), uuid.uuid4().hex, W_RAPID_BOOKINGS)
        declines_user = await _count(_k_declines_user(user_id), W_DECLINES)
        declines_ip = await _count(_k_declines_ip(ip), W_DECLINES) if ip else 0
        small_count = (
            await _touch(_k_small(user_id), uuid.uuid4().hex, W_SMALL_AMOUNTS)
            if amount <= SMALL_AMOUNT_CEILING
            else await _count(_k_small(user_id), W_SMALL_AMOUNTS)
        )
        risk_flag = await get_redis().get(_k_risk(user_id))
    except Exception:  # noqa: BLE001
        # Detection unavailable. Fail open but say so loudly: a silent gap in
        # fraud controls is worse than a noisy one.
        logger.warning("carding detection unavailable; allowing payment attempt")
        return assessment

    # R1 — one account trying many different cards is the core carding pattern.
    if distinct_cards >= T_DISTINCT_CARDS:
        assessment.hits.append(
            RuleHit(
                "distinct_cards_per_account",
                40,
                distinct_cards,
                T_DISTINCT_CARDS,
                W_DISTINCT_CARDS,
                "account has attempted an unusual number of different cards",
            )
        )

    # R2 — decline volume on one account.
    if declines_user >= T_DECLINES_PER_ACCOUNT:
        assessment.hits.append(
            RuleHit(
                "declines_per_account",
                35,
                declines_user,
                T_DECLINES_PER_ACCOUNT,
                W_DECLINES,
                "repeated declines on this account",
            )
        )

    # R3 — decline volume from one address, across accounts.
    if declines_ip >= T_DECLINES_PER_IP:
        assessment.hits.append(
            RuleHit(
                "declines_per_ip",
                30,
                declines_ip,
                T_DECLINES_PER_IP,
                W_DECLINES,
                "repeated declines from this address",
            )
        )

    # R4 — one card appearing on several accounts means a stolen-card list is
    # being worked through, not that a family shares a card.
    if card_accounts >= T_CARD_ACCOUNTS:
        assessment.hits.append(
            RuleHit(
                "card_across_accounts",
                45,
                card_accounts,
                T_CARD_ACCOUNTS,
                W_CARD_ACROSS_ACCOUNTS,
                "this card has been used on multiple accounts",
            )
        )

    # R5 — humans do not book three times in two minutes.
    if rapid_bookings >= T_RAPID_BOOKINGS:
        assessment.hits.append(
            RuleHit(
                "rapid_fire_bookings",
                25,
                rapid_bookings,
                T_RAPID_BOOKINGS,
                W_RAPID_BOOKINGS,
                "booking attempts faster than a human checkout",
            )
        )

    # R6 — low-value auths are how you test a card cheaply.
    if small_count >= T_SMALL_AMOUNTS:
        assessment.hits.append(
            RuleHit(
                "small_amount_velocity",
                20,
                small_count,
                T_SMALL_AMOUNTS,
                W_SMALL_AMOUNTS,
                f"many auths at or below {SMALL_AMOUNT_CEILING}",
            )
        )

    # R7 — set by record_outcome when a decline burst was followed by a success.
    # That sequence is retrospective evidence that a card was just validated, so
    # it keeps the account hot for the next attempt rather than being lost.
    if risk_flag:
        assessment.hits.append(
            RuleHit(
                "recent_card_validation",
                50,
                1,
                1,
                W_RISK_FLAG,
                "a decline burst was recently followed by a success on this account",
            )
        )

    assessment.score = sum(h.score for h in assessment.hits)

    if assessment.decision is not Decision.ALLOW:
        await record_security_event_bg(
            request,
            SecurityEventType.CARDING_BLOCKED
            if assessment.decision is Decision.BLOCK
            else SecurityEventType.CARDING_SUSPECTED,
            assessment.severity,
            actor_user_id=user_id,
            resource_type="payment_attempt",
            resource_id=card_fingerprint[:12],
            decision=str(assessment.decision),
            detail=assessment.as_dict(),
        )
    return assessment


async def record_outcome(
    *,
    user_id: Any,
    ip: str | None,
    card_fingerprint: str,
    approved: bool,
    request: Request | None = None,
) -> None:
    """Feed the result of a payment attempt back into the windows.

    This is where decline-burst-then-success is detected. It can only be seen
    after the fact, so instead of blocking the request that just succeeded we
    raise a risk flag that makes the *next* attempt from this account score 50
    on its own.
    """
    try:
        outcome = "approve" if approved else "decline"
        await _touch(_k_outcomes(user_id), f"{_now_ms()}:{outcome}", W_OUTCOME_SEQUENCE)
        if not approved:
            await _touch(_k_declines_user(user_id), uuid.uuid4().hex, W_DECLINES)
            if ip:
                await _touch(_k_declines_ip(ip), uuid.uuid4().hex, W_DECLINES)
            return

        # Approved: look back over the window for a decline burst immediately
        # before this success.
        members = await _members(_k_outcomes(user_id), W_OUTCOME_SEQUENCE)
        trailing_declines = 0
        for member in reversed(members[:-1]):  # skip the approval we just added
            if member.endswith(":decline"):
                trailing_declines += 1
            else:
                break

        if trailing_declines >= T_DECLINE_BURST:
            await get_redis().set(_k_risk(user_id), "card_validated", ex=W_RISK_FLAG)
            await record_security_event_bg(
                request,
                SecurityEventType.CARDING_SUSPECTED,
                Severity.HIGH,
                actor_user_id=user_id,
                resource_type="payment_attempt",
                resource_id=card_fingerprint[:12],
                decision="flag_account",
                detail={
                    "rule": "decline_burst_then_success",
                    "trailing_declines": trailing_declines,
                    "threshold": T_DECLINE_BURST,
                    "window_seconds": W_OUTCOME_SEQUENCE,
                    "note": (
                        "a card was validated after a run of failures; account "
                        f"flagged for {W_RISK_FLAG}s"
                    ),
                },
            )
    except Exception:  # noqa: BLE001
        logger.warning("failed to record carding outcome", exc_info=True)
