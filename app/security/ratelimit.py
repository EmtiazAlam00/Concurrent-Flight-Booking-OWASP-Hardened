"""Sliding-window rate limiting backed by Redis sorted sets.

A sorted set per (bucket, subject) holds one member per request, scored by
timestamp. Each check trims everything older than the window and counts what's
left — so there is no fixed-window edge where 2x the limit slips through at a
boundary.

Redis failing open is a deliberate choice for a portfolio service: an outage in
the limiter should not take down booking. In a payments-critical deployment you
would fail *closed* on the payment bucket specifically; that tradeoff is noted
in SECURITY.md.
"""

import logging
import time
import uuid
from dataclasses import dataclass

from fastapi import Request

from app.config import settings
from app.domain.enums import SecurityEventType, Severity
from app.errors import RateLimited
from app.redis_client import get_redis
from app.security.events import client_ip, record_security_event_bg

logger = logging.getLogger("skylock.ratelimit")


@dataclass(frozen=True)
class Limit:
    name: str
    max_requests: int
    window_seconds: int

    @property
    def retry_after(self) -> int:
        return self.window_seconds


# Tight buckets where abuse is cheap and damaging; loose everywhere else.
LIMITS = {
    "login": Limit("login", max_requests=10, window_seconds=300),
    # 10/hour/IP: tight enough that scripted account farming shows up quickly,
    # loose enough that a shared office NAT or a family setting up accounts is
    # not collateral damage.
    "register": Limit("register", max_requests=10, window_seconds=3600),
    "refresh": Limit("refresh", max_requests=30, window_seconds=300),
    "hold": Limit("hold", max_requests=30, window_seconds=60),
    "booking": Limit("booking", max_requests=10, window_seconds=60),
    "search": Limit("search", max_requests=120, window_seconds=60),
    "global": Limit("global", max_requests=600, window_seconds=60),
}


async def check_limit(limit: Limit, subject: str, request: Request | None = None) -> None:
    """Raise RateLimited if `subject` has exceeded `limit`."""
    if not settings.rate_limit_enabled:
        return

    key = f"rl:{limit.name}:{subject}"
    now_ms = int(time.time() * 1000)
    cutoff = now_ms - limit.window_seconds * 1000

    try:
        redis = get_redis()
        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zadd(key, {f"{now_ms}-{uuid.uuid4().hex[:8]}": now_ms})
        pipe.zcard(key)
        pipe.expire(key, limit.window_seconds + 1)
        results = await pipe.execute()
        count = int(results[2])
    except Exception:  # noqa: BLE001
        logger.warning("rate limiter unavailable; failing open for %s", limit.name)
        return

    if count > limit.max_requests:
        await record_security_event_bg(
            request,
            SecurityEventType.RATE_LIMITED,
            Severity.LOW,
            decision="block",
            detail={
                "bucket": limit.name,
                "subject": subject,
                "count": count,
                "limit": limit.max_requests,
                "window_seconds": limit.window_seconds,
            },
        )
        raise RateLimited(
            f"Rate limit exceeded for {limit.name}: "
            f"{limit.max_requests} requests per {limit.window_seconds}s",
            retry_after=limit.retry_after,
        )


def rate_limit(bucket: str):
    """FastAPI dependency factory.

    Limits per-IP always, and additionally per-user when the caller is
    authenticated — so one compromised account cannot rotate through IPs to get
    a fresh allowance, and one NAT'd office cannot lock out its own users.
    """
    limit = LIMITS[bucket]

    async def _dep(request: Request) -> None:
        ip = client_ip(request) or "unknown"
        await check_limit(limit, f"ip:{ip}", request)
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            await check_limit(limit, f"user:{user_id}", request)

    return _dep
