import pytest
from sqlalchemy import select

from app.config import settings
from app.domain.enums import SecurityEventType
from app.domain.models import SecurityEvent
from app.security.ratelimit import LIMITS

pytestmark = [pytest.mark.security, pytest.mark.integration]


@pytest.fixture
def rate_limits_on():
    original = settings.rate_limit_enabled
    settings.rate_limit_enabled = True
    yield
    settings.rate_limit_enabled = original


class TestLoginRateLimit:
    async def test_login_attempts_are_capped(self, client, make_user, rate_limits_on):
        user = await make_user()
        limit = LIMITS["login"].max_requests

        statuses = []
        for _ in range(limit + 4):
            response = await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )
            statuses.append(response.status_code)

        assert 429 in statuses, statuses
        limited = next(i for i, code in enumerate(statuses) if code == 429)
        assert limited >= limit, "the limiter must not fire before the limit"

    async def test_the_429_tells_the_client_when_to_come_back(
        self, client, make_user, rate_limits_on
    ):
        user = await make_user()
        response = None
        for _ in range(LIMITS["login"].max_requests + 2):
            response = await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )
        assert response.status_code == 429
        assert response.json()["code"] == "rate_limited"
        assert int(response.headers["Retry-After"]) > 0

    async def test_being_limited_is_recorded(self, client, make_user, db, rate_limits_on):
        user = await make_user()
        for _ in range(LIMITS["login"].max_requests + 2):
            await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password-here"}
            )

        event = await db.scalar(
            select(SecurityEvent)
            .where(SecurityEvent.event_type == SecurityEventType.RATE_LIMITED)
            .order_by(SecurityEvent.id.desc())
        )
        assert event is not None
        assert event.detail["bucket"] == "login"
        assert event.decision == "block"


class TestLimiterConfiguration:
    def test_sensitive_buckets_are_tighter_than_search(self):
        """The shape of the config is itself worth asserting."""
        assert LIMITS["login"].max_requests < LIMITS["search"].max_requests
        assert LIMITS["booking"].max_requests < LIMITS["search"].max_requests
        assert LIMITS["register"].window_seconds >= 3600

    def test_every_bucket_has_a_positive_window(self):
        for limit in LIMITS.values():
            assert limit.max_requests > 0
            assert limit.window_seconds > 0


class TestFailOpen:
    async def test_a_broken_limiter_does_not_break_the_api(
        self, client, user, monkeypatch, rate_limits_on
    ):
        """Rate limiting is a control, not a dependency.

        Failing closed here would let a Redis outage take down login for
        everyone. SECURITY.md notes where that tradeoff would go the other way.
        """
        from app.security import ratelimit

        def exploding_redis():
            raise ConnectionError("redis is down")

        monkeypatch.setattr(ratelimit, "get_redis", exploding_redis)
        response = await client.get("/auth/me", headers=user.headers)
        assert response.status_code == 200
