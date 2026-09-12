import redis.asyncio as redis

from app.config import settings

_pool = redis.ConnectionPool.from_url(
    settings.redis_url,
    decode_responses=True,
    max_connections=50,
)


def get_redis() -> redis.Redis:
    """Redis holds only derived state: rate-limit windows, velocity counters,
    and dashboard caches. Nothing here is a source of truth — see docs/ADR-0001.
    """
    return redis.Redis(connection_pool=_pool)


async def close_redis() -> None:
    await _pool.aclose()
