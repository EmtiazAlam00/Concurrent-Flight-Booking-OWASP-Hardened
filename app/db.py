import typing
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.engine import CursorResult, Result
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine = create_async_engine(
    settings.database_url,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    # Row locks are the whole point of this service; never let the ORM decide
    # to reuse a connection mid-transaction.
    future=True,
)

SessionLocal = async_sessionmaker(
    _engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


def get_engine() -> AsyncEngine:
    return _engine


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request, rolled back on error."""
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Standalone session for jobs, scripts, and out-of-band writes.

    Security events use this so that recording "we denied you" survives a
    rollback of the business transaction that did the denying.
    """
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def rows_affected(result: Result) -> int:
    """Number of rows an UPDATE/DELETE touched.

    `AsyncSession.execute` is typed as returning `Result`, but a DML statement
    actually returns a `CursorResult`, which is where `rowcount` lives. One
    narrow cast here beats scattering `type: ignore` across every caller — and
    the row count matters: for a conditional UPDATE, zero rows *is* the answer.
    """
    return int(typing.cast(CursorResult, result).rowcount or 0)
