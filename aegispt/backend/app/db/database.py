"""Async SQLite (WAL mode) database engine and session management."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def configure_database(db_url: str | None = None) -> AsyncEngine:
    """Initialize (or reconfigure, e.g. for tests) the async SQLAlchemy engine."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.sync_engine.dispose()
    if db_url is None:
        settings = get_settings()
        db_url = f"sqlite+aiosqlite:///{settings.db_path}"

    engine = create_async_engine(
        db_url,
        echo=False,
        future=True,
        connect_args={"timeout": 30},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=5000;")
        finally:
            cursor.close()

    _engine = engine
    _session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    return engine


def get_engine() -> AsyncEngine:
    if _engine is None:
        return configure_database()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    if _session_factory is None:
        configure_database()
    assert _session_factory is not None
    return _session_factory


def _ensure_sqlite_columns(sync_conn) -> None:
    """Idempotently add new V4 columns when upgrading existing SQLite databases."""
    migrations: list[tuple[str, str, str]] = [
        ("engagements", "operator_hints", "JSON DEFAULT '[]'"),
        ("scope_policies", "secondary_headers", "JSON DEFAULT '{}'"),
        ("scope_policies", "secondary_cookies", "JSON DEFAULT '{}'"),
        ("findings", "corroborated_by", "JSON DEFAULT '[]'"),
        ("findings", "verified_at", "DATETIME"),
    ]
    existing_tables = {
        row[0]
        for row in sync_conn.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for table, col, col_def in migrations:
        if table not in existing_tables:
            continue
        cols = {
            row[1]
            for row in sync_conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        }
        if col not in cols:
            sync_conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")


async def init_db(db_url: str | None = None) -> None:
    """Create missing tables and auto-migrate new columns safely."""
    from app.db import models  # noqa: F401

    target_url = db_url or f"sqlite+aiosqlite:///{get_settings().db_path}"
    if _engine is not None and str(_engine.url) != target_url:
        await close_db()
    engine = configure_database(target_url) if _engine is None else _engine
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_ensure_sqlite_columns)
    except Exception:
        await close_db()
        raise
    get_settings().enforce_storage_permissions()


async def close_db() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
