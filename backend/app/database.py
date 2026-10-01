"""SQLAlchemy engine, session, and schema helpers."""

from flask import current_app
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Declarative base for application models."""


def init_engine(database_url: str) -> Engine:
    """Create the SQLAlchemy engine, sharing in-memory SQLite connections."""
    if database_url == "sqlite:///:memory:":
        return create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url)


def init_session_factory(engine: Engine) -> scoped_session:
    """Create a thread-scoped session registry bound to the engine."""
    return scoped_session(sessionmaker(bind=engine))


def create_all_tables(engine: Engine) -> None:
    """Import model declarations and create their tables."""
    from app.models import auth_event, session, user  # noqa: F401

    Base.metadata.create_all(engine)


def get_session():
    """Return the current app's scoped SQLAlchemy session."""
    return current_app.extensions["db_session"]()
