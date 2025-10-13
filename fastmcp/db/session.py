from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlmodel import Session, create_engine

from fastmcp.core.config import get_settings


settings = get_settings()
connect_args = {"check_same_thread": False} if settings.SQLITE_URL.startswith("sqlite") else {}
engine = create_engine(settings.SQLITE_URL, connect_args=connect_args)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

