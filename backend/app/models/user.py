"""User database model."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        Text, primary_key=True, default=lambda: uuid4().hex
    )
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    salt: Mapped[str] = mapped_column(Text, nullable=False)
    verifier: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )
