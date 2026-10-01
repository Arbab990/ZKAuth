"""Ephemeral login handshake session database model."""

from uuid import uuid4

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class LoginSession(Base):
    __tablename__ = "login_sessions"

    id: Mapped[str] = mapped_column(
        Text, primary_key=True, default=lambda: uuid4().hex
    )
    user_id: Mapped[str] = mapped_column(
        Text, ForeignKey("users.id"), nullable=False
    )
    server_ephemeral_secret: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[str] = mapped_column(Text, nullable=False)
