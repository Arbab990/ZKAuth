"""User registration service."""

from app.models.user import User
from app.services.audit_service import append_event


class UsernameTakenError(Exception):
    """Raised when a registration uses an existing username."""


def register_user(username: str, salt: str, verifier: str, session) -> User:
    """Create a user and registration audit event in one transaction."""
    if session.query(User).filter_by(username=username).first():
        raise UsernameTakenError()

    user = User(username=username, salt=salt, verifier=verifier)
    session.add(user)
    session.flush()
    append_event(session, "register", user.id)
    session.commit()
    return user
