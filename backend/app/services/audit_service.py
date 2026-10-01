"""Audit event persistence service."""

from datetime import datetime, timezone

from app.core.audit_chain import GENESIS_HASH, compute_event_hash
from app.models.auth_event import AuthEvent


def append_event(session, event_type: str, user_id: str | None) -> None:
    """Append an event linked to the latest event in the same transaction."""
    last_event = session.query(AuthEvent).order_by(AuthEvent.id.desc()).first()
    prev_hash = last_event.this_hash if last_event else GENESIS_HASH
    timestamp = datetime.now(timezone.utc).isoformat()
    this_hash = compute_event_hash(prev_hash, event_type, timestamp, user_id)
    session.add(
        AuthEvent(
            user_id=user_id,
            event_type=event_type,
            timestamp=timestamp,
            prev_hash=prev_hash,
            this_hash=this_hash,
        )
    )
