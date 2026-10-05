"""Development-only audit-chain diagnostics."""

from flask import Blueprint, current_app, jsonify

from app.core.audit_chain import verify_chain
from app.database import get_session
from app.extensions import limiter
from app.models.auth_event import AuthEvent


admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/verify-chain")
@limiter.limit(lambda: current_app.config["RATE_LIMIT_ADMIN_DIAGNOSTICS"])
def verify_audit_chain():
    events = (
        get_session()
        .query(AuthEvent)
        .order_by(AuthEvent.id.asc())
        .all()
    )
    event_dicts = [
        {
            "id": event.id,
            "user_id": event.user_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp,
            "prev_hash": event.prev_hash,
            "this_hash": event.this_hash,
        }
        for event in events
    ]
    valid, broken_event_id = verify_chain(event_dicts)
    if valid:
        return jsonify({"valid": True, "event_count": len(event_dicts)}), 200
    return jsonify(
        {
            "valid": False,
            "broken_at_event_id": broken_event_id,
            "event_count": len(event_dicts),
        }
    ), 200
