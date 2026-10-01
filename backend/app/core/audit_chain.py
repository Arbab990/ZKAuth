"""Pure helpers for building and verifying the ZKAuth audit hash chain."""

import hashlib


GENESIS_HASH = "0" * 64


def compute_event_hash(
    prev_hash: str,
    event_type: str,
    timestamp: str,
    user_id: str | None,
) -> str:
    """Return the SHA-256 hash of one pipe-delimited audit event."""
    payload = f"{prev_hash}|{event_type}|{timestamp}|{user_id or ''}"
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_chain(events: list[dict]) -> tuple[bool, int | None]:
    """Verify events ordered oldest to newest; return the first broken event id."""
    expected_prev = GENESIS_HASH
    for event in events:
        if event["prev_hash"] != expected_prev:
            return False, event["id"]
        recomputed = compute_event_hash(
            event["prev_hash"],
            event["event_type"],
            event["timestamp"],
            event["user_id"],
        )
        if recomputed != event["this_hash"]:
            return False, event["id"]
        expected_prev = event["this_hash"]
    return True, None
