import pytest

from app.core.audit_chain import GENESIS_HASH, compute_event_hash, verify_chain


def build_valid_chain(count: int) -> list[dict]:
    """Build a linked sequence of correctly hashed audit events."""
    events = []
    previous_hash = GENESIS_HASH
    for event_id in range(1, count + 1):
        event_type = "register" if event_id == 1 else "login_success"
        timestamp = f"2026-10-01T00:00:{event_id:02d}+00:00"
        user_id = None if event_id == 3 else f"user-{event_id}"
        this_hash = compute_event_hash(
            previous_hash, event_type, timestamp, user_id
        )
        events.append(
            {
                "id": event_id,
                "user_id": user_id,
                "event_type": event_type,
                "timestamp": timestamp,
                "prev_hash": previous_hash,
                "this_hash": this_hash,
            }
        )
        previous_hash = this_hash
    return events


def test_empty_chain_is_valid():
    assert verify_chain([]) == (True, None)


def test_single_valid_event_is_valid():
    event = {
        "id": 1,
        "user_id": "user-1",
        "event_type": "register",
        "timestamp": "2026-10-01T00:00:01+00:00",
        "prev_hash": GENESIS_HASH,
    }
    event["this_hash"] = compute_event_hash(
        event["prev_hash"],
        event["event_type"],
        event["timestamp"],
        event["user_id"],
    )

    assert verify_chain([event]) == (True, None)


def test_valid_five_event_chain_is_valid():
    assert verify_chain(build_valid_chain(5)) == (True, None)


@pytest.mark.parametrize("field", ["event_type", "timestamp", "user_id"])
def test_tampered_event_content_returns_that_event_id(field):
    events = build_valid_chain(5)
    broken_event_id = events[2]["id"]
    events[2][field] = "tampered-value"

    assert verify_chain(events) == (False, broken_event_id)


def test_broken_previous_hash_link_returns_that_event_id():
    events = build_valid_chain(5)
    broken_event_id = events[2]["id"]
    previous_hash = events[1]["this_hash"]
    events[2]["prev_hash"] = "f" * 64
    if events[2]["prev_hash"] == previous_hash:
        events[2]["prev_hash"] = "e" * 64

    assert verify_chain(events) == (False, broken_event_id)


def test_first_event_must_link_to_genesis_hash():
    events = build_valid_chain(5)
    first_event_id = events[0]["id"]
    events[0]["prev_hash"] = "a" * 64

    assert verify_chain(events) == (False, first_event_id)


def test_event_hash_is_deterministic_and_sensitive_to_each_input():
    inputs = ("a" * 64, "login_success", "2026-10-01T00:00:00Z", "user-1")
    original = compute_event_hash(*inputs)

    assert compute_event_hash(*inputs) == original
    for index in range(len(inputs)):
        changed = list(inputs)
        changed[index] = "different-value"
        assert compute_event_hash(*changed) != original


def test_none_and_empty_user_id_have_the_same_hash_by_design():
    common_inputs = ("a" * 64, "login_failure", "2026-10-01T00:00:00Z")

    assert compute_event_hash(*common_inputs, None) == compute_event_hash(
        *common_inputs, ""
    )
