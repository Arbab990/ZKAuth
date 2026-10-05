from app.core.audit_chain import verify_chain
from app.models.auth_event import AuthEvent
from app.models.user import User


def registration_payload(username="alice"):
    return {"username": username, "salt": "a1b2c3", "verifier": "deadbeef"}


def test_register_creates_user_and_returns_user_id(client, db_session):
    response = client.post("/api/register", json=registration_payload())

    assert response.status_code == 201
    user_id = response.get_json()["user_id"]
    user = db_session.query(User).filter_by(id=user_id).one_or_none()
    assert user is not None
    assert user.username == "alice"


def test_register_duplicate_username_returns_409(client):
    assert client.post("/api/register", json=registration_payload()).status_code == 201

    response = client.post("/api/register", json=registration_payload())

    assert response.status_code == 409
    assert response.get_json() == {"error": "registration failed"}


def test_register_missing_username_returns_400(client):
    payload = registration_payload()
    payload.pop("username")

    response = client.post("/api/register", json=payload)

    assert response.status_code == 400


def test_register_missing_verifier_returns_400(client):
    payload = registration_payload()
    payload.pop("verifier")

    response = client.post("/api/register", json=payload)

    assert response.status_code == 400


def test_public_key_returns_loaded_pem(client, keypair_files):
    response = client.get("/api/public-key")

    assert response.status_code == 200
    assert response.get_json()["public_key_pem"] == keypair_files["public_key_path"].read_text(
        encoding="ascii"
    )


def test_registration_events_form_a_valid_audit_chain(client, db_session):
    first = client.post("/api/register", json=registration_payload("alice"))
    second = client.post("/api/register", json=registration_payload("bob"))
    assert first.status_code == 201
    assert second.status_code == 201

    events = db_session.query(AuthEvent).order_by(AuthEvent.id).all()
    plain_events = [
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

    assert verify_chain(plain_events) == (True, None)


def test_admin_verify_chain_is_disabled_by_default(client):
    response = client.get("/api/admin/verify-chain")

    assert response.status_code == 404


def test_admin_verify_chain_reports_event_count(app_factory):
    app = app_factory(ENABLE_ADMIN_DIAGNOSTICS=True)
    with app.test_client() as client:
        first = client.post(
            "/api/register", json=registration_payload("alice")
        )
        second = client.post(
            "/api/register", json=registration_payload("bob")
        )
        assert first.status_code == 201
        assert second.status_code == 201

        response = client.get("/api/admin/verify-chain")

    assert response.status_code == 200
    assert response.get_json() == {"valid": True, "event_count": 2}


def test_admin_verify_chain_is_rate_limited(app_factory):
    app = app_factory(
        ENABLE_ADMIN_DIAGNOSTICS=True,
        RATE_LIMIT_ADMIN_DIAGNOSTICS="1 per minute",
    )
    with app.test_client() as client:
        assert client.get("/api/admin/verify-chain").status_code == 200
        response = client.get("/api/admin/verify-chain")

    assert response.status_code == 429
