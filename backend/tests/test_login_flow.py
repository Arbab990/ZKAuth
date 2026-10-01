from datetime import datetime, timedelta, timezone

from app import create_app
from app.core.srp_core import (
    N,
    compute_client_proof,
    compute_client_session,
    compute_verifier,
    generate_salt,
    g,
)
from app.core.token_signer import generate_keypair, sign_token, verify_token
from app.models.session import LoginSession


def register(client, username, password):
    salt = generate_salt()
    verifier = compute_verifier(username, password, salt)
    response = client.post(
        "/api/register",
        json={"username": username, "salt": salt, "verifier": verifier},
    )
    assert response.status_code == 201
    return response.get_json()["user_id"]


def client_proof(username, password, login_init_data, a=13):
    A_hex = f"{pow(g, a, N):x}"
    client_session = compute_client_session(
        username,
        password,
        login_init_data["salt"],
        A_hex,
        f"{a:x}",
        login_init_data["server_public_ephemeral"],
    )
    M1_hex = compute_client_proof(
        A_hex,
        login_init_data["server_public_ephemeral"],
        client_session["K"],
    )
    return A_hex, M1_hex


def begin_login(client, username):
    response = client.post("/api/login/init", json={"username": username})
    assert response.status_code == 200
    return response.get_json()


def test_login_happy_path_issues_verifiable_token(client, keypair_files):
    username, password = "alice", "correct horse battery staple"
    user_id = register(client, username, password)
    login_data = begin_login(client, username)
    A_hex, M1_hex = client_proof(username, password, login_data)

    response = client.post(
        "/api/login/verify",
        json={
            "session_id": login_data["session_id"],
            "client_public_ephemeral": A_hex,
            "client_proof": M1_hex,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["token"]
    assert body["server_proof"]
    claims = verify_token(body["token"], keypair_files["public_key_pem"])
    assert claims["sub"] == user_id
    assert claims["username"] == username


def submit_wrong_password(client):
    username = "alice"
    register(client, username, "correct password")
    login_data = begin_login(client, username)
    A_hex, M1_hex = client_proof(username, "wrong password", login_data)

    response = client.post(
        "/api/login/verify",
        json={
            "session_id": login_data["session_id"],
            "client_public_ephemeral": A_hex,
            "client_proof": M1_hex,
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}
    return response


def test_wrong_password_returns_generic_login_failure(client):
    response = submit_wrong_password(client)
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}

def test_unknown_username_fails_identically_to_wrong_password(client):
    wrong_password_response = submit_wrong_password(client)
    login_data = begin_login(client, "nobody@example.test")

    assert set(login_data) == {
        "session_id",
        "salt",
        "server_public_ephemeral",
    }
    assert isinstance(login_data["session_id"], str) and login_data["session_id"]
    assert len(login_data["salt"]) == 32
    assert len(login_data["server_public_ephemeral"]) == 512

    unknown_response = client.post(
        "/api/login/verify",
        json={
            "session_id": login_data["session_id"],
            "client_public_ephemeral": "02",
            "client_proof": "00",
        },
    )

    assert unknown_response.status_code == wrong_password_response.status_code
    assert unknown_response.data == wrong_password_response.data


def test_login_session_cannot_be_replayed(client):
    username, password = "alice", "correct password"
    register(client, username, password)
    login_data = begin_login(client, username)
    A_hex, M1_hex = client_proof(username, password, login_data)
    verify_body = {
        "session_id": login_data["session_id"],
        "client_public_ephemeral": A_hex,
        "client_proof": M1_hex,
    }

    first_response = client.post("/api/login/verify", json=verify_body)
    replay_response = client.post("/api/login/verify", json=verify_body)

    assert first_response.status_code == 200
    assert replay_response.status_code == 401
    assert replay_response.get_json() == {"error": "invalid credentials"}


def test_expired_login_session_returns_generic_login_failure(
    client, db_session
):
    user_id = register(client, "alice", "password")
    now = datetime.now(timezone.utc)
    login_session = LoginSession(
        user_id=user_id,
        server_ephemeral_secret="01",
        server_public_ephemeral="02",
        created_at=(now - timedelta(minutes=10)).isoformat(),
        expires_at=(now - timedelta(minutes=5)).isoformat(),
    )
    db_session.add(login_session)
    db_session.commit()
    session_id = login_session.id

    response = client.post(
        "/api/login/verify",
        json={
            "session_id": session_id,
            "client_public_ephemeral": "02",
            "client_proof": "00",
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_malicious_client_ephemeral_returns_generic_login_failure(client):
    username = "alice"
    register(client, username, "password")
    login_data = begin_login(client, username)

    response = client.post(
        "/api/login/verify",
        json={
            "session_id": login_data["session_id"],
            "client_public_ephemeral": "00",
            "client_proof": "00",
        },
    )

    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid credentials"}


def test_verify_token_reports_valid_expired_bad_signature_and_malformed(
    client, keypair_files
):
    private_key_pem = keypair_files["private_key_path"].read_text(
        encoding="ascii"
    )
    valid_token = sign_token({"sub": "user-1"}, private_key_pem, 5)
    valid_response = client.get(
        "/api/verify-token",
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert valid_response.status_code == 200
    assert valid_response.get_json()["valid"] is True
    assert valid_response.get_json()["claims"]["sub"] == "user-1"

    expired_token = sign_token({"sub": "user-1"}, private_key_pem, -1)
    expired_response = client.get(
        "/api/verify-token",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert expired_response.status_code == 200
    assert expired_response.get_json() == {
        "valid": False,
        "reason": "expired",
    }

    other_private_key_pem, _ = generate_keypair()
    wrong_key_token = sign_token({"sub": "user-1"}, other_private_key_pem, 5)
    bad_signature_response = client.get(
        "/api/verify-token",
        headers={"Authorization": f"Bearer {wrong_key_token}"},
    )
    assert bad_signature_response.status_code == 200
    assert bad_signature_response.get_json() == {
        "valid": False,
        "reason": "invalid_signature",
    }

    malformed_response = client.get(
        "/api/verify-token",
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert malformed_response.status_code == 200
    assert malformed_response.get_json() == {
        "valid": False,
        "reason": "malformed",
    }

    missing_header_response = client.get("/api/verify-token")
    assert missing_header_response.status_code == 400
    assert missing_header_response.get_json() == {
        "error": "missing or malformed Authorization header"
    }


def test_login_init_is_rate_limited(keypair_files):
    app = create_app(
        test_config={
            "TESTING": True,
            "DATABASE_URL": "sqlite:///:memory:",
            "ED25519_PRIVATE_KEY_PATH": str(keypair_files["private_key_path"]),
            "RATE_LIMIT_LOGIN": "2 per minute",
        }
    )
    assert app.config.get("RATELIMIT_ENABLED", True) is True

    with app.test_client() as rate_client:
        responses = [
            rate_client.post(
                "/api/login/init", json={"username": "rate-limit-user"}
            )
            for _ in range(3)
        ]

    assert any(response.status_code == 429 for response in responses)
