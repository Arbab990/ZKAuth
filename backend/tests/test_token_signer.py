import base64
import json
import time

import jwt
import pytest

from app.core.token_signer import (
    InvalidTokenError,
    TokenExpiredError,
    TokenSignatureError,
    generate_keypair,
    sign_token,
    verify_token,
)


def test_token_signer_round_trips_claims_with_exp_and_iat():
    private_key_pem, public_key_pem = generate_keypair()
    claims = {"sub": "user-123", "purpose": "session"}
    original_claims = claims.copy()

    token = sign_token(claims, private_key_pem, expires_in_minutes=5)
    decoded = verify_token(token, public_key_pem)

    assert decoded["sub"] == "user-123"
    assert decoded["purpose"] == "session"
    assert decoded["iat"] <= int(time.time())
    assert decoded["exp"] == decoded["iat"] + 5 * 60
    assert claims == original_claims


def test_tampered_payload_raises_token_signature_error():
    private_key_pem, public_key_pem = generate_keypair()
    token = sign_token({"sub": "user-123"}, private_key_pem, 5)
    header, payload, signature = token.split(".")
    padding = "=" * (-len(payload) % 4)
    payload_claims = json.loads(base64.urlsafe_b64decode(payload + padding))
    payload_claims["sub"] = "user-456"
    changed_payload = base64.urlsafe_b64encode(
        json.dumps(payload_claims, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    tampered_token = f"{header}.{changed_payload}.{signature}"

    with pytest.raises(TokenSignatureError):
        verify_token(tampered_token, public_key_pem)


def test_wrong_keypair_raises_token_signature_error():
    private_key_pem, _ = generate_keypair()
    _, other_public_key_pem = generate_keypair()
    token = sign_token({"sub": "user-123"}, private_key_pem, 5)

    with pytest.raises(TokenSignatureError):
        verify_token(token, other_public_key_pem)


def test_expired_token_raises_token_expired_error():
    private_key_pem, public_key_pem = generate_keypair()
    token = sign_token({"sub": "user-123"}, private_key_pem, expires_in_minutes=-1)

    with pytest.raises(TokenExpiredError):
        verify_token(token, public_key_pem)


def test_malformed_token_raises_invalid_token_error():
    _, public_key_pem = generate_keypair()

    with pytest.raises(InvalidTokenError) as exc_info:
        verify_token("this-is-not-a-jwt", public_key_pem)

    assert type(exc_info.value) is InvalidTokenError


def test_missing_required_claims_raise_invalid_token_error():
    private_key_pem, public_key_pem = generate_keypair()
    token = jwt.encode({"sub": "user-123"}, private_key_pem, algorithm="EdDSA")

    with pytest.raises(InvalidTokenError) as exc_info:
        verify_token(token, public_key_pem)

    assert type(exc_info.value) is InvalidTokenError

def test_generate_keypair_is_fresh_and_keys_are_not_interchangeable():
    first_private_key_pem, first_public_key_pem = generate_keypair()
    _, second_public_key_pem = generate_keypair()
    token = sign_token({"sub": "user-123"}, first_private_key_pem, 5)

    assert first_public_key_pem != second_public_key_pem
    with pytest.raises(TokenSignatureError):
        verify_token(token, second_public_key_pem)
