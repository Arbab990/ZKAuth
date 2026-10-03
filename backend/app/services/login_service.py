"""SRP login handshake service."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac

from app.core import srp_core, token_signer
from app.models.session import LoginSession
from app.models.user import User
from app.services.audit_service import append_event


class LoginFailedError(Exception):
    """The single outward failure type for every rejected login attempt."""


def initiate_login(username: str, session, enumeration_seed: bytes) -> dict:
    """Create a real or fake SRP session with an identical response shape."""
    user = session.query(User).filter_by(username=username).first()
    if user is not None:
        salt_hex = user.salt
        verifier_hex = user.verifier
        user_id = user.id
    else:
        username_bytes = username.encode("utf-8")
        salt_hex = hmac.new(
            enumeration_seed, username_bytes, hashlib.sha256
        ).hexdigest()[:32]
        fake_password = hmac.new(
            enumeration_seed, username_bytes + b"\x01", hashlib.sha256
        ).hexdigest()
        verifier_hex = srp_core.compute_verifier(
            username, fake_password, salt_hex
        )
        user_id = None

    B_hex, b_hex = srp_core.generate_server_ephemeral(verifier_hex)
    now = datetime.now(timezone.utc)
    login_session = LoginSession(
        user_id=user_id,
        server_ephemeral_secret=b_hex,
        server_public_ephemeral=B_hex,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(),
    )
    session.add(login_session)
    session.flush()
    session.commit()

    return {
        "session_id": login_session.id,
        "salt": salt_hex,
        "server_public_ephemeral": B_hex,
    }


def complete_login(
    session_id: str,
    A_hex: str,
    client_proof_hex: str,
    session,
    private_key_pem: str,
    token_expire_minutes: int,
) -> dict:
    """Consume one valid SRP session and return a token after proof verification."""
    login_session = (
        session.query(LoginSession).filter_by(id=session_id).first()
    )
    if login_session is None:
        raise LoginFailedError()

    try:
        expires_at = datetime.fromisoformat(login_session.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        raise LoginFailedError() from None
    if expires_at <= datetime.now(timezone.utc):
        raise LoginFailedError()

    # Every live handshake is single-use, even when its proof is rejected.
    session.delete(login_session)

    if login_session.user_id is None:
        append_event(session, "login_failure", None)
        session.commit()
        raise LoginFailedError()

    user = session.query(User).filter_by(id=login_session.user_id).first()
    if user is None:
        session.commit()
        raise LoginFailedError()

    try:
        result = srp_core.compute_server_session(
            user.username,
            user.salt,
            user.verifier,
            A_hex,
            login_session.server_ephemeral_secret,
            login_session.server_public_ephemeral,
        )
    except (srp_core.InvalidEphemeralError, TypeError, ValueError):
        append_event(session, "login_failure", user.id)
        session.commit()
        raise LoginFailedError() from None

    if not srp_core.verify_client_proof(
        A_hex,
        login_session.server_public_ephemeral,
        result["K"],
        client_proof_hex,
    ):
        append_event(session, "login_failure", user.id)
        session.commit()
        raise LoginFailedError()

    server_proof = srp_core.compute_server_proof(
        A_hex, client_proof_hex, result["K"]
    )
    token = token_signer.sign_token(
        {"sub": user.id, "username": user.username},
        private_key_pem,
        token_expire_minutes,
    )
    append_event(session, "login_success", user.id)
    session.commit()
    return {"token": token, "server_proof": server_proof}
