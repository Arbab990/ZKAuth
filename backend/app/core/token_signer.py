"""Pure Ed25519 JWT signing and verification helpers."""

import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class InvalidTokenError(ValueError):
    """Base error for malformed, invalid, or unverifiable tokens."""


class TokenExpiredError(InvalidTokenError):
    """Raised when a token's expiration time has passed."""


class TokenSignatureError(InvalidTokenError):
    """Raised when a token signature cannot be verified."""


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair and return private/public PEM strings."""
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_key_pem, public_key_pem


def sign_token(
    claims: dict, private_key_pem: str, expires_in_minutes: int
) -> str:
    """Sign a copy of claims with EdDSA and add issued-at and expiry claims."""
    issued_at = int(time.time())
    payload = claims.copy()
    payload["iat"] = issued_at
    payload["exp"] = issued_at + (expires_in_minutes * 60)
    return jwt.encode(payload, private_key_pem, algorithm="EdDSA")


def verify_token(token: str, public_key_pem: str) -> dict:
    """Verify an EdDSA JWT and normalize failures to token signer errors."""
    try:
        return jwt.decode(
            token,
            public_key_pem,
            algorithms=["EdDSA"],
            options={"require": ["exp", "iat"]},
        )
    except jwt.exceptions.ExpiredSignatureError as exc:
        raise TokenExpiredError("token has expired") from exc
    except jwt.exceptions.InvalidSignatureError as exc:
        raise TokenSignatureError("token signature is invalid") from exc
    except jwt.exceptions.PyJWTError as exc:
        raise InvalidTokenError("token is malformed or invalid") from exc
    except Exception as exc:
        # Normalize invalid key material and other decode failures as well, so
        # callers never need to handle an implementation-specific exception.
        raise InvalidTokenError("token is malformed or invalid") from exc
