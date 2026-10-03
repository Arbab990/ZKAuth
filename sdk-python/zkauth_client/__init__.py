"""Public API for the standalone ZKAuth Python SDK."""

from .client import (
    InvalidTokenError,
    LoginFailedError,
    RegistrationError,
    ServerProofMismatchError,
    TokenExpiredError,
    TokenSignatureError,
    fetch_public_key,
    login,
    register,
    verify_token,
)
from . import srp_client

__all__ = [
    "InvalidTokenError",
    "LoginFailedError",
    "RegistrationError",
    "ServerProofMismatchError",
    "TokenExpiredError",
    "TokenSignatureError",
    "fetch_public_key",
    "login",
    "register",
    "srp_client",
    "verify_token",
]
