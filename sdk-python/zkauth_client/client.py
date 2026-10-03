"""Standalone HTTP client for the ZKAuth service."""

import hmac

import jwt
import requests

from . import srp_client


class RegistrationError(Exception):
    """Raised when registration is rejected by the server."""


class LoginFailedError(Exception):
    """Raised for any unsuccessful login."""


class ServerProofMismatchError(Exception):
    """Raised when the server cannot prove knowledge of the SRP session key."""


class InvalidTokenError(ValueError):
    """Base error for malformed, invalid, or unverifiable tokens."""


class TokenExpiredError(InvalidTokenError):
    """Raised when a token's expiration time has passed."""


class TokenSignatureError(InvalidTokenError):
    """Raised when a token's signature cannot be verified."""


def register(base_url: str, username: str, password: str) -> str:
    salt = srp_client.generate_salt()
    verifier = srp_client.compute_verifier(username, password, salt)
    try:
        response = requests.post(
            f"{base_url.rstrip('/')}/api/register",
            json={"username": username, "salt": salt, "verifier": verifier},
            timeout=10,
        )
    except requests.RequestException as exc:
        raise RegistrationError("registration request failed") from exc
    if response.status_code != 201:
        try:
            message = response.json().get("error", "registration failed")
        except (ValueError, AttributeError):
            message = "registration failed"
        raise RegistrationError(str(message))
    try:
        return response.json()["user_id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RegistrationError("registration response was malformed") from exc


def login(base_url: str, username: str, password: str) -> dict[str, str]:
    base_url = base_url.rstrip("/")
    try:
        init_response = requests.post(
            f"{base_url}/api/login/init",
            json={"username": username},
            timeout=10,
        )
        if init_response.status_code != 200:
            raise LoginFailedError("invalid credentials")
        init_data = init_response.json()
        A_hex, a_hex = srp_client.generate_client_ephemeral()
        session = srp_client.compute_client_session(
            username,
            password,
            init_data["salt"],
            A_hex,
            a_hex,
            init_data["server_public_ephemeral"],
        )
        client_proof = srp_client.compute_client_proof(
            A_hex, init_data["server_public_ephemeral"], session["K"]
        )
        response = requests.post(
            f"{base_url}/api/login/verify",
            json={
                "session_id": init_data["session_id"],
                "client_public_ephemeral": A_hex,
                "client_proof": client_proof,
            },
            timeout=10,
        )
    except LoginFailedError:
        raise
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise LoginFailedError("invalid credentials") from exc
    if response.status_code != 200:
        raise LoginFailedError("invalid credentials")
    try:
        result = response.json()
        expected_proof = srp_client.compute_server_proof(
            A_hex, client_proof, session["K"]
        )
        received_proof = result["server_proof"]
        token = result["token"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ServerProofMismatchError("server proof response was malformed") from exc
    if not isinstance(received_proof, str) or not hmac.compare_digest(
        expected_proof, received_proof
    ):
        raise ServerProofMismatchError("server proof did not match")
    return {"token": token}


def verify_token(token: str, public_key_pem: str) -> dict:
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
        raise InvalidTokenError("token is malformed or invalid") from exc


def fetch_public_key(base_url: str) -> str:
    try:
        response = requests.get(f"{base_url.rstrip('/')}/api/public-key", timeout=10)
        response.raise_for_status()
        public_key = response.json()["public_key_pem"]
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("could not fetch a valid ZKAuth public key") from exc
    if not isinstance(public_key, str) or not public_key:
        raise RuntimeError("could not fetch a valid ZKAuth public key")
    return public_key
