"""Public token verification-key and diagnostic token routes."""

from flask import Blueprint, current_app, jsonify, request

from app.core.token_signer import (
    InvalidTokenError,
    TokenExpiredError,
    TokenSignatureError,
    verify_token,
)


token_bp = Blueprint("token", __name__, url_prefix="/api")


@token_bp.get("/public-key")
def public_key():
    public_key_pem = current_app.config.get("PUBLIC_KEY_PEM")
    if public_key_pem is None:
        return jsonify({"error": "Ed25519 public key is not configured"}), 500
    return jsonify({"public_key_pem": public_key_pem}), 200


@token_bp.get("/verify-token")
def verify_token_route():
    authorization = request.headers.get("Authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        return jsonify(
            {"error": "missing or malformed Authorization header"}
        ), 400

    try:
        claims = verify_token(
            parts[1], current_app.config.get("PUBLIC_KEY_PEM")
        )
    except TokenExpiredError:
        return jsonify({"valid": False, "reason": "expired"}), 200
    except TokenSignatureError:
        return jsonify({"valid": False, "reason": "invalid_signature"}), 200
    except InvalidTokenError:
        return jsonify({"valid": False, "reason": "malformed"}), 200

    return jsonify({"valid": True, "claims": claims}), 200
