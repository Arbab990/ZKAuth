"""Public token verification-key API routes."""

from flask import Blueprint, current_app, jsonify


token_bp = Blueprint("token", __name__, url_prefix="/api")


@token_bp.get("/public-key")
def public_key():
    public_key_pem = current_app.config.get("PUBLIC_KEY_PEM")
    if public_key_pem is None:
        return jsonify({"error": "Ed25519 public key is not configured"}), 500
    return jsonify({"public_key_pem": public_key_pem}), 200
