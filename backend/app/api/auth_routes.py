"""Registration and login API routes."""

from flask import Blueprint, current_app, jsonify, request

from app.database import get_session
from app.extensions import limiter
from app.services import login_service
from app.services.registration_service import (
    UsernameTakenError,
    register_user,
)


auth_bp = Blueprint("auth", __name__, url_prefix="/api")


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    username = data.get("username")
    salt = data.get("salt")
    verifier = data.get("verifier")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (username, salt, verifier)
    ):
        return jsonify(
            {"error": "username, salt, and verifier are required"}
        ), 400

    try:
        user = register_user(username, salt, verifier, get_session())
    except UsernameTakenError:
        return jsonify({"error": "registration failed"}), 409

    return jsonify({"user_id": user.id}), 201


@auth_bp.post("/login/init")
@limiter.limit(lambda: current_app.config["RATE_LIMIT_LOGIN"])
def login_init():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400
    username = data.get("username")
    if not isinstance(username, str) or not username.strip():
        return jsonify({"error": "username is required"}), 400

    result = login_service.initiate_login(
        username,
        get_session(),
        current_app.config["ENUMERATION_SEED"],
    )
    return jsonify(result), 200


@auth_bp.post("/login/verify")
@limiter.limit(lambda: current_app.config["RATE_LIMIT_LOGIN"])
def login_verify():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    session_id = data.get("session_id")
    client_public_ephemeral = data.get("client_public_ephemeral")
    client_proof = data.get("client_proof")
    if not all(
        isinstance(value, str) and value.strip()
        for value in (session_id, client_public_ephemeral, client_proof)
    ):
        return jsonify(
            {
                "error": (
                    "session_id, client_public_ephemeral, and client_proof "
                    "are required"
                )
            }
        ), 400

    private_key_pem = current_app.config.get("PRIVATE_KEY_PEM")
    if private_key_pem is None:
        return jsonify({"error": "Ed25519 private key is not configured"}), 500

    try:
        result = login_service.complete_login(
            session_id,
            client_public_ephemeral,
            client_proof,
            get_session(),
            private_key_pem,
            current_app.config["TOKEN_EXPIRE_MINUTES"],
        )
    except login_service.LoginFailedError:
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify(result), 200
