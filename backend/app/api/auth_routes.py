"""Registration API routes."""

from flask import Blueprint, jsonify, request

from app.database import get_session
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
