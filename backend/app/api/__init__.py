"""API blueprint registration."""

from app.api.admin_routes import admin_bp
from app.api.auth_routes import auth_bp
from app.api.token_routes import token_bp


def register_blueprints(app) -> None:
    app.register_blueprint(auth_bp)
    app.register_blueprint(token_bp)
    if app.config["ENABLE_ADMIN_DIAGNOSTICS"]:
        app.register_blueprint(admin_bp)
