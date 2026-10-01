"""Flask application factory."""

from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS

from app.api import register_blueprints
from app.config import load_config
from app.database import create_all_tables, init_engine, init_session_factory


def create_app(test_config: dict | None = None) -> Flask:
    config = load_config()
    if test_config is not None:
        config.update(test_config)

    private_key_path = Path(config["ED25519_PRIVATE_KEY_PATH"]).expanduser()
    config["ED25519_PUBLIC_KEY_PATH"] = str(
        private_key_path.with_name("public_key.pem")
    )
    config.setdefault("PUBLIC_KEY_PEM", None)

    app = Flask(__name__)
    app.config.update(config)

    origins = app.config["CORS_ORIGINS"]
    if isinstance(origins, str) and "," in origins:
        origins = [origin.strip() for origin in origins.split(",") if origin.strip()]
    CORS(app, origins=origins)

    engine = init_engine(app.config["DATABASE_URL"])
    create_all_tables(engine)
    app.extensions["db_session"] = init_session_factory(engine)

    @app.teardown_appcontext
    def remove_db_session(exception=None):
        app.extensions["db_session"].remove()

    try:
        app.config["PUBLIC_KEY_PEM"] = Path(
            app.config["ED25519_PUBLIC_KEY_PATH"]
        ).read_text(encoding="ascii")
    except OSError:
        app.config["PUBLIC_KEY_PEM"] = None

    register_blueprints(app)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"}), 200

    return app
