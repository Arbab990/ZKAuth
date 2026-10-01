"""Environment-driven application configuration."""

import os
from pathlib import Path

from dotenv import load_dotenv


def load_config() -> dict:
    """Read environment settings into a fresh configuration dictionary."""
    load_dotenv()
    private_key_path = Path(
        os.environ.get("ED25519_PRIVATE_KEY_PATH", "./keys/private_key.pem")
    ).expanduser()
    public_key_path = private_key_path.with_name("public_key.pem")

    return {
        "DATABASE_URL": os.environ.get("DATABASE_URL", "sqlite:///zkauth.db"),
        "ED25519_PRIVATE_KEY_PATH": str(private_key_path),
        "ED25519_PUBLIC_KEY_PATH": str(public_key_path),
        "TOKEN_EXPIRE_MINUTES": int(os.environ.get("TOKEN_EXPIRE_MINUTES", "60")),
        "CORS_ORIGINS": os.environ.get(
            "CORS_ORIGINS", "http://localhost:5173"
        ),
    }
