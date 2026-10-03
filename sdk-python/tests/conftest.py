from pathlib import Path
import sys
from threading import Thread

import pytest
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app import create_app
from app.core.token_signer import generate_keypair


@pytest.fixture(scope="session")
def live_server(tmp_path_factory):
    key_dir = tmp_path_factory.mktemp("sdk-keypair")
    private_key_pem, public_key_pem = generate_keypair()
    private_key_path = key_dir / "private_key.pem"
    private_key_path.write_text(private_key_pem, encoding="ascii")
    (key_dir / "public_key.pem").write_text(public_key_pem, encoding="ascii")

    app = create_app(
        test_config={
            "TESTING": True,
            "DATABASE_URL": "sqlite:///:memory:",
            "ED25519_PRIVATE_KEY_PATH": str(private_key_path),
            "RATE_LIMIT_LOGIN": "1000 per minute",
        }
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
