from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from werkzeug.serving import make_server

from app import create_app
from app.core.token_signer import generate_keypair


key_dir = Path(tempfile.gettempdir()) / "zkauth-js-interop"
key_dir.mkdir(parents=True, exist_ok=True)
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

server = make_server("127.0.0.1", 5099, app, threaded=True)
try:
    server.serve_forever()
finally:
    server.shutdown()
