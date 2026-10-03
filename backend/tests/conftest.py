import pytest

from app import create_app
from app.core.token_signer import generate_keypair


@pytest.fixture
def keypair_files(tmp_path):
    private_key_pem, public_key_pem = generate_keypair()
    private_key_path = tmp_path / "private_key.pem"
    public_key_path = tmp_path / "public_key.pem"
    private_key_path.write_text(private_key_pem, encoding="ascii")
    public_key_path.write_text(public_key_pem, encoding="ascii")
    return {
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
        "public_key_pem": public_key_pem,
    }


@pytest.fixture
def app(keypair_files):
    return create_app(
        test_config={
            "TESTING": True,
            "RATE_LIMIT_LOGIN": "1000 per minute",
            "DATABASE_URL": "sqlite:///:memory:",
            "ED25519_PRIVATE_KEY_PATH": str(keypair_files["private_key_path"]),
        }
    )


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def db_session(app):
    session = app.extensions["db_session"]()
    yield session
    app.extensions["db_session"].remove()
