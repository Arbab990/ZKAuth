"""Generate an Ed25519 keypair at the configured local paths."""

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from app.core.token_signer import generate_keypair


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Generate ZKAuth Ed25519 keys")
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace existing key files",
    )
    args = parser.parse_args()

    private_key_path_value = os.environ.get("ED25519_PRIVATE_KEY_PATH")
    if not private_key_path_value:
        parser.error("ED25519_PRIVATE_KEY_PATH must be set in the environment or .env")

    private_key_path = Path(private_key_path_value).expanduser()
    public_key_path = private_key_path.with_name("public_key.pem")
    if private_key_path.exists() and not args.force:
        print(
            f"Private key already exists at {private_key_path}; refusing to overwrite. "
            "Pass --force to replace it."
        )
        return 1
    if public_key_path.exists() and not args.force:
        print(
            f"Public key already exists at {public_key_path}; refusing to overwrite. "
            "Pass --force to replace it."
        )
        return 1

    private_key_pem, public_key_pem = generate_keypair()
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_text(private_key_pem, encoding="ascii")
    public_key_path.write_text(public_key_pem, encoding="ascii")
    try:
        private_key_path.chmod(0o600)
    except (OSError, NotImplementedError):
        # File permission modes may not be supported on every platform.
        pass

    print(f"Generated Ed25519 keypair: {private_key_path} and {public_key_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
