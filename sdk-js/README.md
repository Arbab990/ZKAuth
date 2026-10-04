# ZKAuth JavaScript SDK

JavaScript client SDK for ZKAuth, including client-side SRP-6a and EdDSA JWT verification.

## Tests

The SDK test suite includes an interoperability test that starts a local Python backend. It requires a Python environment with backend/requirements.txt installed. The tests use python3 by default; set ZKAUTH_TEST_PYTHON to the executable for the correct environment when needed (for example, ../backend/venv/Scripts/python.exe on Windows).

- JavaScript BigInt modPow is not constant-time and provides no secret-dependent timing guarantees.
- fetchPublicKey trusts the server on first use; production consumers should pin the public key.
- Errors: LoginFailedError means HTTP 401 from login/verify; RateLimitError means HTTP 429; ServerUnavailableError means network/5xx/unexpected status or response; ServerProofMismatchError means invalid SRP ephemeral or M2; InvalidTokenError covers malformed/missing-claim tokens, with TokenExpiredError and TokenSignatureError for expiry and signature failures; RegistrationError means registration failed.