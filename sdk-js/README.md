# ZKAuth JavaScript SDK

JavaScript client SDK for ZKAuth, including client-side SRP-6a and EdDSA JWT verification.

## Tests

The SDK test suite includes an interoperability test that starts a local Python backend. It requires a Python environment with backend/requirements.txt installed. The tests use python3 by default; set ZKAUTH_TEST_PYTHON to the executable for the correct environment when needed (for example, ../backend/venv/Scripts/python.exe on Windows).
