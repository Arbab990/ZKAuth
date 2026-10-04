# ZKAuth

> **An early-stage, self-hostable authentication service built around SRP-6a password proofs, Ed25519-signed tokens, and a hash-linked authentication event log.**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Backend](https://img.shields.io/badge/Backend-Flask-000000?style=flat-square&logo=flask&logoColor=white)
![Password protocol](https://img.shields.io/badge/Password%20protocol-SRP--6a-0052CC?style=flat-square)
![Tokens](https://img.shields.io/badge/Tokens-Ed25519%20%2F%20EdDSA-7B42BC?style=flat-square)
![Database](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)

ZKAuth provides an HTTP authentication API and JavaScript and Python client SDKs. Its SRP-6a flow keeps the user's password out of registration and login requests; the service stores an SRP salt and verifier rather than the password. Successful logins receive a JWT signed with an Ed25519 private key, so an application can verify tokens with the corresponding public key.

> **Project status:** This is an early-stage authentication project, not a production-ready identity platform. The current scope is registration, login, token verification, and authentication-event recording. Authorization (such as roles and permissions) is not implemented. The React frontend is currently a demo scaffold.

---

## Tech Stack

The icons below are visual labels for the technologies used in the repository; they do not imply that every part of the demo frontend is fully implemented.

### Frontend

| Technology | Role |
|:---|:---|
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/atom.svg" width="18" align="center" alt="React icon" /> **React 18** | Demo frontend UI |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/zap.svg" width="18" align="center" alt="Vite icon" /> **Vite 5** | Frontend development and build tool |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/palette.svg" width="18" align="center" alt="Tailwind CSS icon" /> **Tailwind CSS 3.4** | Utility-first styling |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/arrow-left-right.svg" width="18" align="center" alt="Axios icon" /> **Axios** | HTTP client dependency; the demo integration is not wired up yet |

### Backend and Cryptography

| Technology | Role |
|:---|:---|
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/code-xml.svg" width="18" align="center" alt="Python icon" /> **Python 3.12** | Backend runtime |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/server.svg" width="18" align="center" alt="Flask icon" /> **Flask 3** | HTTP API and application factory |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/database.svg" width="18" align="center" alt="SQLAlchemy and SQLite icons" /> **SQLAlchemy 2 + SQLite** | ORM and local relational storage |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/lock.svg" width="18" align="center" alt="SRP icon" /> **SRP-6a + SHA-256** | Password verifier and proof exchange |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/key-round.svg" width="18" align="center" alt="Ed25519 icon" /> **Ed25519 / EdDSA JWT** | Token signing and verification with PyJWT and `cryptography` |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/fingerprint.svg" width="18" align="center" alt="Audit chain icon" /> **SHA-256 hash chain** | Links authentication events for tamper detection |

### SDKs and Quality

| Technology | Role |
|:---|:---|
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/square-code.svg" width="18" align="center" alt="JavaScript SDK icon" /> **JavaScript SDK** | SRP client, HTTP requests, and local EdDSA JWT verification |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/package.svg" width="18" align="center" alt="Python SDK icon" /> **Python SDK** | SRP client, HTTP requests, and local JWT verification |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/check-check.svg" width="18" align="center" alt="Tests icon" /> **pytest + Vitest** | Backend and JavaScript SDK tests |
| <img src="https://raw.githubusercontent.com/lucide-icons/lucide/main/icons/github.svg" width="18" align="center" alt="GitHub Actions icon" /> **GitHub Actions** | Runs backend and JavaScript SDK tests in CI |

---

## What ZKAuth Provides

- **SRP-6a registration and login:** Client-side password proof calculations; the password itself is not sent to the backend.
- **Ed25519-signed JWTs:** Tokens can be verified locally by consumers that trust ZKAuth's public key.
- **Hash-linked event records:** Registration and login events include hashes linked to the preceding event, allowing changes to the recorded chain to be detected when checked against a trusted copy.
- **JavaScript and Python SDKs:** Helpers for registration, login, server-proof checking, public-key retrieval, and local token verification.
- **A small Flask API:** SQLite-backed persistence, configurable login rate limits, and a health endpoint.

## Security Model and Limitations

| Area | How it works | Important limitation |
|---|---|---|
| Password proof | The client computes an SRP-6a verifier and performs the login proof exchange. The API receives the salt/verifier at registration, not the password. | SRP does not make weak passwords safe. A database breach exposes verifier material that may aid offline password guessing. A compromised client or a malicious server can also undermine authentication. |
| Session tokens | The server signs EdDSA JWTs with its Ed25519 private key. Consumers can verify signatures with the public key without calling ZKAuth. | Consumers must obtain and trust the correct public key. Keep the private key private and use HTTPS in deployments. |
| Authentication event log | Each event's SHA-256 hash includes the prior event's hash. | This is tamper-evident when independently checked; it is not an externally anchored or immutable audit service. An attacker able to rewrite the database may also be able to rebuild the chain. |

The JavaScript SDK uses JavaScript `BigInt` for SRP arithmetic, which is not constant-time. Its `fetchPublicKey` helper trusts the key returned by the server; production consumers should pin or otherwise authenticate the expected public key instead of trusting an unverified first fetch.

---

## Authentication Flow

```text
┌─────────────────────────────┐             ┌─────────────────────────────┐
│ Application + ZKAuth SDK    │             │ ZKAuth Flask API            │
│                             │             │                             │
│ Password ── SRP client ─────┼── register ─► Store salt + verifier       │
│              calculations   │             │                             │
│                             │◄── salt, B ──┼── login/init                │
│ SRP proof ──────────────────┼── verify ───► Check proof; record event    │
│                             │◄── JWT + M2 ─┼── Sign JWT with Ed25519     │
└─────────────┬───────────────┘             └─────────────────────────────┘
              │
              └── Verify JWT locally with a trusted Ed25519 public key
```

During registration, the SDK creates the salt and verifier locally and sends those values to `/api/register`. During login, the client and server exchange SRP public values and proofs; the server returns a signed token only after validating the client's proof. The SDK also checks the server's proof before returning the token to the application.

## Quick Start

### 1. Install and configure the backend

The backend requires Python 3.12. From the repository root, create and activate a virtual environment, then install the backend requirements:

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

On macOS or Linux, activate the environment with `source .venv/bin/activate` instead. The example configuration uses SQLite at `backend/zkauth.db` and expects the signing key under `backend/keys/`.

### 2. Generate the signing keys and start the API

```powershell
python -m app.generate_keys
flask --app app run
```

The key-generation command refuses to overwrite existing keys unless explicitly run with `--force`. Keep the private key secure and out of source control. The API will be available at `http://127.0.0.1:5000`; check it with:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```

For non-local deployments, configure HTTPS, restrict CORS origins, protect the signing key, and review the rate limit and token lifetime in `backend/.env`.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Basic service health check. |
| `POST` | `/api/register` | Register `{ "username", "salt", "verifier" }`; returns a `user_id`. |
| `POST` | `/api/login/init` | Begin an SRP login with `{ "username" }`; returns `session_id`, `salt`, and `server_public_ephemeral`. |
| `POST` | `/api/login/verify` | Submit `session_id`, `client_public_ephemeral`, and `client_proof`; returns a signed `token` and `server_proof` on success. |
| `GET` | `/api/public-key` | Return the Ed25519 public key in PEM format for token verification. |
| `GET` | `/api/verify-token` | Convenience endpoint to check a bearer token. Applications can instead verify tokens locally using the SDK. |

Login initialization returns a consistent response shape for known and unknown usernames. Failed proof checks return a generic authentication error. Login endpoints are rate-limited; the default is `5 per minute`.

## Client SDKs

The SDKs are included in this repository and can be installed from the local checkout.

### JavaScript

```bash
npm install ./sdk-js
```

```js
import {
  fetchPublicKey,
  login,
  register,
  verifyToken,
} from "zkauth-client"

const baseUrl = "http://127.0.0.1:5000"

await register(baseUrl, "alice", "a-long-unique-password")
const { token } = await login(baseUrl, "alice", "a-long-unique-password")

// For production, use a public key obtained through a trusted channel or pin.
const publicKeyPem = await fetchPublicKey(baseUrl)
const claims = await verifyToken(token, publicKeyPem)
console.log(claims)
```

### Python

From the repository root, install the local package into the active Python environment:

```bash
python -m pip install -e ./sdk-python
```

```python
from zkauth_client import fetch_public_key, login, register, verify_token

base_url = "http://127.0.0.1:5000"

register(base_url, "alice", "a-long-unique-password")
result = login(base_url, "alice", "a-long-unique-password")
public_key_pem = fetch_public_key(base_url)
claims = verify_token(result["token"], public_key_pem)
```

## Tests

Run the backend test suite from the repository root:

```bash
python -m pip install -r backend/requirements.txt
python -m pytest backend/tests
```

Run the JavaScript SDK tests:

```bash
cd sdk-js
npm install
npm test
```

The JavaScript SDK tests include Python-backend interoperability coverage and require the backend requirements to be installed. The repository's GitHub Actions workflow runs the backend and JavaScript SDK suites.

## Project Layout

```text
ZKAuth/
├── backend/
│   ├── app/
│   │   ├── api/          # Flask endpoints
│   │   ├── core/         # SRP, token signing, and audit-chain primitives
│   │   ├── models/       # SQLite/SQLAlchemy models
│   │   └── services/     # Registration, login, and event persistence
│   └── tests/
├── frontend/             # React/Vite demo scaffold
├── sdk-js/               # JavaScript client and SRP implementation
├── sdk-python/           # Python client and SRP implementation
├── ROADMAP.md            # Planned work; not a list of implemented features
└── context.md            # Project design and implementation reference
```

## Current Scope

Authentication is the current focus. Roles, permissions, token revocation, and a complete end-user frontend are not part of the implemented feature set. See [ROADMAP.md](./ROADMAP.md) for planned work.
