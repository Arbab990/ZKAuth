"""Pure client-side SRP-6a primitives matching the backend protocol."""

import hashlib
import secrets


N = int(
    """AC6BDB41324A9A9BF166DE5E1389582F
    AF72B6651987EE07FC3192943DB56050
    A37329CBB4A099ED8193E0757767A13D
    D52312AB4B03310DCD7F48A9DA04FD50
    E8083969EDB767B0CF6095179A163AB3
    661A05FBD5FAAAE82918A9962F0B93B8
    55F97993EC975EEAA80D740ADBF4FF74
    7359D041D5C33EA71D281E446B14773B
    CA97B43A23FB801676BD207A436C6481
    F1D2B9078717461A5B9D32E688F87748
    544523B524B0D57D5EA77A2775D2ECFA
    032CFBDBF52FB3786160279004E57AE6
    AF874E7303CE53299CCC041C7BC308D8
    2A5698F3A8D0C38271AE35F8E9DBFBB6
    94B5C803D89F7AE435DE236D525F5475
    9B65E372FCD68EF20FA7111F9E4AFF73""".replace("\n", "").replace(" ", ""),
    16,
)

g = 2
_BYTE_WIDTH = (N.bit_length() + 7) // 8


class InvalidEphemeralError(ValueError):
    """Raised when the server ephemeral value is invalid or u is zero."""


def _pad(value: int) -> bytes:
    if value < 0 or value >= 1 << (_BYTE_WIDTH * 8):
        raise ValueError("integer does not fit the SRP group width")
    return value.to_bytes(_BYTE_WIDTH, "big")


def _int_hex(value: int) -> str:
    return _pad(value).hex()


def _parse_hex(value: str, name: str) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty hex string")
    if len(value) % 2:
        value = "0" + value
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal") from exc
    if len(raw) > _BYTE_WIDTH:
        raise ValueError(f"{name} exceeds the SRP group width")
    return int.from_bytes(raw, "big")


def _digest_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def _compute_k() -> int:
    return _digest_int(_pad(N) + _pad(g))


def _compute_x(username: str, password: str, salt_hex: str) -> int:
    try:
        salt_bytes = bytes.fromhex(salt_hex)
    except (TypeError, ValueError) as exc:
        raise ValueError("salt_hex must be hexadecimal") from exc
    if not salt_bytes:
        raise ValueError("salt_hex must not be empty")
    inner = hashlib.sha256(f"{username}:{password}".encode("utf-8")).digest()
    return _digest_int(salt_bytes + inner)


def _compute_u(A: int, B: int) -> int:
    u = _digest_int(_pad(A) + _pad(B))
    if u == 0:
        raise InvalidEphemeralError("SRP scrambling parameter u must not be zero")
    return u


def generate_salt() -> str:
    """Return a fresh 16-byte random salt as hex."""
    return secrets.token_bytes(16).hex()


def compute_verifier(username: str, password: str, salt_hex: str) -> str:
    """Compute the fixed-width SRP verifier for registration."""
    x = _compute_x(username, password, salt_hex)
    return _int_hex(pow(g, x, N))


def generate_client_ephemeral() -> tuple[str, str]:
    """Return the client's public A and private a as fixed-width hex."""
    a = secrets.randbelow(N - 1) + 1
    A = pow(g, a, N)
    return _int_hex(A), _int_hex(a)


def compute_client_session(
    username: str,
    password: str,
    salt_hex: str,
    A_hex: str,
    a_hex: str,
    B_hex: str,
) -> dict[str, str]:
    """Validate server B and derive the client's shared session key."""
    A = _parse_hex(A_hex, "A_hex")
    a = _parse_hex(a_hex, "a_hex")
    B = _parse_hex(B_hex, "B_hex")
    if B % N == 0:
        raise InvalidEphemeralError("B must not be congruent to zero modulo N")
    u = _compute_u(A, B)
    x = _compute_x(username, password, salt_hex)
    k = _compute_k()
    base = (B - k * pow(g, x, N)) % N
    S = pow(base, a + u * x, N)
    K = _digest_int(_pad(S))
    return {"K": _int_hex(K)}


def compute_client_proof(A_hex: str, B_hex: str, K_hex: str) -> str:
    """Compute the client proof M1."""
    A = _parse_hex(A_hex, "A_hex")
    B = _parse_hex(B_hex, "B_hex")
    K = _parse_hex(K_hex, "K_hex")
    return _int_hex(_digest_int(_pad(A) + _pad(B) + _pad(K)))


def compute_server_proof(A_hex: str, M1_hex: str, K_hex: str) -> str:
    """Compute expected server proof M2 for mutual authentication."""
    A = _parse_hex(A_hex, "A_hex")
    M1 = _parse_hex(M1_hex, "M1_hex")
    K = _parse_hex(K_hex, "K_hex")
    return _int_hex(_digest_int(_pad(A) + _pad(M1) + _pad(K)))
