"""Pure SRP-6a primitives for ZKAuth.

This implementation uses the RFC 5054 2048-bit group with SHA-256 as the
hash parameter. RFC 5054's examples use SHA-1; ZKAuth deliberately uses
SHA-256 as specified by its protocol contract.

Integer encodings used in protocol hashes are unsigned, big-endian, and padded
to the 256-byte width of N. Hash outputs used as protocol integers are encoded
the same way when returned as hex strings, so Python and JavaScript peers share
one canonical fixed-width representation. The x formula intentionally uses
the raw salt bytes and the raw 32-byte inner SHA-256 digest, as specified.
"""

import hashlib
import hmac
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
_HEX_WIDTH = _BYTE_WIDTH * 2


class InvalidEphemeralError(ValueError):
    """Raised when an SRP ephemeral value is invalid or produces u = 0."""


def _pad(value: int) -> bytes:
    """Encode an integer at the fixed byte width of N."""
    if value < 0 or value >= 1 << (_BYTE_WIDTH * 8):
        raise ValueError("integer does not fit the SRP group width")
    return value.to_bytes(_BYTE_WIDTH, "big")


def _int_hex(value: int) -> str:
    """Return the canonical fixed-width hex encoding of an integer."""
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


def _validate_ephemeral(value: int, name: str) -> None:
    if value % N == 0:
        raise InvalidEphemeralError(f"{name} must not be congruent to zero modulo N")


def generate_salt() -> str:
    """Return a fresh 16-byte random salt as hex."""
    return secrets.token_bytes(16).hex()


def compute_verifier(username: str, password: str, salt_hex: str) -> str:
    """Compute the fixed-width SRP verifier for a username, password, and salt."""
    x = _compute_x(username, password, salt_hex)
    return _int_hex(pow(g, x, N))


def generate_server_ephemeral(verifier_hex: str) -> tuple[str, str]:
    """Generate server public B and private b, both as fixed-width hex."""
    verifier = _parse_hex(verifier_hex, "verifier_hex")
    k = _compute_k()
    while True:
        b = secrets.randbelow(N - 1) + 1
        B = (k * verifier + pow(g, b, N)) % N
        if B % N != 0:
            return _int_hex(B), _int_hex(b)


def compute_server_session(
    username: str,
    salt_hex: str,
    verifier_hex: str,
    A_hex: str,
    b_hex: str,
    B_hex: str,
) -> dict[str, str]:
    """Validate client A and derive the server shared key and scrambling value."""
    del username, salt_hex  # These inputs are part of the shared API signature.
    A = _parse_hex(A_hex, "A_hex")
    b = _parse_hex(b_hex, "b_hex")
    B = _parse_hex(B_hex, "B_hex")
    verifier = _parse_hex(verifier_hex, "verifier_hex")
    _validate_ephemeral(A, "A")
    _validate_ephemeral(B, "B")
    u = _compute_u(A, B)
    S = pow((A * pow(verifier, u, N)) % N, b, N)
    K = _digest_int(_pad(S))
    return {"K": _int_hex(K), "u": _int_hex(u)}


def compute_client_session(
    username: str,
    password: str,
    salt_hex: str,
    A_hex: str,
    a_hex: str,
    B_hex: str,
) -> dict[str, str]:
    """Validate server B and derive the client shared key and scrambling value."""
    A = _parse_hex(A_hex, "A_hex")
    a = _parse_hex(a_hex, "a_hex")
    B = _parse_hex(B_hex, "B_hex")
    _validate_ephemeral(A, "A")
    _validate_ephemeral(B, "B")
    u = _compute_u(A, B)
    x = _compute_x(username, password, salt_hex)
    k = _compute_k()
    base = (B - k * pow(g, x, N)) % N
    S = pow(base, a + u * x, N)
    K = _digest_int(_pad(S))
    return {"K": _int_hex(K), "u": _int_hex(u)}


def compute_client_proof(A_hex: str, B_hex: str, K_hex: str) -> str:
    """Compute M1 from A, B, and the shared session key."""
    A = _parse_hex(A_hex, "A_hex")
    B = _parse_hex(B_hex, "B_hex")
    K = _parse_hex(K_hex, "K_hex")
    return _int_hex(_digest_int(_pad(A) + _pad(B) + _pad(K)))


def verify_client_proof(
    A_hex: str, B_hex: str, K_hex: str, received_M1_hex: str
) -> bool:
    """Constant-time verification of a client's M1 proof."""
    try:
        expected = bytes.fromhex(compute_client_proof(A_hex, B_hex, K_hex))
        received = _pad(_parse_hex(received_M1_hex, "received_M1_hex"))
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, received)


def compute_server_proof(A_hex: str, M1_hex: str, K_hex: str) -> str:
    """Compute mutual-authentication proof M2."""
    A = _parse_hex(A_hex, "A_hex")
    M1 = _parse_hex(M1_hex, "M1_hex")
    K = _parse_hex(K_hex, "K_hex")
    return _int_hex(_digest_int(_pad(A) + _pad(M1) + _pad(K)))
