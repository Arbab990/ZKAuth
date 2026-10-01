import pytest

from app.core.srp_core import (
    N,
    InvalidEphemeralError,
    compute_client_proof,
    compute_client_session,
    compute_server_proof,
    compute_server_session,
    compute_verifier,
    generate_salt,
    generate_server_ephemeral,
    verify_client_proof,
)


def test_group_modulus_is_2048_bits():
    assert N.bit_length() == 2048

def test_srp_happy_path_derives_matching_keys_and_proofs():
    username, password = "alice", "correct horse battery staple"
    salt_hex = generate_salt()
    verifier_hex = compute_verifier(username, password, salt_hex)
    a_value = 13
    A_hex = f"{pow(2, a_value, N):x}"
    B_hex, b_hex = generate_server_ephemeral(verifier_hex)

    client = compute_client_session(username, password, salt_hex, A_hex, f"{a_value:x}", B_hex)
    server = compute_server_session(username, salt_hex, verifier_hex, A_hex, b_hex, B_hex)

    assert client["K"] == server["K"]
    assert client["u"] == server["u"]
    M1 = compute_client_proof(A_hex, B_hex, client["K"])
    assert verify_client_proof(A_hex, B_hex, server["K"], M1)
    M2 = compute_server_proof(A_hex, M1, client["K"])
    assert M2 == compute_server_proof(A_hex, M1, client["K"])


def test_wrong_password_produces_unverifiable_client_proof():
    username, password = "alice", "correct password"
    salt_hex = generate_salt()
    verifier_hex = compute_verifier(username, password, salt_hex)
    a = 13
    A_hex = f"{pow(2, a, N):x}"
    B_hex, b_hex = generate_server_ephemeral(verifier_hex)

    client = compute_client_session(username, "wrong password", salt_hex, A_hex, f"{a:x}", B_hex)
    server = compute_server_session(username, salt_hex, verifier_hex, A_hex, b_hex, B_hex)
    M1 = compute_client_proof(A_hex, B_hex, client["K"])

    assert client["K"] != server["K"]
    assert verify_client_proof(A_hex, B_hex, server["K"], M1) is False


@pytest.mark.parametrize("A_hex", ["00", f"{N:x}"])
def test_server_rejects_A_congruent_to_zero_modulo_N(A_hex):
    salt_hex = generate_salt()
    verifier_hex = compute_verifier("alice", "password", salt_hex)
    B_hex, b_hex = generate_server_ephemeral(verifier_hex)

    with pytest.raises(InvalidEphemeralError):
        compute_server_session("alice", salt_hex, verifier_hex, A_hex, b_hex, B_hex)


@pytest.mark.parametrize("B_hex", ["00", f"{N:x}"])
def test_client_rejects_B_congruent_to_zero_modulo_N(B_hex):
    a = 13
    A_hex = f"{pow(2, a, N):x}"
    with pytest.raises(InvalidEphemeralError):
        compute_client_session("alice", "password", generate_salt(), A_hex, f"{a:x}", B_hex)


def test_verifier_is_deterministic_for_same_salt_and_changes_for_new_salt():
    username, password = "alice", "password"
    salt_hex = generate_salt()

    first = compute_verifier(username, password, salt_hex)
    second = compute_verifier(username, password, salt_hex)
    third = compute_verifier(username, password, generate_salt())

    assert first == second
    assert first != third
