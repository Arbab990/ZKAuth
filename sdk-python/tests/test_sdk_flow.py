"""Integration tests for the standalone SDK against a real local HTTP server."""

from app.core.srp_core import N as BACKEND_N

from zkauth_client import (
    LoginFailedError,
    RegistrationError,
    fetch_public_key,
    login,
    register,
    verify_token,
)
from zkauth_client.srp_client import N, compute_verifier


RFC5054_2048_N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582F"
    "AF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13D"
    "D52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3"
    "661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF74"
    "7359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481"
    "F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA"
    "032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D8"
    "2A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F5475"
    "9B65E372FCD68EF20FA7111F9E4AFF73"
)


def test_sdk_srp_group_matches_rfc_and_backend():
    assert f"{N:X}" == RFC5054_2048_N_HEX
    assert N == BACKEND_N


def test_sdk_register_login_and_verify_token(live_server):
    username = "sdk-happy-path-user"
    user_id = register(live_server, username, "correct horse battery staple")
    token_result = login(live_server, username, "correct horse battery staple")
    assert token_result["token"]

    public_key = fetch_public_key(live_server)
    claims = verify_token(token_result["token"], public_key)
    assert claims["sub"] == user_id
    assert claims["username"] == username
    # login() only returns after independently validating M2, exercising mutual authentication.


def test_sdk_wrong_password_raises_generic_login_error(live_server):
    username = "sdk-wrong-password-user"
    register(live_server, username, "right-password")
    try:
        login(live_server, username, "wrong-password")
    except LoginFailedError:
        pass
    else:
        raise AssertionError("wrong password should raise LoginFailedError")


def test_sdk_duplicate_registration_raises_registration_error(live_server):
    username = "sdk-duplicate-user"
    register(live_server, username, "some-password")
    try:
        register(live_server, username, "some-password")
    except RegistrationError:
        pass
    else:
        raise AssertionError("duplicate registration should raise RegistrationError")
