"""Contract tests for the five-stanza serializer and parser.

Contract: serialize_jwe(payload, header, protected, aad, kem_ct,
recipient_key) produces the compact RFC 7516 + PQC-extended 5-stanza
format: base64url(header).base64url(protected).base64url(payload).
base64url(AAD).base64url(kem_ct).

Test: test_serialize_jwe_baseline - produce JWE from known inputs,
verify round-trip deserialization.
"""

import json

import pytest

from pqblocks_jwe import InvalidJWEError, parse_jwe, serialize_jwe

HEADER = {"alg": "MLKEM768-X25519", "enc": "A256GCM", "kid": "pq-settlement-2025", "typ": "application/jwe"}
PROTECTED = {"alg": "A256GCM", "enc": "A256GCM", "cty": "application/json"}
PAYLOAD = b'{"amount":1000000,"currency":"USD"}'
AAD = b"settlement-v1"
KEM_CT = bytes(range(256)) * 4 + bytes(range(64))  # 1088 bytes, ML-KEM-768 ct size


def test_serialize_jwe_baseline():
    """Known inputs produce a 5-stanza compact token that round-trips."""
    token = serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT)
    assert isinstance(token, bytes)
    stanzas = token.split(b".")
    assert len(stanzas) == 5
    parsed = parse_jwe(token)
    assert parsed["header"] == HEADER
    assert parsed["protected"] == PROTECTED
    assert parsed["payload"] == PAYLOAD
    assert parsed["aad"] == AAD
    assert parsed["kem_ct"] == KEM_CT


def test_serialize_jwe_deterministic():
    """Same inputs give bit-identical output (seed-free determinism)."""
    first = serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT)
    second = serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT)
    assert first == second


def test_serialize_jwe_key_order_canonical():
    """Header key insertion order does not change the wire bytes."""
    shuffled = {"typ": "application/jwe", "kid": "pq-settlement-2025", "enc": "A256GCM", "alg": "MLKEM768-X25519"}
    assert serialize_jwe(PAYLOAD, shuffled, PROTECTED, AAD, KEM_CT) == serialize_jwe(
        PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT
    )


def test_serialize_jwe_rejects_bad_types():
    """Garbage in raises loudly, never silent corruption (spec 3.11)."""
    with pytest.raises(InvalidJWEError):
        serialize_jwe("not-bytes", HEADER, PROTECTED, AAD, KEM_CT)  # type: ignore[arg-type]
    with pytest.raises(InvalidJWEError):
        serialize_jwe(PAYLOAD, ["not-a-dict"], PROTECTED, AAD, KEM_CT)  # type: ignore[arg-type]
    with pytest.raises(InvalidJWEError):
        serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, "not-bytes")  # type: ignore[arg-type]


def test_parse_jwe_empty():
    """Empty token raises InvalidJWEError (spec 3.1)."""
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"")
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"....")


def test_parse_jwe_single_stanza():
    """Token with missing stanzas raises InvalidJWEError (spec 3.1)."""
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"aGVsbG8")
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"e30.e30.e30")


def test_parse_jwe_bad_base64():
    """Non-base64url stanza raises InvalidJWEError."""
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"!!!.e30.e30.e30.e30")


def test_parse_jwe_non_json_header():
    """Header stanza that is not JSON raises InvalidJWEError."""
    import base64

    not_json = base64.urlsafe_b64encode(b"plain-bytes").rstrip(b"=")
    token = b".".join([not_json, b"e30", b"e30", b"e30", b"e30"])
    with pytest.raises(InvalidJWEError):
        parse_jwe(token)


def test_stanzas_are_jwcrypto_base64url():
    """Wire stanzas decode with jwcrypto's own base64url primitive."""
    from jwcrypto.common import base64url_decode

    token = serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT)
    stanzas = token.decode("ascii").split(".")
    assert json.loads(base64url_decode(stanzas[0])) == HEADER
    assert base64url_decode(stanzas[2]) == PAYLOAD


# ---------------------------------------------------------------------------
# Error-path tests: each one drives a specific raise site in
# src/pqblocks_jwe/jwe.py (line numbers below refer to that file).
# ---------------------------------------------------------------------------


def test_serialize_header_not_json_serializable():
    """Header containing a non-JSON-serializable value raises (covers 38-39)."""
    with pytest.raises(InvalidJWEError):
        serialize_jwe(PAYLOAD, {"kid": {1, 2}}, PROTECTED, AAD, KEM_CT)


def test_parse_header_json_not_object():
    """Header stanza decoding to a JSON array raises (covers 59)."""
    import base64

    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")
    with pytest.raises(InvalidJWEError):
        parse_jwe(b".".join([b64(b"[1,2]"), b64(b"{}"), b64(b"x"), b64(b"a"), b64(b"k")]))


def test_parse_bad_base64_length_json_stanza():
    """Malformed base64 in a JSON stanza raises (covers 52-53)."""
    import base64

    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")
    with pytest.raises(InvalidJWEError):
        parse_jwe(b".".join([b"e", b64(b"{}"), b64(b"x"), b64(b"a"), b64(b"k")]))


def test_parse_bad_base64_length_bytes_stanza():
    """Malformed base64 in a bytes stanza raises (covers 66-67)."""
    import base64

    b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=")
    with pytest.raises(InvalidJWEError):
        parse_jwe(b".".join([b64(b"{}"), b64(b"{}"), b"e", b64(b"a"), b64(b"k")]))


def test_serialize_rejects_non_bytes_recipient_key():
    """Non-bytes recipient_key raises (covers 86)."""
    with pytest.raises(InvalidJWEError):
        serialize_jwe(PAYLOAD, HEADER, PROTECTED, AAD, KEM_CT, recipient_key="not-bytes")


def test_parse_rejects_str_token():
    """A str token (instead of bytes) raises (covers 92)."""
    with pytest.raises(InvalidJWEError):
        parse_jwe("str-token")  # type: ignore[arg-type]


def test_parse_rejects_non_ascii_token():
    """Non-ASCII token bytes raise (covers 95-96)."""
    with pytest.raises(InvalidJWEError):
        parse_jwe(b"\xc0\xff\xee")
