"""Compact five-part wire format for hybrid ML-KEM-768 + X25519 JWE-style tokens.

A token is five base64url stanzas (RFC 4648 section 5, no padding) joined by ".":

    header . protected . payload . aad . kem_ct

header and protected are JSON objects encoded canonically (sorted keys, no
whitespace); payload, aad and kem_ct are raw bytes. This module only
serializes and parses that layout. It performs no key encapsulation, no key
derivation and no encryption: the caller supplies payload as ciphertext it has
already produced, and kem_ct as the hybrid KEM ciphertext. The header values
are not checked; the caller must check alg and enc after parse_jwe.

Every rejected input raises InvalidJWEError (a ValueError subclass).
parse_jwe requires bytes, ASCII, exactly five non-empty stanzas, JSON
objects in the first two stanzas and valid base64url in all five.
Base64url encoding and decoding use jwcrypto.common.
"""

import json
from typing import Any, Dict, Optional

from jwcrypto.common import base64url_decode, base64url_encode

ALG_HYBRID = "MLKEM768-X25519"
ENC_A256GCM = "A256GCM"


class InvalidJWEError(ValueError):
    pass


def _encode_json_canonical(mapping: Dict[str, Any], what: str) -> str:
    if not isinstance(mapping, dict):
        raise InvalidJWEError(f"{what} must be a JSON object, got {type(mapping).__name__}")
    try:
        text = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise InvalidJWEError(f"{what} is not JSON-serializable: {exc}") from exc
    return base64url_encode(text.encode("utf-8"))


def _encode_bytes(raw: bytes, what: str) -> str:
    if not isinstance(raw, bytes):
        raise InvalidJWEError(f"{what} must be bytes, got {type(raw).__name__}")
    return base64url_encode(raw)


def _decode_json(stanza: str, what: str) -> Dict[str, Any]:
    try:
        raw = base64url_decode(stanza)
    except Exception as exc:
        raise InvalidJWEError(f"{what} stanza is not base64url: {exc}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidJWEError(f"{what} stanza is not JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise InvalidJWEError(f"{what} stanza must decode to a JSON object")
    return value


def _decode_bytes(stanza: str, what: str) -> bytes:
    try:
        return base64url_decode(stanza)
    except Exception as exc:
        raise InvalidJWEError(f"{what} stanza is not base64url: {exc}") from exc


def serialize_jwe(
    payload: bytes,
    header: Dict[str, Any],
    protected: Dict[str, Any],
    aad: bytes,
    kem_ct: bytes,
    recipient_key: Optional[bytes] = None,
) -> bytes:
    stanzas = [
        _encode_json_canonical(header, "header"),
        _encode_json_canonical(protected, "protected"),
        _encode_bytes(payload, "payload"),
        _encode_bytes(aad, "aad"),
        _encode_bytes(kem_ct, "kem_ct"),
    ]
    if recipient_key is not None and not isinstance(recipient_key, bytes):
        raise InvalidJWEError(f"recipient_key must be bytes, got {type(recipient_key).__name__}")
    return ".".join(stanzas).encode("ascii")


def parse_jwe(token: bytes) -> Dict[str, Any]:
    if not isinstance(token, bytes):
        raise InvalidJWEError(f"token must be bytes, got {type(token).__name__}")
    try:
        text = token.decode("ascii")
    except UnicodeDecodeError as exc:
        raise InvalidJWEError(f"token is not ASCII: {exc}") from exc
    stanzas = text.split(".")
    if len(stanzas) != 5 or any(s == "" for s in stanzas):
        raise InvalidJWEError(f"token must have 5 non-empty stanzas, got {len(stanzas)}")
    header_s, protected_s, payload_s, aad_s, kem_ct_s = stanzas
    return {
        "header": _decode_json(header_s, "header"),
        "protected": _decode_json(protected_s, "protected"),
        "payload": _decode_bytes(payload_s, "payload"),
        "aad": _decode_bytes(aad_s, "aad"),
        "kem_ct": _decode_bytes(kem_ct_s, "kem_ct"),
    }
