"""pqblocks_jwe - compact five-part wire format for hybrid ML-KEM-768 + X25519 JWE-style tokens.

Serializer and parser only: this package performs no key encapsulation, key derivation or encryption.
"""

from .jwe import (
    ALG_HYBRID,
    ENC_A256GCM,
    InvalidJWEError,
    parse_jwe,
    serialize_jwe,
)

__all__ = [
    "ALG_HYBRID",
    "ENC_A256GCM",
    "InvalidJWEError",
    "parse_jwe",
    "serialize_jwe",
]
