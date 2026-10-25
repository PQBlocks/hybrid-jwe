"""Feed malformed tokens to parse_jwe and show what the caller still has to check.

parse_jwe rejects structurally bad input with InvalidJWEError. It does NOT
check header values: a well-formed token with "alg": "none" parses fine. The
caller must compare alg and enc against what it expects, as `accept` does here.
"""
import base64

from pqblocks_jwe import ALG_HYBRID, ENC_A256GCM, InvalidJWEError, parse_jwe, serialize_jwe


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


malformed = {
    "empty token": b"",
    "three stanzas": b"e30.e30.e30",
    "empty stanza": b"e30.e30..YQ.YQ",
    "not base64url": b"!!!.e30.YQ.YQ.YQ",
    "header not JSON": b".".join([b64(b"plain"), b"e30", b"YQ", b"YQ", b"YQ"]),
    "header is a JSON array": b".".join([b64(b"[1,2]"), b"e30", b"YQ", b"YQ", b"YQ"]),
    "non-ASCII bytes": b"\xc0\xff\xee",
    "str instead of bytes": "e30.e30.YQ.YQ.YQ",
}
rejected = 0
for name, token in malformed.items():
    try:
        parse_jwe(token)
        print("ACCEPTED (unexpected):", name)
    except InvalidJWEError:
        rejected += 1
print("malformed tokens rejected: %d / %d" % (rejected, len(malformed)))


def accept(token):
    """Caller-side policy: the parser does not do this for you."""
    parsed = parse_jwe(token)
    if parsed["header"].get("alg") != ALG_HYBRID or parsed["header"].get("enc") != ENC_A256GCM:
        raise InvalidJWEError("unexpected alg/enc: %r" % parsed["header"])
    return parsed


downgrade = serialize_jwe(b"ct", {"alg": "none"}, {}, b"aad", b"kem")
print("parse_jwe accepts alg=none token:", parse_jwe(downgrade)["header"])
try:
    accept(downgrade)
    policy_rejects = False
except InvalidJWEError:
    policy_rejects = True
print("caller policy rejects it:", policy_rejects)
assert rejected == len(malformed) and policy_rejects
