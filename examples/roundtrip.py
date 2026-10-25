"""Serialize five stanzas, parse them back, and check the round trip.

pqblocks-jwe only lays out bytes the caller already has. In real use `payload`
is AEAD ciphertext and `kem_ct` is the hybrid ML-KEM-768 + X25519 KEM
ciphertext (1088 + 32 bytes). Here both are fixed placeholder bytes, so the
check is about the wire format only: every field must come back unchanged,
the output must be deterministic, and header key order must not matter.
"""
from pqblocks_jwe import ALG_HYBRID, ENC_A256GCM, parse_jwe, serialize_jwe

header = {"alg": ALG_HYBRID, "enc": ENC_A256GCM, "kid": "recipient-2026"}
protected = {"cty": "application/json"}
ciphertext = bytes(range(48))                    # placeholder: caller-produced AEAD output
aad = b"settlement-v1"
kem_ct = bytes(1088) + bytes(32)                 # placeholder: ML-KEM-768 ct || X25519 ephemeral key

token = serialize_jwe(ciphertext, header, protected, aad, kem_ct)
parsed = parse_jwe(token)

print("stanza lengths:", [len(s) for s in token.split(b".")])
print("token bytes:", len(token))
fields_ok = (parsed["header"] == header and parsed["protected"] == protected and parsed["payload"] == ciphertext
             and parsed["aad"] == aad and parsed["kem_ct"] == kem_ct)
print("round trip preserves every field:", fields_ok)
reordered = dict(reversed(list(header.items())))
print("deterministic and key-order independent:",
      serialize_jwe(ciphertext, reordered, protected, aad, kem_ct) == token)
assert fields_ok
