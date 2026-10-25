# pqblocks-jwe

A compact five-part wire format for hybrid post-quantum/classical (ML-KEM-768 + X25519) JWE-style tokens, plus a serializer and a structural parser (it does not validate `alg` or `enc` values). **It does not encrypt anything.**
Use it when you already produce the AEAD ciphertext and the hybrid KEM ciphertext yourself and need one deterministic, structurally validated token to carry them. To actually encrypt, decrypt or sign, use [`pqblocks-jose`](https://github.com/PQBlocks/hybrid-jose) instead.
Standards used: base64url (RFC 4648 §5) and JSON (RFC 8259), with a layout modelled on JWE compact serialization (RFC 7516). The layout is **not** RFC 7516 compact serialization, and standard JOSE libraries cannot read it.

```bash
pip install pqblocks-jwe
```

```python
from pqblocks_jwe import ALG_HYBRID, ENC_A256GCM, parse_jwe, serialize_jwe

ciphertext = bytes(48)        # your AEAD output; this package does not encrypt
kem_ct = bytes(1088 + 32)     # your ML-KEM-768 ciphertext || X25519 ephemeral public key
header = {"alg": ALG_HYBRID, "enc": ENC_A256GCM, "kid": "recipient-1"}

token = serialize_jwe(ciphertext, header, {"cty": "application/json"}, b"settlement-v1", kem_ct)
parsed = parse_jwe(token)
assert parsed["header"]["alg"] == ALG_HYBRID   # parse_jwe does not check alg/enc for you
print(len(token), parsed["aad"], len(parsed["kem_ct"]))   # 1697 b'settlement-v1' 1120
```

## Why PQBlocks

- **What this package is:** a wire format and its parser/serializer. It does no key generation, KEM encapsulation, key derivation or AEAD. Everything you pass in as `payload` is written to the token **as is**. If you pass plaintext, the token carries plaintext.
- **When to use `pqblocks-jose` instead:** whenever you need the cryptography itself. `pqblocks-jose` is the full PQBlocks JOSE suite: hybrid encryption and decryption (`encrypt_jwe` / `decrypt_jwe`) and signatures (`encode_jws` / `decode_jws`). Use `pqblocks-jwe` only for this five-part layout, for example to carry ciphertext produced by your own KEM and AEAD stack, or to inspect and validate tokens in that layout.
- **Tested:** 16 tests in one test file, 100 % statement and branch coverage of a 53-statement module. That suite is small. See [TESTING.md](TESTING.md) for what it does not cover.
- **Honest benchmarks:** the comparison with jwcrypto is published, including the case where jwcrypto is faster, together with the reason the comparison is not like-for-like ([BENCHMARKS.md](BENCHMARKS.md)).
- **Licence:** Apache-2.0.

## Usage

**Token layout.** Five base64url stanzas (no padding) joined by `.`:

```
base64url(header) . base64url(protected) . base64url(payload) . base64url(aad) . base64url(kem_ct)
```

| # | Stanza | Encoding | Intended content |
|---|---|---|---|
| 1 | `header` | canonical JSON object (`sort_keys=True`, separators `,` `:`) | e.g. `{"alg": "MLKEM768-X25519", "enc": "A256GCM", "kid": ...}` |
| 2 | `protected` | canonical JSON object | e.g. `{"cty": "application/json"}` |
| 3 | `payload` | raw bytes | ciphertext you produced |
| 4 | `aad` | raw bytes | additional authenticated data you bound into your AEAD |
| 5 | `kem_ct` | raw bytes | hybrid KEM ciphertext (ML-KEM-768 ciphertext is 1088 bytes, FIPS 203 Table 3) |

**Determinism.** The same inputs always give the same bytes, and the key order of `header` / `protected` does not change the output.

**There is no IV or tag stanza.** Unlike RFC 7516, the layout has no slot for an AEAD nonce or authentication tag. If your AEAD needs them, you must carry them yourself, for example inside the ciphertext bytes, and agree that convention with the receiver.

**Validate after parsing.** `parse_jwe` checks structure only. It accepts any `alg` and `enc` value, including `"none"`. Compare them with what you expect before using the token (`examples/reject_hostile.py`).

**Empty fields.** `parse_jwe` rejects empty stanzas, but `serialize_jwe` does not reject empty `payload`, `aad` or `kem_ct`. A token serialized with an empty field therefore cannot be parsed back. Do not pass empty fields.

## API reference

`serialize_jwe(payload: bytes, header: dict, protected: dict, aad: bytes, kem_ct: bytes, recipient_key: bytes | None = None) -> bytes`

- Returns the ASCII token.
- Raises `InvalidJWEError` when `payload`, `aad` or `kem_ct` is not `bytes`, when `header` or `protected` is not a `dict` or is not JSON-serializable, or when `recipient_key` is not `None` and not `bytes`.
- `recipient_key` is type-checked and then **ignored**. It is not written to the token and not used.

`parse_jwe(token: bytes) -> dict`

- Returns `{"header": dict, "protected": dict, "payload": bytes, "aad": bytes, "kem_ct": bytes}`.
- Raises `InvalidJWEError` when the token is not `bytes`, not ASCII, does not have exactly 5 non-empty stanzas, a stanza is not decodable base64url, or the first two stanzas are not JSON objects.

`InvalidJWEError`: subclass of `ValueError`.

`ALG_HYBRID = "MLKEM768-X25519"` and `ENC_A256GCM = "A256GCM"`: label constants for your header. Neither function uses them.

## Limitations

- **No cryptography.** No KEM, KDF or AEAD, so no confidentiality and no integrity. The `alg` label is not enforced.
- **Not RFC 7516 compatible.** RFC 7516 compact serialization is `protected.encrypted_key.iv.ciphertext.tag`. This layout uses the same five-part shape but different contents, so jwcrypto, python-jose and other JOSE libraries cannot interpret these tokens, and this package cannot interpret theirs.
- **Lenient base64url decoding** (from `jwcrypto.common.base64url_decode`): `=` padding is accepted, characters outside the base64 alphabet are silently dropped, and non-canonical trailing bits are accepted. Several different byte strings can therefore parse to the same fields. Do not use raw token bytes as a replay-cache or deduplication key.
- **Parser edge cases:** for duplicate JSON keys the last value wins; `NaN` / `Infinity` are accepted and emitted; deeply nested JSON (about 100,000 levels in our probe) raises `RecursionError` instead of `InvalidJWEError`; there is no token size limit.
- **Empty fields** do not round-trip (see Usage).
- **No official test vectors:** there is no published standard for this exact layout, so there are none to run.

## Security notes

This package protects nothing by itself. See [SECURITY_NOTES.md](SECURITY_NOTES.md) for the full list, including the open review findings.

## Verification

[TESTING.md](TESTING.md) · [BENCHMARKS.md](BENCHMARKS.md) · [EVIDENCE.md](EVIDENCE.md) · [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md) · [USE_CASES.md](USE_CASES.md)

## Part of PQBlocks

[PQBlocks](https://github.com/PQBlocks) builds open, tested building blocks for the post-quantum transition. This package is the wire-format layer. The cryptography lives in [`pqblocks-jose`](https://github.com/PQBlocks/hybrid-jose).
