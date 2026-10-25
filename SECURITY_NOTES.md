# Security notes: pqblocks-jwe

## What this package is

A serializer and parser for a five-part token layout. **It contains no cryptography:** no key generation, no ML-KEM, no X25519, no key derivation and no AEAD. It is not "post-quantum secure" by itself. The `alg: "MLKEM768-X25519"` label in a token is only a string that the caller writes and reads.

## What it protects and what it does not

- **Protects:** nothing. It offers structural parsing and rejects malformed tokens with a typed error. It does not check `alg` or `enc` values, so `alg: none` parses.
- **Does not protect confidentiality.** `payload` is written as given. Plaintext in means plaintext on the wire.
- **Does not protect integrity or authenticity.** No stanza is authenticated by this package, including the one named `protected`. Any binding between header, AAD and ciphertext must come from the AEAD you run yourself.
- **Does not stop algorithm downgrade.** `parse_jwe` accepts any `alg` / `enc` value, including `"none"`. The caller must check both (`examples/reject_hostile.py`).
- **`recipient_key` is ignored.** It is accepted and type-checked, then neither used nor written to the token.

## Backend

Pure Python. The only runtime dependency is jwcrypto, and only its base64url helpers are used. No liboqs, no pyca/cryptography calls and no native code.

## Constant-time status, zeroization, RNG

- **Constant time:** not applicable. No secret-dependent computation takes place. Parsing time depends on token length.
- **Zeroization:** none. The package holds no keys. Callers who pass secret bytes (they should not) get no zeroization; Python `bytes` cannot be wiped.
- **RNG:** none is used. Output is fully deterministic.

## Input handling (hostile tokens)

`parse_jwe` rejects input that is not `bytes`, non-ASCII input, a wrong stanza count, empty stanzas, undecodable base64url and non-object JSON, all with `InvalidJWEError`. The remaining weaknesses come from the crypto-integration review (see VERIFICATION_REPORT.md) and none are fixed in 0.1.0:

| Severity | Issue | What to do |
|---|---|---|
| MEDIUM | No encryption is performed, and the `alg` label and the parameter name `payload` can suggest otherwise. | Pass only ciphertext you produced. Use `pqblocks-jose` if you need encryption. |
| MEDIUM | `alg` / `enc` are never checked, so a token with `alg: none` parses without error. | Check both against your expected values after `parse_jwe`. |
| MEDIUM | Very deeply nested JSON in the header stanzas (around 100,000 levels in our probe) raises `RecursionError`, which is **not** an `InvalidJWEError`. There is no size limit. | Cap the token length before parsing, and catch `RecursionError` as well as `InvalidJWEError`. |
| LOW | Lenient base64url: `=` padding is accepted, characters outside the alphabet are silently dropped (`YWJj!!!!` decodes like `YWJj`), and non-canonical trailing bits are accepted. Different byte strings parse to the same fields. | Do not key replay caches or deduplication on raw token bytes; key them on parsed fields or on your AEAD output. |
| LOW | `serialize_jwe` accepts empty `payload`, `aad` or `kem_ct`, but `parse_jwe` rejects the resulting token. | Never serialize empty fields. |
| LOW | Duplicate JSON keys: the last value wins (allowed by RFC 7515 §4). `NaN` / `Infinity` are accepted and emitted, which is not valid RFC 8259 JSON. Non-string keys such as `1` are turned into `"1"`. | Use plain string keys and finite numbers in headers. |

Error messages contain only the stanza name and the decoder's message, never key material, because there is none.

## Dependencies

- Runtime: `jwcrypto` (LGPL-3.0-or-later), which pulls in `cryptography` and `typing_extensions`.
- `pip-audit` found no known vulnerabilities in jwcrypto 1.6.1 at build time (see VERIFICATION_REPORT.md).

## Audit status

Checked by its own 16-test suite, an internal adversarial input review and a read-only crypto-integration review. It has had no external third-party audit.

## Validation status

Not FIPS 140-3 or CMVP validated. Because the package contains no cryptographic algorithm, there is nothing to validate. Validation questions belong to whatever KEM and AEAD implementation you use alongside it.
