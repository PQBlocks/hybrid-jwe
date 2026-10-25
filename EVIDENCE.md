# Evidence: pqblocks-jwe

This file lists the standards behind each part of the wire format and shows where each rule lives in the code. The code is small (`src/pqblocks_jwe/jwe.py`, 53 statements). Where earlier internal design documents described more than the code does, **the code is authoritative**. In particular, those documents described ML-KEM, KMAC256 key derivation and AES-GCM steps, and none of them are implemented.

## Primary sources

1. **RFC 4648**, *The Base16, Base32, and Base64 Data Encodings*, §5 "Base 64 Encoding with URL and Filename Safe Alphabet". S. Josefsson, October 2006. doi:[10.17487/RFC4648](https://doi.org/10.17487/RFC4648)
   - Encoding of all five stanzas (no padding).
2. **RFC 8259**, *The JavaScript Object Notation (JSON) Data Interchange Format*. T. Bray (ed.), December 2017. doi:[10.17487/RFC8259](https://doi.org/10.17487/RFC8259)
   - The header and protected stanzas are JSON objects.
3. **RFC 7516**, *JSON Web Encryption (JWE)*. M. Jones, J. Hildebrand, May 2015. doi:[10.17487/RFC7516](https://doi.org/10.17487/RFC7516)
   - Inspiration for the five-part, dot-separated shape. **Not implemented:** RFC 7516 §7.1 compact serialization is `protected.encrypted_key.iv.ciphertext.tag`, and this package uses a different layout.
4. **RFC 7515**, *JSON Web Signature (JWS)*. M. Jones, J. Bradley, N. Sakimura, May 2015. doi:[10.17487/RFC7515](https://doi.org/10.17487/RFC7515)
   - §4: header parameter names must be unique, and a parser must either reject duplicates or keep only the lexically last one. This package keeps the last one (see the method-to-code table).
5. **NIST FIPS 203**, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024. doi:[10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
   - Table 3: an ML-KEM-768 ciphertext is 1088 bytes. This is the content the `kem_ct` stanza is meant to carry. This package does not implement ML-KEM.
6. **RFC 7748**, *Elliptic Curves for Security*. A. Langley, M. Hamburg, S. Turner, January 2016. doi:[10.17487/RFC7748](https://doi.org/10.17487/RFC7748)
   - X25519: 32-byte public values, which the `kem_ct` stanza is meant to carry alongside the ML-KEM ciphertext. This package does not implement X25519.

All DOIs above were resolved through the Crossref API on 2026-10-25.

Third-party code used: **jwcrypto** (https://github.com/latchset/jwcrypto), but only its `jwcrypto.common.base64url_encode` and `base64url_decode` helpers.

## Method to code

| Rule | Source | Implementation (`src/pqblocks_jwe/jwe.py`) |
|---|---|---|
| Five stanzas joined by `.` | layout of this package, shaped like RFC 7516 | `serialize_jwe` builds `[header, protected, payload, aad, kem_ct]` and joins them with `"."`; `parse_jwe` splits on `"."` and requires exactly 5 |
| Stanzas are non-empty | this package | `parse_jwe`: `any(s == "" for s in stanzas)` → `InvalidJWEError`. `serialize_jwe` does **not** enforce this (known gap) |
| base64url without padding | RFC 4648 §5 | `jwcrypto.common.base64url_encode` (strips `=`) |
| base64url decoding | RFC 4648 §5 | `jwcrypto.common.base64url_decode`: re-adds padding, then calls Python's non-validating `urlsafe_b64decode`, which also accepts `=`, drops characters outside the alphabet and ignores non-canonical trailing bits |
| JSON objects in stanzas 1 and 2 | RFC 8259 | `_encode_json_canonical` rejects non-`dict` values; `_decode_json` rejects non-objects |
| Canonical JSON | this package (sorted keys, no whitespace) | `json.dumps(mapping, sort_keys=True, separators=(",", ":"))`. This is **not** RFC 8785 JCS: non-ASCII text is `\u`-escaped and `NaN`/`Infinity` are allowed |
| Duplicate header names | RFC 7515 §4 (keep lexically last) | Python `json.loads` keeps the last duplicate |
| Token is ASCII bytes | this package | `parse_jwe` requires `bytes` and ASCII; `serialize_jwe` returns `.encode("ascii")` |
| `alg` / `enc` labels | this package | constants `ALG_HYBRID = "MLKEM768-X25519"`, `ENC_A256GCM = "A256GCM"`; **not checked by either function** |
| `recipient_key` argument | this package | type-checked (`bytes` or `None`), then unused |

## Independent checks of the mapping

- **jwcrypto decodes our stanzas:** `test_stanzas_are_jwcrypto_base64url` decodes the header and payload stanzas with jwcrypto's own base64url function and compares them with the inputs.
- **Hand-made tokens:** the error-path tests build tokens with Python's standard `base64.urlsafe_b64encode` rather than with the package's own encoder, and check that each malformed stanza is rejected.
- **Not available:** there is no published standard or official test-vector set for this exact five-part layout, so no external vectors exist to run against it.

## Licence and provenance

- Original code, distributed under Apache-2.0.
- The only runtime dependency is jwcrypto (LGPL-3.0-or-later), which is used through its public API and not copied.
