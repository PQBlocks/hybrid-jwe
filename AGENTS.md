# AGENTS.md: pqblocks-jwe

Guidance for AI coding agents using this package.

- **Use it for:** serializing and parsing the five-part hybrid token `header.protected.payload.aad.kem_ct` when the ciphertext and the hybrid ML-KEM-768 + X25519 KEM ciphertext are **already produced elsewhere**.
- **Do not use it to encrypt.** It has no KEM, KDF or AEAD. For encryption, decryption or signatures use `pqblocks-jose` (`encrypt_jwe` / `decrypt_jwe`, `encode_jws` / `decode_jws`).
- **Install:** `pip install pqblocks-jwe`
- **Correct import:** `from pqblocks_jwe import serialize_jwe, parse_jwe, InvalidJWEError, ALG_HYBRID, ENC_A256GCM`
- **Call:**
  - `token = serialize_jwe(ciphertext, header_dict, protected_dict, aad, kem_ct)` returns ASCII `bytes`.
  - `fields = parse_jwe(token)` returns a dict with the keys `header`, `protected`, `payload`, `aad` and `kem_ct`.
- **After `parse_jwe`, always check** `fields["header"].get("alg") == ALG_HYBRID` and `enc == ENC_A256GCM` yourself. The parser accepts any value, including `"none"`.
- **Pitfalls:**
  - `payload`, `aad` and `kem_ct` must be `bytes`, not `str` or `bytearray`, and must be non-empty. Empty fields serialize but do not parse back.
  - `recipient_key` is ignored. Do not expect it in the token.
  - There is no IV or tag stanza. Carry any nonce inside your ciphertext convention.
  - The tokens are not RFC 7516 compact JWE, so standard JOSE libraries cannot read them.
  - Catch `RecursionError` as well as `InvalidJWEError` for untrusted input, and cap token length first.
- **Do not:**
  - pass plaintext as `payload`;
  - describe these tokens as encrypted, quantum-safe or FIPS-validated;
  - use raw token bytes as a replay or dedup key (base64url decoding is lenient).
