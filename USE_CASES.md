# Use cases: pqblocks-jwe

This package lays out and parses tokens; it never encrypts. Each scenario assumes that the ciphertext and the hybrid KEM ciphertext come from somewhere else: your own ML-KEM-768 + X25519 + AEAD stack, an HSM, or another service. If you want the encryption done for you, see "When to use something else" at the end.

## 1. Carry ciphertext from your own hybrid PQ stack

A service already runs ML-KEM-768 + X25519 and AES-256-GCM (for example through an HSM) and needs one compact, deterministic token to send the results between services, such as a payment-settlement instruction.

```bash
python examples/roundtrip.py
```

```
stanza lengths: [86, 35, 64, 18, 1494]
token bytes: 1701
round trip preserves every field: True
deterministic and key-order independent: True
```

The script uses placeholder bytes for the ciphertext and for a 1120-byte `kem_ct` (1088-byte ML-KEM-768 ciphertext plus a 32-byte X25519 value). It checks that every field comes back unchanged and that header key order does not change the output. The layout has no IV or tag stanza, so if your AEAD needs a nonce, agree with the receiver where it goes (for example, prepended to the ciphertext).

## 2. Validate tokens at a boundary before handing them on

A gateway or audit tool receives tokens in this layout and must reject anything malformed, and anything carrying an unexpected algorithm label, before the token reaches the code that decrypts it.

```bash
python examples/reject_hostile.py
```

```
malformed tokens rejected: 8 / 8
parse_jwe accepts alg=none token: {'alg': 'none'}
caller policy rejects it: True
```

`parse_jwe` rejects structurally bad tokens with `InvalidJWEError`. It accepts any header values, including `alg: none`, so the script adds the caller-side `alg`/`enc` check that a real gateway must have. Also catch `RecursionError` if tokens can come from untrusted senders (see SECURITY_NOTES.md), and cap the token length before parsing.

## 3. Size planning for headers and message limits

Hybrid PQ tokens are large: the 1088-byte ML-KEM-768 ciphertext alone becomes about 1,450 base64url characters. You can check whether a token fits an HTTP header, cookie or broker message limit before you deploy:

```python
from pqblocks_jwe import serialize_jwe

header = {"alg": "MLKEM768-X25519", "enc": "A256GCM", "kid": "k1"}
for n in (64, 1024, 8192):
    token = serialize_jwe(bytes(n + 16), header, {}, b"aad", bytes(1120))   # ciphertext + 16-byte tag
    print(n, "byte plaintext ->", len(token), "byte token")
```

```
64 byte plaintext -> 1682 byte token
1024 byte plaintext -> 2962 byte token
8192 byte plaintext -> 12519 byte token
```

## When to use something else

- **You need encryption, decryption or signatures.** Use [`pqblocks-jose`](https://github.com/PQBlocks/hybrid-jose), the full PQBlocks JOSE suite (`encrypt_jwe` / `decrypt_jwe`, `encode_jws` / `decode_jws`).
- **You need standard RFC 7516 JWE interoperability** with existing JOSE libraries or identity providers. This layout is not RFC 7516 compact serialization. Use a JOSE library for that.
- **You need a FIPS 140-3 validated module.** This package is not one, and it contains no cryptography to validate.
