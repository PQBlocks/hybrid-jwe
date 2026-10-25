# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-25

### Added
- `serialize_jwe` and `parse_jwe` for the five-part token layout `header.protected.payload.aad.kem_ct`, using base64url without padding and canonical (sorted-key) JSON headers, with deterministic output.
- `InvalidJWEError` (a `ValueError` subclass) for every rejected input: wrong types, non-ASCII input, wrong stanza count, empty stanzas, bad base64url and non-object JSON.
- `ALG_HYBRID` (`"MLKEM768-X25519"`) and `ENC_A256GCM` (`"A256GCM"`) label constants.
- Examples: a round-trip check and a hostile-input check with a caller-side `alg`/`enc` policy.
- Benchmarks against jwcrypto 1.6.1, including the losing case and the reason the comparison is not like-for-like.
