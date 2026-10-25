# Testing: pqblocks-jwe

**Status at release 0.1.0:**
- **16 of 16 tests pass** on Python 3.11, 3.12, 3.13 and 3.14. All 16 are in **one test file**, `tests/test_serialize_jwe.py`.
- Each run used the built wheel, installed in a fresh virtual environment with dependencies from PyPI.
- Statement and branch coverage are both 100 %, over 55 statements and 12 branches. The module is small, so 100 % coverage still leaves real gaps (see "What is not covered").

## How to run

```bash
pip install "pqblocks-jwe[test]"
pytest -q                      # from a checkout: pip install -e ".[test]" first
pytest -q --cov=pqblocks_jwe --cov-branch --cov-report=term-missing   # needs pytest-cov
```

## Results (measured 2026-10-25 UTC)

| Python | Install source | Tests | Examples |
|---|---|---|---|
| 3.11 | wheel + PyPI dependencies | 16 passed | 2 / 2 passed |
| 3.12 | wheel + PyPI dependencies | 16 passed | 2 / 2 passed |
| 3.13 | wheel + PyPI dependencies | 16 passed | 2 / 2 passed |
| 3.14 | wheel + PyPI dependencies | 16 passed | 2 / 2 passed |

The dependencies resolved at release were jwcrypto 1.6.1, cryptography 50.0.2, cffi 2.1.1, pycparser 3.12 and typing-extensions 4.16.0, with pytest 9.1.1.

### Coverage (installed wheel, Python 3.13.14, coverage 7.17.0)

| Module | Statements | Missed | Branches | Partial | Coverage |
|---|---|---|---|---|---|
| `__init__.py` | 2 | 0 | 0 | 0 | 100 % |
| `jwe.py` | 53 | 0 | 12 | 0 | 100 % |
| **Total** | **55** | **0** | **12** | **0** | **100 %** |

During the build, mutation testing killed 83 mutants and 52 survived (61.5 % of the mutants that had a covering test). That means about four in ten small code changes that the tests reach are not detected by them.

## What the tests check: `tests/test_serialize_jwe.py` (16)

### Round trip and determinism (4)

| Test | What it checks |
|---|---|
| `test_serialize_jwe_baseline` | Known inputs give a 5-stanza `bytes` token, and `parse_jwe` returns every field unchanged (1088-byte `kem_ct`) |
| `test_serialize_jwe_deterministic` | The same inputs give byte-identical tokens |
| `test_serialize_jwe_key_order_canonical` | Shuffled header key order gives the same bytes |
| `test_stanzas_are_jwcrypto_base64url` | The header and payload stanzas decode with jwcrypto's own base64url function (an independent decoder) |

### Rejection of bad input, all raising `InvalidJWEError` (12)

| Test | Input |
|---|---|
| `test_serialize_jwe_rejects_bad_types` | `str` payload, `list` header, `str` kem_ct |
| `test_serialize_header_not_json_serializable` | header containing a `set` |
| `test_serialize_rejects_non_bytes_recipient_key` | `str` recipient_key |
| `test_parse_jwe_empty` | `b""` and `b"...."` |
| `test_parse_jwe_single_stanza` | 1 and 3 stanzas |
| `test_parse_jwe_bad_base64` | `!!!` in the header stanza |
| `test_parse_bad_base64_length_json_stanza` | 1-character (impossible-length) header stanza |
| `test_parse_bad_base64_length_bytes_stanza` | 1-character payload stanza |
| `test_parse_jwe_non_json_header` | header stanza is base64url of non-JSON bytes |
| `test_parse_header_json_not_object` | header stanza decodes to a JSON array |
| `test_parse_rejects_str_token` | `str` instead of `bytes` |
| `test_parse_rejects_non_ascii_token` | non-ASCII bytes |

`tests/conftest.py` only adds `src/` to `sys.path` for checkout runs. It contains no tests.

### Official vectors

None. There is no published standard or official test-vector set for this five-part layout. The package performs no ML-KEM, X25519, KDF or AEAD operation, so NIST ACVP / FIPS 203 vectors do not apply to it.

## Examples run as tests

Each example checks its own answer (it ends with an `assert`) and runs in every release check above:

| Example | Check |
|---|---|
| `examples/roundtrip.py` | every field survives serialize → parse; output is deterministic and independent of header key order |
| `examples/reject_hostile.py` | 8 / 8 malformed tokens raise `InvalidJWEError`; a token with `alg: none` parses, and the caller-side policy rejects it |

## What is not covered

- **Empty fields:** no test serializes an empty `payload`, `aad` or `kem_ct`. Such tokens do not parse back (a known gap; see SECURITY_NOTES.md).
- **Lenient base64url:** no test pins down that padding, out-of-alphabet characters and non-canonical trailing bits are accepted.
- **Header semantics:** nothing tests `alg` / `enc` values, because the parser does not check them.
- **Hostile-size input:** no tests for deeply nested JSON (which raises `RecursionError`), very large tokens, `NaN` / `Infinity` or duplicate keys.
- **Property-based or fuzz testing:** none.
- **Interoperability:** no test against another implementation of this layout (none is known to exist).
- **Cryptography:** none to test. No KEM, KDF or AEAD code exists in this package.
- **Not in this suite:** a larger generated case matrix (60 cases) was run before release but is not shipped. Its results are summarised in [VERIFICATION_REPORT.md](VERIFICATION_REPORT.md).
