# Verification report: pqblocks-jwe 0.1.0

This is a **self-verification** report: what was checked, how, and with what result. It is not a third-party audit or external validation of any kind.

## Summary

| Area | Result |
|---|---|
| Correctness | 16/16 tests pass (one test file); round trip, determinism, key-order independence and 12 rejection paths |
| Coverage | 100 % statements and branches (55 statements, 12 branches); mutation testing: 83 killed, 52 survived |
| Install as a user gets it | wheel installed from scratch with PyPI dependencies on Python 3.11, 3.12, 3.13 and 3.14: all tests and both examples pass |
| Packaging | sdist and wheel build cleanly; `twine check --strict` passes |
| Dependencies | `pip-audit` 2.10.1: no known vulnerabilities (jwcrypto 1.6.1, cryptography 50.0.2, cffi 2.1.1, pycparser 3.12, typing-extensions 4.16.0) |
| Benchmarks | compared with jwcrypto 1.6.1 at 4 payload sizes; losing case and the non-like-for-like caveat published ([BENCHMARKS.md](BENCHMARKS.md)) |
| Crypto-integration review | 0 critical, 0 high, 3 medium, 3 low; none fixed in 0.1.0, all listed in [SECURITY_NOTES.md](SECURITY_NOTES.md) |
| Scope honesty | wire format only; no KEM, KDF or AEAD; not RFC 7516 compatible; no official vectors exist for this layout |

## Review checks completed before release

| Check | Purpose | Result |
|---|---|---|
| Check 1 (design review) | Scope and method; reuse of maintained primitives instead of new cryptography | Pass after several failed attempts. The scope was cut to the wire format; the KEM/KDF/AEAD steps of the original design were not built |
| Check 2 (spec review) | Specification of the stanza layout and edge cases | Pass |
| Check 3 (correctness) | Test suite and coverage | Pass (16/16, 100 %) after several attempts that added the error-path tests |
| Check 4 (benchmark review) | Baseline run, raw data consistent with the summary card, losing cases kept | Pass after eight failed attempts. Earlier attempts found summary cards citing raw runs with fewer iterations than claimed, and disagreement over how to read the internal 1,568-byte size target. See BENCHMARKS.md for how that target is treated here |
| Check 5 (adversarial review) | Pathological input, misuse, claims audit | Pass after three failed attempts. Earlier attempts raised empty-field handling, which remains open (see below) |
| Release check (this report) | Rename, build, fresh-environment install on four Pythons, leak scan, dependency audit, crypto-integration review | Pass |

## Release-check evidence (2026-10-25 UTC)

```
build sdist+wheel                  PASS  pqblocks_jwe-0.1.0-py3-none-any.whl
twine check --strict               PASS
python 3.11: tests                 PASS  16 passed
python 3.12: tests                 PASS  16 passed
python 3.13: tests                 PASS  16 passed
python 3.14: tests                 PASS  16 passed
examples (roundtrip, reject_hostile) PASS on all four versions
public-text scan (folder + wheel + sdist) PASS  0 hits
pip-audit                          No known vulnerabilities found
```

Before the rename, the original suite gave 16 passed. After the rename it gave 16 passed again (equal to the baseline), and 16 passed on the installed wheel in a clean room.

## Defects found and fixed during this release

1. **Import broken by the package rename.** The implementation module inside the package still carried the product's former name, and renaming the package import made `__init__.py` look for a module that did not exist (`ModuleNotFoundError`, every test failed to collect). The module is now `pqblocks_jwe/jwe.py`, and `__init__.py` imports from it. Code lines are byte-identical to the verified original; only the file name and the docstring changed.
2. **Misleading module docstrings.** The package and module docstrings described a "Hybrid PQ JWE envelope (ML-KEM-768 + X25519)" and planned KEM/KDF/AEAD stages that were never built. They now describe the wire format, state that nothing is encrypted, and say that `alg` / `enc` are not checked.
3. **Earlier internal documentation disagreed with the code.** It described ML-KEM, X25519, KMAC256 and AES-GCM steps, helper functions that do not exist, RFC 7516 conformance and a non-deterministic output. The code is authoritative: it does none of those things, and its output is deterministic. All public docs were written from the code.

## Known limitations (open)

- **No cryptography:** this package is a format, not a protection. Use `pqblocks-jose` for encryption.
- **Open review findings** (details in SECURITY_NOTES.md):
  - MEDIUM: no encryption behind a JWE-like name;
  - MEDIUM: `alg` / `enc` are not checked;
  - MEDIUM: deeply nested JSON raises `RecursionError` instead of `InvalidJWEError`, and there is no size cap;
  - LOW: lenient base64url decoding;
  - LOW: empty fields serialize but do not parse;
  - LOW: `NaN` / duplicate-key / non-string-key handling.
- **Generated case matrix:** 60 cases were run before release: 47 passed, 6 failed and 7 were skipped. The 7 skips are official-vector cases, which do not apply to a layout with no cryptography. Of the 6 failures:
  - 3 are a lenient reference oracle;
  - 2 are a generator bug, with a missing parameter;
  - 1 is the real empty-AAD round-trip gap listed above. It was first classified as an oracle defect, but the product does reject that token.
- **Small suite:** 16 tests, no property-based or fuzz testing; mutation testing left 52 surviving mutants.
- **Benchmarks:** one machine, high run-to-run variance; the jwcrypto comparison is not like-for-like.

## Validation status

Not FIPS 140-3 or CMVP validated. The package contains no cryptographic algorithm, so there is nothing to validate.
