# Benchmarks: pqblocks-jwe

Serialization and parse latency, plus token size, at four payload sizes, next to jwcrypto 1.6.1. **No performance claim is made for this package.** The jwcrypto side encrypts and ours does not (see "Read these numbers carefully"), so the timings are not like-for-like. The numbers are published for size planning and as a latency budget for the wire-format step alone.
Raw data: [benchmarks/](benchmarks/). There is one file per payload size with all 200 samples per measurement, plus [benchmarks/benchmark-card.json](benchmarks/benchmark-card.json), the summary the tables below are taken from. Internal labels were renamed; no number was changed.

## Setup

| Item | Value |
|---|---|
| Date of run | 2026-10-22, 09:51 UTC |
| CPU | Intel Core i5-10300H @ 2.50 GHz, 8 logical CPUs, CPU governor `powersave` |
| OS / Python | Linux 7.2.6 (glibc 2.44), CPython 3.14.8 |
| Libraries | jwcrypto 1.6.1, cryptography 50.0.1 |
| Method | per (implementation, payload size): 20 warm-up calls excluded, then 200 timed calls with `time.perf_counter_ns`; single thread, same process |
| Reported | median and p99 per call, in milliseconds |
| Inputs | deterministic filler payloads of 64 B, 1 KiB, 64 KiB and 1 MiB; fixed header and protected header; 13-byte AAD; a fixed 1088-byte placeholder in the `kem_ct` stanza |
| Correctness check | every case records a round-trip check for both sides; all were `true` |

**What is timed on each side:**
- **Ours:** `serialize_jwe` (and, separately, `parse_jwe`), which is canonical JSON plus base64url encoding of bytes the caller already holds. No cryptography is involved.
- **jwcrypto:** JWE compact serialization with `alg=dir`, `enc=A256GCM` and a 256-bit key. This **encrypts the payload with AES-256-GCM**. jwcrypto rejects the `MLKEM768-X25519` algorithm (`InvalidJWEOperation: Algorithm not allowed`), so its nearest supported path was used. The jwcrypto calls ran without AAD, because jwcrypto compact mode does not accept a separate AAD.

## Results

### Serialize, ms per call

| Payload | Ours median | Ours p99 | jwcrypto median | jwcrypto p99 |
|---|---|---|---|---|
| 64 B | 0.0289 | 0.0512 | 0.2512 | 0.5915 |
| 1 KiB | 0.0418 | 0.0698 | 0.2579 | 0.4816 |
| 64 KiB | 0.5984 | 0.8529 | 0.8450 | 1.4320 |
| 1 MiB | **7.7725** | **10.8423** | **5.9597** | **8.2544** |

### Parse, ms per call (ours only)

| Payload | Median | p99 |
|---|---|---|
| 64 B | 0.0150 | 0.0316 |
| 1 KiB | 0.0454 | 0.0765 |
| 64 KiB | 0.6139 | 2.5119 |
| 1 MiB | 7.5523 | 11.4023 |

The jwcrypto parse timings were not recorded in the raw data, so no parse comparison is shown.

### Token size, bytes

| Payload | Ours, full token | Ours, without the payload stanza | jwcrypto token |
|---|---|---|---|
| 64 B | 1,760 | 1,674 | 171 |
| 1 KiB | 3,040 | 1,674 | 1,451 |
| 64 KiB | 89,056 | 1,674 | 87,467 |
| 1 MiB | 1,399,776 | 1,674 | 1,398,187 |

At 1 KiB the stanzas are: header 123, protected 78, payload 1,366, aad 18, kem_ct 1,451 characters, plus 4 dots.

## Losing cases

- **1 MiB serialize:** jwcrypto is faster (median 5.96 ms against 7.77 ms; p99 8.25 ms against 10.84 ms), even though it also encrypts. The cause was not profiled.
- **Size:** our tokens are always larger than jwcrypto's. About 1,451 of the 1,674 fixed bytes are the base64url-encoded 1088-byte KEM ciphertext placeholder, a cost that every ML-KEM-768 token pays. jwcrypto's `dir` mode carries no key-encapsulation data at all.

## Read these numbers carefully

- **Not like-for-like.** Ours encodes bytes; jwcrypto encrypts them. Our lower latency at small and medium sizes does **not** show that a hybrid PQ JWE is faster than a classical one. A complete hybrid flow adds ML-KEM-768 encapsulation, X25519, a KDF and AEAD on top of these numbers. None of that was measured here.
- **The `kem_ct` stanza holds a 1088-byte placeholder.** It does not hold real ML-KEM-768 + X25519 output, which would be 1088 + 32 bytes. With a real 1120-byte value the token grows by about 43 characters.
- **About the internal 1,568-byte size target:** an internal benchmark summary reported a "measured" hybrid KEM ciphertext of 1,120 bytes against a 1,568-byte target. That value is a constant written into the benchmark script, not a measurement, and it is not repeated here as a result. The measured full token at 1 KiB is 3,040 bytes.
- **One machine, `powersave` governor, no confidence intervals.** Run-to-run variance is large. An identical run two minutes earlier (09:49 UTC) gave lower medians. Its raw files are not shipped, so its numbers are not reproduced here. The ordering, including the 1 MiB loss, was the same.

## Reproducing

The original benchmark driver is not shipped in this repository. A rough equivalent with the public API:

```python
import json, statistics, time
from pqblocks_jwe import serialize_jwe
payload = bytes(1024); header = {"alg": "MLKEM768-X25519", "enc": "A256GCM", "kid": "pq-settlement-2025", "typ": "application/jwe"}
protected = {"alg": "A256GCM", "enc": "A256GCM", "cty": "application/json"}
kem_ct = bytes(range(256)) * 4 + bytes(range(64))
for _ in range(20): serialize_jwe(payload, header, protected, b"settlement-v1", kem_ct)
s = []
for _ in range(200):
    t = time.perf_counter_ns(); serialize_jwe(payload, header, protected, b"settlement-v1", kem_ct); s.append((time.perf_counter_ns() - t) / 1e6)
print("median ms", statistics.median(s))
```

The raw files in `benchmarks/` remain the record for the numbers above.
