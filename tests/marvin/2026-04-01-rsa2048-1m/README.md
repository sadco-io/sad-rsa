# Marvin Attack Timing Analysis — 2026-04-01

## Configuration

- **Key size:** RSA-2048
- **Repetitions:** 1,000,000 (12M total decryptions)
- **Toolkit:** [marvin-toolkit](https://github.com/tomato42/marvin-toolkit) (tlsfuzzer analyse.py v9)
- **Environment:** Docker (python:3.12-bookworm), WSL2 Linux 6.6.87
- **sad-rsa version:** v0.1.1 + fix/constant-time-unpadding branch (PR #14)

## Test Cases

11 ciphertext classes covering all Marvin attack vectors:

| ID | Class | Description |
|----|-------|-------------|
| 0 | `no_structure` | Completely invalid padding |
| 1 | `no_padding_48` | Missing PKCS#1 v1.5 padding |
| 2 | `signature_padding_8` | Wrong padding type (0x01 vs 0x02) |
| 3 | `valid_repeated_byte_payload_246_0xff` | Valid padding, 246-byte 0xFF payload |
| 4 | `valid_repeated_byte_payload_246_0x01` | Valid padding, 246-byte 0x01 payload |
| 5 | `valid_48` | Valid padding, 48-byte message |
| 6 | `header_only` | Valid header (0x00 0x02), no message |
| 7 | `no_header_with_payload_48` | Missing header, 48-byte payload |
| 8 | `zero_byte_in_padding_48_4` | Premature zero in padding string |
| 9 | `valid_0` | Valid padding, empty message |
| 10 | `valid_192` | Valid padding, 192-byte message |
| 11 | `valid_246` | Valid padding, 246-byte message (max) |

## Results Summary

```
Friedman test p-value: 0.461 (threshold: 0.05)
Sign test median p-value: 0.606
Worst pair: valid_48 vs valid_192 (two valid messages, not valid-vs-invalid)
Median timing difference: 43.5ns, 95% CI: ±34ns
```

**Verdict: No timing side channel detected.**

## How to Reproduce

```bash
cd marvin-toolkit

# Build the Docker image
docker build -t marvin:latest .

# Build the sad-rsa test harness and run analysis
# See entrypoint-sadrsa.sh for the full pipeline
docker run -d --rm \
    --name marvin \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    marvin:latest -s 2048 -n 1000000
```

## Files

- `report.txt` — Human-readable analysis summary
- `report.csv` — Detailed pairwise statistical comparisons (all 66 pairs)
- `legend.csv` — Mapping of class IDs to test case names
- `sample_stats.csv` — Per-class timing statistics
- `box_plot.png` — Box plot of timing distributions per class
- `ecdf_plot.png` — Empirical CDF of timing distributions
- `diff_ecdf_plot.png` — ECDF of timing differences (worst pair)
