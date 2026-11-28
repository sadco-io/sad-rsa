# Marvin attack timing analysis: 2026-11-24, published 0.10.5 baseline, 1M

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** `sad-rsa` 0.10.5 from crates.io
- **Key size:** RSA-2048, `RsaPrivateKey::decrypt` with `Pkcs1v15Encrypt`, no blinding
- **Repetitions:** 1,000,000 per class, twelve classes (12 million decryptions)
- **Run:** 2026-11-25 00:37 UTC to 04:00 UTC, on the same machine, directly after the candidate run

## Result

```
Friedman test p-value: 0.316 (threshold: 0.05)
Sign test, lowest p-value of 66 pairs: 0.0067 (Bonferroni threshold: about 0.0008)
Worst pair: no_padding_48 vs valid_repeated_byte_payload_246_255, mean difference -23.8 ns, 95% CI -38.2 to -10.2 ns
```

**No timing side channel detected at this sample size.** This run is the same-machine reference for the 0.10.6 candidate. Its worst pair is about as large as the candidate's and is a different pair, which puts the noise floor of this machine at about 20 ns for 1M repetitions. `header_only` vs `valid_0` is -5.0 ns here (sign-test p = 0.76).

## Files

- `report.txt`: the toolkit's summary
- `report.csv`: all 66 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `box_plot.png`, `ecdf_plot.png`, `diff_ecdf_plot.png`: the toolkit's plots
