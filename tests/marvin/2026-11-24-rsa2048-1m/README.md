# Marvin attack timing analysis: 2026-11-24, 0.10.6 candidate, 1M

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** 0.10.6 release candidate (source tree hash in `../README.md`)
- **Key size:** RSA-2048, `RsaPrivateKey::decrypt` with `Pkcs1v15Encrypt`, no blinding
- **Repetitions:** 1,000,000 per class, twelve classes (12 million decryptions)
- **Run:** 2026-11-24 21:15 UTC to 2026-11-25 00:37 UTC

## Result

```
Friedman test p-value: 0.481 (threshold: 0.05)
Sign test, lowest p-value of 66 pairs: 0.0052 (Bonferroni threshold: about 0.0008)
Worst pair: header_only vs valid_0, mean difference 18.9 ns, 95% CI 3.1 to 36.8 ns
```

**No timing side channel detected at this sample size.** The worst pair involves `valid_0` and its interval excludes zero, so the run was repeated at 4M repetitions with that pair as the stated question; see [`../2026-11-25-rsa2048-4m`](../2026-11-25-rsa2048-4m/), where it does not replicate.

## Files

- `report.txt`: the toolkit's summary
- `report.csv`: all 66 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `box_plot.png`, `ecdf_plot.png`, `diff_ecdf_plot.png`: the toolkit's plots
