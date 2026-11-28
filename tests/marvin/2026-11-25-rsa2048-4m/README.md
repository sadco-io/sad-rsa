# Marvin attack timing analysis: 2026-11-25, 0.10.6 candidate, 4M

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** 0.10.6 release candidate, the same source tree as the 1M run (hash in `../README.md`)
- **Key size:** RSA-2048, `RsaPrivateKey::decrypt` with `Pkcs1v15Encrypt`, no blinding
- **Repetitions:** 4,000,000 per class, twelve classes (48 million decryptions)
- **Run:** 2026-11-25 04:03 UTC to 17:31 UTC

## Result

```
Friedman test p-value: 0.111 (threshold: 0.05)
Sign test, lowest p-value of 66 pairs: 0.0073 (Bonferroni threshold: about 0.0008)
Worst pair: no_header_with_payload_48 vs valid_repeated_byte_payload_246_255, mean difference -8.2 ns, 95% CI -16.0 to -0.9 ns
```

**No timing side channel detected at this sample size.** The toolkit reports that a leak below about 7 ns cannot be excluded. The pair this run was started for, `header_only` vs `valid_0`, is -3.6 ns with a sign-test p of 0.35: the 1M difference did not replicate. Eight pairs have a sign-test p below 0.05 where about three are expected, four of them involving `valid_repeated_byte_payload_246_255`; none is significant after correction.

## Files

- `report.txt`: the toolkit's summary
- `report.csv`: all 66 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `box_plot.png`, `ecdf_plot.png`, `diff_ecdf_plot.png`: the toolkit's plots
