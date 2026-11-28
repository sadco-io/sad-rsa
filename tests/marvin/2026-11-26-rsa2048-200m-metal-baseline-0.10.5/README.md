# Marvin attack timing analysis: 2026-11-26, published 0.10.5 baseline, 200M, bare metal

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** `sad-rsa` 0.10.5 from crates.io
- **Operation:** RSA-2048, `RsaPrivateKey::decrypt` with `Pkcs1v15Encrypt`, no blinding
- **Repetitions:** 200,002,500 per class, twelve classes (2,400,030,000 decryptions)
- **Layout:** the same machine, key, cores and settings as the 0.10.6 run in
  [`../2026-11-26-rsa2048-200m-metal/`](../2026-11-26-rsa2048-200m-metal/)
- **Run:** 2026-11-26 13:12 UTC to 23:34 UTC

## Result

```
Friedman test p-value: 2.7e-160 (threshold: 0.05)
Sign test, lowest p-value of 66 pairs: 5.2e-78 (Bonferroni threshold: about 0.0008)
Worst pair: no_padding_48 vs valid_0
  mean difference -11.0 ns, 95% CI -12.7 to -9.4 ns
  trimmed mean (5%) -12.3 ns, 95% CI -13.6 to -11.1 ns
Toolkit verdict: Definite side-channel detected, implementation is VULNERABLE
```

**0.10.5 has a measurable timing side channel.** `no_padding_48` takes 10.4 to 12.1 ns longer
than each of the other eleven classes, with sign-test p-values between 10⁻⁵⁹ and 10⁻⁷⁸.
Twelve pairs have a sign-test p below 0.05: those eleven, and one unrelated pair at p = 0.018
(`no_header_with_payload_48` vs `zero_byte_in_padding_48_4`), which is not significant after
correction.

`no_padding_48` is the one class whose decrypted value starts with 208 zero bytes; the others
start with one zero byte or none. In 0.10.5 the decrypted value was converted to bytes by
skipping its leading zero bytes and copying the rest, so the copy had a different length and
offset for this class. 0.10.6 copies a fixed number of bytes, and the difference is
gone in the 0.10.6 run.

The eleven other classes do not differ from each other after correction: the lowest sign-test
p among their 55 pairs is 0.018, and `header_only` is within 1.3 ns of each of them.

## Why earlier runs did not show this

The 1M runs on a virtual machine had a noise floor of about 20 ns and the 4M run about 7 ns.
An 11 ns difference needed this sample size, or a quieter measurement, to be seen.

## Notes on the data

- **Clock resolution.** The clock on this machine advances in steps of 10 ns, so medians of
  differences are multiples of 10 ns.
- **Plots.** The confidence-interval, scatter and ECDF plots were skipped, as in the 0.10.6 run.
- **Exit status.** The toolkit's analysis exits with status 1 when it detects a side channel.

## Files

- `report.txt`: the toolkit's summary
- `report.csv`: all 66 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `harness-deps.txt`: the crate the harness was built against
- `box_plot.png`, `worst_pair_diff_heatmap.png`: two of the toolkit's plots

The raw timings are 6.9 GB compressed and are not in the repository. SHA-256 of
`timing-50-rounds.csv.zst`:
`d55f75f07af9aaf420f7f6c49338dea4a093afb6a360bc570cc8fe8c13218f34`.
