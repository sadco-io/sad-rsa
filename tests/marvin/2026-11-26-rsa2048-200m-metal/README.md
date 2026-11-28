# Marvin attack timing analysis: 2026-11-26, 0.10.6, 200M, bare metal

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** 0.10.6 source tree (hash in `../README.md`)
- **Operation:** RSA-2048, `RsaPrivateKey::decrypt` with `Pkcs1v15Encrypt`, no blinding
- **Repetitions:** 200,002,500 per class, twelve classes (2,400,030,000 decryptions)
- **Layout:** 90 processes, each pinned to its own core, 50 rounds of 44,445 repetitions per
  process, one key shared by all (`marvin-toolkit/parallel-run.sh -c 2-91 -n 200000000 -b 50`)
- **Run:** 2026-11-25 21:15 UTC to 2026-11-26 07:49 UTC

## Result

```
Friedman test p-value: 0.526 (threshold: 0.05)
Sign test, lowest p-value of 66 pairs: 0.022 (Bonferroni threshold: about 0.0008)
Worst pair: header_only vs valid_246
  mean difference 3.2 ns, 95% CI 1.5 to 4.8 ns
  trimmed mean (5%) 1.8 ns, 95% CI 0.5 to 3.1 ns
```

**No timing side channel detected.** The toolkit reports that a leak smaller than 1.3 ns
cannot be excluded, which is just short of its 1 ns bar. Three pairs have a sign-test p below
0.05, the number expected by chance among 66.

`no_padding_48`, the class that is 11 ns slower in 0.10.5 on this machine (see
[`../2026-11-26-rsa2048-200m-metal-baseline-0.10.5/`](../2026-11-26-rsa2048-200m-metal-baseline-0.10.5/)),
is within 2.6 ns of every other class here, with no sign-test p below 0.11.

## Open observation

`header_only` is on average 2.1 ns faster than the other eleven classes. It was faster in 36
of the 50 rounds (standard error of the per-round difference 0.6 ns), and the paired t-test
for `header_only` vs `valid_246` has p = 0.0006. The sign and Wilcoxon tests show nothing
after correction, the class was picked after looking at the data, and the difference is absent
in the 0.10.5 baseline. It is recorded here and not explained.

## Notes on the data

- **One round replaced.** The fourth round overlapped an unrelated analysis job on the same
  machine. It was removed before analysis and one extra round was run after the fiftieth, so
  the analysed data is 50 rounds. The raw data holds all 51.
- **Clock resolution.** The clock on this machine advances in steps of 10 ns, so the medians
  of differences are multiples of 10 ns (here 0). Read the mean and trimmed-mean lines.
- **Plots.** The confidence-interval, scatter and ECDF plots were skipped
  (`--no-conf-interval-plot --no-scatter-plot --no-ecdf-plot`); at this size they take many
  hours. The statistics in `report.txt` are not affected.

## Files

- `report.txt`: the toolkit's summary
- `report.csv`: all 66 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `harness-deps.txt`: the crate the harness was built against (the source tree still carried
  the version number 0.10.5 when it was measured)
- `box_plot.png`, `worst_pair_diff_heatmap.png`: two of the toolkit's plots

The raw timings are 7.1 GB compressed and are not in the repository. SHA-256 of
`timing-all-51-rounds.csv.zst`:
`1362fbd1e8963e8bb8ed8d3589482e2f975b89c7d99e9e642e0ce3d1f1518acb`.
