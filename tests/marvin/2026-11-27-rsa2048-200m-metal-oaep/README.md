# Marvin attack timing analysis: 2026-11-27, 0.10.6, OAEP, 200M, bare metal

See [`../README.md`](../README.md) for the method, the environment, how to reproduce the run,
and how this run fits with the others.

## Configuration

- **Code under test:** 0.10.6 source tree (hash in `../README.md`)
- **Operation:** RSA-2048, `RsaPrivateKey::decrypt` with `Oaep::<Sha256>::new()` (MGF1-SHA-256,
  empty label), no blinding
- **Repetitions:** 200,002,500 per class, eleven classes (2,200,027,500 decryptions)
- **Classes:** nine that OAEP decryption rejects (the toolkit's OAEP set) and two valid OAEP
  ciphertexts, with 32-byte and 190-byte messages
- **Layout:** the same machine, key, cores and settings as the PKCS#1 v1.5 runs
  (`marvin-toolkit/parallel-run.sh -c 2-91 -n 200002500 -b 50 -m oaep`)
- **Run:** 2026-11-27 01:38 UTC to 10:40 UTC

## Result

The question for OAEP is whether two ciphertexts that are both rejected can be told apart,
because that is what Manger's attack needs. Whether a ciphertext is accepted is not secret:
OAEP decryption returns an error for a rejected one.

**Among the nine rejected classes: no timing side channel detected.**

```
Friedman test over the nine rejected classes: p = 0.82 (threshold: 0.05)
Sign test, lowest p-value of their 36 pairs: 0.11
Wilcoxon signed-rank test, lowest p-value: 0.095
Paired t-test, lowest p-value: 0.057
Largest mean difference: no_padding_48 vs too_short_payload_0_1, 1.5 ns (95% CI about ±1.6 ns)
```

`no_padding_48`, whose decrypted value starts with 208 zero bytes, is within 1.6 ns of every
other rejected class. `no_structure`, whose decrypted value does not start with a zero byte,
is within 1.1 ns of the classes that do.

**Valid against rejected: about 35 ns, expected.**

```
Friedman test over all eleven classes: p = 0 (the toolkit reports VULNERABLE)
valid_oaep_32, valid_oaep_190: 33.1 to 36.3 ns slower than each rejected class
valid_oaep_32 vs valid_oaep_190: 1.7 ns, sign-test p = 0.31
```

On success, decryption copies the message out of the decoded block into a new buffer; on
failure it returns the error. The harness also drops the returned plaintext inside the
timed region. The 35 ns has not been attributed between these by measurement.

## Where the numbers come from

- The pairwise figures are from `report.csv`, the toolkit's analysis of all eleven classes.
- The Friedman test over the nine rejected classes is not in `report.txt`, which covers all
  eleven. It was computed from the raw timings with `rejected_only.py`
  (`rejected-only-local.json`), which reproduces the toolkit's pairwise sign-test figures
  exactly. To get the toolkit's own report for the nine classes, remove the two `valid_oaep`
  columns from `timing.csv` and run its analysis on the result.

## Notes on the data

- **Clock resolution.** The clock on this machine advances in steps of 10 ns.
- **Plots.** The confidence-interval, scatter and ECDF plots were skipped.
- **Exit status.** The toolkit's analysis exits with status 1 because of the valid-against-rejected
  difference.

## Files

- `report.txt`: the toolkit's summary, all eleven classes
- `report.csv`: all 55 pairwise comparisons
- `legend.csv`: class numbers and names
- `sample_stats.csv`: mean, median and MAD per class
- `rejected_only.py`, `rejected-only-local.json`: Friedman test, sign tests and mean
  differences over the nine rejected classes
- `harness-deps.txt`: the crate the harness was built against (the source tree still carried
  the version number 0.10.5 when it was measured)
- `box_plot.png`, `worst_pair_diff_heatmap.png`: two of the toolkit's plots

The raw timings are 6.4 GB compressed and are not in the repository. SHA-256 of
`timing-50-rounds.csv.zst`:
`23d6afe5aa1382df09d66fca90ed0d71ddb9e876a899bdf40e04f078ba51cf1c`.
