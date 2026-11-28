# Marvin attack timing evidence

This directory holds the results of running the [Marvin toolkit][toolkit] against `sad-rsa`
decryption. Each subdirectory is one run; `marvin-toolkit/` at the repository root holds the
harness used to produce them.

From 0.10.6 onwards, every release tag is tested with this harness, for PKCS#1 v1.5 and for
OAEP decryption, before it is published, and the reports are added here (see `SECURITY.md`).

## What is claimed

For `sad-rsa` 0.10.6, on the 200M runs listed below:

- **PKCS#1 v1.5 decryption passes.** The Friedman test over all twelve ciphertext classes
  passes (p = 0.53) at 200 million repetitions per class, and no pair of classes differs
  significantly once the 66 pairwise comparisons are accounted for. The largest mean
  difference between two classes is 3.2 ns on a 1,097,700 ns operation.
- **0.10.5 fails the same test on the same machine with the same key** (p = 2.7 × 10⁻¹⁶⁰).
  A ciphertext whose decrypted value starts with 208 zero bytes takes 11 ns longer than every
  other class. 0.10.6 removes that difference.
- **OAEP decryption: rejected ciphertexts cannot be told apart.** Over the nine classes that
  OAEP rejects, the Friedman test passes (p = 0.82) and no pair has a sign-test p below 0.11.

## What is not claimed

- **Not the toolkit's strictest bar.** The toolkit documentation asks for confidence
  intervals below 1 ns, or one CPU cycle, before saying that a timing side channel cannot be
  shown. The 0.10.6 PKCS#1 v1.5 run reaches 1.3 ns, so its `report.txt` ends with the
  toolkit's line "Large confidence intervals detected, collecting more data necessary".
- **One open observation.** In the 0.10.6 PKCS#1 v1.5 run, `header_only` is about 2 ns faster
  than the other classes on average. It is not significant by the sign test after correction
  and is absent in 0.10.5; see that run's README.
- **Valid and rejected OAEP ciphertexts do differ**, by about 35 ns. OAEP reports that outcome
  to the caller, so it is not secret, but the toolkit's all-classes test fails because of it.
- **One configuration.** RSA-2048, `RsaPrivateKey::decrypt` without blinding, x86-64, one CPU
  model, release build. Blinded decryption, other key sizes, other hash functions for OAEP
  and other architectures are not measured.
- **In-process timing.** The clock is read inside the decrypting process. Nothing here
  measures what a network attacker could observe.

## Runs

PKCS#1 v1.5 decryption:

| Directory | Code under test | Repetitions | Friedman p | Lowest sign-test p | Worst pair, mean difference (95% CI) |
|---|---|---|---|---|---|
| [`2026-11-26-rsa2048-200m-metal`](2026-11-26-rsa2048-200m-metal/) | 0.10.6 | 200,002,500 | 0.526 | 0.022 | `header_only` vs `valid_246`: 3.2 ns (1.5 to 4.8) |
| [`2026-11-26-rsa2048-200m-metal-baseline-0.10.5`](2026-11-26-rsa2048-200m-metal-baseline-0.10.5/) | published 0.10.5 | 200,002,500 | 2.7 × 10⁻¹⁶⁰ | 5.2 × 10⁻⁷⁸ | `no_padding_48` vs `valid_0`: −11.0 ns (−12.7 to −9.4) |
| [`2026-11-25-rsa2048-4m`](2026-11-25-rsa2048-4m/) | 0.10.6 | 4,000,000 | 0.111 | 0.0073 | `no_header_with_payload_48` vs `valid_repeated_byte_payload_246_255`: −8.2 ns (−16.0 to −0.9) |
| [`2026-11-24-rsa2048-1m`](2026-11-24-rsa2048-1m/) | 0.10.6 | 1,000,000 | 0.481 | 0.0052 | `header_only` vs `valid_0`: 18.9 ns (3.1 to 36.8) |
| [`2026-11-24-rsa2048-1m-baseline-0.10.5`](2026-11-24-rsa2048-1m-baseline-0.10.5/) | published 0.10.5 | 1,000,000 | 0.316 | 0.0067 | `no_padding_48` vs `valid_repeated_byte_payload_246_255`: −23.8 ns (−38.2 to −10.2) |
| [`2026-04-01-rsa2048-1m`](2026-04-01-rsa2048-1m/) | 0.1.1 plus constant-time unpadding | 1,000,000 | 0.461 | 0.011 | `valid_48` vs `valid_192`: median 43.5 ns (±34) |

OAEP decryption:

| Directory | Code under test | Repetitions | Friedman p, rejected classes | Lowest sign-test p, rejected pairs | Largest mean difference, rejected pairs | Valid against rejected |
|---|---|---|---|---|---|---|
| [`2026-11-27-rsa2048-200m-metal-oaep`](2026-11-27-rsa2048-200m-metal-oaep/) | 0.10.6 | 200,002,500 | 0.82 | 0.11 | 1.5 ns | 33 to 36 ns slower |

With 66 pairs, a sign-test p-value has to be below about 0.0008 to be significant at 0.05
after a Bonferroni correction.

## How to read the runs

1. **The 200M runs are the evidence.** They were taken on a bare-metal machine with one process
   pinned to each of 90 cores, and both versions used the same key. The 0.10.5 run shows an
   11 ns difference for the one class with 208 leading zero bytes in the decrypted value;
   0.10.5 skipped leading zero bytes when it converted the decrypted value to bytes, and
   0.10.6 does not.
2. **The 1M and 4M runs could not see 11 ns.** They ran on a virtual machine with a noise floor
   of about 20 ns at 1M and 7 ns at 4M, and both 0.10.5 and 0.10.6 passed. In the 1M
   baseline, `no_padding_48` was in the worst pair at −23.8 ns, which is the right class with
   the wrong sign; at that sample size it was noise. A pass at 1M says little about
   differences of this size.
3. **The 1M candidate's worst pair, `header_only` vs `valid_0`, did not replicate** at 4M
   (−3.6 ns, p = 0.35) or at 200M (1.7 ns, p = 0.49).
4. **The 4M observation about `valid_repeated_byte_payload_246_255` did not replicate** at
   200M: no pair involving it has a sign-test p below 0.11 in the 0.10.6 run.
5. **OAEP is judged on the rejected classes.** These nine are the classes the toolkit
   recommends for an OAEP interface, and the pass criterion is the toolkit's verdict over
   them. The two `valid_oaep` classes are our addition and are reported for information.
   From the next run on, the harness writes the nine-class report to `rejected-only/` and
   takes its exit status from it. See the OAEP run's README for why, and for how the
   nine-class Friedman figure was computed for the 0.10.6 run.

## Specifications the behaviour is checked against

| Property | Specification | Checked by |
|---|---|---|
| Implicit rejection output for invalid ciphertexts | [draft-irtf-cfrg-rsa-guidance-04][draft] §7 and Appendix B | `tests/implicit_rejection_vectors.rs`: all 48 Appendix B vectors (2048, 2049, 3072 and 4096-bit keys), with and without blinding |
| No valid/invalid distinction in the result or error | draft §7 | `tests/marvin_attack.rs` |
| PKCS#1 v1.5 and PSS signature acceptance | RFC 8017 §8.1.2, §8.2.2, §5.2.2 | `tests/hardening.rs`, `tests/wycheproof.rs` |
| Timing independence across ciphertext classes | [Marvin attack][marvin] method, [toolkit][toolkit] | the runs in this directory |

## Reproducing a run

Requirements: Docker with BuildKit, and an otherwise idle machine.

A single process, 1M repetitions per class (about 4 GB of disk, 3 h 23 min on a 16-core AMD
EPYC 9R45 virtual machine):

```bash
cd marvin-toolkit
docker build -t marvin:latest .
mkdir -p outputs && chmod a+rw outputs

docker run -d --rm --name marvin \
    -v "$(cd .. && pwd)":/sad-rsa:ro \
    -v "$(pwd)/outputs":/home/rustcrypto/marvin-toolkit/outputs \
    -v "$(pwd)/Cargo.toml":/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest -s 2048 -n 1000000

docker logs -f marvin
cat outputs/results/report.txt
```

The 200M runs, 90 pinned processes in 50 rounds (about 10 hours each on a 96-core machine,
40 GB of disk for the merged timings, plus about 2 hours and 20 GB for the analysis):

```bash
cd marvin-toolkit
# PKCS#1 v1.5; add `-m oaep` for OAEP. -o must be an absolute path. -a skips the analysis.
./parallel-run.sh -c 2-91 -n 200002500 -b 50 -a -o /data/run

docker run --rm --entrypoint bash \
    -v /data/run/merged:/home/rustcrypto/marvin-toolkit/merged marvin:latest -c \
    "PYTHONPATH=tlsfuzzer marvin-venv/bin/python3 tlsfuzzer/tlsfuzzer/analysis.py -o merged/ \
     --verbose --no-conf-interval-plot --no-scatter-plot --no-ecdf-plot --workers 10"
```

- **Check the pipeline first.** Run once with `-n 2000`; it takes under a minute and must end
  with a `report.txt`.
- **A published release.** Change the `rsa` line in `marvin-toolkit/Cargo.toml` to
  `rsa = { version = "=0.10.5", package = "sad-rsa", features = ["sha2"] }`; the `/sad-rsa`
  mount is then unused.
- **The same key for two versions.** Copy the `keys/` directory of the first run's output
  directory into the second run's output directory before starting it.
- **Analysis memory.** At 200M repetitions the analysis ran out of memory on a 187 GB machine
  with 90 workers; 10 workers fit.
- **What was built.** `harness-deps.txt` records the crate the harness was compiled against.
- **Pinned inputs.** The Dockerfile pins the toolkit and `tlsfuzzer` revisions used for the
  2026-11 runs. Ciphertexts are generated fresh on each run, so the numbers will differ from
  run to run; the conclusions should not.

## Environment of the 2026-11 runs

| | 200M runs | 1M and 4M runs |
|---|---|---|
| Machine | AWS EC2 `c8a.metal-24xl`, bare metal: AMD EPYC 9R45, 96 cores, no SMT, 187 GB | AWS EC2 `m8a.4xlarge`, virtual machine: 16 vCPU AMD EPYC 9R45, 64 GB |
| Processes | 90, each pinned to one core (cores 2 to 91) | 1, not pinned |
| CPU settings | `performance` governor, frequency boost on | defaults |
| Clock | `std::time::Instant` inside the harness process; 10 ns steps | `std::time::Instant` inside the harness process |
| Mean decryption time | 1,097.7 µs (0.10.6), 1,094.3 µs (0.10.5), 1,023.2 µs (OAEP) | 869.3 µs (0.10.6), 867.9 µs (0.10.5) |
| OS | Ubuntu 26.04, kernel 7.0.0-1018-aws | Ubuntu 26.04.1, kernel 7.0.0-1018-aws |
| Image | `python:3.12-bookworm`, release profile | `python:3.12-bookworm`, Python 3.12.16, rustc 1.100.0, release profile |
| Toolkit | marvin-toolkit `7d264ab` with `step2.py` from `3b42df3`; tlsfuzzer `51aad6e` (analyse.py version 9) | the same |

Decryption is slower in the 200M runs because 90 cores were busy at once; with one process on
the same machine it took 868 µs.

The 0.10.6 source tree that was measured is identified by a hash over `src/`, `Cargo.toml` and
`Cargo.lock`. It was taken before the version number in `Cargo.toml` was changed to 0.10.6, so
`harness-deps.txt` in those runs shows 0.10.5 with a local path:

```bash
find src Cargo.toml Cargo.lock -type f | sort | xargs sha256sum | sha256sum
# 8a7f9b76763b902e12e330ded9d16055b3f097b3bcd079fe183a018ce9ce93dc
```

[toolkit]: https://github.com/tomato42/marvin-toolkit
[marvin]: https://people.redhat.com/~hkario/marvin/
[draft]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-guidance/04/
