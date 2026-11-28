# Marvin tool-kit integration
This document describes the procedure for replicating the analysis for the Marvin attack. This analysis is best done on a container for reproducibility. Results of past runs, and how to read them, are in [`tests/marvin/`](../tests/marvin/README.md).

**TL;DR**:
```bash
# Build the image (the toolkit and tlsfuzzer revisions are pinned in the Dockerfile)
docker build -t marvin:latest .

# Create the output directory and allow container to write to it
mkdir -p outputs
chmod a+rw outputs

# Run the analysis against the sad-rsa source tree in this checkout
docker run -d --rm \
    --name marvin \
    -v "$(cd .. && pwd)":/sad-rsa:ro \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest

# Use "docker logs -f marvin" to read live output

# Read the output
cat outputs/results/report.txt
```

Run once with `-n 2000` first: it takes under a minute and confirms the whole pipeline works before a run that takes hours. The container exits with a non-zero status if the harness fails to build or any later step fails.

## Adjusting analysis parameters
For more help on the options pass in the `-h` flag in the `docker run` command:

```
docker run ... marvin:latest -h
```

There are two main parameters of the analysis: RSA key size and the number of repetitions during ciphertext generation.

RSA key size is specified through `-s <1024|2048|4096>`. The number of repetition is specified through `-n <num>`. A larger repetition number will increase the confidence of the analysis, but will make the analysis take longer. The default key size is 2048 and the default repetition count is 100,000.

```bash
# Run analysis for RSA 4096 with 1 million repetition
docker run -d --rm \
    --name marvin \
    -v "$(cd .. && pwd)":/sad-rsa:ro \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest -s 4096 -n 1000000
```

## Testing OAEP decryption
Pass `-m oaep` to measure `RsaPrivateKey::decrypt` with `Oaep::<Sha256>::new()` instead of PKCS#1 v1.5:

```bash
docker run -d --rm \
    --name marvin-oaep \
    -v "$(cd .. && pwd)":/sad-rsa:ro \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest -m oaep -s 2048 -n 1000000
```

The ciphertext classes are the ones the toolkit recommends for an OAEP interface (its `step2-oaep-alt.sh`): `no_structure`, `valid_0`, `no_padding_48`, `signature_padding_8`, a zero-filled payload, and `too_short_payload` with 1, 3, 7 and 15 extra leading zero bytes in the decrypted value. All of those are rejected by OAEP decryption, so `oaep_step2.py` adds two classes the toolkit does not have: `valid_oaep_32` and a maximum-length valid OAEP ciphertext (SHA-256, MGF1-SHA-256, empty label).

The harness prints how many decryptions returned a plaintext and how many returned an error. In OAEP mode the first number must equal twice the repetition count; in PKCS#1 v1.5 mode every decryption returns a plaintext, because of implicit rejection.

The harness source is `harness/main.rs`: the upstream toolkit's `example/rust-crypto` measurement loop with a `--mode` switch added.

The verdict of an OAEP run is the toolkit's analysis of the rejected classes, which the harness writes to `results/rejected-only/` (`merged/rejected-only/` for `parallel-run.sh`). The exit status comes from that analysis. The analysis of all eleven classes is still written to the main results directory, for information only: a valid OAEP ciphertext takes about 35 ns longer than a rejected one, because the message is copied out only on success, so over all classes the toolkit's report says "VULNERABLE". That outcome is not secret: OAEP decryption returns an error for a rejected ciphertext. What must not be distinguishable is one rejected ciphertext from another.

To produce the rejected-classes data by hand from an existing `timing.csv`:

```bash
cols=$(head -1 timing.csv | tr ',' '\n' | grep -n -v '^valid_oaep' | cut -d: -f1 | paste -sd, -)
cut -d, -f"$cols" timing.csv > rejected-only/timing.csv
```

## Running several processes in parallel
A large run can be split across CPU cores with `parallel-run.sh`. It generates one key, starts one container per core (each pinned with `--cpuset-cpus`), concatenates the rows of every `timing.csv`, and runs the toolkit's analysis on the merged data:

```bash
# 1M repetitions per class in total, split over cores 1 to 15
./parallel-run.sh -c 1-15 -n 1000000 -o outputs-parallel
cat outputs-parallel/merged/report.txt
```

For a large run, split it into rounds with `-b` so that only the timings of each round are kept (ciphertexts take 3 GB per million repetitions), give `-o` as an absolute path, and either pass `-a` to skip the analysis and run it afterwards, or set `ANALYSIS_ARGS="--no-conf-interval-plot --no-scatter-plot --no-ecdf-plot --workers 10"` so the built-in analysis skips the slow plots and stays within memory. `tests/marvin/README.md` has the commands used for the 200M runs.

On a 16-core virtual machine this took 23 minutes against 3 hours 23 minutes for one process, and gave the same Friedman result and the same confidence intervals for the median and the trimmed means. The interval for the plain mean was about four times wider, because parallel processes see more rare, large delays; read the median or trimmed-mean lines of the report for a parallel run. Leave at least one core free for the operating system.

## Extracting keys, ciphertexts, and analysis results (WIP)
After the analysis is done, the generate keys, ciphertexts, and the analysis outputs are all copied into the directory `/home/rustcrypto/marvin-toolkit/outputs`. To extract and preserve these artifacts, mount a volume into this directory, such as using a bind mount:

```bash
mkdir -p outputs
chmod a+rw outputs

# Mount
docker run -d --rm --name "marvin" \
    -v $(pwd)/outputs:/home/rustcrypto/marvin-toolkit/outputs \
    marvin:latest
```

## Compile test harness with custom `Cargo.toml`
The test harness is compiled at container run-time, so a custom `Cargo.toml` can be passed into the container at runtime to compile the test harness using custom versions of `RustCrypto/RSA` and/or `RustCrypto/crypto-bigint`:

```bash
docker run -d --rm --name "marvin" \
    -v $(pwd)/Cargo.toml:/home/rustcrypto/marvin-toolkit/example/rust-crypto/Cargo.toml \
    marvin:latest
```

The `Cargo.toml` in this directory builds the harness against the `sad-rsa` source tree mounted at `/sad-rsa`. To test a published release, change its `rsa` line to, for example, `rsa = { version = "=0.10.5", package = "sad-rsa" }` and leave out the `/sad-rsa` mount. The harness source comes from the upstream toolkit and refers to the crate as `rsa`; the `package = "sad-rsa"` key maps that name to this crate.

If no `Cargo.toml` is mounted, the toolkit's own default is used, which tests the upstream `rsa` crate and not `sad-rsa`.

`outputs/results/harness-deps.txt` records which crate the harness was built against.
