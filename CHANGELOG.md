# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Public-exponent operations (`rsa_encrypt`, and so signature verification and encryption, plus
  the `r^e` blinding factor) now exponentiate over the bit length of `e` instead of its full
  precision. With `e = 65537` this makes RSA-2048 verification and encryption about 2.5x faster.
  `e` is public, so nothing secret is exposed; private-exponent operations are unchanged ([#74]).

[#74]: https://github.com/sadco-io/sad-rsa/issues/74

## [0.10.4] - 2026-11-19

### Security

- Fix panics during RSA private-key construction, validation, or re-encoding. 0.10.4 rejects factors below 2, even factors, repeated factors, and a zero private exponent during prime recovery. It also computes the CRT coefficient and re-encodes valid two-prime keys when the first prime occupies more limbs than the second. Previously a factor of 1 reached a later check that panicked (in `RsaPrivateKey::from_components` and when decoding a PKCS#1 or PKCS#8 private key), `RsaPrivateKey::from_primes` and `RsaPrivateKey::from_p_q` could panic during construction when a supplied factor was 0, 1, or even, and `crt_coefficient`, `to_pkcs1_der`, `to_pkcs8_der`, and `serde` serialization could panic even for valid two-prime keys when the first prime occupied more limbs than the second. See GHSA-3hj7-mch7-c7cc.

### Security hardening

- Use constant-time remainder (`BoxedUint::rem`) instead of `rem_vartime` with
  secret divisors (`p - 1`, `q - 1`, `prime - 1`) in private-key precomputation
  and validation, matching upstream `rsa` 0.10.0.

## [0.10.3] - 2026-11-13

### Security

- Upgraded `crypto-bigint` `0.7.5` -> `0.7.11` and `ctutils` `0.4.2` -> `0.4.8`
  (minimum requirement bumped to `crypto-bigint = "0.7.11"`). Intermediate releases
  `0.7.4`–`0.7.8` were **yanked** upstream. Fixes **RUSTSEC-2026-0387** (secret-dependent
  branching / timing variability in `borrowing_sub`, CTZ, `div_rem`, `nlimbs`, Montgomery
  multiplication, `UintRef::PartialEq`, and `BoxedMontyForm::invert`), **RUSTSEC-2026-0385**
  (non-constant-time `const fn` mask generation in `ctutils::Choice` and branching `u128`
  comparisons on 32-bit targets), and Thumb-1 constant-time issues
  (RustCrypto/crypto-bigint#1391, #1399).
- Upgraded `der` `0.8.1` -> `0.8.3`, fixing BER indefinite-length nesting stack overflows
  and panics on malformed/truncated binary `REAL` values.

### Changed

- Upgraded `pkcs1` `0.8.0-rc.4` -> `0.8.0` stable, eliminating the last pre-release (`-rc`)
  dependency from the dependency tree (#18, #61). `TryFrom<pkcs1::RsaPrivateKey<U>>` and
  `TryFrom<pkcs1::RsaPublicKey<U>>` are now generic over `der::asn1::AsUintRef`, supporting
  both borrowed (`*Ref`) and owned (`*Owned`) PKCS#1 key types, with checked bit-length
  multiplication on untrusted DER inputs.
- Upgraded `spki` `0.8.0` -> `0.8.1`.
- Raised Minimum Supported Rust Version (MSRV) from `1.85` to `1.89` (required by
  `aes 0.9.4` via `pkcs5`, `sha2 0.11.1`, `proptest 1.12.0`, and
  `crypto-bigint 0.7.11` / `ctutils 0.4.8`).
- Migrated deprecated `BoxedUint::bits` / `bits_vartime` call sites to
  `bit_width` / `bit_width_vartime`; incorporates `crypto-bigint 0.7.11` `BoxedMontyForm`
  squaring optimizations for RSA CRT decryption (#1397, #1398).
- Refreshed dependencies: `sha2` `0.11.0` -> `0.11.1`, `zeroize` `1.9.0` -> `1.9.1`,
  `const-oid` `0.10.2` -> `0.10.3`, `aes` `0.9.2` -> `0.9.4`, `cpufeatures` `0.3.0` -> `0.3.1`,
  `hybrid-array` `0.4.14` -> `0.4.15`, `inout` `0.2.2` -> `0.2.6`, plus dev/CI bumps
  (`rand` `0.10.2` -> `0.10.3`, `rstest` `0.26.1` -> `0.28.0`, `proptest` `1.11.0` -> `1.12.0`,
  `serde_json` `1.0.151` -> `1.0.154`, `crate-ci/typos` `v1.48.0` -> `v1.51.1`).

## [0.10.2] - 2026-08-28

### Security

- **PKCS#1 v1.5 unpad no longer memmoves from a secret offset.** After the
  constant-time mix, compact used `copy_within(start..)` with
  `start = (k-11) - output_length`, so the source address leaked plaintext
  length. Compact now scans the public `2*(k-11)` buffer with CMOV; `len` is
  unchanged. A 1M RSA-2048 Marvin run on this change (unpinned, default
  release, same harness as 0.10.1) gave Friedman p=0.527 (pass at 0.05);
  worst pair `signature_padding_8` vs `valid_48`; mean-of-differences 95% CI
  included 0; sign-test min p=0.019; `valid_0` was slowest, not fastest.
  Mean decrypt rose ~100 µs (1.56 ms → 1.66 ms) from the public-index CMOV
  scan. Mean spread stayed ~22 ns, the same noise floor as 0.10.1.

## [0.10.1] - 2026-08-26

### Security

- **PKCS#1 v1.5 decrypt no longer allocates the returned `Vec` to the exact
  plaintext length.** After the constant-time mix into a `k-11` buffer, unpad
  used to finish with `output[start..].to_vec()`. Rust's empty `Vec` skips
  malloc/`memcpy`/free, so Marvin class `valid_0` (empty valid message) was
  ~20 ns faster than every other class on a 1M RSA-2048 run (Friedman p=0.006;
  worst pair two valid lengths, not valid-vs-invalid). Unpad now always
  allocates `2*(k-11)`, compacting with a public-length copy and
  `truncate(len)` so `len` (the public API) is unchanged and drop always frees
  the same allocation.
- **`PrecomputedValues::zeroize()` now wipes `qinv` (Q⁻¹ mod P).** It previously
  only cleared `dp`/`dq`, so the CRT coefficient remained in the heap after
  drop (#19). `p_params` / `q_params` still cannot be wiped: `BoxedMontyParams`
  has no `Zeroize` impl in crypto-bigint 0.7.5.

## [0.10.0] - 2026-08-25

### Changed — version realignment

- **The version number now tracks the upstream API line it targets.** `sad-rsa`
  was forked from RustCrypto's `rsa` at `0.10.0-rc.12` and has always tracked the
  **0.10** API, but shipped under `0.1.x`/`0.2.x` version numbers. That mismatch
  led users to assume compatibility with the released `rsa` 0.9.x and hit a wall
  (sadco-io/sad-rsa#44). From this release, **`sad-rsa 0.10.x` targets `rsa 0.10.x`**.
- **This is a version-numbering change, not an API change.** There are no breaking
  API changes from `0.2.3`/`0.2.4`; the code is the same. Because Cargo treats
  `0.2` and `0.10` as incompatible ranges, existing `0.2.x` users will not receive
  this via `cargo update` and must bump the requirement to `"0.10"` by hand. No
  code changes are required to do so.
- Upstream has not yet published `rsa 0.10.0` final; the newest upstream release is
  `0.10.0-rc.18`. This crate's API was verified against `rc.18`. One known drift:
  upstream added `Error::InputSize` after `rc.12` where this crate returns
  `Error::Decryption`.

### Fixed — documentation

- **The README claimed "The API is fully compatible with the upstream `rsa` crate"
  and gave a two-step migration** (swap the dependency, rename `use` paths). That was
  false for every *released* version of `rsa`. Measured: a test crate exercising ten
  `rsa 0.9.10` API surfaces builds clean against 0.9.10, and the documented migration
  produces **14 compile errors** — six of the ten surfaces break at compile time, two
  more change behaviour under implicit rejection. The README now states the version-line
  contract plainly and carries a real migration guide with a difference table and
  before/after code, split by whether you are coming from `0.10-rc` (rename only) or
  `0.9.x` (ecosystem upgrade).
- The README's install snippet said `sad-rsa = "0.1"`, and its example passed
  `features = ["pem"]`, which does not exist in this crate and fails at dependency
  resolution.

## [0.2.4] - 2026-08-25

### Security

- Upgraded `crypto-bigint` `0.7.3` -> `0.7.5`. Intermediate release `0.7.4` was **yanked**
  upstream for a truncated Karatsuba carry (RustCrypto/crypto-bigint#1305) producing silently
  incorrect multiplication results; `0.7.5` carries the fix. `0.7.5` additionally preserves the
  `NonZero` and `Odd` invariants in its `Zeroize` impls (#1287), which directly backs this
  crate's zeroization guarantees for private key material.

### Changed

- Upgraded `crypto-primes` `0.7.0` -> `0.7.2` (vendors the previously-required `libm`
  functions, removing `libm` from the dependency tree; gates heap allocation behind `alloc`).
- Refreshed all semver-compatible dependencies: `getrandom` `0.4.2` -> `0.4.3`,
  `zeroize` `1.8.2` -> `1.9.0`, `der` `0.8.0` -> `0.8.1`, `hybrid-array` `0.4.10` -> `0.4.14`,
  plus dev-only bumps (`rand` `0.10.1` -> `0.10.2`, `serde_json` `1.0.150` -> `1.0.151`,
  `futures-util` `0.3.32` -> `0.3.34`).
- Removed a redundant `sha2` `[dev-dependencies]` entry that duplicated the mandatory
  `[dependencies]` entry verbatim. The `sha1` dev-dependency is retained -- the regular
  `sha1` dependency is optional, so tests still need their own.

### Notes

- `pkcs1` remains pinned to `0.8.0-rc.4`; upstream has not yet published `0.8.0` stable.
  It is the last pre-release dependency, and it is reachable from the default feature set
  via `encoding`. See #18.

## [0.2.3] - 2026-06-03

### Changed

- Upgraded `pkcs8` from `0.11.0-rc.11` to stable `0.11.0`. `pkcs8 0.11.0` changed
  `Error::KeyMalformed` from a unit variant to a tuple variant `KeyMalformed(KeyError)`;
  non-ASN.1 PKCS#1 errors are now mapped to `KeyMalformed(KeyError::Invalid)`. This also
  resolves the PKCS#5 encryption stack (`aead` / `aes-gcm` / etc.) to stable releases. (#35)
- Upgraded `signature` from `3.0.0-rc.10` to stable `3.0.0`
- Upgraded `spki` from `0.8.0-rc.4` to stable `0.8.0`
- Bumped dev-dependencies: `sha3` `0.11` -> `0.12`, `serde_json` `1.0.138` -> `1.0.150`
- Bumped `crate-ci/typos` CI action `1.44.0` -> `1.47.0`

## [0.2.2] - 2026-04-02

### Changed

- Upgraded all RustCrypto dependencies from pre-release to stable versions
- Removed `[patch.crates-io]` section -- no more floating git references
- See issue #18 for details

## [0.2.1] - 2026-04-02

### Security

- **RSA plaintext buffer now securely zeroed**: `uint_to_zeroizing_be_pad` returns
  `Zeroizing<Vec<u8>>` instead of plain `Vec<u8>`. The raw RSA-decrypted block (`em`)
  is now securely zeroed on drop across all decrypt paths (PKCS#1 v1.5, OAEP, PSS).

## [0.2.0] - 2026-04-02

### Security

- **Constant-time PS length check**: Replaced self-acknowledged "very likely not sufficient"
  arithmetic shift trick with `ctutils::CtLt::ct_lt()` (branchless `overflowing_sub`).
  Assembly verified: compiles to `cmpl + cmovbl` (no conditional jumps).
- **Fixed-size buffer allocation**: Variable-length `vec![0u8; output_length]` leaked message
  length via allocator timing. Now always allocates `k-11` bytes and iterates the full buffer
  unconditionally. Validated by Marvin toolkit (12M decryptions, Friedman p=0.46).

### Changed

- Aligned `rand_core` dependency to `0.10.0-rc-3` (was `rc-2` in deps, `rc-3` in dev-deps)
- CI now triggers on `main` branch (was `master`)
- Added `.DS_Store`, `._*` to `.gitignore` and `exclude` in `Cargo.toml`
- Added copyright notice header to `LICENSE-MIT`
- Updated `rand::thread_rng()` to `rand::rng()` in README and doc examples

### Added

- Marvin toolkit timing analysis evidence in `tests/marvin/`

## [0.1.1] - 2026-03-06

### Changed

- Use forked `crypto-primes` with `RngCore` trait bounds fix
- Fix doc tests: replace `rsa::` with `sad_rsa::` imports
- Bump version to 0.1.1

## [0.1.0] - 2026-01-16

Initial release of `sad-rsa`, a security-hardened fork of the RustCrypto `rsa` crate.

### Fork Base

Forked from [RustCrypto/RSA](https://github.com/RustCrypto/RSA) at version `0.10.0-rc.12`
(commit `e4f6bce`).

### Added

- **Implicit rejection for PKCS#1 v1.5 decryption** - Mitigates the Marvin Attack
  (RUSTSEC-2023-0071) by returning deterministic pseudo-random messages instead of
  errors when padding validation fails
- **IRPRF (Implicit Rejection Pseudo-Random Function)** - Implements the PRF specified
  in draft-irtf-cfrg-rsa-guidance-04 Section 7
- **KDK (Key Derivation Key) derivation** - Derives keys for synthetic message generation
  using HMAC-SHA256(SHA256(d), ciphertext)
- **RFC 8017 Section 7.2.2 ciphertext length validation** - Validates ciphertext is
  exactly k bytes before processing
- **Enhanced key material zeroization** - Private exponent bytes are wrapped in
  `Zeroizing` to ensure secure memory cleanup
- **Comprehensive test suite** - 16 tests specifically for implicit rejection behavior

### Changed

- `sha2` and `hmac` are now mandatory dependencies (required for implicit rejection)
- `pkcs1v15_encrypt_unpad` now takes a KDK parameter and never returns errors based
  on padding validity
- Decryption with invalid padding returns synthetic messages instead of `Error::Decryption`

### Security

- **Marvin Attack (RUSTSEC-2023-0071)**: Fully mitigated through implicit rejection
- **Timing side-channels**: Constant-time padding validation and message selection
- **Memory safety**: Sensitive key material properly zeroed after use

### Compatibility

- API is fully compatible with upstream `rsa` crate for valid ciphertexts
- Code using explicit error checking for decryption failures should be reviewed
  (invalid ciphertexts now return synthetic messages instead of errors)

## Attribution

This crate is based on the excellent work of the [RustCrypto](https://github.com/RustCrypto)
project. See the [NOTICE](NOTICE) file for full attribution details.
