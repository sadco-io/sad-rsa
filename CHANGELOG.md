# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
