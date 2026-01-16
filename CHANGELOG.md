# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
