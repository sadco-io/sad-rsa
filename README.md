# sad-rsa

[![crates.io][crate-image]][crate-link]
[![Documentation][doc-image]][doc-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![MSRV][msrv-image]

A **hardened** pure Rust RSA implementation with protection against timing side-channel attacks.

This is a security-focused fork of the [RustCrypto RSA crate][rustcrypto-rsa] that implements **implicit rejection** for PKCS#1 v1.5 decryption to mitigate the [Marvin Attack][marvin-attack] ([RUSTSEC-2023-0071][rustsec]).

## Security Improvements

| Feature | sad-rsa | upstream rsa |
|---------|---------|--------------|
| Marvin Attack mitigation | **Yes** | No |
| Implicit rejection (PKCS#1 v1.5) | **Default** | Not implemented |
| RFC 8017 length validation | **Yes** | Partial |
| Key material zeroization | **Enhanced** | Basic |

### Implicit Rejection

Instead of returning distinguishable errors for invalid PKCS#1 v1.5 padding, this crate returns a deterministic pseudo-random message derived from the ciphertext. This makes valid and invalid ciphertexts indistinguishable to attackers, preventing padding oracle attacks.

Implementation follows [draft-irtf-cfrg-rsa-guidance-04][irtf-guidance].

## Usage

Replace `rsa` with `sad-rsa` in your `Cargo.toml`:

```toml
[dependencies]
sad-rsa = "0.1"
```

The API is fully compatible with the upstream `rsa` crate:

```rust
use sad_rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

let mut rng = rand::rng();
let bits = 2048;
let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
let pub_key = RsaPublicKey::from(&priv_key);

// Encrypt
let data = b"hello world";
let enc_data = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
assert_ne!(&data[..], &enc_data[..]);

// Decrypt - now protected against Marvin attack
let dec_data = priv_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
assert_eq!(&data[..], &dec_data[..]);
```

## Migration from `rsa`

1. Replace `rsa` with `sad-rsa` in `Cargo.toml`
2. Replace `use rsa::` with `use sad_rsa::` in your code
3. That's it - the API is identical

**Note:** Invalid ciphertexts will now return synthetic messages instead of errors. If your code explicitly checks for decryption errors to detect tampering, you should use authenticated encryption (e.g., RSA-OAEP or hybrid encryption with AES-GCM) instead.

## Performance

> **Note:** Key generation is much faster when building with higher optimization levels:
> ```toml
> [profile.dev]
> opt-level = 2
> ```

## Minimum Supported Rust Version (MSRV)

This crate supports Rust 1.85 or higher.

## Attribution

This crate is a fork of the excellent [RustCrypto RSA][rustcrypto-rsa] crate. We are grateful to the RustCrypto developers for their foundational work.

See the [NOTICE](NOTICE) file for full attribution details.

## License

Licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/sad-rsa?logo=rust
[crate-link]: https://crates.io/crates/sad-rsa
[doc-image]: https://docs.rs/sad-rsa/badge.svg
[doc-link]: https://docs.rs/sad-rsa
[build-image]: https://github.com/sadco-io/sad-rsa/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/sadco-io/sad-rsa/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg

[//]: # (links)

[rustcrypto-rsa]: https://github.com/RustCrypto/RSA
[marvin-attack]: https://people.redhat.com/~hkario/marvin/
[rustsec]: https://rustsec.org/advisories/RUSTSEC-2023-0071.html
[irtf-guidance]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-guidance/
