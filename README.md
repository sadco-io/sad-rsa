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

```toml
[dependencies]
sad-rsa = "0.2"
```

The API matches the upstream `rsa` **0.10 pre-release line** (this crate was
forked at `rsa 0.10.0-rc.12`). It is **not** API-compatible with the released
`rsa` 0.9.x — see [Compatibility](#compatibility-with-the-rsa-crate) below
before migrating.

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

## Compatibility with the `rsa` crate

`sad-rsa` was forked from [RustCrypto/RSA][rustcrypto-rsa] at version
`0.10.0-rc.12` — the **unreleased 0.10 line**, not the released 0.9.x series.
Upstream 0.10 replaced the bignum backend (`num-bigint-dig` → `crypto-bigint`)
and moved to new major versions of the `rand_core`, `digest`, `sha2`,
`signature`, `pkcs1`, and `pkcs8` ecosystems. All of those API changes are
inherited here.

### Migrating from `rsa` 0.10.0-rc.x

Replace the dependency and the crate name in `use` paths — the API is the
same. (Verified against `rsa 0.10.0-rc.18`; behavioral differences are the
implicit-rejection semantics described below, and error variants upstream
added after rc.12, e.g. `Error::InputSize` where this crate returns
`Error::Decryption`.)

### Migrating from `rsa` 0.9.x

This is the same amount of work as upgrading to the upstream 0.10
pre-releases. The changes you will hit:

| What changed | `rsa` 0.9.x | `sad-rsa` 0.2 |
|---|---|---|
| Big-integer type | `rsa::BigUint` (from `num-bigint-dig`) | `sad_rsa::BoxedUint` (from `crypto-bigint`) |
| RNG traits | `rand_core` 0.6 (`rand` 0.8, `rand::thread_rng()`) | `rand_core` 0.10 (`rand` 0.10, `rand::rng()`) |
| Digest traits | `digest`/`sha2` 0.10 | `digest`/`sha2` 0.11 |
| Signature traits | `signature` 2.x | `signature` 3.0 |
| Key encoding | `pkcs1` 0.7, `pkcs8` 0.10 | `pkcs1` 0.8.0-rc, `pkcs8` 0.11 (same trait names) |
| Feature flags | `pem` feature | no `pem` feature — PEM is always on via the default `encoding` feature |
| MSRV | 1.65 | 1.85 |

Concretely, in `Cargo.toml`:

```toml
# before                                  # after
rsa = { version = "0.9", features = ["sha2"] }
rand = "0.8"                              # rand = "0.10"
sha2 = "0.10"                             # sha2 = "0.11"
                                          # sad-rsa = "0.2"
```

And in code (illustrative before/after, not a complete program):

```rust,ignore
// RNG: rand 0.8 types don't implement rand_core 0.10 traits
let mut rng = rand::thread_rng();         // before (rand 0.8)
let mut rng = rand::rng();                // after  (rand 0.10)

// Key-component accessors: BigUint -> BoxedUint, and n() is NonZero-wrapped
let n: &BigUint = key.n();                // before
let n: &BoxedUint = key.n().as_ref();     // after

// from_components / RsaPublicKey::new now take BoxedUint values
// (BoxedUint has a fixed bit precision; build values with
// BoxedUint::from_be_slice(bytes, bits) or similar)

// OAEP: the digest moved from the constructor to the type
let padding = Oaep::new::<Sha256>();      // before
let padding = Oaep::<Sha256>::new();      // after

// Signing keys require sha2 0.11 types (sha2 0.10's Sha256 will not
// satisfy the Digest bound) and the signature 3.0 traits
let sk = SigningKey::<Sha256>::new(key);  // same shape, new sha2/signature versions
```

Unchanged from 0.9.x: the `encrypt`/`decrypt` call shapes
(`pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, msg)`), the `pkcs1`/`pkcs8`
encode/decode trait method names (`to_pkcs8_pem`, `from_pkcs1_der`, ...), and
the `Error::Decryption`-style error variants (the enum has gained variants, so
exhaustive matches need updating).

### Behavioral change: implicit rejection

**Note:** Invalid PKCS#1 v1.5 ciphertexts will now return synthetic messages instead of errors. If your code explicitly checks for decryption errors to detect tampering, you should use authenticated encryption (e.g., RSA-OAEP or hybrid encryption with AES-GCM) instead.

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
