# Security Policy

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| Latest `0.10.x` patch | Yes | Current release line, tracking the upstream `rsa` 0.10 API line. Security fixes ship as a new `0.10.x` patch release. |
| All earlier releases | No | Upgrade to the latest `0.10.x` patch. |

## Scope

`sad-rsa` implements RSA key generation, encoding (`encoding`, `pkcs5`, `serde`), encryption and decryption (`Oaep`, `Pkcs1v15Encrypt`), and digital signatures (`Pkcs1v15Sign`, `Pss`, and the `pkcs1v15` / `pss` signing and verifying keys), with PKCS#1 v1.5 decryption using implicit rejection (`draft-irtf-cfrg-rsa-guidance-04`) to mitigate the Marvin attack (`RUSTSEC-2023-0071`).

- **In scope:** Cryptographic correctness bugs, padding-oracle leaks, key-material zeroization failures, panics or denial-of-service on untrusted keys, signatures, or ciphertexts, and timing or other side-channel leaks in operations on secret data (including PKCS#1 v1.5 implicit rejection and private-key decryption/signing). Timing leaks in unblinded private-key operations are in scope.
- **Out of scope:** Misuse of the `hazmat` raw RSA primitives (`rsa_encrypt`, `rsa_decrypt`, `rsa_decrypt_and_check`), treating synthetic plaintexts returned by PKCS#1 v1.5 implicit rejection as authenticated messages (as warned in `README.md`), use of a cryptographically insecure caller-supplied RNG, or side channels confined to caller-supplied RNGs or application code, and vulnerabilities in dependencies such as `crypto-bigint` or `pkcs8` (which belong to the upstream dependency, though we will release an update when needed).

## Advisories

For each security fix we publish a GitHub Security Advisory for `sad-rsa` and request a RustSec
advisory. Fixed versions are listed in the advisory and in [CHANGELOG.md](CHANGELOG.md). We watch the upstream [RustCrypto/RSA](https://github.com/RustCrypto/RSA) issue tracker
and RustSec advisories for `rsa`, and mirror any that affect shared code. Because `cargo audit` and
`cargo deny` match advisories by package name, an upstream `rsa` advisory will not flag `sad-rsa`
on its own.

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please report
it privately. **Do not disclose it as a public issue.** This gives us time to
work with you to fix the issue before public exposure, reducing the chance that
the exploit will be used before a patch is released.

Please disclose it at [security advisory](https://github.com/sadco-io/sad-rsa/security/advisories/new).

This project is maintained by a team of volunteers on a reasonable-effort basis.
As such, please give us at least 90 days to work on a fix before public exposure.
