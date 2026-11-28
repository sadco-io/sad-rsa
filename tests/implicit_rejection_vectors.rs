//! Test vectors for PKCS#1 v1.5 decryption with implicit rejection, taken from
//! Appendix B of `draft-irtf-cfrg-rsa-guidance-04`.
//!
//! Every vector decrypts without an error: valid ciphertexts give the real
//! message, invalid ones give the synthetic message the draft specifies.

#![cfg(feature = "encoding")]

use rand::rngs::ChaCha8Rng;
use rand_core::SeedableRng;
use sad_rsa::pkcs8::DecodePrivateKey;
use sad_rsa::traits::PublicKeyParts;
use sad_rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    name: String,
    private_key_pem: String,
    tests: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    section: String,
    name: String,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    plaintext: Vec<u8>,
}

#[test]
fn draft_rsa_guidance_appendix_b() {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "examples/implicit_rejection/draft-rsa-guidance-04.json"
    ))
    .expect("valid vector file");
    assert_eq!(vectors.groups.len(), 4);

    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let mut failures = Vec::new();
    let mut total = 0;
    for group in &vectors.groups {
        let key = RsaPrivateKey::from_pkcs8_pem(&group.private_key_pem).expect("valid key");
        for case in &group.tests {
            total += 1;
            assert_eq!(case.ciphertext.len(), key.size(), "{}", case.section);
            let plain = key.decrypt(Pkcs1v15Encrypt, &case.ciphertext);
            let blinded = key.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, &case.ciphertext);
            if plain.as_deref() != Ok(&case.plaintext[..])
                || blinded.as_deref() != Ok(&case.plaintext[..])
            {
                failures.push(format!("{} {} ({})", case.section, case.name, group.name));
            }
        }
    }
    assert_eq!(total, 48);
    assert!(failures.is_empty(), "mismatches:\n{}", failures.join("\n"));
}
