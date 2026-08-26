//! Tests for Marvin attack mitigation via implicit rejection.
//!
//! These tests verify that the PKCS#1 v1.5 decryption implementation
//! correctly implements implicit rejection as specified in
//! draft-irtf-cfrg-rsa-guidance-04.

use crypto_bigint::BoxedUint;
use rand::rngs::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use sad_rsa::pkcs1v15::DecryptingKey;
use sad_rsa::traits::{Decryptor, EncryptingKeypair, RandomizedDecryptor, RandomizedEncryptor};
use sad_rsa::RsaPrivateKey;

/// Helper function to create a test key
fn get_test_key() -> RsaPrivateKey {
    RsaPrivateKey::from_components(
        BoxedUint::from_be_hex(
            "B2990F49C47DFA8CD400AE6A4D1B8A3B6A13642B23F28B003BFB97790ADE9A4CC82B8B2A81747DDEC08B6296E53A08C331687EF25C4BF4936BA1C0E6041E9D15",
            512,
        )
        .unwrap(),
        BoxedUint::from(65_537u64),
        BoxedUint::from_be_hex(
            "8ABD6A69F4D1A4B487F0AB8D7AAEFD38609405C999984E30F567E1E8AEEFF44E8B18BDB1EC78DFA31A55E32A48D7FB131F5AF1F44D7D6B2CED2A9DF5E5AE4535",
            512,
        )
        .unwrap(),
        vec![
            BoxedUint::from_be_hex(
                "DAB2F18048BAA68DE7DF04D2D35D5D80E60E2DFA42D50A9B04219032715E46B3",
                256,
            )
            .unwrap(),
            BoxedUint::from_be_hex(
                "D10F2E66B1D0C13F10EF9927BF5324A379CA218146CBF9CAFC795221F16A3117",
                256,
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

#[test]
fn test_valid_ciphertext_decrypts_correctly() {
    // Test that valid ciphertexts still decrypt properly with implicit rejection
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let encrypting_key = decrypting_key.encrypting_key();

    // Test with various message lengths
    for msg_len in [1, 8, 16, 32, 53] {
        let mut message = vec![0u8; msg_len];
        rng.fill_bytes(&mut message);

        let ciphertext = RandomizedEncryptor::encrypt_with_rng(&encrypting_key, &mut rng, &message)
            .expect("encryption should succeed");

        let decrypted =
            Decryptor::decrypt(&decrypting_key, &ciphertext).expect("decryption should succeed");

        assert_eq!(
            message, decrypted,
            "Valid ciphertext should decrypt to original message"
        );
    }
}

/// `pkcs1v15_encrypt_unpad` used to finish with `output[start..].to_vec()`,
/// which allocated exactly `output_length` bytes. Rust's allocator special-cases
/// length 0 (no malloc, `memcpy(0)`, drop skips free), so empty valid messages
/// (`valid_0`) were ~20 ns faster than every other Marvin class.
///
/// Returning `len == message.len()` is the public API; the allocation size is
/// not. The returned `Vec` must keep a `k-11` (or larger, length-independent)
/// allocation even when the message is empty, so construction and drop do not
/// depend on plaintext length.
#[test]
fn test_decrypt_vec_capacity_independent_of_message_length() {
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let priv_key = get_test_key();
    let k = 64; // 512-bit key
    let max_msg = k - 11;
    let decrypting_key = DecryptingKey::new(priv_key);
    let encrypting_key = decrypting_key.encrypting_key();

    let mut capacities = Vec::new();
    for msg_len in [0usize, 1, 8, 16, 32, max_msg] {
        let mut message = vec![0u8; msg_len];
        rng.fill_bytes(&mut message);

        let ciphertext = RandomizedEncryptor::encrypt_with_rng(&encrypting_key, &mut rng, &message)
            .expect("encryption should succeed");
        let decrypted =
            Decryptor::decrypt(&decrypting_key, &ciphertext).expect("decryption should succeed");

        assert_eq!(message, decrypted, "round-trip for len={msg_len}");
        assert!(
            decrypted.capacity() >= max_msg,
            "len={msg_len} cap={} must be >= k-11={max_msg} so drop always frees a fixed-size buffer",
            decrypted.capacity()
        );
        capacities.push(decrypted.capacity());
    }

    let invalid = vec![0u8; k];
    let synthetic = Decryptor::decrypt(&decrypting_key, &invalid)
        .expect("invalid ciphertext returns synthetic");
    assert!(
        synthetic.capacity() >= max_msg,
        "synthetic cap={} must be >= k-11={max_msg}",
        synthetic.capacity()
    );

    let expected = capacities[0];
    for (i, cap) in capacities.iter().enumerate() {
        assert_eq!(
            *cap, expected,
            "capacity must not depend on message length (index {i})"
        );
    }
    assert_eq!(
        synthetic.capacity(),
        expected,
        "invalid path must use the same allocation size as the valid path"
    );
}

#[test]
fn test_invalid_ciphertext_returns_synthetic_message() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64; // 512-bit key = 64 bytes

    let invalid_ciphertext = vec![0u8; k];

    let result = Decryptor::decrypt(&decrypting_key, &invalid_ciphertext);

    assert!(
        result.is_ok(),
        "Invalid ciphertext should return synthetic message, not error"
    );
    let synthetic_message = result.unwrap();
    assert!(
        !synthetic_message.is_empty(),
        "Synthetic message should not be empty"
    );
    assert!(
        synthetic_message.len() <= k - 11,
        "Synthetic message length should be <= k-11"
    );
}

#[test]
fn test_deterministic_synthetic_messages() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut invalid_ciphertext = vec![0u8; k];
    invalid_ciphertext[0] = 0x01; // Small value < n

    let result1 = Decryptor::decrypt(&decrypting_key, &invalid_ciphertext)
        .expect("should return synthetic message");
    let result2 = Decryptor::decrypt(&decrypting_key, &invalid_ciphertext)
        .expect("should return synthetic message");
    let result3 = Decryptor::decrypt(&decrypting_key, &invalid_ciphertext)
        .expect("should return synthetic message");

    assert_eq!(
        result1, result2,
        "Same invalid ciphertext should produce same synthetic message"
    );
    assert_eq!(
        result2, result3,
        "Synthetic message should be deterministic"
    );
}

#[test]
fn test_different_invalid_ciphertexts_produce_different_synthetic_messages() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut invalid_ct1 = vec![0u8; k];
    invalid_ct1[0] = 0x01;

    let mut invalid_ct2 = vec![0u8; k];
    invalid_ct2[0] = 0x02;

    let synthetic1 =
        Decryptor::decrypt(&decrypting_key, &invalid_ct1).expect("should return synthetic message");
    let synthetic2 =
        Decryptor::decrypt(&decrypting_key, &invalid_ct2).expect("should return synthetic message");

    assert_ne!(
        synthetic1, synthetic2,
        "Different invalid ciphertexts should produce different synthetic messages"
    );
}

#[test]
fn test_invalid_padding_corruption() {
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let encrypting_key = decrypting_key.encrypting_key();
    let k = 64;

    let message = b"test";
    let ciphertext = RandomizedEncryptor::encrypt_with_rng(&encrypting_key, &mut rng, message)
        .expect("encryption should succeed");

    let mut corrupted = ciphertext.clone();
    corrupted[k - 5] ^= 0xFF;

    let result = Decryptor::decrypt(&decrypting_key, &corrupted);
    assert!(
        result.is_ok(),
        "Corrupted ciphertext should return synthetic message"
    );
}

#[test]
fn test_short_padding_string() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    // Manually construct a ciphertext with short PS (< 8 bytes)
    let mut em = vec![0xFF; k];
    em[0] = 0x00;
    em[1] = 0x02;
    for i in 2..9 {
        em[i] = 0x42;
    }
    em[9] = 0x00; // PS is only 7 bytes
    em[10] = 0xAA;

    let result = Decryptor::decrypt(&decrypting_key, &em);
    assert!(
        result.is_ok(),
        "Short padding should return synthetic message"
    );

    let result2 = Decryptor::decrypt(&decrypting_key, &em);
    assert_eq!(
        result.unwrap(),
        result2.unwrap(),
        "Deterministic synthetic message"
    );
}

#[test]
fn test_wrong_first_byte() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut em = vec![0xFF; k];
    em[0] = 0x01; // Wrong! Should be 0x00
    em[1] = 0x02;
    for i in 2..11 {
        em[i] = 0x42;
    }
    em[11] = 0x00;
    em[12] = 0xAA;

    let result = Decryptor::decrypt(&decrypting_key, &em);
    assert!(
        result.is_ok(),
        "Wrong first byte should return synthetic message"
    );
}

#[test]
fn test_wrong_second_byte() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut em = vec![0xFF; k];
    em[0] = 0x00;
    em[1] = 0x01; // Wrong! Should be 0x02
    for i in 2..11 {
        em[i] = 0x42;
    }
    em[11] = 0x00;
    em[12] = 0xAA;

    let result = Decryptor::decrypt(&decrypting_key, &em);
    assert!(
        result.is_ok(),
        "Wrong second byte should return synthetic message"
    );
}

#[test]
fn test_zero_in_padding_string() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut em = vec![0xFF; k];
    em[0] = 0x00;
    em[1] = 0x02;
    for i in 2..11 {
        em[i] = 0x42;
    }
    em[5] = 0x00; // Zero in PS (invalid)
    em[11] = 0x00;
    em[12] = 0xAA;

    let result = Decryptor::decrypt(&decrypting_key, &em);
    assert!(
        result.is_ok(),
        "Zero in padding string should return synthetic message"
    );
}

#[test]
fn test_no_separator_byte() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut em = vec![0xFF; k];
    em[0] = 0x00;
    em[1] = 0x02;
    for i in 2..k {
        em[i] = 0x42;
    }

    let result = Decryptor::decrypt(&decrypting_key, &em);
    assert!(
        result.is_ok(),
        "Missing separator should return synthetic message"
    );
}

#[test]
fn test_synthetic_message_unpredictability() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut synthetic_messages = Vec::new();

    for i in 0..20 {
        let mut invalid_ct = vec![0u8; k];
        invalid_ct[0] = i;

        let synthetic = Decryptor::decrypt(&decrypting_key, &invalid_ct)
            .expect("should return synthetic message");
        synthetic_messages.push(synthetic);
    }

    for i in 0..synthetic_messages.len() {
        for j in i + 1..synthetic_messages.len() {
            assert_ne!(
                synthetic_messages[i], synthetic_messages[j],
                "Synthetic messages should all be different"
            );
        }
    }
}

#[test]
fn test_valid_and_invalid_mixed() {
    let mut rng = ChaCha8Rng::from_seed([99; 32]);
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let encrypting_key = decrypting_key.encrypting_key();
    let k = 64;

    let message = b"valid message";
    let valid_ct = RandomizedEncryptor::encrypt_with_rng(&encrypting_key, &mut rng, message)
        .expect("encryption should succeed");

    let invalid_ct = vec![0x01; k]; // Small values < n

    let valid_result =
        Decryptor::decrypt(&decrypting_key, &valid_ct).expect("valid ciphertext should decrypt");
    assert_eq!(
        valid_result, message,
        "Valid message should decrypt correctly"
    );

    let invalid_result = Decryptor::decrypt(&decrypting_key, &invalid_ct)
        .expect("invalid ciphertext should return synthetic message");
    assert_ne!(
        invalid_result, message,
        "Invalid ciphertext should not decrypt to original message"
    );

    let valid_result2 = Decryptor::decrypt(&decrypting_key, &valid_ct)
        .expect("valid ciphertext should still decrypt");
    assert_eq!(
        valid_result2, message,
        "Valid message should still decrypt correctly"
    );
}

#[test]
fn test_ciphertext_length_variations() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let short_ct = vec![0x01; k - 1];
    let result = Decryptor::decrypt(&decrypting_key, &short_ct);
    assert!(result.is_err(), "Too short ciphertext should error");

    let long_ct = vec![0x01; k + 1];
    let result = Decryptor::decrypt(&decrypting_key, &long_ct);
    assert!(result.is_err(), "Too long ciphertext should error");

    let exact_ct = vec![0x01; k]; // Valid length, < n, but invalid padding
    let result = Decryptor::decrypt(&decrypting_key, &exact_ct);
    assert!(
        result.is_ok(),
        "Exact size invalid ciphertext should return synthetic message"
    );
}

#[test]
fn test_kdk_derivation_varies_with_ciphertext() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut ct1 = vec![0x01; k];
    ct1[k - 1] = 0x10;

    let mut ct2 = vec![0x01; k];
    ct2[k - 1] = 0x20;

    let synthetic1 =
        Decryptor::decrypt(&decrypting_key, &ct1).expect("should return synthetic message");
    let synthetic2 =
        Decryptor::decrypt(&decrypting_key, &ct2).expect("should return synthetic message");

    assert_ne!(
        synthetic1, synthetic2,
        "Different ciphertexts should produce different synthetic messages"
    );
}

#[test]
fn test_synthetic_message_length_variations() {
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let k = 64;

    let mut lengths = std::collections::HashSet::new();

    for i in 0..50 {
        let mut invalid_ct = vec![0u8; k];
        invalid_ct[1] = i;

        let synthetic = Decryptor::decrypt(&decrypting_key, &invalid_ct)
            .expect("should return synthetic message");
        lengths.insert(synthetic.len());
    }

    for &len in &lengths {
        assert!(
            len <= k - 11,
            "Synthetic message length {} should be <= {}",
            len,
            k - 11
        );
    }
}

#[test]
fn test_implicit_rejection_with_blinding() {
    let mut rng = ChaCha8Rng::from_seed([42; 32]);
    let priv_key = get_test_key();
    let decrypting_key = DecryptingKey::new(priv_key);
    let encrypting_key = decrypting_key.encrypting_key();

    let message = b"test with blinding";
    let valid_ct = RandomizedEncryptor::encrypt_with_rng(&encrypting_key, &mut rng, message)
        .expect("encryption should succeed");

    let decrypted = RandomizedDecryptor::decrypt_with_rng(&decrypting_key, &mut rng, &valid_ct)
        .expect("decryption with blinding should succeed");

    assert_eq!(
        message,
        decrypted.as_slice(),
        "Blinded decryption should work correctly"
    );

    let k = 64;
    let invalid_ct = vec![0x01; k]; // Small values < n
    let synthetic = RandomizedDecryptor::decrypt_with_rng(&decrypting_key, &mut rng, &invalid_ct)
        .expect("invalid ciphertext should return synthetic message even with blinding");

    let synthetic2 = RandomizedDecryptor::decrypt_with_rng(&decrypting_key, &mut rng, &invalid_ct)
        .expect("should be deterministic");

    assert_eq!(
        synthetic, synthetic2,
        "Synthetic message should be deterministic even with blinding"
    );
}
