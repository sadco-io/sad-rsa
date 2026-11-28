//! Regression tests for input checks on untrusted keys and signatures.

use crypto_bigint::{BoxedUint, Limb};
use rand::rngs::ChaCha8Rng;
use rand_core::SeedableRng;
use sad_rsa::traits::PublicKeyParts;
use sad_rsa::{pkcs1v15, pss, Error, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use signature::{Keypair, RandomizedSigner, SignatureEncoding, Signer, Verifier};

fn key(bits: usize, seed: u8) -> RsaPrivateKey {
    let mut rng = ChaCha8Rng::from_seed([seed; 32]);
    RsaPrivateKey::new(&mut rng, bits).unwrap()
}

/// A public key with an arbitrary odd modulus of `bytes` bytes. Nobody knows its factors,
/// which is all an attacker needs to feed a verifier.
fn arbitrary_public_key(bytes: usize) -> RsaPublicKey {
    let n = BoxedUint::from_be_slice(&vec![0xC1; bytes], (bytes * 8) as u32).unwrap();
    RsaPublicKey::new(n, BoxedUint::from(65_537u64)).unwrap()
}

/// Verifying with a detected salt length used to panic when the modulus was too small for
/// the hash: nothing checked that the encoded message could hold the hash at all.
#[test]
fn pss_auto_salt_len_rejects_keys_too_small_for_the_hash() {
    fn check<D>(bytes: usize)
    where
        D: Digest + digest::FixedOutputReset,
    {
        let public_key = arbitrary_public_key(bytes);
        let verifying_key = pss::VerifyingKey::<D>::new_with_auto_salt_len(public_key.clone());
        let hashed = D::digest(b"msg");

        // One in 256 signatures passes the trailer check that comes first, so try enough of
        // them to get past it many times.
        for i in 0..4000u32 {
            let mut sig = vec![0x11u8; bytes];
            sig[bytes - 4..].copy_from_slice(&i.to_be_bytes());

            let signature = pss::Signature::try_from(&sig[..]).unwrap();
            assert!(verifying_key.verify(b"msg", &signature).is_err());

            let mut scheme = Pss::<D>::new();
            scheme.salt_len = None;
            assert_eq!(
                public_key.verify(scheme, &hashed, &sig),
                Err(Error::Verification)
            );
        }
    }

    // em_len == h_len: the split point underflowed.
    check::<Sha512>(64);
    check::<Sha256>(32);
    // em_len == h_len + 1: the masked data block is empty.
    check::<Sha256>(33);
    // far too small
    check::<Sha256>(8);
}

/// Detecting the salt length still works when the key is large enough.
#[test]
fn pss_auto_salt_len_accepts_valid_signatures() {
    let mut rng = ChaCha8Rng::from_seed([5; 32]);
    let private_key = key(1024, 7);
    for salt_len in [0usize, 20, 32, 64] {
        let signing_key =
            pss::SigningKey::<Sha256>::new_with_salt_len(private_key.clone(), salt_len);
        let verifying_key =
            pss::VerifyingKey::<Sha256>::new_with_auto_salt_len(private_key.to_public_key());
        let signature = signing_key.sign_with_rng(&mut rng, b"msg");
        verifying_key.verify(b"msg", &signature).unwrap();
    }
}

/// `s + n` encrypts to the same value as `s`. The signature representative must be below
/// the modulus on every verification path.
#[test]
fn signature_plus_modulus_is_rejected() {
    let private_key = key(1024, 7);
    let public_key = private_key.to_public_key();
    let n = public_key.n().as_ref().clone();
    let mut rng = ChaCha8Rng::from_seed([9; 32]);
    let hashed = Sha256::digest(b"hello");

    let plus_n = |sig: &[u8]| -> Option<Vec<u8>> {
        let s = BoxedUint::from_be_slice(sig, n.bits_precision()).unwrap();
        let (sum, carry) = s.carrying_add(&n, Limb::ZERO);
        (carry == Limb::ZERO).then(|| sum.to_be_bytes().to_vec())
    };

    // PSS
    let mut checked = 0;
    for _ in 0..64 {
        let sig = private_key
            .sign_with_rng(&mut rng, Pss::<Sha256>::new(), &hashed)
            .unwrap();
        public_key
            .verify(Pss::<Sha256>::new(), &hashed, &sig)
            .unwrap();
        let Some(forged) = plus_n(&sig) else { continue };
        assert_eq!(forged.len(), sig.len());

        assert_eq!(
            public_key.verify(Pss::<Sha256>::new(), &hashed, &forged),
            Err(Error::Verification)
        );
        let verifying_key = pss::VerifyingKey::<Sha256>::new(public_key.clone());
        assert!(verifying_key
            .verify(b"hello", &pss::Signature::try_from(&forged[..]).unwrap())
            .is_err());
        checked += 1;
    }
    assert!(checked > 0);

    // PKCS#1 v1.5
    let mut checked = 0;
    for i in 0..64u32 {
        let msg = i.to_be_bytes();
        let hashed = Sha256::digest(msg);
        let sig = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &hashed)
            .unwrap();
        let Some(forged) = plus_n(&sig) else { continue };

        assert_eq!(
            public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &forged),
            Err(Error::Verification)
        );
        let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key.clone());
        assert!(verifying_key
            .verify(&msg, &pkcs1v15::Signature::try_from(&forged[..]).unwrap())
            .is_err());
        checked += 1;
    }
    assert!(checked > 0);
}

/// RFC 8017 § 8.1.2 and § 8.2.2, step 1: a signature that is not exactly as long as the
/// modulus is invalid, even if it is the right number with a different number of leading
/// zero bytes.
#[test]
fn signature_of_the_wrong_length_is_rejected() {
    let private_key = key(1024, 7);
    let public_key = private_key.to_public_key();
    let k = public_key.size();

    // PKCS#1 v1.5: find a signature that starts with a zero byte.
    let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key.clone());
    let verifying_key = signing_key.verifying_key();
    let (msg, sig) = (0..20_000u32)
        .map(|i| {
            (
                i.to_be_bytes(),
                signing_key.sign(&i.to_be_bytes()).to_bytes(),
            )
        })
        .find(|(_, sig)| sig[0] == 0)
        .expect("a signature with a leading zero byte");
    assert_eq!(sig.len(), k);
    let hashed = Sha256::digest(msg);
    let short = &sig[1..];
    let mut long = vec![0u8];
    long.extend_from_slice(&sig);

    verifying_key
        .verify(&msg, &pkcs1v15::Signature::try_from(&sig[..]).unwrap())
        .unwrap();
    public_key
        .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, &sig)
        .unwrap();
    for wrong in [short, &long[..]] {
        assert!(verifying_key
            .verify(&msg, &pkcs1v15::Signature::try_from(wrong).unwrap())
            .is_err());
        assert_eq!(
            public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, wrong),
            Err(Error::Verification)
        );
    }

    // PSS
    let mut rng = ChaCha8Rng::from_seed([3; 32]);
    let signing_key = pss::SigningKey::<Sha256>::new(private_key.clone());
    let verifying_key = signing_key.verifying_key();
    let sig = (0..20_000u32)
        .map(|_| signing_key.sign_with_rng(&mut rng, b"m").to_bytes())
        .find(|sig| sig[0] == 0)
        .expect("a signature with a leading zero byte");
    let hashed = Sha256::digest(b"m");
    let short = &sig[1..];
    let mut long = vec![0u8];
    long.extend_from_slice(&sig);

    verifying_key
        .verify(b"m", &pss::Signature::try_from(&sig[..]).unwrap())
        .unwrap();
    for wrong in [short, &long[..]] {
        assert!(verifying_key
            .verify(b"m", &pss::Signature::try_from(wrong).unwrap())
            .is_err());
        assert_eq!(
            public_key.verify(Pss::<Sha256>::new(), &hashed, wrong),
            Err(Error::Verification)
        );
    }
}

/// Signatures are exactly as long as the modulus, also when that is not a whole number of
/// machine words, and they round trip through their byte encoding.
#[test]
fn signatures_have_the_length_of_the_modulus() {
    let mut rng = ChaCha8Rng::from_seed([4; 32]);
    // 1025 bits: 129 bytes, and the PSS encoded message is one byte shorter than the modulus.
    for bits in [1024usize, 1025, 1032, 1100] {
        let private_key = key(bits, 11);
        let k = private_key.size();
        assert_eq!(k, bits.div_ceil(8));

        let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.sign(b"msg");
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), k, "pkcs1v15 {bits}");
        let decoded = pkcs1v15::Signature::try_from(&bytes[..]).unwrap();
        assert_eq!(decoded, signature);
        signing_key
            .verifying_key()
            .verify(b"msg", &decoded)
            .unwrap();
        private_key
            .to_public_key()
            .verify(
                Pkcs1v15Sign::new::<Sha256>(),
                &Sha256::digest(b"msg"),
                &bytes,
            )
            .unwrap();

        let signing_key = pss::SigningKey::<Sha256>::new(private_key.clone());
        let signature = signing_key.sign_with_rng(&mut rng, b"msg");
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), k, "pss {bits}");
        let decoded = pss::Signature::try_from(&bytes[..]).unwrap();
        assert_eq!(decoded, signature);
        signing_key
            .verifying_key()
            .verify(b"msg", &decoded)
            .unwrap();
        private_key
            .to_public_key()
            .verify(Pss::<Sha256>::new(), &Sha256::digest(b"msg"), &bytes)
            .unwrap();
        assert_eq!(format!("{signature:x}").len(), 2 * k);
    }
}

/// Private keys above `RsaPrivateKey::MAX_SIZE` are rejected before any work is done.
#[test]
fn private_key_size_is_capped() {
    assert_eq!(RsaPrivateKey::MAX_SIZE, 16384);
    let e = BoxedUint::from(65_537u64);
    let odd = |bits: u32| {
        let mut bytes = vec![0xffu8; (bits / 8) as usize];
        bytes[0] = 0x80;
        BoxedUint::from_be_slice(&bytes, bits).unwrap()
    };
    let factors = || vec![BoxedUint::from(3u64), BoxedUint::from(5u64)];

    // One limb above the limit, also when padded with leading zeros to a wider precision.
    let too_large = odd(16384 + 64);
    assert_eq!(
        RsaPrivateKey::from_components(too_large.clone(), e.clone(), e.clone(), factors()),
        Err(Error::ModulusTooLarge)
    );
    // No factors: prime recovery must not start either.
    assert_eq!(
        RsaPrivateKey::from_components(too_large, e.clone(), e.clone(), vec![]),
        Err(Error::ModulusTooLarge)
    );

    // Exactly at the limit the size is fine; the key fails for what is wrong with it.
    assert_eq!(
        RsaPrivateKey::from_components(odd(16384), e.clone(), e.clone(), factors()),
        Err(Error::InvalidModulus)
    );

    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    assert_eq!(
        RsaPrivateKey::new(&mut rng, 16385),
        Err(Error::ModulusTooLarge)
    );
}

/// An oversized PKCS#1 / PKCS#8 private key is rejected when decoding.
#[cfg(feature = "encoding")]
#[test]
fn oversized_private_key_der_is_rejected() {
    use sad_rsa::pkcs1::{der::Encode, DecodeRsaPrivateKey, RsaPrivateKeyRef, UintRef};
    use sad_rsa::pkcs8::DecodePrivateKey;

    let encode = |modulus_len: usize| {
        let mut modulus = vec![0xffu8; modulus_len];
        modulus[0] = 0x80;
        let small = [0x03u8];
        RsaPrivateKeyRef {
            modulus: UintRef::new(&modulus).unwrap(),
            public_exponent: UintRef::new(&[1, 0, 1]).unwrap(),
            private_exponent: UintRef::new(&small).unwrap(),
            prime1: UintRef::new(&small).unwrap(),
            prime2: UintRef::new(&small).unwrap(),
            exponent1: UintRef::new(&small).unwrap(),
            exponent2: UintRef::new(&small).unwrap(),
            coefficient: UintRef::new(&small).unwrap(),
            other_prime_infos: None,
        }
        .to_der()
        .unwrap()
    };

    let oversized = encode(2049);
    assert!(matches!(
        RsaPrivateKey::from_pkcs1_der(&oversized),
        Err(sad_rsa::pkcs1::Error::KeyMalformed)
    ));

    // The same key wrapped in PKCS#8.
    let pkcs8 = sad_rsa::pkcs8::PrivateKeyInfoRef::new(
        sad_rsa::pkcs1::ALGORITHM_ID,
        sad_rsa::pkcs8::der::asn1::OctetStringRef::new(&oversized).unwrap(),
    )
    .to_der()
    .unwrap();
    assert!(RsaPrivateKey::from_pkcs8_der(&pkcs8).is_err());

    // A key of the largest allowed size gets past the size check and fails validation.
    assert!(RsaPrivateKey::from_pkcs1_der(&encode(2048)).is_err());
}
