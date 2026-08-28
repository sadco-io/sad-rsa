//! PKCS#1 v1.5 support as described in [RFC8017 § 8.2].
//!
//! # Usage
//!
//! See [code example in the toplevel rustdoc](../index.html#pkcs1-v15-signatures).
//!
//! [RFC8017 § 8.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-8.2

use alloc::vec::Vec;
use const_oid::AssociatedOid;
use crypto_bigint::{BoxedUint, Choice, CtAssign, CtEq, CtLt, CtSelect};
use digest::{Digest, KeyInit, Mac};
use hmac::Hmac;
use rand_core::TryCryptoRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Fills the provided slice with random values, which are guaranteed
/// to not be zero.
#[inline]
fn non_zero_random_bytes<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    data: &mut [u8],
) -> core::result::Result<(), R::Error> {
    rng.try_fill_bytes(data)?;

    for el in data {
        if *el == 0u8 {
            // TODO: break after a certain amount of time
            while *el == 0u8 {
                rng.try_fill_bytes(core::slice::from_mut(el))?;
            }
        }
    }

    Ok(())
}

/// Applied the padding scheme from PKCS#1 v1.5 for encryption.  The message must be no longer than
/// the length of the public modulus minus 11 bytes.
pub(crate) fn pkcs1v15_encrypt_pad<R>(
    rng: &mut R,
    msg: &[u8],
    k: usize,
) -> Result<Zeroizing<Vec<u8>>>
where
    R: TryCryptoRng + ?Sized,
{
    if msg.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x02 || PS || 0x00 || M
    let mut em = Zeroizing::new(vec![0u8; k]);
    em[1] = 2;
    non_zero_random_bytes(rng, &mut em[2..k - msg.len() - 1]).map_err(|_: R::Error| Error::Rng)?;
    em[k - msg.len() - 1] = 0;
    em[k - msg.len()..].copy_from_slice(msg);
    Ok(em)
}

/// Implicit Rejection Pseudo-Random Function (IRPRF) as specified in
/// draft-irtf-cfrg-rsa-guidance-04 Section 7.
///
/// This function generates deterministic pseudo-random output from a key and label.
/// It is used to generate synthetic messages for implicit rejection.
///
/// # Arguments
/// * `key` - The key material (typically KDK)
/// * `label` - A label to domain-separate different uses
/// * `output_length` - Number of bytes to generate
#[inline]
fn irprf(key: &[u8], label: &[u8], output_length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_length);
    let mut counter: u16 = 0;

    while output.len() < output_length {
        // message = counter || label || (output_length * 8 as u16)
        let mut message = Vec::with_capacity(2 + label.len() + 2);
        message.extend_from_slice(&counter.to_be_bytes());
        message.extend_from_slice(label);
        message.extend_from_slice(&((output_length * 8) as u16).to_be_bytes());

        // HMAC-SHA256(key, message)
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        Mac::update(&mut mac, &message);
        output.extend_from_slice(&Mac::finalize(mac).into_bytes());

        counter += 1;
    }

    output.truncate(output_length);
    output
}

/// Derives the Key Derivation Key (KDK) from the private exponent and ciphertext.
///
/// This implements the KDK derivation as specified in draft-irtf-cfrg-rsa-guidance-04.
/// The KDK is used to generate deterministic pseudo-random messages for implicit rejection.
///
/// # Arguments
/// * `private_exponent` - The RSA private exponent (d)
/// * `ciphertext` - The ciphertext being decrypted (must be exactly k bytes)
///
/// # Returns
/// A 32-byte KDK derived from HMAC-SHA256(SHA256(I2OSP(d, k)), ciphertext)
#[inline]
pub(crate) fn derive_kdk(private_exponent: &BoxedUint, ciphertext: &[u8]) -> [u8; 32] {
    // k = modulus size in bytes (ciphertext must be exactly k bytes per RFC 8017)
    let k = ciphertext.len();

    // Convert private exponent to bytes with I2OSP(d, k) - left-pad to k bytes
    // Wrap in Zeroizing to ensure sensitive key material is cleared from memory
    let d_raw = Zeroizing::new(private_exponent.to_be_bytes());
    let mut d_bytes = Zeroizing::new(vec![0u8; k]);
    // Left-pad: copy d_raw to the end of d_bytes
    let start = k.saturating_sub(d_raw.len());
    let copy_len = d_raw.len().min(k);
    d_bytes[start..start + copy_len].copy_from_slice(&d_raw[d_raw.len() - copy_len..]);

    // Hash the private exponent (DH = SHA256(D))
    let dh = Sha256::digest(&*d_bytes);

    // HMAC with ciphertext to create KDK
    let mut mac = HmacSha256::new_from_slice(&dh).expect("HMAC can take key of any size");
    Mac::update(&mut mac, ciphertext);

    Mac::finalize(mac).into_bytes().into()
}

/// Selects an alternative (synthetic) message length from pseudo-random candidates.
///
/// This function derives a message length in the valid range [0, max_message_length]
/// from pseudo-random input. The selection is performed in constant-time.
///
/// # Arguments
/// * `length_candidates` - 256 bytes of pseudo-random data from IRPRF
/// * `k` - The modulus size in bytes
///
/// # Returns
/// A message length in the range [0, k-11]
#[inline]
fn select_alternative_length(length_candidates: &[u8], k: usize) -> u32 {
    // Maximum message length for PKCS#1 v1.5 is k - 11
    let max_message_length = k.saturating_sub(11) as u32;

    // Use first 4 bytes as u32
    let mut candidate = u32::from_be_bytes([
        length_candidates[0],
        length_candidates[1],
        length_candidates[2],
        length_candidates[3],
    ]);

    // Modulo to ensure candidate is in valid range
    // This is acceptable as the distribution is close enough to uniform
    // for cryptographic purposes when max_message_length is not a power of 2
    if max_message_length > 0 {
        candidate %= max_message_length + 1;
    } else {
        candidate = 0;
    }

    candidate
}

/// Removes the encryption padding scheme from PKCS#1 v1.5 using implicit rejection.
///
/// This function implements the implicit rejection technique as specified in
/// draft-irtf-cfrg-rsa-guidance-04 to mitigate the Marvin attack (RUSTSEC-2023-0071).
///
/// Instead of returning an error when padding validation fails, this function returns
/// a deterministic pseudo-random message. This makes valid and invalid ciphertexts
/// indistinguishable in timing and memory access patterns, preventing padding oracle attacks.
///
/// # Arguments
/// * `em` - The encoded message after RSA decryption
/// * `k` - The modulus size in bytes
/// * `kdk` - The Key Derivation Key derived from private exponent and ciphertext
///
/// # Returns
/// Either the actual decrypted message (if padding is valid) or a synthetic pseudo-random
/// message (if padding is invalid). This function never returns an error based on padding
/// validity.
#[inline]
pub(crate) fn pkcs1v15_encrypt_unpad(em: Vec<u8>, k: usize, kdk: &[u8; 32]) -> Vec<u8> {
    let (valid, out, index) = match decrypt_inner(em, k) {
        Ok(result) => result,
        // If k < 11, decrypt_inner returns error - handle safely
        Err(_) => (0, vec![0; k], 0),
    };

    // Maximum possible message length for PKCS#1 v1.5: k - 11
    let max_message_length = k.saturating_sub(11);

    // Generate synthetic message and length using IRPRF
    let synthetic_full = irprf(kdk, b"message", k);
    let length_candidates = irprf(kdk, b"length", 256);
    let synthetic_length = select_alternative_length(&length_candidates, k) as usize;

    // Calculate actual message length
    let actual_length = (k as u32).saturating_sub(index) as usize;

    // Constant-time selection of length
    let valid_choice = Choice::from_u8_lsb(valid);
    let output_length = usize::ct_select(&synthetic_length, &actual_length, valid_choice);

    // SECURITY: Allocate 2*(k-11), not `output_length`. The extra half is
    // zeros so a memcpy of exactly `max_message_length` bytes from `start`
    // is in-bounds for every length, including 0. `truncate` then sets
    // `len` (the public API) without shrinking capacity, so drop always
    // frees the same allocation.
    //
    // Returning `output[start..].to_vec()` allocated exactly
    // `output_length` bytes. Rust's empty Vec skips malloc/`memcpy`/free,
    // which leaked empty vs non-empty plaintext (~20 ns on Marvin
    // `valid_0`). `len` is unchanged; `capacity` is not part of the API.
    let mut output = vec![0u8; max_message_length.saturating_mul(2)];

    // SECURITY: Always iterate over the full max_message_length to prevent
    // loop iteration count from leaking message length.
    //
    // Both `out` and `synthetic_full` have length k. We read right-aligned:
    // position i in the output maps to position (k - max_message_length + i)
    // in both source buffers, ranging from index 11 to k-1 — always in-bounds.
    //
    // The mixed bytes are right-aligned in the first half of `output`.
    // The actual message occupies the last `actual_length` positions, and
    // the synthetic message occupies the last `synthetic_length` positions.
    // Iterate the first half only -- `output` is 2 * max_message_length, and
    // the upper half stays zero as copy_within headroom. Bounds are public
    // constants, so the iteration count is still independent of the plaintext.
    for (i, out_byte) in output[..max_message_length].iter_mut().enumerate() {
        let src_index = k - max_message_length + i;
        let act_byte = out[src_index];
        let syn_byte = synthetic_full[src_index];
        *out_byte = u8::ct_select(&syn_byte, &act_byte, valid_choice);
    }

    // Compact the right-aligned message to index 0, then expose only
    // `output_length` bytes via `len`. Addresses and loop bounds are
    // public; only CMOV masks depend on `output_length`.
    ct_left_align(&mut output, max_message_length, output_length);
    output.truncate(output_length);
    output
}

/// Slide a right-aligned payload in `buf` (length `2 * max_message_length`)
/// to index 0.
///
/// `copy_within(start..)` used a secret source offset (`start = max -
/// output_length`), so the memmove address leaked plaintext length through
/// the cache. Every load/store index here is public: we scan the whole
/// buffer and CMOV the byte whose index equals `dest + start`.
#[inline]
fn ct_left_align(buf: &mut [u8], max_message_length: usize, output_length: usize) {
    debug_assert_eq!(buf.len(), max_message_length.saturating_mul(2));
    let start = max_message_length.saturating_sub(output_length);
    let mut dest = vec![0u8; max_message_length.saturating_mul(2)];
    for dest_i in 0..max_message_length {
        let want = dest_i.saturating_add(start) as u32;
        let mut acc = 0u8;
        for (src_j, &byte) in buf.iter().enumerate() {
            let eq = (src_j as u32).ct_eq(&want);
            acc = u8::ct_select(&acc, &byte, eq);
        }
        dest[dest_i] = acc;
    }
    buf.copy_from_slice(&dest);
}

/// Removes the PKCS1v15 padding It returns one or zero in valid that indicates whether the
/// plaintext was correctly structured. In either case, the plaintext is
/// returned in em so that it may be read independently of whether it was valid
/// in order to maintain constant memory access patterns. If the plaintext was
/// valid then index contains the index of the original message in em.
#[inline]
fn decrypt_inner(em: Vec<u8>, k: usize) -> Result<(u8, Vec<u8>, u32)> {
    if k < 11 {
        return Err(Error::Decryption);
    }

    let first_byte_is_zero = em[0].ct_eq(&0u8);
    let second_byte_is_two = em[1].ct_eq(&2u8);

    // The remainder of the plaintext must be a string of non-zero random
    // octets, followed by a 0, followed by the message.
    //   looking_for_index: 1 iff we are still looking for the zero.
    //   index: the offset of the first zero byte.
    let mut looking_for_index = Choice::TRUE;
    let mut index = 0u32;

    for (i, el) in em.iter().enumerate().skip(2) {
        let equals0 = el.ct_eq(&0u8);
        index.ct_assign(&(i as u32), looking_for_index & equals0);
        looking_for_index &= !equals0;
    }

    // The PS padding must be at least 8 bytes long, and it starts two
    // bytes into em. The 0x00 separator must be at index >= 10.
    // Uses ctutils::CtLt which compiles to branchless overflowing_sub.
    let valid_ps = !index.ct_lt(&10u32);
    let valid = first_byte_is_zero & second_byte_is_two & !looking_for_index & valid_ps;
    index = u32::ct_select(&0, &(index + 1), valid);

    Ok((valid.to_u8(), em, index))
}

#[inline]
pub(crate) fn pkcs1v15_sign_pad(prefix: &[u8], hashed: &[u8], k: usize) -> Result<Vec<u8>> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::MessageTooLong);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut em = vec![0xff; k];
    em[0] = 0;
    em[1] = 1;
    em[k - t_len - 1] = 0;
    em[k - t_len..k - hash_len].copy_from_slice(prefix);
    em[k - hash_len..k].copy_from_slice(hashed);

    Ok(em)
}

#[inline]
pub(crate) fn pkcs1v15_sign_unpad(prefix: &[u8], hashed: &[u8], em: &[u8], k: usize) -> Result<()> {
    let hash_len = hashed.len();
    let t_len = prefix.len() + hashed.len();
    if k < t_len + 11 {
        return Err(Error::Verification);
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let mut ok = em[0].ct_eq(&0u8);
    ok &= em[1].ct_eq(&1u8);
    ok &= em[k - hash_len..k].ct_eq(hashed);
    ok &= em[k - t_len..k - hash_len].ct_eq(prefix);
    ok &= em[k - t_len - 1].ct_eq(&0u8);

    for el in em.iter().skip(2).take(k - t_len - 3) {
        ok &= el.ct_eq(&0xff)
    }

    // TODO(tarcieri): avoid branching here by e.g. using a pseudorandom rejection symbol
    if !ok.to_bool() {
        return Err(Error::Verification);
    }

    Ok(())
}

/// prefix = 0x30 <oid_len + 8 + digest_len> 0x30 <oid_len + 4> 0x06 <oid_len> oid 0x05 0x00 0x04 <digest_len>
#[inline]
pub(crate) fn pkcs1v15_generate_prefix<D>() -> Vec<u8>
where
    D: Digest + AssociatedOid,
{
    let oid = D::OID.as_bytes();
    let oid_len = oid.len() as u8;
    let digest_len = <D as Digest>::output_size() as u8;
    let mut v = vec![
        0x30,
        oid_len + 8 + digest_len,
        0x30,
        oid_len + 4,
        0x6,
        oid_len,
    ];
    v.extend_from_slice(oid);
    v.extend_from_slice(&[0x05, 0x00, 0x04, digest_len]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_non_zero_bytes() {
        for _ in 0..10 {
            let mut rng = ChaCha8Rng::from_seed([42; 32]);
            let mut b = vec![0u8; 512];
            non_zero_random_bytes(&mut rng, &mut b).unwrap();
            for el in &b {
                assert_ne!(*el, 0u8);
            }
        }
    }

    #[test]
    fn test_encrypt_tiny_no_crash() {
        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let k = 8;
        let message = vec![1u8; 4];
        let res = pkcs1v15_encrypt_pad(&mut rng, &message, k);
        assert_eq!(res, Err(Error::MessageTooLong));
    }

    /// Right-aligned payload in a 2*max buffer must land at index 0 for every
    /// length, including 0 and max. The compact must not use a secret source
    /// offset (`copy_within(start..)`).
    #[test]
    fn test_ct_left_align_empty_mid_full() {
        let max = 4usize;

        // empty: start = max, source is the zeroed second half
        let mut buf = vec![0u8; max * 2];
        buf[..max].copy_from_slice(&[9, 8, 7, 6]);
        ct_left_align(&mut buf, max, 0);
        assert_eq!(&buf[..max], &[0, 0, 0, 0]);
        assert_eq!(buf.len(), max * 2);

        // mid: last 2 of the first half are the message
        let mut buf = vec![0u8; max * 2];
        buf[..max].copy_from_slice(&[1, 2, 3, 4]);
        ct_left_align(&mut buf, max, 2);
        assert_eq!(&buf[..max], &[3, 4, 0, 0]);

        // full: start = 0, first half is the message
        let mut buf = vec![0u8; max * 2];
        buf[..max].copy_from_slice(&[5, 6, 7, 8]);
        ct_left_align(&mut buf, max, max);
        assert_eq!(&buf[..max], &[5, 6, 7, 8]);
    }
}
