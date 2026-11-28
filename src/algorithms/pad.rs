//! Special handling for converting the BigUint to u8 vectors

use alloc::vec::Vec;
use crypto_bigint::BoxedUint;
use zeroize::Zeroizing;

use crate::errors::{Error, Result};

/// Writes the low `out.len()` bytes of the big endian `bytes` into `out`, left padding with
/// zeros when `bytes` is shorter.
///
/// Every length and offset used here depends only on `bytes.len()` and `out.len()`, never on
/// the value in `bytes`. Bytes that do not fit in `out` must all be zero; they are folded into
/// a single flag, so only the fact that the value does not fit is revealed.
#[inline]
fn copy_be_padded(bytes: &[u8], out: &mut [u8]) -> Result<()> {
    let padded_len = out.len();
    if bytes.len() >= padded_len {
        let (excess, low) = bytes.split_at(bytes.len() - padded_len);
        let nonzero = excess.iter().fold(0u8, |acc, b| acc | b);
        if nonzero != 0 {
            return Err(Error::InvalidPadLen);
        }
        out.copy_from_slice(low);
    } else {
        let (pad, low) = out.split_at_mut(padded_len - bytes.len());
        pad.fill(0);
        low.copy_from_slice(bytes);
    }
    Ok(())
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
///
/// The precision of a `BoxedUint` is rounded up to whole limbs, so its encoding may be longer
/// than `padded_len`; the extra leading bytes must be zero.
#[inline]
pub(crate) fn uint_to_be_pad(input: BoxedUint, padded_len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; padded_len];
    copy_be_padded(&input.to_be_bytes(), &mut out)?;
    Ok(out)
}

/// Converts input to the new vector of the given length, using BE and with 0s left padded.
/// The returned buffer and the intermediate copies are zeroed when dropped.
///
/// The value may be secret (a decrypted message), so the number of bytes copied does not
/// depend on how many leading zero bytes it has.
#[inline]
pub(crate) fn uint_to_zeroizing_be_pad(
    input: BoxedUint,
    padded_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let m = Zeroizing::new(input);
    let m = Zeroizing::new(m.to_be_bytes());

    let mut out = Zeroizing::new(vec![0u8; padded_len]);
    copy_be_padded(&m, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_be_padded() {
        // shorter input is left padded
        let mut out = [0xffu8; 4];
        copy_be_padded(&[1, 2, 3], &mut out).unwrap();
        assert_eq!(out, [0, 1, 2, 3]);

        // equal length
        let mut out = [0xffu8; 3];
        copy_be_padded(&[0, 0, 3], &mut out).unwrap();
        assert_eq!(out, [0, 0, 3]);

        // longer input with zero excess keeps the low bytes
        let mut out = [0xffu8; 2];
        copy_be_padded(&[0, 0, 7, 8], &mut out).unwrap();
        assert_eq!(out, [7, 8]);

        // longer input with non-zero excess does not fit
        let mut out = [0u8; 2];
        assert_eq!(
            copy_be_padded(&[0, 1, 7, 8], &mut out),
            Err(Error::InvalidPadLen)
        );
    }

    #[test]
    fn test_uint_to_be_pad_keeps_leading_zeros() {
        // 64 bits of precision, value with five leading zero bytes
        let value = BoxedUint::from(0x00aa_bbccu64);
        assert_eq!(
            uint_to_be_pad(value.clone(), 8).unwrap(),
            [0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            uint_to_be_pad(value.clone(), 3).unwrap(),
            [0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            uint_to_be_pad(value.clone(), 10).unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(uint_to_be_pad(value.clone(), 2), Err(Error::InvalidPadLen));

        assert_eq!(
            &**uint_to_zeroizing_be_pad(value.clone(), 5).unwrap(),
            &[0, 0, 0xaa, 0xbb, 0xcc]
        );
        assert!(uint_to_zeroizing_be_pad(value, 2).is_err());
    }
}
