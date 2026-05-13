//! Signature verification - the only crypto operation the server
//! performs during the WebAuthn auth ceremony.
//!
//! Algorithms supported (matching `cose::CoseKey`):
//!   * ES256 (P-256 ECDSA over SHA-256), the universal default
//!   * EdDSA (Ed25519), used by some authenticators (e.g. Yubikey 5+)
//!
//! WebAuthn signs `authenticatorData || SHA-256(clientDataJSON)`. The
//! ES256 signature on the wire is **DER-encoded**, not raw r||s - be
//! careful here.

use ed25519_dalek::{Signature as EdSig, Verifier as _, VerifyingKey as EdKey};
use p256::ecdsa::{Signature as EsSig, VerifyingKey as EsKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};

use crate::cose::CoseKey;
use crate::error::{Error, Result};

/// Verify `sig` over `msg` using the COSE public key. Returns `Ok(())`
/// on a valid signature; any failure path (wrong key, malformed sig,
/// algorithm mismatch) collapses to [`Error::BadSignature`] so we
/// don't leak which check failed to the wire.
pub(crate) fn verify(key: &CoseKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    match key {
        CoseKey::Es256 { x, y } => verify_es256(x, y, msg, sig),
        CoseKey::Ed25519 { key } => verify_ed25519(key, msg, sig),
    }
}

fn verify_es256(x: &[u8; 32], y: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    // SEC1 uncompressed point: 0x04 || X || Y.
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..65].copy_from_slice(y);
    let point = EncodedPoint::from_bytes(sec1).map_err(|_| Error::BadSignature)?;
    let pk = PublicKey::from_encoded_point(&point);
    let pk = Option::<PublicKey>::from(pk).ok_or(Error::BadSignature)?;
    let vk = EsKey::from(&pk);

    // WebAuthn ES256 signatures are DER-encoded ECDSA. p256 has a
    // direct `from_der` parser.
    let parsed = EsSig::from_der(sig).map_err(|_| Error::BadSignature)?;

    // Reject high-S signatures (signature malleability defence; see
    // RFC 6979 §6.4 and WebAuthn §7.2 step 17). `p256::ecdsa` does
    // NOT enforce low-S in `verify` itself, so we must check first.
    // `normalize_s` returns Some(low_s_form) ONLY when the input was
    // high-S; treat that as a bad signature outright rather than
    // silently accepting the malleable variant.
    if parsed.normalize_s().is_some() {
        return Err(Error::BadSignature);
    }

    vk.verify(msg, &parsed).map_err(|_| Error::BadSignature)
}

fn verify_ed25519(key: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = EdKey::from_bytes(key).map_err(|_| Error::BadSignature)?;
    if sig.len() != 64 {
        return Err(Error::BadSignature);
    }
    let mut sb = [0u8; 64];
    sb.copy_from_slice(sig);
    let parsed = EdSig::from_bytes(&sb);
    vk.verify(msg, &parsed).map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::{SigningKey as EsSigningKey, signature::Signer as _};
    use rand::RngCore;

    #[test]
    fn ed25519_round_trip() {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk_bytes = sk.verifying_key().to_bytes();
        let msg = b"hello passkey world";
        let sig: EdSig = sk.sign(msg);
        let key = CoseKey::Ed25519 { key: vk_bytes };
        verify(&key, msg, &sig.to_bytes()).expect("good sig must verify");

        // Tamper → rejected.
        let mut bad = sig.to_bytes();
        bad[0] ^= 0x01;
        assert!(verify(&key, msg, &bad).is_err());
    }

    #[test]
    fn es256_round_trip() {
        let sk = EsSigningKey::random(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let pt = vk.to_encoded_point(false);
        let xs = pt.x().expect("x coord");
        let ys = pt.y().expect("y coord");
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(xs.as_slice());
        y.copy_from_slice(ys.as_slice());

        let msg = b"hello passkey world";
        let sig: EsSig = sk.sign(msg);
        let der = sig.to_der().to_bytes().to_vec();

        let key = CoseKey::Es256 { x, y };
        verify(&key, msg, &der).expect("good sig must verify");

        // Tamper → rejected.
        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(verify(&key, msg, &bad).is_err());
    }

    /// Regression test for ECDSA signature malleability. For every
    /// valid (r, s), the value (r, n - s) is ALSO a valid signature
    /// for the same message and key under standard ECDSA verification.
    /// The crate MUST reject the high-S form.
    #[test]
    fn es256_high_s_rejected() {
        // Loop a few times because `EsSigningKey::random` could (very
        // rarely) hand us a signature that's already at the boundary;
        // most iterations produce a clearly-low-S signature whose
        // negation is clearly high-S.
        for _ in 0..16 {
            let sk = EsSigningKey::random(&mut rand::thread_rng());
            let vk = sk.verifying_key();
            let pt = vk.to_encoded_point(false);
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(pt.x().unwrap().as_slice());
            y.copy_from_slice(pt.y().unwrap().as_slice());
            let key = CoseKey::Es256 { x, y };

            let msg = b"malleability check";
            let sig: EsSig = sk.sign(msg);
            // `p256::ecdsa::Signature::sign` already returns low-S
            // form, so its `normalize_s` will be None. Flip to high-S
            // by negating s mod n.
            let high_s = match negate_s(&sig) {
                Some(h) => h,
                None => continue,
            };

            let der_high = high_s.to_der().to_bytes().to_vec();

            // Sanity: the unsafe variant DOES verify against the raw
            // p256 API (proves the malleability really exists).
            assert!(
                vk.verify(msg, &high_s).is_ok(),
                "high-S sig must be cryptographically valid",
            );
            // But our `verify` wrapper MUST reject it.
            assert!(
                verify(&key, msg, &der_high).is_err(),
                "high-S sig must be rejected by passkey-auth",
            );
        }
    }

    /// Helper: given a signature with low-S, return the high-S twin
    /// (r, n - s). Returns None if s is already at the half-order
    /// boundary or if the parse fails.
    fn negate_s(sig: &EsSig) -> Option<EsSig> {
        use p256::FieldBytes;
        use p256::elliptic_curve::{Curve, ScalarPrimitive};
        type Scalar = p256::Scalar;

        let (r, s) = sig.split_scalars();
        // Reconstruct s as a Scalar, negate (n - s), reassemble.
        let s_scalar: Scalar = *s.as_ref();
        let neg_s = -s_scalar;
        let neg_s_bytes: FieldBytes = neg_s.into();
        let neg_s_prim = ScalarPrimitive::<p256::NistP256>::from_bytes(&neg_s_bytes).into_option()?;
        let _ = p256::NistP256::ORDER; // silence unused-import in some toolchains
        let r_bytes: FieldBytes = (*r.as_ref()).into();
        EsSig::from_scalars(r_bytes, neg_s_bytes).ok()
    }
}
