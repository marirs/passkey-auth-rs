//! Signature verification, the only cryptographic operation the server
//! performs in a WebAuthn ceremony.
//!
//! Algorithms (matching [`CoseKey`]):
//!   * ES256: ECDSA P-256 with SHA-256, signature DER-encoded (not raw r||s)
//!   * EdDSA: Ed25519, 64-byte signature
//!   * RS256: RSASSA-PKCS1-v1_5 with SHA-256, signature as long as the modulus
//!   * ML-DSA-44/65/87 (`pqc` feature): FIPS 204 pure mode, empty context
//!
//! WebAuthn signs `authenticatorData || SHA-256(clientDataJSON)`.

use ed25519_dalek::Verifier as _;
use p256::ecdsa::Signature as EsSig;

use crate::cose::CoseKey;
use crate::error::{Error, Result};

/// Verifies `sig` over `msg` with `key`. Every failure (malformed
/// signature, wrong key) is [`Error::BadSignature`], so the error does not
/// tell a client which check failed.
pub(crate) fn verify(key: &CoseKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    let ok = match key {
        // Signature malleability (high-S): ECDSA admits (r, s) and
        // (r, n - s) for the same message. WebAuthn does not require
        // rejecting the high-S form, and webauthn-rs, WebAuthn4J and
        // Yubico java-webauthn-server accept both. The single-use
        // challenge makes the malleable variant useless for replay, so
        // either form is accepted here.
        CoseKey::Es256(vk) => EsSig::from_der(sig).is_ok_and(|s| vk.verify(msg, &s).is_ok()),
        CoseKey::Ed25519(vk) => {
            ed25519_dalek::Signature::from_slice(sig).is_ok_and(|s| vk.verify(msg, &s).is_ok())
        }
        CoseKey::Rs256(vk) => {
            use rsa::signature::Verifier as _;
            rsa::pkcs1v15::Signature::try_from(sig).is_ok_and(|s| vk.verify(msg, &s).is_ok())
        }
        #[cfg(feature = "pqc")]
        CoseKey::MlDsa(vk) => vk.verify(msg, b"", sig),
    };
    if ok { Ok(()) } else { Err(Error::BadSignature) }
}

/// ML-DSA verifying key for one of the three FIPS 204 parameter sets.
/// Boxed because the decoded keys are 1-2.5 KiB.
#[cfg(feature = "pqc")]
#[derive(Debug, Clone)]
pub(crate) enum MlDsaKey {
    MlDsa44(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>),
    MlDsa65(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>),
    MlDsa87(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>),
}

#[cfg(feature = "pqc")]
impl MlDsaKey {
    /// Decodes the AKP `pub` parameter for COSE algorithm `alg`. The key
    /// must be exactly the FIPS 204 encoded size for the parameter set
    /// (1312, 1952 or 2592 bytes).
    pub(crate) fn from_cose(alg: i64, public_key: &[u8]) -> Result<Self> {
        use crate::cose::{ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87};
        fn decode<P: ml_dsa::MlDsaParams>(bytes: &[u8]) -> Result<Box<ml_dsa::VerifyingKey<P>>> {
            let encoded = ml_dsa::EncodedVerifyingKey::<P>::try_from(bytes)
                .map_err(|_| Error::Cbor("cose: ML-DSA public key has the wrong length".into()))?;
            Ok(Box::new(ml_dsa::VerifyingKey::decode(&encoded)))
        }
        match alg {
            ALG_ML_DSA_44 => decode(public_key).map(Self::MlDsa44),
            ALG_ML_DSA_65 => decode(public_key).map(Self::MlDsa65),
            ALG_ML_DSA_87 => decode(public_key).map(Self::MlDsa87),
            other => Err(Error::UnsupportedAlg(other)),
        }
    }

    pub(crate) fn alg(&self) -> i64 {
        use crate::cose::{ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87};
        match self {
            Self::MlDsa44(_) => ALG_ML_DSA_44,
            Self::MlDsa65(_) => ALG_ML_DSA_65,
            Self::MlDsa87(_) => ALG_ML_DSA_87,
        }
    }

    /// Verifies a pure ML-DSA signature with context string `ctx`. COSE
    /// (RFC 9964) fixes the context to the empty string; the test vectors
    /// use others.
    pub(crate) fn verify(&self, msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        fn check<P: ml_dsa::MlDsaParams>(
            vk: &ml_dsa::VerifyingKey<P>,
            msg: &[u8],
            ctx: &[u8],
            sig: &[u8],
        ) -> bool {
            ml_dsa::Signature::<P>::try_from(sig)
                .is_ok_and(|s| vk.verify_with_context(msg, ctx, &s))
        }
        match self {
            Self::MlDsa44(vk) => check(vk, msg, ctx, sig),
            Self::MlDsa65(vk) => check(vk, msg, ctx, sig),
            Self::MlDsa87(vk) => check(vk, msg, ctx, sig),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use p256::ecdsa::SigningKey as EsSigningKey;

    const MSG: &[u8] = b"hello passkey world";

    #[test]
    fn ed25519_round_trip() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let key = CoseKey::Ed25519(sk.verifying_key());
        let sig = sk.sign(MSG).to_bytes();
        verify(&key, MSG, &sig).expect("good sig must verify");

        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(verify(&key, MSG, &bad).is_err());
        assert!(verify(&key, MSG, &sig[..63]).is_err(), "short signature");
    }

    #[test]
    fn es256_round_trip() {
        use p256::ecdsa::signature::Signer as _;
        let sk = EsSigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let key = CoseKey::Es256(*sk.verifying_key());
        let sig: EsSig = sk.sign(MSG);
        let der = sig.to_der().to_bytes().to_vec();
        verify(&key, MSG, &der).expect("good sig must verify");

        let mut bad = der.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(verify(&key, MSG, &bad).is_err());
        assert!(
            verify(&key, MSG, &sig.to_bytes()).is_err(),
            "raw r||s is not DER"
        );
    }

    /// C2SP Wycheproof RSASSA-PKCS1-v1_5 SHA-256 vectors (2048-bit keys)
    /// through the same key bounds and verify call as a COSE RS256 key.
    #[test]
    fn wycheproof_rs256() {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/wycheproof-rsa-2048-sha256.json"
        ))
        .unwrap();
        let mut checked = 0;
        for group in doc["testGroups"].as_array().unwrap() {
            let n = hex::decode(group["n"].as_str().unwrap()).unwrap();
            let e = hex::decode(group["e"].as_str().unwrap()).unwrap();
            let key = CoseKey::Rs256(Box::new(crate::cose::rsa_key(&n, &e).unwrap()));
            for case in group["tests"].as_array().unwrap() {
                let msg = hex::decode(case["msg"].as_str().unwrap()).unwrap();
                let sig = hex::decode(case["sig"].as_str().unwrap()).unwrap();
                let verified = verify(&key, &msg, &sig).is_ok();
                match case["result"].as_str().unwrap() {
                    "valid" => assert!(verified, "tcId {} must verify", case["tcId"]),
                    "invalid" => assert!(!verified, "tcId {} must not verify", case["tcId"]),
                    _ => {} // "acceptable": either outcome is allowed
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 259);
    }

    /// NIST ACVP ML-DSA sigVer vectors (FIPS 204, external interface, pure
    /// mode) for ML-DSA-44, ML-DSA-65 and ML-DSA-87.
    #[cfg(feature = "pqc")]
    #[test]
    fn acvp_ml_dsa_sigver() {
        use crate::cose::{ALG_ML_DSA_44, ALG_ML_DSA_65, ALG_ML_DSA_87};
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/ml-dsa-acvp-sigver.json"))
                .unwrap();
        let cases = doc["tests"].as_array().unwrap();
        for case in cases {
            let field = |name: &str| hex::decode(case[name].as_str().unwrap()).unwrap();
            let alg = match case["parameterSet"].as_str().unwrap() {
                "ML-DSA-44" => ALG_ML_DSA_44,
                "ML-DSA-65" => ALG_ML_DSA_65,
                "ML-DSA-87" => ALG_ML_DSA_87,
                other => panic!("unknown parameter set {other}"),
            };
            let key = MlDsaKey::from_cose(alg, &field("pk")).unwrap();
            let verified = key.verify(&field("message"), &field("context"), &field("signature"));
            assert_eq!(
                verified,
                case["testPassed"].as_bool().unwrap(),
                "tcId {}",
                case["tcId"]
            );
            // The COSE path always uses the empty context.
            if case["context"].as_str().unwrap().is_empty() {
                let result = verify(&CoseKey::MlDsa(key), &field("message"), &field("signature"));
                assert_eq!(result.is_ok(), verified, "tcId {} via verify", case["tcId"]);
            }
        }
        assert_eq!(cases.len(), 9);
    }
}
