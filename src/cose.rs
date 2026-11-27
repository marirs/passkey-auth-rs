//! COSE_Key (RFC 9052 / RFC 9053) parsing for the credential algorithms
//! this crate verifies.
//!
//! Key layout (CBOR map, integer labels):
//! ```text
//!   1 (kty):  OKP=1, EC2=2, RSA=3, AKP=7
//!   3 (alg):  ES256=-7, EdDSA=-8, RS256=-257, ML-DSA-44/65/87=-48/-49/-50
//!   EC2 / OKP (RFC 9053):  -1 crv (P-256=1, Ed25519=6), -2 x, -3 y (EC2 only)
//!   RSA (RFC 8230):        -1 n (modulus), -2 e (public exponent)
//!   AKP (RFC 9964):        -1 pub (FIPS 204 public key encoding)
//! ```
//!
//! Parsing builds the verifying key, so a key that cannot verify (a point
//! off the curve, an RSA modulus outside 2048-4096 bits, a truncated
//! ML-DSA key) is refused at registration instead of at the first sign-in.

use ciborium::value::Value as CborValue;
use rsa::BoxedUint;
use sha2::Sha256;

use crate::error::{Error, Result};

pub(crate) const ALG_ES256: i64 = -7;
pub(crate) const ALG_EDDSA: i64 = -8;
pub(crate) const ALG_RS256: i64 = -257;
#[cfg(feature = "pqc")]
pub(crate) const ALG_ML_DSA_44: i64 = -48;
#[cfg(feature = "pqc")]
pub(crate) const ALG_ML_DSA_65: i64 = -49;
#[cfg(feature = "pqc")]
pub(crate) const ALG_ML_DSA_87: i64 = -50;

const KTY: i64 = 1;
const ALG: i64 = 3;
/// `crv` for EC2/OKP, `n` for RSA, `pub` for AKP.
const PARAM_1: i64 = -1;
/// `x` for EC2/OKP, `e` for RSA.
const PARAM_2: i64 = -2;
/// `y` for EC2.
const PARAM_3: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;
#[cfg(feature = "pqc")]
const KTY_AKP: i64 = 7;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// Accepted RSA modulus sizes in bits. Below 2048 bits RSA is too weak;
/// above 4096 bits verification cost grows without a security need.
pub(crate) const RSA_MODULUS_BITS: std::ops::RangeInclusive<usize> = 2048..=4096;
/// Largest accepted RSA public exponent. Authenticators use 65537; the
/// bound keeps a hostile key from making verification slow.
pub(crate) const RSA_MAX_EXPONENT: u64 = u32::MAX as u64;

/// RS256 verifying key: RSASSA-PKCS1-v1_5 with SHA-256.
pub(crate) type RsaKey = rsa::pkcs1v15::VerifyingKey<Sha256>;

/// A credential public key, ready to verify signatures.
#[derive(Debug, Clone)]
pub(crate) enum CoseKey {
    /// ECDSA on the NIST P-256 curve, hashed with SHA-256.
    Es256(p256::ecdsa::VerifyingKey),
    /// Ed25519 with EdDSA.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// RSASSA-PKCS1-v1_5 with SHA-256, 2048 to 4096 bit modulus.
    Rs256(Box<RsaKey>),
    /// ML-DSA (FIPS 204), pure mode with an empty context string.
    #[cfg(feature = "pqc")]
    MlDsa(crate::crypto::MlDsaKey),
}

impl CoseKey {
    /// Parses a COSE_Key CBOR blob (as stored by the caller or as carried
    /// in `attestedCredentialData.credentialPublicKey`).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let value: CborValue =
            ciborium::de::from_reader(bytes).map_err(|e| Error::Cbor(format!("cose: {e}")))?;
        let CborValue::Map(entries) = value else {
            return Err(Error::Cbor("cose: top-level not a map".into()));
        };

        // RFC 9052 §3: a map that repeats a label MUST NOT be processed.
        for (i, (label, _)) in entries.iter().enumerate() {
            if entries[..i].iter().any(|(earlier, _)| earlier == label) {
                return Err(Error::Cbor("cose: duplicate map label".into()));
            }
        }
        let field = |label: i64| {
            entries
                .iter()
                .find(|(k, _)| int_of(k) == Some(label))
                .map(|(_, v)| v)
        };

        let kty = field(KTY)
            .ok_or_else(|| Error::Cbor("cose: missing kty".into()))
            .and_then(|v| {
                int_of(v).ok_or_else(|| Error::Cbor("cose: kty not an integer".into()))
            })?;
        let alg = field(ALG)
            .ok_or_else(|| Error::Cbor("cose: missing alg".into()))
            .and_then(|v| {
                int_of(v).ok_or_else(|| Error::Cbor("cose: alg not an integer".into()))
            })?;
        let int_param = |label| field(label).and_then(int_of);
        let bytes_param = |label, name: &str| {
            field(label)
                .and_then(bytes_of)
                .ok_or_else(|| Error::Cbor(format!("cose: missing {name}")))
        };

        match (kty, alg) {
            (KTY_EC2, ALG_ES256) => {
                if int_param(PARAM_1) != Some(CRV_P256) {
                    return Err(Error::Cbor("cose: ES256 expects crv=P-256".into()));
                }
                let (x, y) = (bytes_param(PARAM_2, "x")?, bytes_param(PARAM_3, "y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(Error::Cbor("cose: P-256 coords must be 32 bytes".into()));
                }
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(x);
                sec1[33..].copy_from_slice(y);
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map(Self::Es256)
                    .map_err(|_| Error::Cbor("cose: P-256 point not on the curve".into()))
            }
            (KTY_OKP, ALG_EDDSA) => {
                if int_param(PARAM_1) != Some(CRV_ED25519) {
                    return Err(Error::Cbor("cose: EdDSA expects crv=Ed25519".into()));
                }
                let key: &[u8; 32] = bytes_param(PARAM_2, "x")?
                    .try_into()
                    .map_err(|_| Error::Cbor("cose: Ed25519 key must be 32 bytes".into()))?;
                ed25519_dalek::VerifyingKey::from_bytes(key)
                    .map(Self::Ed25519)
                    .map_err(|_| Error::Cbor("cose: invalid Ed25519 public key".into()))
            }
            (KTY_RSA, ALG_RS256) => rsa_key(bytes_param(PARAM_1, "n")?, bytes_param(PARAM_2, "e")?)
                .map(|key| Self::Rs256(Box::new(key))),
            #[cfg(feature = "pqc")]
            (KTY_AKP, ALG_ML_DSA_44 | ALG_ML_DSA_65 | ALG_ML_DSA_87) => {
                crate::crypto::MlDsaKey::from_cose(alg, bytes_param(PARAM_1, "pub")?)
                    .map(Self::MlDsa)
            }
            _ => Err(Error::UnsupportedAlg(alg)),
        }
    }

    pub(crate) fn alg(&self) -> i64 {
        match self {
            Self::Es256(_) => ALG_ES256,
            Self::Ed25519(_) => ALG_EDDSA,
            Self::Rs256(_) => ALG_RS256,
            #[cfg(feature = "pqc")]
            Self::MlDsa(key) => key.alg(),
        }
    }
}

/// Builds an RS256 verifying key from the big-endian modulus and public
/// exponent, refusing moduli outside [`RSA_MODULUS_BITS`] and exponents
/// that are even, below 3 or above [`RSA_MAX_EXPONENT`].
///
/// Only public-key operations happen here and in verification.
/// RUSTSEC-2023-0071 (the Marvin timing attack on `rsa`) concerns
/// private-key decryption and signing, which this crate never performs.
pub(crate) fn rsa_key(n: &[u8], e: &[u8]) -> Result<RsaKey> {
    let n = strip_leading_zeros(n);
    let e = strip_leading_zeros(e);
    if n.len() * 8 > *RSA_MODULUS_BITS.end() + 7 {
        return Err(Error::Cbor("rsa: modulus larger than 4096 bits".into()));
    }
    let exponent = match e.len() {
        1..=8 => e.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)),
        _ => return Err(Error::Cbor("rsa: public exponent out of range".into())),
    };
    if !(3..=RSA_MAX_EXPONENT).contains(&exponent) || exponent % 2 == 0 {
        return Err(Error::Cbor("rsa: public exponent out of range".into()));
    }
    let key = rsa::PublicKey::new_with_size_limits(
        BoxedUint::from_be_slice_vartime(n),
        BoxedUint::from(exponent),
        RSA_MODULUS_BITS,
    )
    .map_err(|_| Error::Cbor("rsa: modulus must be an odd 2048-4096 bit integer".into()))?;
    Ok(RsaKey::new(key))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

/// Integer value of a CBOR item, or `None` when it is not an integer or
/// does not fit in `i64` (no truncation: 2^64 - 7 must not read as -7).
fn int_of(v: &CborValue) -> Option<i64> {
    match v {
        CborValue::Integer(i) => i64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

fn bytes_of(v: &CborValue) -> Option<&[u8]> {
    match v {
        CborValue::Bytes(b) => Some(b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(entries: Vec<(CborValue, CborValue)>) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&CborValue::Map(entries), &mut out).unwrap();
        out
    }

    fn int(n: i64) -> CborValue {
        CborValue::Integer(n.into())
    }

    fn p256_entries() -> Vec<(CborValue, CborValue)> {
        let sk = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let point = sk.verifying_key().to_sec1_point(false);
        vec![
            (int(1), int(2)),
            (int(3), int(-7)),
            (int(-1), int(1)),
            (int(-2), CborValue::Bytes(point.x().unwrap().to_vec())),
            (int(-3), CborValue::Bytes(point.y().unwrap().to_vec())),
        ]
    }

    #[test]
    fn parses_es256_key() {
        let key = CoseKey::parse(&encode(p256_entries())).unwrap();
        assert_eq!(key.alg(), ALG_ES256);
    }

    #[test]
    fn refuses_p256_point_off_the_curve() {
        let mut entries = p256_entries();
        entries[4].1 = CborValue::Bytes(vec![0xBB; 32]);
        assert!(matches!(
            CoseKey::parse(&encode(entries)),
            Err(Error::Cbor(_))
        ));
    }

    #[test]
    fn refuses_duplicate_labels() {
        let mut entries = p256_entries();
        entries.push((int(3), int(-7)));
        let err = CoseKey::parse(&encode(entries)).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn huge_alg_value_is_not_truncated_to_es256() {
        // 2^64 - 7 as an unsigned CBOR integer truncates to -7 under `as i64`.
        let mut entries = p256_entries();
        entries[1].1 = CborValue::Integer(ciborium::value::Integer::from(u64::MAX - 6));
        assert!(CoseKey::parse(&encode(entries)).is_err());
    }

    #[test]
    fn huge_label_is_not_truncated_to_crv() {
        // Label 2^64 - 1 truncates to -1 (crv) under `as i64`.
        let mut entries = p256_entries();
        entries[2].0 = CborValue::Integer(ciborium::value::Integer::from(u64::MAX));
        assert!(CoseKey::parse(&encode(entries)).is_err());
    }

    #[test]
    fn rsa_exponent_bounds() {
        let n = [0xC5u8; 256]; // odd top byte, 2048 bits
        for e in [&[1u8][..], &[2], &[0x01, 0x00, 0x00], &[1, 0, 0, 0, 1]] {
            assert!(rsa_key(&n, e).is_err(), "exponent {e:02x?} must be refused");
        }
        assert!(rsa_key(&n, &[0x01, 0x00, 0x01]).is_ok());
        assert!(
            rsa_key(&n, &[0x00, 0x01, 0x00, 0x01]).is_ok(),
            "leading zeros allowed"
        );
    }

    #[test]
    fn rsa_modulus_bounds() {
        let e = [0x01, 0x00, 0x01];
        let n = |bytes: usize| vec![0xC5u8; bytes];
        assert!(rsa_key(&n(128), &e).is_err(), "1024 bits");
        assert!(rsa_key(&n(255), &e).is_err(), "2040 bits");
        assert!(rsa_key(&n(256), &e).is_ok(), "2048 bits");
        assert!(rsa_key(&n(512), &e).is_ok(), "4096 bits");
        assert!(rsa_key(&n(513), &e).is_err(), "4104 bits");
        assert!(rsa_key(&[0xC4; 256], &e).is_err(), "even modulus");
    }
}
