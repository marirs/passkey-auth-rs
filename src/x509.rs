//! Minimal X.509 inspection for attestation certificates.
//!
//! The `packed` and `fido-u2f` attestation formats need three things from
//! the leaf certificate in `x5c`:
//!
//! 1. **The subject public key**, to verify the attestation `sig`. P-256
//!    ECDSA keys (ES256) and 2048-4096 bit RSA keys (RS256) are read.
//! 2. **The FIDO AAGUID extension** (OID `1.3.6.1.4.1.45724.1.1.4`) when
//!    present. WebAuthn-3 §8.2 requires it to match `authData`'s AAGUID.
//! 3. **The `packed` certificate requirements** of WebAuthn-3 §8.2.1:
//!    version 3; a subject with C, O, CN and OU set to
//!    "Authenticator Attestation"; Basic Constraints with CA false; and a
//!    non-critical AAGUID extension.
//!
//! This module does not validate the chain against a root store (no FIDO
//! MDS) and does not check expiry: attestation certificates have long
//! validity and rotate per authenticator batch.

use const_oid::ObjectIdentifier;
use const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS;
use const_oid::db::rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::BasicConstraints;

use crate::cose::{self, CoseKey};
use crate::error::{Error, Result};

/// FIDO Alliance AAGUID extension OID. The extension value is an OCTET
/// STRING wrapping another OCTET STRING of 16 bytes.
const OID_FIDO_AAGUID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.45724.1.1.4");

/// The OU WebAuthn-3 §8.2.1 requires in a `packed` attestation certificate.
const PACKED_SUBJECT_OU: &str = "Authenticator Attestation";

/// What the attestation formats read from a leaf certificate.
#[derive(Debug)]
pub(crate) struct AttestationCert {
    /// Subject public key: [`CoseKey::Es256`] or [`CoseKey::Rs256`].
    pub key: CoseKey,
    /// AAGUID from the certificate extension, if present.
    pub aaguid: Option<[u8; 16]>,
    /// The first WebAuthn-3 §8.2.1 requirement the certificate breaks, if
    /// any. Only the `packed` format applies these requirements.
    pub packed_violation: Option<&'static str>,
}

impl AttestationCert {
    /// Parses one DER certificate (an `x5c` element). Refuses keys other
    /// than P-256 ECDSA and 2048-4096 bit RSA, and a malformed AAGUID
    /// extension.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self> {
        // x509-cert decodes into owned structures. Attestation with x5c is
        // rare (browsers send `none` when the RP asks for it), so this cold
        // path keeps the simple API.
        let cert =
            Certificate::from_der(der).map_err(|e| Error::Cbor(format!("x509 parse: {e}")))?;
        let tbs = cert.tbs_certificate();
        let spki = tbs.subject_public_key_info();
        let key_bits = spki.subject_public_key.as_bytes().ok_or_else(|| {
            Error::Cbor("attestation cert: pubkey bit-string has unused bits".into())
        })?;

        let key = match spki.algorithm.oid {
            ID_EC_PUBLIC_KEY => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.decode_as().ok());
                if curve != Some(SECP_256_R_1) {
                    return Err(Error::Cbor("attestation cert: EC key is not P-256".into()));
                }
                if key_bits.len() != 65 || key_bits[0] != 0x04 {
                    return Err(Error::Cbor(
                        "attestation cert: pubkey not SEC1-uncompressed P-256".into(),
                    ));
                }
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                    .map(CoseKey::Es256)
                    .map_err(|_| {
                        Error::Cbor("attestation cert: P-256 point not on the curve".into())
                    })?
            }
            RSA_ENCRYPTION => {
                let rsa = rsa::pkcs1::RsaPublicKey::<rsa::pkcs1::UintRef<'_>>::from_der(key_bits)
                    .map_err(|_| {
                    Error::Cbor("attestation cert: malformed RSA public key".into())
                })?;
                let key = cose::rsa_key(rsa.modulus.as_bytes(), rsa.public_exponent.as_bytes())?;
                CoseKey::Rs256(Box::new(key))
            }
            other => {
                return Err(Error::Cbor(format!(
                    "attestation cert: unsupported public key (alg OID {other})"
                )));
            }
        };

        // Presence of the AAGUID extension is optional, but a malformed one
        // is an error, not "absent": otherwise a garbled inner OCTET STRING
        // would skip the cert-AAGUID == authData-AAGUID check.
        let extensions = tbs.extensions().map(|e| e.as_slice()).unwrap_or_default();
        let aaguid_ext = extensions.iter().find(|e| e.extn_id == OID_FIDO_AAGUID);
        let aaguid = aaguid_ext
            .map(|ext| parse_aaguid_octet_string(ext.extn_value.as_bytes()))
            .transpose()?;

        let basic_constraints = extensions
            .iter()
            .find(|e| e.extn_id == ID_CE_BASIC_CONSTRAINTS)
            .map(|ext| BasicConstraints::from_der(ext.extn_value.as_bytes()));
        let subject = tbs.subject();
        let ou_ok =
            matches!(subject.organization_unit(), Ok(Some(ou)) if ou.value() == PACKED_SUBJECT_OU);

        let packed_violation = if tbs.version() != Version::V3 {
            Some("certificate is not version 3")
        } else if !has(subject.country()) || !has(subject.organization()) {
            Some("subject lacks C or O")
        } else if !has(subject.common_name()) {
            Some("subject lacks CN")
        } else if !ou_ok {
            Some("subject OU is not \"Authenticator Attestation\"")
        } else if matches!(
            basic_constraints,
            Some(Err(_)) | Some(Ok(BasicConstraints { ca: true, .. }))
        ) {
            Some("Basic Constraints CA is not false")
        } else if aaguid_ext.is_some_and(|ext| ext.critical) {
            Some("AAGUID extension is marked critical")
        } else {
            None
        };

        Ok(Self {
            key,
            aaguid,
            packed_violation,
        })
    }
}

/// The AAGUID extension value is an OCTET STRING containing another
/// OCTET STRING of 16 bytes (per the FIDO spec). Strip the inner DER
/// header by hand - it is always `0x04 0x10 <16 bytes>`.
fn parse_aaguid_octet_string(value: &[u8]) -> Result<[u8; 16]> {
    match value {
        [0x04, 0x10, aaguid @ ..] => aaguid.try_into().map_err(|_| malformed_aaguid()),
        _ => Err(malformed_aaguid()),
    }
}

/// `true` when a subject attribute is present and decodes.
fn has<T>(value: x509_cert::der::Result<Option<T>>) -> bool {
    matches!(value, Ok(Some(_)))
}

fn malformed_aaguid() -> Error {
    Error::Cbor("attestation cert: malformed AAGUID extension".into())
}
