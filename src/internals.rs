//! Parser entry points for the fuzz targets in `fuzz/` and the parser
//! benchmarks in `benches/`. Compiled only with `--cfg fuzzing`, which
//! cargo-fuzz sets; no Cargo feature reaches it. Not part of the public
//! API: names and signatures change without notice.

use crate::attestation::ParsedAttestation;
use crate::auth_data::AuthenticatorData;
use crate::client_data::{self, TYPE_AUTHENTICATE};
use crate::cose::CoseKey;
use crate::error::Result;
use crate::types::Challenge;
use crate::x509::AttestationCert;

/// Challenge [`client_data_json`] compares against: 32 bytes of 0x2a.
pub const CLIENT_DATA_CHALLENGE: [u8; 32] = [0x2a; 32];
/// Origin [`client_data_json`] compares against.
pub const CLIENT_DATA_ORIGIN: &str = "https://example.com";

/// Parses an attestationObject, its authenticator data and credential
/// public key, then verifies the attestation statement against an
/// all-zero client data hash.
pub fn attestation_object(bytes: &[u8]) -> Result<()> {
    let att = ParsedAttestation::parse(bytes)?;
    let Some(attested) = att.auth_data.attested.as_ref() else {
        return Ok(());
    };
    let key = CoseKey::parse(attested.public_key_cose)?;
    att.verify_statement(&key, &[0; 32])
}

/// Parses binary authenticator data.
pub fn authenticator_data(bytes: &[u8]) -> Result<()> {
    AuthenticatorData::parse(bytes).map(drop)
}

/// Parses a COSE_Key.
pub fn cose_key(bytes: &[u8]) -> Result<()> {
    CoseKey::parse(bytes).map(drop)
}

/// Runs the `webauthn.get` clientDataJSON checks on decoded JSON bytes
/// against [`CLIENT_DATA_CHALLENGE`] and [`CLIENT_DATA_ORIGIN`].
pub fn client_data_json(raw: &[u8]) -> Result<()> {
    let challenge = Challenge(CLIENT_DATA_CHALLENGE.to_vec()); // copy: the API stores challenges as Vec
    client_data::check(
        raw,
        TYPE_AUTHENTICATE,
        &challenge,
        CLIENT_DATA_ORIGIN,
        false,
    )
}

/// Parses a DER attestation certificate the way the `packed` and
/// `fido-u2f` formats read their leaf certificate.
pub fn attestation_cert(der: &[u8]) -> Result<()> {
    AttestationCert::from_der(der).map(drop)
}
