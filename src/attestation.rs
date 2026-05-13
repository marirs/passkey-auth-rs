//! `attestationObject` - the CBOR-encoded blob the authenticator
//! returns at registration time.
//!
//! Shape:
//! ```text
//!   { "fmt": "<format>", "attStmt": <map>, "authData": <bstr> }
//! ```
//!
//! Format support is deliberately narrow for passkey use:
//!
//! - **`none`** - the authenticator skipped attestation entirely.
//!   `attStmt` is empty. We trust the supplied public key as-is.
//!   This is the format every passkey-class authenticator uses
//!   when the RP requests `attestation: "none"`.
//!
//! - **`packed`** - self-attestation only (no cert chain). The
//!   authenticator signs `authData || clientDataHash` with the
//!   *same* key the credential carries. We verify that self-signature.
//!   Skips full cert-chain validation; sufficient for the threat
//!   model of "the user controls the key that just signed".
//!
//! All other formats (`fido-u2f`, `tpm`, `android-key`,
//! `android-safetynet`, `apple`) are rejected with a clear error so
//! the caller can decide to ask the browser to retry with a different
//! attestation preference.

use ciborium::value::Value as CborValue;

use crate::auth_data::AuthenticatorData;
use crate::cose::CoseKey;
use crate::crypto;
use crate::error::{Error, Result};

#[derive(Debug)]
pub(crate) struct ParsedAttestation {
    pub auth_data_raw: Vec<u8>,
    pub auth_data: AuthenticatorData,
    pub fmt: String,
    pub att_stmt: CborValue,
}

impl ParsedAttestation {
    /// Decode the CBOR envelope and parse the binary `authData` inside.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let v: CborValue = ciborium::de::from_reader(bytes)
            .map_err(|e| Error::Cbor(format!("attestationObject: {e}")))?;
        let map = match v {
            CborValue::Map(m) => m,
            _ => return Err(Error::Cbor("attestationObject: top-level not a map".into())),
        };

        let mut fmt = None;
        let mut att_stmt = None;
        let mut auth_data = None;
        for (k, val) in map {
            let key = match k {
                CborValue::Text(t) => t,
                _ => continue,
            };
            match key.as_str() {
                "fmt" => {
                    fmt = match val {
                        CborValue::Text(t) => Some(t),
                        _ => return Err(Error::Cbor("attestationObject.fmt not text".into())),
                    };
                }
                "attStmt" => att_stmt = Some(val),
                "authData" => {
                    auth_data = match val {
                        CborValue::Bytes(b) => Some(b),
                        _ => {
                            return Err(Error::Cbor("attestationObject.authData not bytes".into()));
                        }
                    };
                }
                _ => {}
            }
        }

        let fmt = fmt.ok_or_else(|| Error::Cbor("attestationObject: missing fmt".into()))?;
        let att_stmt = att_stmt.unwrap_or(CborValue::Map(Vec::new()));
        let ad_bytes =
            auth_data.ok_or_else(|| Error::Cbor("attestationObject: missing authData".into()))?;
        let parsed_ad = AuthenticatorData::parse(&ad_bytes)?;
        Ok(Self {
            auth_data_raw: ad_bytes,
            auth_data: parsed_ad,
            fmt,
            att_stmt,
        })
    }

    /// Verify the attestation statement (if any). For `fmt=none` this
    /// is a no-op. For `fmt=packed` self-attestation, the att_stmt's
    /// `sig` field is verified using the credential's own public key.
    ///
    /// `client_data_hash` is SHA-256(clientDataJSON) - the second half
    /// of the signed message in the packed scheme.
    pub(crate) fn verify_statement(
        &self,
        credential_key: &CoseKey,
        client_data_hash: &[u8; 32],
    ) -> Result<()> {
        match self.fmt.as_str() {
            "none" => Ok(()),
            "packed" => verify_packed(self, credential_key, client_data_hash),
            other => Err(Error::Cbor(format!("unsupported attestation fmt: {other}"))),
        }
    }
}

/// Packed *self*-attestation: `attStmt = { alg, sig }`, no `x5c`.
/// The signature is over `authData || clientDataHash` using the same
/// credential public key embedded in `authData.attestedCredentialData`.
fn verify_packed(
    att: &ParsedAttestation,
    cred_key: &CoseKey,
    client_data_hash: &[u8; 32],
) -> Result<()> {
    let map = match &att.att_stmt {
        CborValue::Map(m) => m,
        _ => return Err(Error::Cbor("packed: attStmt not a map".into())),
    };

    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut has_x5c = false;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "alg" => {
                alg = match v {
                    CborValue::Integer(i) => Some(i128::from(*i) as i64),
                    _ => None,
                };
            }
            "sig" => {
                sig = match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                };
            }
            "x5c" => has_x5c = true,
            _ => {}
        }
    }

    if has_x5c {
        // x5c means a full cert chain - we don't do FIDO MDS cert
        // validation. Reject so the client can retry with attestation
        // set to "none".
        return Err(Error::Cbor(
            "packed attestation with x5c (cert chain) not supported".into(),
        ));
    }

    let alg = alg.ok_or_else(|| Error::Cbor("packed: missing alg".into()))?;
    if alg != cred_key.alg() {
        return Err(Error::Cbor(format!(
            "packed: alg mismatch ({} vs cred {})",
            alg,
            cred_key.alg()
        )));
    }
    let sig = sig.ok_or_else(|| Error::Cbor("packed: missing sig".into()))?;

    // Signed message: authData || clientDataHash.
    let mut msg = Vec::with_capacity(att.auth_data_raw.len() + 32);
    msg.extend_from_slice(&att.auth_data_raw);
    msg.extend_from_slice(client_data_hash);
    crypto::verify(cred_key, &msg, &sig)
}
