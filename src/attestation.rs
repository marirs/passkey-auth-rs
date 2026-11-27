//! `attestationObject` - the CBOR-encoded blob the authenticator
//! returns at registration time.
//!
//! Shape:
//! ```text
//!   { "fmt": "<format>", "attStmt": <map>, "authData": <bstr> }
//! ```
//!
//! Format support and what each verification proves:
//!
//! - **`none`** - the authenticator skipped attestation entirely.
//!   `attStmt` is empty. We trust the supplied public key as-is.
//!   Every passkey-class authenticator uses this when the RP
//!   requests `attestation: "none"` (this crate's default).
//!
//! - **`packed` self-attestation** (no `x5c`) - `attStmt = { alg, sig }`.
//!   The signature is over `authData || cdjHash` using the
//!   credential's own public key. Proves "whoever owns the
//!   credential's private key signed this", which is tautological
//!   for a freshly-minted credential but matches the spec.
//!
//! - **`packed` with `x5c`** (full cert chain) - `attStmt = { alg, sig, x5c }`.
//!   The signature is over `authData || cdjHash` using the
//!   public key of the **leaf cert** in `x5c` (ES256 with a P-256
//!   cert, RS256 with an RSA cert). We parse the leaf, check the
//!   WebAuthn-3 §8.2.1 certificate requirements, verify the signature,
//!   and (if the cert carries the FIDO AAGUID extension) verify that
//!   AAGUID matches `authData`.
//!   **We do NOT validate the cert chain to a trusted root.** Without
//!   the FIDO Metadata Service we cannot tell whether the cert really
//!   came from Yubico / Feitian / etc.; we only confirm internal
//!   consistency.
//!
//! - **`fido-u2f`** - legacy format from older Yubikeys.
//!   `attStmt = { sig, x5c }`. Signature is over a specific
//!   pre-image: `(0x00 || rpIdHash || cdjHash || credId || pubKey-SEC1)`
//!   and verified against the public key of the single P-256 cert in
//!   `x5c`. Same chain-validation caveat as packed-x5c.
//!
//! Other formats (`tpm`, `android-key`, `android-safetynet`, `apple`)
//! are still rejected with a clear error.

use ciborium::value::Value as CborValue;

use crate::auth_data::AuthenticatorData;
use crate::cose::{ALG_ES256, CoseKey};
use crate::crypto;
use crate::error::{Error, Result};
use crate::x509::AttestationCert;

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

    /// Verify the attestation statement. Dispatches by `fmt`.
    ///
    /// `credential_key` is the COSE public key extracted from
    /// `authData.attestedCredentialData` - used for packed
    /// self-attestation only. For x5c / fido-u2f the cert's own
    /// public key is the verifier.
    ///
    /// `client_data_hash` is SHA-256(clientDataJSON).
    pub(crate) fn verify_statement(
        &self,
        credential_key: &CoseKey,
        client_data_hash: &[u8; 32],
    ) -> Result<()> {
        match self.fmt.as_str() {
            "none" => Ok(()),
            "packed" => verify_packed(self, credential_key, client_data_hash),
            "fido-u2f" => verify_fido_u2f(self, credential_key, client_data_hash),
            other => Err(Error::Cbor(format!("unsupported attestation fmt: {other}"))),
        }
    }
}

// ---------- packed -----------------------------------------------------------

/// Parsed `attStmt` for the `packed` format. `x5c` is the cert chain
/// (leaf-first) when present; absent means self-attestation.
struct PackedAttStmt {
    alg: i64,
    sig: Vec<u8>,
    x5c: Option<Vec<Vec<u8>>>,
}

fn parse_packed_att_stmt(att_stmt: &CborValue) -> Result<PackedAttStmt> {
    let map = match att_stmt {
        CborValue::Map(m) => m,
        _ => return Err(Error::Cbor("packed: attStmt not a map".into())),
    };
    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "alg" => {
                alg = match v {
                    CborValue::Integer(i) => i64::try_from(i128::from(*i)).ok(),
                    _ => None,
                };
            }
            "sig" => {
                sig = match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                };
            }
            "x5c" => {
                x5c = match v {
                    CborValue::Array(certs) => {
                        let mut out = Vec::with_capacity(certs.len());
                        for c in certs {
                            match c {
                                CborValue::Bytes(b) => out.push(b.clone()),
                                _ => return Err(Error::Cbor("packed: x5c entry not bytes".into())),
                            }
                        }
                        Some(out)
                    }
                    _ => return Err(Error::Cbor("packed: x5c not an array".into())),
                };
            }
            _ => {}
        }
    }
    Ok(PackedAttStmt {
        alg: alg.ok_or_else(|| Error::Cbor("packed: missing alg".into()))?,
        sig: sig.ok_or_else(|| Error::Cbor("packed: missing sig".into()))?,
        x5c,
    })
}

fn verify_packed(
    att: &ParsedAttestation,
    cred_key: &CoseKey,
    client_data_hash: &[u8; 32],
) -> Result<()> {
    let stmt = parse_packed_att_stmt(&att.att_stmt)?;

    // Signed message is `authData || clientDataHash` for BOTH the
    // self-attestation and x5c paths - the only difference is WHICH
    // key verifies it.
    let mut msg = Vec::with_capacity(att.auth_data_raw.len() + 32);
    msg.extend_from_slice(&att.auth_data_raw);
    msg.extend_from_slice(client_data_hash);

    match stmt.x5c {
        // ── Self-attestation: cert chain absent ─────────────────────
        None => {
            if stmt.alg != cred_key.alg() {
                return Err(Error::Cbor(format!(
                    "packed (self): alg mismatch ({} vs cred {})",
                    stmt.alg,
                    cred_key.alg(),
                )));
            }
            crypto::verify(cred_key, &msg, &stmt.sig)
        }
        // ── Full chain: verify against the leaf cert's public key ───
        Some(chain) => {
            let leaf_der = chain
                .first()
                .ok_or_else(|| Error::Cbor("packed (x5c): empty cert chain".into()))?;
            let leaf = AttestationCert::from_der(leaf_der)?;
            if let Some(violation) = leaf.packed_violation {
                return Err(Error::Cbor(format!("packed (x5c): {violation}")));
            }
            // `alg` names the algorithm of the cert key: ES256 for a P-256
            // cert, RS256 for an RSA cert. Anything else is refused rather
            // than verified with the wrong algorithm.
            if stmt.alg != leaf.key.alg() {
                return Err(Error::Cbor(format!(
                    "packed (x5c): alg {} does not match the certificate key",
                    stmt.alg,
                )));
            }

            // If the cert carries the FIDO AAGUID extension, it MUST
            // match the AAGUID inside authData (spec WebAuthn-3 §8.2).
            if let (Some(cert_aaguid), Some(attested)) =
                (leaf.aaguid, att.auth_data.attested.as_ref())
            {
                if cert_aaguid != attested.aaguid {
                    return Err(Error::Cbor(
                        "packed (x5c): cert AAGUID does not match authData".into(),
                    ));
                }
            }

            crypto::verify(&leaf.key, &msg, &stmt.sig)
        }
    }
}

// ---------- fido-u2f --------------------------------------------------------

fn verify_fido_u2f(
    att: &ParsedAttestation,
    cred_key: &CoseKey,
    client_data_hash: &[u8; 32],
) -> Result<()> {
    // The credential key MUST be ES256 (U2F is P-256 only).
    let cred_point = match cred_key {
        CoseKey::Es256(vk) => vk.to_sec1_point(false),
        _ => {
            return Err(Error::Cbor(
                "fido-u2f: credential key must be ES256 / P-256".into(),
            ));
        }
    };

    // Parse the attestation statement. U2F format: { sig, x5c }.
    let map = match &att.att_stmt {
        CborValue::Map(m) => m,
        _ => return Err(Error::Cbor("fido-u2f: attStmt not a map".into())),
    };
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c: Option<Vec<Vec<u8>>> = None;
    for (k, v) in map {
        let key = match k {
            CborValue::Text(t) => t.as_str(),
            _ => continue,
        };
        match key {
            "sig" => {
                sig = match v {
                    CborValue::Bytes(b) => Some(b.clone()),
                    _ => None,
                };
            }
            "x5c" => {
                x5c = match v {
                    CborValue::Array(certs) => {
                        let mut out = Vec::with_capacity(certs.len());
                        for c in certs {
                            match c {
                                CborValue::Bytes(b) => out.push(b.clone()),
                                _ => {
                                    return Err(Error::Cbor(
                                        "fido-u2f: x5c entry not bytes".into(),
                                    ));
                                }
                            }
                        }
                        Some(out)
                    }
                    _ => return Err(Error::Cbor("fido-u2f: x5c not an array".into())),
                };
            }
            _ => {}
        }
    }
    let sig = sig.ok_or_else(|| Error::Cbor("fido-u2f: missing sig".into()))?;
    let chain = x5c.ok_or_else(|| Error::Cbor("fido-u2f: missing x5c".into()))?;
    // WebAuthn-3 §8.6: x5c holds exactly one certificate.
    let [leaf_der] = chain.as_slice() else {
        return Err(Error::Cbor(
            "fido-u2f: x5c must hold exactly one certificate".into(),
        ));
    };
    let leaf = AttestationCert::from_der(leaf_der)?;
    if leaf.key.alg() != ALG_ES256 {
        return Err(Error::Cbor(
            "fido-u2f: certificate key must be P-256".into(),
        ));
    }

    // U2F pre-image: 0x00 || rpIdHash || cdjHash || credId || pubKey-SEC1
    // where pubKey-SEC1 is 0x04 || X || Y (uncompressed).
    let attested =
        att.auth_data.attested.as_ref().ok_or_else(|| {
            Error::Cbor("fido-u2f: authData missing attestedCredentialData".into())
        })?;
    let cred_id = attested.credential_id.as_bytes();

    let mut pre_image = Vec::with_capacity(1 + 32 + 32 + cred_id.len() + 65);
    pre_image.push(0x00);
    pre_image.extend_from_slice(&att.auth_data.rp_id_hash);
    pre_image.extend_from_slice(client_data_hash);
    pre_image.extend_from_slice(cred_id);
    pre_image.extend_from_slice(cred_point.as_bytes());

    crypto::verify(&leaf.key, &pre_image, &sig)
}
