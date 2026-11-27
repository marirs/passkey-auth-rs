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

use crate::auth_data::AuthenticatorData;
use crate::cbor::{self, Value};
use crate::cose::{ALG_ES256, CoseKey};
use crate::crypto;
use crate::error::{Error, Result};
use crate::x509::AttestationCert;

/// A decoded attestationObject, borrowing from the input bytes.
#[derive(Debug)]
pub(crate) struct ParsedAttestation<'a> {
    pub auth_data_raw: &'a [u8],
    pub auth_data: AuthenticatorData<'a>,
    pub fmt: &'a str,
    /// `None` when the object has no `attStmt` (valid for `none` only).
    pub att_stmt: Option<Value<'a>>,
}

impl<'a> ParsedAttestation<'a> {
    /// Decodes the CBOR envelope (which must fill `bytes` exactly) and
    /// parses the binary `authData` inside.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        let map = cbor::decode_exact(bytes)
            .map_err(|e| Error::Cbor(format!("attestationObject: {e}")))?
            .as_map()
            .ok_or_else(|| Error::Cbor("attestationObject: top-level not a map".into()))?;

        let (mut fmt, mut att_stmt, mut auth_data) = (None, None, None);
        for (key, value) in map {
            let slot = match key.as_text() {
                Some("fmt") => &mut fmt,
                Some("attStmt") => &mut att_stmt,
                Some("authData") => &mut auth_data,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(Error::Cbor("attestationObject: duplicate key".into()));
            }
        }

        let fmt = fmt
            .ok_or_else(|| Error::Cbor("attestationObject: missing fmt".into()))?
            .as_text()
            .ok_or_else(|| Error::Cbor("attestationObject.fmt not text".into()))?;
        let auth_data_raw = auth_data
            .ok_or_else(|| Error::Cbor("attestationObject: missing authData".into()))?
            .as_bytes()
            .ok_or_else(|| Error::Cbor("attestationObject.authData not bytes".into()))?;
        Ok(Self {
            auth_data_raw,
            auth_data: AuthenticatorData::parse(auth_data_raw)?,
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
        match self.fmt {
            "none" => Ok(()),
            "packed" => verify_packed(self, credential_key, client_data_hash),
            "fido-u2f" => verify_fido_u2f(self, credential_key, client_data_hash),
            other => Err(Error::Cbor(format!("unsupported attestation fmt: {other}"))),
        }
    }
}

/// The `attStmt` fields `packed` and `fido-u2f` read. A field of the wrong
/// type counts as missing, as before; a repeated field is refused.
struct Statement<'a> {
    alg: Option<i64>,
    sig: Option<&'a [u8]>,
    /// Certificates, leaf first; every element is a byte string.
    x5c: Option<cbor::Items<'a>>,
}

fn parse_statement<'a>(att: &ParsedAttestation<'a>, fmt: &str) -> Result<Statement<'a>> {
    let Some(stmt) = att.att_stmt else {
        return Ok(Statement {
            alg: None,
            sig: None,
            x5c: None,
        });
    };
    let map = stmt
        .as_map()
        .ok_or_else(|| Error::Cbor(format!("{fmt}: attStmt not a map")))?;
    let (mut alg, mut sig, mut x5c) = (None, None, None);
    for (key, value) in map {
        let slot = match key.as_text() {
            Some("alg") => &mut alg,
            Some("sig") => &mut sig,
            Some("x5c") => &mut x5c,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(Error::Cbor(format!("{fmt}: duplicate attStmt key")));
        }
    }
    let x5c = x5c
        .map(|chain| {
            let certs = chain
                .as_array()
                .ok_or_else(|| Error::Cbor(format!("{fmt}: x5c not an array")))?;
            // `Items` is a cursor into the input; cloning it copies no data.
            if certs.clone().any(|cert| cert.as_bytes().is_none()) {
                return Err(Error::Cbor(format!("{fmt}: x5c entry not bytes")));
            }
            Ok(certs)
        })
        .transpose()?;
    Ok(Statement {
        alg: alg.and_then(|v| v.as_i64()),
        sig: sig.and_then(|v| v.as_bytes()),
        x5c,
    })
}

// ---------- packed -----------------------------------------------------------

fn verify_packed(
    att: &ParsedAttestation<'_>,
    cred_key: &CoseKey,
    client_data_hash: &[u8; 32],
) -> Result<()> {
    let stmt = parse_statement(att, "packed")?;
    let alg = stmt
        .alg
        .ok_or_else(|| Error::Cbor("packed: missing alg".into()))?;
    let sig = stmt
        .sig
        .ok_or_else(|| Error::Cbor("packed: missing sig".into()))?;

    // Signed message is `authData || clientDataHash` for BOTH the
    // self-attestation and x5c paths - the only difference is WHICH
    // key verifies it.
    let msg = [att.auth_data_raw, client_data_hash];

    match stmt.x5c {
        // ── Self-attestation: cert chain absent ─────────────────────
        None => {
            if alg != cred_key.alg() {
                return Err(Error::Cbor(format!(
                    "packed (self): alg mismatch ({alg} vs cred {})",
                    cred_key.alg(),
                )));
            }
            crypto::verify(cred_key, &msg, sig)
        }
        // ── Full chain: verify against the leaf cert's public key ───
        Some(mut chain) => {
            let leaf_der = chain
                .next()
                .and_then(|cert| cert.as_bytes())
                .ok_or_else(|| Error::Cbor("packed (x5c): empty cert chain".into()))?;
            let leaf = AttestationCert::from_der(leaf_der)?;
            if let Some(violation) = leaf.packed_violation {
                return Err(Error::Cbor(format!("packed (x5c): {violation}")));
            }
            // `alg` names the algorithm of the cert key: ES256 for a P-256
            // cert, RS256 for an RSA cert. Anything else is refused rather
            // than verified with the wrong algorithm.
            if alg != leaf.key.alg() {
                return Err(Error::Cbor(format!(
                    "packed (x5c): alg {alg} does not match the certificate key"
                )));
            }

            // If the cert carries the FIDO AAGUID extension, it MUST
            // match the AAGUID inside authData (spec WebAuthn-3 §8.2).
            if let (Some(cert_aaguid), Some(attested)) =
                (leaf.aaguid, att.auth_data.attested.as_ref())
                && &cert_aaguid != attested.aaguid
            {
                return Err(Error::Cbor(
                    "packed (x5c): cert AAGUID does not match authData".into(),
                ));
            }

            crypto::verify(&leaf.key, &msg, sig)
        }
    }
}

// ---------- fido-u2f --------------------------------------------------------

fn verify_fido_u2f(
    att: &ParsedAttestation<'_>,
    cred_key: &CoseKey,
    client_data_hash: &[u8; 32],
) -> Result<()> {
    // The credential key MUST be ES256 (U2F is P-256 only).
    let CoseKey::Es256(cred_vk) = cred_key else {
        return Err(Error::Cbor(
            "fido-u2f: credential key must be ES256 / P-256".into(),
        ));
    };

    // U2F format: { sig, x5c }.
    let stmt = parse_statement(att, "fido-u2f")?;
    let sig = stmt
        .sig
        .ok_or_else(|| Error::Cbor("fido-u2f: missing sig".into()))?;
    let mut chain = stmt
        .x5c
        .ok_or_else(|| Error::Cbor("fido-u2f: missing x5c".into()))?;
    // WebAuthn-3 §8.6: x5c holds exactly one certificate.
    let (Some(leaf_der), None) = (chain.next().and_then(|c| c.as_bytes()), chain.next()) else {
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

    let attested =
        att.auth_data.attested.as_ref().ok_or_else(|| {
            Error::Cbor("fido-u2f: authData missing attestedCredentialData".into())
        })?;

    // U2F pre-image: 0x00 || rpIdHash || cdjHash || credId || pubKey-SEC1
    // where pubKey-SEC1 is 0x04 || X || Y (uncompressed).
    let point = cred_vk.to_sec1_point(false);
    let pre_image = [
        &[0x00][..],
        att.auth_data.rp_id_hash,
        client_data_hash,
        attested.credential_id,
        point.as_bytes(),
    ];
    crypto::verify(&leaf.key, &pre_image, sig)
}
