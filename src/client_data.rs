//! Parse + validate `clientDataJSON`.
//!
//! Format (UTF-8 JSON, NOT to be transformed before SHA-256ing):
//! ```text
//! {
//!   "type":      "webauthn.create" | "webauthn.get",
//!   "challenge": "<base64url>",
//!   "origin":    "https://example.com",
//!   "crossOrigin": false,
//!   ...
//! }
//! ```
//! We deserialize the typed shape *for validation* but keep the raw
//! bytes around because the spec hashes those exact bytes into the
//! signed message (any pretty-printing or field reordering would
//! break verification).

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::types::{Challenge, b64url_decode, b64url_decode_strict};

/// Type tags the spec puts in `clientDataJSON.type`.
pub(crate) const TYPE_REGISTER: &str = "webauthn.create";
pub(crate) const TYPE_AUTHENTICATE: &str = "webauthn.get";

#[derive(Debug, Deserialize)]
struct Parsed {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
    #[serde(rename = "topOrigin")]
    top_origin: Option<serde::de::IgnoredAny>,
}

/// UTF-8 byte order mark, which WebAuthn-3 §7.1 step 6 strips before parsing.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Decode the base64url envelope, parse the JSON, then enforce the
/// invariants: type matches, challenge matches what we issued,
/// origin matches what we configured.
///
/// `strict` selects the base64 decoder used for the envelope and the
/// inner `challenge` field. When `false` (default), the lenient
/// `b64url_decode` (multi-alphabet, padding-tolerant) is used. When
/// `true`, only spec-compliant url-safe-no-pad is accepted.
///
/// Returns the *raw decoded bytes* (the canonical UTF-8 JSON the
/// authenticator hashed) so callers can SHA-256 them for the signed
/// message in authentication.
pub(crate) fn validate(
    encoded: &str,
    expected_type: &str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    strict: bool,
) -> Result<Vec<u8>> {
    let decode = if strict {
        b64url_decode_strict
    } else {
        b64url_decode
    };
    let raw = decode(encoded)?;
    check(
        &raw,
        expected_type,
        expected_challenge,
        expected_origin,
        decode,
    )?;
    Ok(raw)
}

/// Runs the `clientDataJSON` checks on the decoded JSON bytes. `decode`
/// is the base64 decoder for the inner `challenge` field.
pub(crate) fn check(
    raw: &[u8],
    expected_type: &str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    decode: fn(&str) -> Result<Vec<u8>>,
) -> Result<()> {
    let json = raw.strip_prefix(UTF8_BOM).unwrap_or(raw);
    let p: Parsed = serde_json::from_slice(json).map_err(|e| Error::ClientData(e.to_string()))?;

    if p.kind != expected_type {
        return Err(Error::ClientDataType {
            expected: if expected_type == TYPE_REGISTER {
                "webauthn.create"
            } else {
                "webauthn.get"
            },
            actual: p.kind,
        });
    }

    let got_challenge = decode(&p.challenge)?;
    if got_challenge != expected_challenge.as_bytes() {
        return Err(Error::ChallengeMismatch);
    }

    if p.origin != expected_origin {
        return Err(Error::OriginMismatch {
            expected: expected_origin.to_owned(),
            actual: p.origin,
        });
    }

    // WebAuthn-3 §7.1 step 10 and §7.2 step 14: a ceremony run inside a
    // cross-origin iframe is accepted only by an RP that expects one. This
    // crate serves top-level pages only.
    if p.cross_origin || p.top_origin.is_some() {
        return Err(Error::ClientData(
            "ceremony ran in a cross-origin iframe (crossOrigin or topOrigin set)".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

    fn make_cdj(kind: &str, challenge_b64: &str, origin: &str) -> String {
        let json = format!(
            r#"{{"type":"{kind}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
        );
        B64URL.encode(json.as_bytes())
    }

    #[test]
    fn happy_path_register() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://example.com");
        let raw = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap();
        // Returned raw is the decoded JSON, suitable for hashing.
        assert!(raw.starts_with(b"{\"type\":\"webauthn.create\""));
    }

    #[test]
    fn wrong_type_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.get", &chal.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ClientDataType { .. }));
    }

    #[test]
    fn wrong_challenge_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let bad = Challenge(vec![9, 9, 9]);
        let cdj = make_cdj("webauthn.create", &bad.to_b64url(), "https://example.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    fn raw(extra: &str) -> Vec<u8> {
        let chal = Challenge(vec![1, 2, 3, 4]).to_b64url();
        format!(r#"{{"type":"webauthn.get","challenge":"{chal}","origin":"https://example.com"{extra}}}"#)
            .into_bytes()
    }

    fn run(raw: &[u8]) -> Result<()> {
        let chal = Challenge(vec![1, 2, 3, 4]);
        check(
            raw,
            TYPE_AUTHENTICATE,
            &chal,
            "https://example.com",
            b64url_decode,
        )
    }

    #[test]
    fn cross_origin_and_top_origin_rejected() {
        assert!(run(&raw("")).is_ok());
        assert!(run(&raw(r#","crossOrigin":false"#)).is_ok());
        assert!(run(&raw(r#","crossOrigin":true"#)).is_err());
        assert!(run(&raw(r#","topOrigin":"https://evil.example""#)).is_err());
    }

    #[test]
    fn leading_bom_is_stripped() {
        let mut bytes = UTF8_BOM.to_vec();
        bytes.extend_from_slice(&raw(""));
        assert!(run(&bytes).is_ok());
    }

    #[test]
    fn duplicate_fields_rejected() {
        assert!(run(&raw(r#","origin":"https://example.com""#)).is_err());
    }

    #[test]
    fn wrong_origin_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.create", &chal.to_b64url(), "https://evil.com");
        let err = validate(&cdj, TYPE_REGISTER, &chal, "https://example.com", false).unwrap_err();
        assert!(matches!(err, Error::OriginMismatch { .. }));
    }
}
