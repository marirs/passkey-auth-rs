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

use std::borrow::Cow;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::types::{Challenge, b64url_decode_into};

/// Type tags the spec puts in `clientDataJSON.type`.
pub(crate) const TYPE_REGISTER: &str = "webauthn.create";
pub(crate) const TYPE_AUTHENTICATE: &str = "webauthn.get";

/// The fields this crate checks. Strings borrow from the JSON unless they
/// contain escapes.
#[derive(Debug, Deserialize)]
struct Parsed<'a> {
    #[serde(rename = "type", borrow)]
    kind: Cow<'a, str>,
    #[serde(borrow)]
    challenge: Cow<'a, str>,
    #[serde(borrow)]
    origin: Cow<'a, str>,
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
/// message. They are decoded into `buf` when they fit.
pub(crate) fn validate<'b>(
    encoded: &str,
    buf: &'b mut [u8],
    expected_type: &str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    strict: bool,
) -> Result<Cow<'b, [u8]>> {
    let raw = b64url_decode_into(encoded, buf, strict)?;
    check(
        &raw,
        expected_type,
        expected_challenge,
        expected_origin,
        strict,
    )?;
    Ok(raw)
}

/// Runs the `clientDataJSON` checks on the decoded JSON bytes. `strict`
/// selects the base64 decoder for the inner `challenge` field.
pub(crate) fn check(
    raw: &[u8],
    expected_type: &str,
    expected_challenge: &Challenge,
    expected_origin: &str,
    strict: bool,
) -> Result<()> {
    let json = raw.strip_prefix(UTF8_BOM).unwrap_or(raw);
    let p: Parsed<'_> =
        serde_json::from_slice(json).map_err(|e| Error::ClientData(e.to_string()))?;

    if p.kind != expected_type {
        return Err(Error::ClientDataType {
            expected: if expected_type == TYPE_REGISTER {
                "webauthn.create"
            } else {
                "webauthn.get"
            },
            actual: p.kind.into_owned(), // copy: error path only
        });
    }

    // Challenges this crate issues are 32 bytes; longer ones still decode.
    let mut buf = [0u8; 64];
    if *b64url_decode_into(&p.challenge, &mut buf, strict)? != *expected_challenge.as_bytes() {
        return Err(Error::ChallengeMismatch);
    }

    if p.origin != expected_origin {
        return Err(Error::OriginMismatch {
            expected: expected_origin.to_owned(), // copy: error path only
            actual: p.origin.into_owned(),
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
        let mut buf = [0; 1024];
        let raw = validate(
            &cdj,
            &mut buf,
            TYPE_REGISTER,
            &chal,
            "https://example.com",
            false,
        )
        .unwrap();
        // Returned raw is the decoded JSON, suitable for hashing.
        assert!(raw.starts_with(b"{\"type\":\"webauthn.create\""));
    }

    #[test]
    fn wrong_type_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let cdj = make_cdj("webauthn.get", &chal.to_b64url(), "https://example.com");
        let err = validate(
            &cdj,
            &mut [0; 1024],
            TYPE_REGISTER,
            &chal,
            "https://example.com",
            false,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ClientDataType { .. }));
    }

    #[test]
    fn wrong_challenge_rejected() {
        let chal = Challenge(vec![1, 2, 3, 4]);
        let bad = Challenge(vec![9, 9, 9]);
        let cdj = make_cdj("webauthn.create", &bad.to_b64url(), "https://example.com");
        let err = validate(
            &cdj,
            &mut [0; 1024],
            TYPE_REGISTER,
            &chal,
            "https://example.com",
            false,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    fn raw(extra: &str) -> Vec<u8> {
        let chal = Challenge(vec![1, 2, 3, 4]).to_b64url();
        format!(r#"{{"type":"webauthn.get","challenge":"{chal}","origin":"https://example.com"{extra}}}"#)
            .into_bytes()
    }

    fn run(raw: &[u8]) -> Result<()> {
        let chal = Challenge(vec![1, 2, 3, 4]);
        check(raw, TYPE_AUTHENTICATE, &chal, "https://example.com", false)
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
        let err = validate(
            &cdj,
            &mut [0; 1024],
            TYPE_REGISTER,
            &chal,
            "https://example.com",
            false,
        )
        .unwrap_err();
        assert!(matches!(err, Error::OriginMismatch { .. }));
    }
}
