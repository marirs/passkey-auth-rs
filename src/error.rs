//! Errors surfaced from registration / authentication ceremonies.
//!
//! All variants are deliberately specific (not "verification failed")
//! so callers can log/audit them - they don't leak data to the client
//! since the route layer is expected to translate any error into a
//! generic 401/400 before responding.

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
/// Why a registration or authentication ceremony failed.
///
/// The enum is `#[non_exhaustive]`: a `match` on it needs a `_` arm.
pub enum Error {
    /// Invalid base64url encoding on a wire field (challenge, credential
    /// id, signature, etc.).
    #[error("invalid base64url: {0}")]
    Base64(String),

    /// `clientDataJSON` failed to parse as UTF-8 JSON, or was JSON but
    /// missing required fields.
    #[error("clientDataJSON parse failed: {0}")]
    ClientData(String),

    /// `clientDataJSON.type` was wrong for the ceremony in flight
    /// (expected `webauthn.create` / `webauthn.get`).
    #[error("clientDataJSON.type mismatch: expected {expected}, got {actual}")]
    ClientDataType {
        /// The type this ceremony expects.
        expected: &'static str,
        /// The type the client sent.
        actual: String,
    },

    /// `clientDataJSON.challenge` did not match the challenge issued
    /// at the start of the ceremony.
    #[error("challenge mismatch")]
    ChallengeMismatch,

    /// `clientDataJSON.origin` was not exactly the configured RP origin.
    #[error("origin mismatch: expected {expected}, got {actual}")]
    OriginMismatch {
        /// The configured origin.
        expected: String,
        /// The origin the client sent.
        actual: String,
    },

    /// `authenticatorData.rpIdHash` did not match SHA-256(RP_ID).
    #[error("rpIdHash mismatch")]
    RpIdHashMismatch,

    /// The user-present (UP) bit was 0 - caller required UP.
    #[error("user-present flag not set")]
    UserNotPresent,

    /// The user-verified (UV) bit was 0 - caller required UV.
    #[error("user-verified flag not set")]
    UserNotVerified,

    /// Binary parse of `authenticatorData` failed at the byte level.
    #[error("authenticatorData parse failed: {0}")]
    AuthData(&'static str),

    /// CBOR parse of attestationObject or COSE key failed.
    #[error("CBOR decode failed: {0}")]
    Cbor(String),

    /// COSE key used an algorithm this build does not accept: ES256,
    /// EdDSA and RS256 always, ML-DSA-44/65/87 with the `pqc` feature (and,
    /// at registration, only when the relying party enabled ML-DSA).
    #[error("unsupported COSE algorithm: {0}")]
    UnsupportedAlg(i64),

    /// Signature verification with the stored public key failed.
    #[error("signature verification failed")]
    BadSignature,

    /// The authenticator counter went backwards or did not increase
    /// when the spec requires it. Caller should treat this as a cloned
    /// credential and reject.
    #[error("counter went backwards (stored={stored}, new={new}): possible cloned credential")]
    CounterReplay {
        /// Counter stored with the credential.
        stored: u32,
        /// Counter in this assertion.
        new: u32,
    },

    /// The assertion's BE (backup eligible) flag differs from the one
    /// stored with the credential (WebAuthn-3 §7.2 step 17). BE is fixed
    /// when the credential is created, so the caller should treat this
    /// like [`Error::CounterReplay`] and reject.
    #[error("backup eligibility changed (stored={stored}, new={new})")]
    BackupEligibilityChanged {
        /// BE stored with the credential.
        stored: bool,
        /// BE in this assertion.
        new: bool,
    },

    /// The ceremony state handed to `finish_*` is older than the
    /// allowed ceiling (default 5 minutes). Indicates the caller did
    /// not TTL their session store, or the response came back after
    /// the user walked away. Reject and restart the ceremony.
    #[error("ceremony state expired ({age_secs} seconds old, max {max_secs})")]
    CeremonyExpired {
        /// Age of the ceremony state.
        age_secs: u64,
        /// Oldest state accepted.
        max_secs: u64,
    },

    /// The `userHandle` carried in the assertion response did not
    /// match the user handle recorded at `start_authentication_for_user`
    /// time (WebAuthn-3 §7.2 step 6). Indicates an attack — the
    /// assertion is for a different user than the ceremony was
    /// started for — or, when `require_user_handle(true)` is set, an
    /// authenticator that did not emit a user_handle at all.
    #[error(
        "user handle mismatch: assertion is for a different user than the ceremony was started for"
    )]
    UserHandleMismatch,

    /// Internal invariant violation (bug). Should never reach a user.
    #[error("internal: {0}")]
    Internal(&'static str),
}

/// Result with this crate's [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;
