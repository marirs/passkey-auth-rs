//! Wire types shared by registration + authentication ceremonies.
//!
//! All byte-array fields on the wire are base64url-encoded with no
//! padding (per the WebAuthn spec). The browser's `PublicKeyCredential`
//! is normally surfaced as JSON; we mirror that JSON shape in
//! [`RegistrationResponse`] / [`AuthenticationResponse`] so a Rocket
//! handler can deserialize directly off the request body.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ---------- Challenge ----------------------------------------------------

/// 32 random bytes the browser signs (indirectly) to prove freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Challenge(pub Vec<u8>);

impl Challenge {
    /// Cryptographic random; uses `rand::thread_rng()` (OS CSPRNG).
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Self(buf.to_vec())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Browser-friendly base64url encoding (no padding).
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
}

// ---------- CredentialId -------------------------------------------------

/// Authenticator-assigned credential ID. Opaque, treat as raw bytes;
/// not a UUID. Up to 1023 bytes long per the spec, in practice ~64–256.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialId(pub Vec<u8>);

impl CredentialId {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
    pub fn from_b64url(s: &str) -> Result<Self> {
        b64url_decode(s).map(Self)
    }
}

// ---------- COSE / public-key blob --------------------------------------

/// COSE_Key-encoded public key (CBOR), exactly as carried in
/// `attestedCredentialData.credentialPublicKey`. Stored as-is so we can
/// re-verify signatures without re-parsing the COSE structure beyond
/// the alg + key params already extracted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CosePublicKey(pub Vec<u8>);

impl CosePublicKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ---------- Configuration -----------------------------------------------

/// Relying-party identifier. By spec this is a domain (no scheme, no
/// port). `example.com`, not `https://example.com`. The browser's
/// SHA-256 of this string is what the authenticator signs into
/// `authenticatorData.rpIdHash`.
#[derive(Debug, Clone)]
pub struct RpId(pub(crate) String);

impl RpId {
    /// Construct from a string. Stripped of leading scheme/port if the
    /// caller accidentally pasted a URL.
    pub fn new(rp_id: impl Into<String>) -> Self {
        let mut s = rp_id.into();
        if let Some(rest) = s.strip_prefix("https://") {
            s = rest.to_owned();
        } else if let Some(rest) = s.strip_prefix("http://") {
            s = rest.to_owned();
        }
        // Drop a trailing port: "example.com:8443" → "example.com".
        // The RP ID is a domain, ports never participate.
        if let Some((host, _)) = s.split_once(':') {
            s = host.to_owned();
        }
        // Drop a trailing path.
        if let Some((host, _)) = s.split_once('/') {
            s = host.to_owned();
        }
        Self(s)
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------- Helpers ------------------------------------------------------

/// Decode a base64url-no-pad string the way the WebAuthn spec demands.
/// Also accepts standard base64 with padding for tolerance.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // Try strict url-safe-no-pad first (the spec).
    if let Ok(v) = B64URL.decode(s) {
        return Ok(v);
    }
    // Fallback: standard / url-safe with padding, just in case the
    // browser-side serializer added padding. Strip `=` and retry.
    let trimmed = s.trim_end_matches('=');
    B64URL
        .decode(trimmed)
        .map_err(|e| Error::Base64(e.to_string()))
}

// ---------- Wire structs (request bodies) -------------------------------

/// JSON body posted by the client to finish a registration ceremony.
/// Mirrors the browser's `PublicKeyCredential` (registration variant)
/// after the standard "base64url every binary field" transformation
/// callers do in JS before posting.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    /// The base64url-encoded raw credential ID.
    pub id: String,
    /// Authenticator-attached transports (USB / NFC / BLE / internal).
    /// Optional; some browsers omit it.
    #[serde(default)]
    pub transports: Vec<String>,
    /// The attestation object (CBOR), base64url-encoded.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// The clientDataJSON (UTF-8 JSON), base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// JSON body posted by the client to finish an authentication ceremony.
#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub id: String,
    /// Raw authenticator data, base64url-encoded.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature over `authenticatorData || SHA-256(clientDataJSON)`,
    /// base64url-encoded.
    pub signature: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// User handle (the opaque user id we registered with). Optional;
    /// only present for discoverable credentials. Currently informational.
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

// ---------- Challenge JSON for the START side ---------------------------

/// What we send to the browser for `navigator.credentials.create()`.
/// All byte fields are base64url-encoded; the client JS is expected
/// to decode them before passing to the WebAuthn API.
#[derive(Debug, Serialize)]
pub struct RegistrationChallenge {
    pub challenge: String, // base64url
    pub rp: RpInfo,
    pub user: UserInfo,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Credentials we already have for this user - browser SHOULD
    /// refuse to register a duplicate.
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub timeout: u32, // milliseconds
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    pub attestation: &'static str, // "none"
}

#[derive(Debug, Serialize)]
pub struct RpInfo {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String, // base64url
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub kind: &'static str, // "public-key"
    pub id: String, // base64url
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct AuthenticatorSelection {
    /// Pins the ceremony to a particular authenticator class. We set
    /// this to `"platform"` so the browser only offers built-in
    /// authenticators (Touch ID, Windows Hello, Android biometrics) -
    /// roaming/USB hardware keys aren't part of the supported flow.
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<&'static str>,
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<&'static str>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str, // "preferred"
}

/// What we send to the browser for `navigator.credentials.get()`.
#[derive(Debug, Serialize)]
pub struct AuthenticationChallenge {
    pub challenge: String, // base64url
    #[serde(rename = "rpId")]
    pub rp_id: String,
    pub timeout: u32,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

// ---------- Ceremony state (server-side, opaque to client) --------------

/// Per-ceremony state retained between start_* and finish_*. Caller
/// stores this server-side keyed by however they like (session cookie,
/// user id, in-memory map). Treat as secret-ish: contains the
/// challenge we issued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    pub challenge: Challenge,
    pub user_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    pub challenge: Challenge,
    /// Credentials the browser was allowed to use, so finish_* can
    /// verify the asserted credential id is one of them.
    pub allow_credentials: Vec<CredentialId>,
}

// ---------- Outcomes ----------------------------------------------------

/// Stored after a successful registration. The caller persists this
/// (one row per credential per user) and looks it up at auth time.
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub id: CredentialId,
    pub public_key_cose: CosePublicKey,
    pub counter: u32,
    pub transports: Vec<String>,
    pub aaguid: [u8; 16],
}

/// Successful authentication outcome. Caller updates the stored
/// credential's `counter` to `new_counter` before responding.
#[derive(Debug, Clone)]
pub struct AuthSuccess {
    pub credential_id: CredentialId,
    pub new_counter: u32,
    pub user_verified: bool,
}
