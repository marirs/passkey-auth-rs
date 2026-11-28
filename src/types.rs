//! Wire types shared by registration + authentication ceremonies.
//!
//! All byte-array fields on the wire are base64url-encoded with no
//! padding (per the WebAuthn spec). The browser's `PublicKeyCredential`
//! is normally surfaced as JSON; we mirror that JSON shape in
//! [`RegistrationResponse`] / [`AuthenticationResponse`] so a Rocket
//! handler can deserialize directly off the request body.

use std::borrow::Cow;

use base64::engine::GeneralPurpose;
use base64::engine::general_purpose::{
    STANDARD as B64STD, STANDARD_NO_PAD as B64STD_NO_PAD, URL_SAFE as B64URL_PAD,
    URL_SAFE_NO_PAD as B64URL,
};
use base64::{DecodeSliceError, Engine};
use rand::Rng as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ---------- Challenge ----------------------------------------------------

/// 32 random bytes the browser signs (indirectly) to prove freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Challenge(pub Vec<u8>);

impl Challenge {
    /// Cryptographic random; uses `rand::rng()`, the thread-local CSPRNG seeded from the OS.
    #[must_use]
    pub fn random() -> Self {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        Self(buf.to_vec())
    }

    /// The raw challenge bytes.
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
    /// The raw credential ID bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Encodes the ID as base64url without padding, the WebAuthn wire form.
    #[must_use]
    pub fn to_b64url(&self) -> String {
        B64URL.encode(&self.0)
    }
    /// Decodes an ID from base64url, accepting the same variants as the
    /// lenient response decoder (padding, standard alphabet).
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
    /// The COSE_Key CBOR bytes.
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
    /// Construct from a string that already IS a bare RP ID
    /// (`example.com`, `subdomain.example.com`). Use this in
    /// production code where the value comes from a config file or
    /// known constant.
    ///
    /// If you might receive a full URL, use [`Self::try_from_url`]
    /// instead - this constructor stores the input verbatim and does
    /// NOT strip scheme/port/path, so passing `"https://example.com"`
    /// here gives you a broken RP ID.
    pub fn new(rp_id: impl Into<String>) -> Self {
        Self(rp_id.into())
    }

    /// Try to extract an RP ID from a URL or URL-like input.
    /// Accepts:
    ///   - bare domains:        `"example.com"`
    ///   - full origins:        `"https://example.com:8443"`
    ///   - origins with a path: `"https://example.com/auth/start"`
    ///
    /// Returns `Err` if the input is neither parseable as a URL nor a
    /// plausible bare hostname (no whitespace, no userinfo, etc.).
    /// Use this when the input might be a URL the operator pasted.
    pub fn try_from_url(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::Internal("RP ID is empty"));
        }

        // First try a strict URL parse - works for "https://..." inputs.
        if let Ok(u) = url::Url::parse(trimmed) {
            if let Some(host) = u.host_str() {
                return Ok(Self(host.to_owned()));
            }
            return Err(Error::Internal("URL has no host component"));
        }

        // Fall back: treat as a bare hostname. Reject anything that
        // contains characters a hostname cannot legitimately have
        // (whitespace, `@` for userinfo, `:` for ports, `/` for paths)
        // rather than silently mangling them as the v1 implementation
        // did.
        if trimmed
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '@' | ':' | '/' | '?' | '#'))
        {
            return Err(Error::Internal(
                "RP ID is not a bare hostname (contains scheme/port/path/userinfo)",
            ));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The RP ID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------- Helpers ------------------------------------------------------

/// Decode a base64url-no-pad string the way the WebAuthn spec demands,
/// with permissive fallbacks for client serializers that emit:
///   - base64url WITH padding (some JSON helpers add `=`)
///   - standard base64 (`+`/`/` alphabet) with or without padding -
///     common when client JS uses `btoa(String.fromCharCode(...))`
///
/// We try strict url-safe-no-pad first (spec), then progressively
/// looser variants. All four alphabets are checked before giving up.
///
/// For strict spec-conformant decoding (rejects everything except
/// url-safe-no-pad), see [`b64url_decode_strict`]. Production
/// deployments that control the client JS should prefer the strict
/// form via [`crate::Webauthn::strict_base64`].
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // 1. spec-compliant: url-safe, no padding
    if let Ok(v) = B64URL.decode(s) {
        return Ok(v);
    }
    // 2. url-safe WITH padding
    if let Ok(v) = B64URL_PAD.decode(s) {
        return Ok(v);
    }
    // 3. standard alphabet, no padding
    if let Ok(v) = B64STD_NO_PAD.decode(s) {
        return Ok(v);
    }
    // 4. standard alphabet, with padding (last-ditch; report this error)
    B64STD.decode(s).map_err(|e| Error::Base64(e.to_string()))
}

/// Strict spec-conformant base64url decode: ONLY accepts the
/// url-safe alphabet with no padding. Any other variant is rejected.
///
/// WebAuthn §6.1 requires this exact encoding. Lenient decoding
/// ([`b64url_decode`]) silently accepts non-conformant client JS,
/// which is convenient during development but hides client-side bugs
/// and broadens the input surface. Strict mode forces the client to
/// emit the right thing.
pub(crate) fn b64url_decode_strict(s: &str) -> Result<Vec<u8>> {
    B64URL.decode(s).map_err(|e| Error::Base64(e.to_string()))
}

/// Decodes `s` into `buf` with the alphabets of [`b64url_decode`] (only
/// url-safe-no-pad when `strict`), so short fields such as challenges,
/// credential IDs and user handles need no allocation. A value too long
/// for `buf` falls back to an allocated buffer, with the same result.
pub(crate) fn b64url_decode_into<'b>(
    s: &str,
    buf: &'b mut [u8],
    strict: bool,
) -> Result<Cow<'b, [u8]>> {
    let engines: &[&GeneralPurpose] = if strict {
        &[&B64URL]
    } else {
        &[&B64URL, &B64URL_PAD, &B64STD_NO_PAD, &B64STD]
    };
    let mut error = None;
    for engine in engines {
        match engine.decode_slice(s, buf) {
            Ok(len) => return Ok(Cow::Borrowed(&buf[..len])),
            Err(DecodeSliceError::DecodeError(e)) => error = Some(e),
            Err(DecodeSliceError::OutputSliceTooSmall) => {
                let decode = if strict {
                    b64url_decode_strict
                } else {
                    b64url_decode
                };
                return decode(s).map(Cow::Owned);
            }
        }
    }
    Err(Error::Base64(
        error.map(|e| e.to_string()).unwrap_or_default(),
    ))
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
    /// The base64url-encoded raw credential ID.
    pub id: String,
    /// Raw authenticator data, base64url-encoded.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature over `authenticatorData || SHA-256(clientDataJSON)`,
    /// base64url-encoded.
    pub signature: String,
    /// The clientDataJSON (UTF-8 JSON), base64url-encoded.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// User handle (the opaque user id registered with the credential),
    /// base64url-encoded. Always present for discoverable credentials;
    /// `finish_authentication` requires it in discoverable flows and
    /// compares it in flows started for a known user.
    #[serde(rename = "userHandle", default)]
    pub user_handle: Option<String>,
}

// ---------- Challenge JSON for the START side ---------------------------

/// What we send to the browser for `navigator.credentials.create()`.
/// All byte fields are base64url-encoded; the client JS is expected
/// to decode them before passing to the WebAuthn API.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct RegistrationChallenge {
    /// The challenge, base64url-encoded.
    pub challenge: String,
    /// The relying party.
    pub rp: RpInfo,
    /// The user the credential is created for.
    pub user: UserInfo,
    /// Accepted COSE algorithms, most preferred first.
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Credentials we already have for this user - browser SHOULD
    /// refuse to register a duplicate.
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    /// Ceremony timeout in milliseconds.
    pub timeout: u32,
    /// Authenticator attachment, resident key and user verification hints.
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    /// Attestation conveyance preference; always `"none"`.
    pub attestation: &'static str,
}

/// `rp` member of the registration options.
#[derive(Debug, Serialize)]
pub struct RpInfo {
    /// The relying party ID.
    pub id: String,
    /// Human-readable relying party name.
    pub name: String,
}

/// `user` member of the registration options.
#[derive(Debug, Serialize)]
pub struct UserInfo {
    /// The user handle, base64url-encoded.
    pub id: String,
    /// Account name, such as an email address.
    pub name: String,
    /// Name shown to the user.
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// One entry of `pubKeyCredParams`.
#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    /// Always `"public-key"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// COSE algorithm identifier.
    pub alg: i64,
}

/// One entry of `excludeCredentials` or `allowCredentials`.
#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    /// Always `"public-key"`.
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The credential ID, base64url-encoded.
    pub id: String,
    /// Transports the browser may try; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

/// `authenticatorSelection` member of the registration options.
#[derive(Debug, Serialize, Clone)]
#[non_exhaustive]
pub struct AuthenticatorSelection {
    /// Authenticator class from [`crate::Attachment`]: `"platform"` (the
    /// default), `"cross-platform"`, or omitted for any.
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<&'static str>,
    /// Discoverable credential preference; `"preferred"`.
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<&'static str>,
    /// `"required"` or `"preferred"`, following `require_user_verification`.
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

/// What we send to the browser for `navigator.credentials.get()`.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct AuthenticationChallenge {
    /// The challenge, base64url-encoded.
    pub challenge: String,
    /// The relying party ID.
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Ceremony timeout in milliseconds.
    pub timeout: u32,
    /// Credentials the browser may use; empty for discoverable flows.
    #[serde(rename = "allowCredentials", skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    /// `"required"` or `"preferred"`, following `require_user_verification`.
    #[serde(rename = "userVerification")]
    pub user_verification: &'static str,
}

// ---------- Ceremony state (server-side, opaque to client) --------------

/// Per-ceremony state retained between start_* and finish_*. Caller
/// stores this server-side keyed by however they like (session cookie,
/// user id, in-memory map). Treat as secret-ish: contains the
/// challenge we issued.
///
/// The state carries a `created_at` (Unix seconds, UTC) so callers can
/// reject stale ceremonies without needing their own out-of-band TTL.
/// `finish_*` ALSO enforces a hard ceiling (see
/// `Webauthn::CEREMONY_MAX_AGE_SECS`) so a forgetful caller cannot
/// accept a registration response from yesterday.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    /// The challenge issued to the browser.
    pub challenge: Challenge,
    /// The user handle the credential is created for.
    pub user_id: Vec<u8>,
    /// Unix timestamp (seconds, UTC) when `start_registration` was
    /// called. Stable serialization-friendly form.
    #[serde(default)]
    pub created_at: u64,
}

impl RegistrationState {
    /// `true` if more than `max_age_secs` seconds have elapsed since
    /// the ceremony was started. Cheap helper for callers that want
    /// to evict stale state from their session store proactively;
    /// `finish_registration` ALSO enforces its own ceiling.
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        now_secs().saturating_sub(self.created_at) > max_age_secs
    }
}

/// Per-ceremony state retained between `start_authentication*` and
/// `finish_authentication`; see [`RegistrationState`] for how to store it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    /// The challenge issued to the browser.
    pub challenge: Challenge,
    /// Credentials the browser was allowed to use, so finish_* can
    /// verify the asserted credential id is one of them.
    pub allow_credentials: Vec<CredentialId>,
    /// Unix timestamp (seconds, UTC) when `start_authentication` was
    /// called.
    #[serde(default)]
    pub created_at: u64,
    /// User handle the caller expects to authenticate. Populated by
    /// [`crate::Webauthn::start_authentication_for_user`] for
    /// username-first flows; left `None` for discoverable-credential
    /// (passwordless) flows where the user is not known until the
    /// response arrives.
    ///
    /// When `Some` AND the assertion response carries a `userHandle`,
    /// `finish_authentication` enforces equality (WebAuthn-3 §7.2 step
    /// 6). `#[serde(default)]` means states persisted by older
    /// versions of the crate deserialize cleanly with `None`.
    #[serde(default)]
    pub user_handle: Option<Vec<u8>>,
}

impl AuthenticationState {
    /// See [`RegistrationState::is_expired`].
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        now_secs().saturating_sub(self.created_at) > max_age_secs
    }
}

/// Current Unix time in seconds. Used to stamp ceremony states.
/// Saturates to 0 if the system clock is before the Unix epoch (which
/// will never happen on a sane host) so the helpers never panic.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- Outcomes ----------------------------------------------------

/// Stored after a successful registration. The caller persists this
/// (one row per credential per user) and looks it up at auth time.
///
/// `Serialize + Deserialize` are derived so callers can stash the
/// whole credential in a single column (e.g. a JSONB blob or a
/// `SecretString`-wrapped JSON string) without writing a wrapper struct.
/// The wire shape is the natural serde-of-struct mapping; field-level
/// derives on `CredentialId` and `CosePublicKey` produce base64-ish
/// transparent byte vecs.
///
/// The struct is `#[non_exhaustive]`: build one from stored parts with
/// [`PasskeyCredential::new`] and set the other public fields after.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PasskeyCredential {
    /// Credential ID the authenticator assigned.
    pub id: CredentialId,
    /// Credential public key as the COSE_Key the authenticator sent.
    pub public_key_cose: CosePublicKey,
    /// Last signature counter seen; update it from [`AuthSuccess::new_counter`].
    pub counter: u32,
    /// Transports the browser reported at registration.
    pub transports: Vec<String>,
    /// Authenticator AAGUID, as carried in attestedCredentialData.
    ///
    /// Informational only - this crate does NOT validate it against
    /// the FIDO Metadata Service or any allow/deny list. Callers who
    /// want authenticator-attestation policy (e.g. "reject Yubikeys
    /// older than firmware 5.2") must implement that check themselves
    /// using this field. With attestation "none" (our default), the
    /// AAGUID is all zeros anyway; meaningful values only appear when
    /// the client opts into a non-"none" attestation format.
    pub aaguid: [u8; 16],
    /// The authenticator's BE (backup eligible) flag: whether the
    /// credential can be synced or backed up. It is fixed for the life of
    /// the credential, so `finish_authentication` fails with
    /// [`Error::BackupEligibilityChanged`] when an assertion reports a
    /// different value (WebAuthn-3 §7.2 step 17).
    ///
    /// `None` means unknown: credentials stored by 0.1.x and 0.2.0 have
    /// no such field. The first assertion for such a credential is
    /// accepted with either value, and its
    /// [`AuthSuccess::backup_eligible`] is the value to store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_eligible: Option<bool>,
    /// The authenticator's BS (backed up) flag at the last ceremony:
    /// whether the credential is currently backed up. It may change
    /// between assertions; update it from [`AuthSuccess::backup_state`].
    /// `None` means unknown, as for [`Self::backup_eligible`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_state: Option<bool>,
}

impl PasskeyCredential {
    /// Builds a credential from stored parts, for callers that keep
    /// credentials in their own format. `transports` starts empty, `aaguid`
    /// all zeros and both backup flags unknown (`None`); set the public
    /// fields to the stored values where they are known.
    #[must_use]
    pub fn new(id: CredentialId, public_key_cose: CosePublicKey, counter: u32) -> Self {
        Self {
            id,
            public_key_cose,
            counter,
            transports: Vec::new(),
            aaguid: [0; 16],
            backup_eligible: None,
            backup_state: None,
        }
    }
}

/// Successful authentication outcome. Caller updates the stored
/// credential's `counter` to `new_counter`, `backup_eligible` to
/// `Some(backup_eligible)` and `backup_state` to `Some(backup_state)`
/// before responding.
///
/// `Serialize + Deserialize` are derived for symmetry with
/// [`PasskeyCredential`] — useful when an outer service wants to log
/// or forward the outcome as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AuthSuccess {
    /// The credential that signed the assertion.
    pub credential_id: CredentialId,
    /// Signature counter from the assertion, to store with the credential.
    pub new_counter: u32,
    /// Whether the authenticator set the UV flag.
    pub user_verified: bool,
    /// The assertion's BE (backup eligible) flag. Equal to the stored
    /// value when that is known; store it when the stored value is `None`.
    pub backup_eligible: bool,
    /// The assertion's BS (backed up) flag, to store with the credential.
    pub backup_state: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 5 bytes → 7 base64 chars + 1 pad char. Length is chosen so the
    /// padded variants actually carry a trailing `=`. The byte values
    /// include 0xFB which encodes to `+`/`-` (last alphabet slot) and
    /// 0xFF which encodes to `/`/`_`, so any alphabet confusion in the
    /// decoder surfaces here.
    const SAMPLE: &[u8] = &[0xFB, 0xEF, 0xBE, 0xFF, 0xCC];

    #[test]
    fn decodes_url_safe_no_pad() {
        // base64url-no-pad of SAMPLE
        let encoded = B64URL.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_url_safe_with_pad() {
        let encoded = B64URL_PAD.encode(SAMPLE);
        assert!(encoded.ends_with('=')); // sanity
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_standard_no_pad() {
        let encoded = B64STD_NO_PAD.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn decodes_standard_with_pad() {
        // The killer case: standard alphabet with padding, exactly
        // what `btoa(String.fromCharCode(...new Uint8Array(buf)))`
        // produces in browser JS.
        let encoded = B64STD.encode(SAMPLE);
        assert_eq!(b64url_decode(&encoded).unwrap(), SAMPLE);
    }

    #[test]
    fn rejects_garbage() {
        assert!(b64url_decode("!!!not-base64!!!").is_err());
    }

    #[test]
    fn decode_into_matches_decode() {
        for encoded in [
            B64URL.encode(SAMPLE),
            B64URL_PAD.encode(SAMPLE),
            B64STD_NO_PAD.encode(SAMPLE),
            B64STD.encode(SAMPLE),
            "!!!not-base64!!!".to_owned(),
        ] {
            for strict in [false, true] {
                let mut buf = [0u8; 64];
                let into = b64url_decode_into(&encoded, &mut buf, strict).map(Cow::into_owned);
                let decode = if strict {
                    b64url_decode_strict
                } else {
                    b64url_decode
                };
                assert_eq!(
                    into.ok(),
                    decode(&encoded).ok(),
                    "{encoded} strict={strict}"
                );
            }
        }
        let long = B64URL.encode([7u8; 200]);
        let mut small = [0u8; 8];
        let decoded = b64url_decode_into(&long, &mut small, true).unwrap();
        assert!(matches!(decoded, Cow::Owned(_)));
        assert_eq!(&*decoded, &[7u8; 200][..]);
    }

    // ---- RpId ----------------------------------------------------------

    #[test]
    fn rpid_new_stores_verbatim() {
        assert_eq!(RpId::new("example.com").as_str(), "example.com");
        // No magic stripping any more.
        assert_eq!(RpId::new("sub.example.com").as_str(), "sub.example.com");
    }

    #[test]
    fn rpid_try_from_url_bare_domain() {
        assert_eq!(
            RpId::try_from_url("example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_https_origin() {
        assert_eq!(
            RpId::try_from_url("https://example.com").unwrap().as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_with_port_and_path() {
        assert_eq!(
            RpId::try_from_url("https://example.com:8443/auth/start")
                .unwrap()
                .as_str(),
            "example.com",
        );
    }

    #[test]
    fn rpid_try_from_url_rejects_userinfo_in_bare() {
        // "user:pass@host" looks like a hostname but isn't one. The v1
        // implementation silently truncated to "user" - we reject.
        assert!(RpId::try_from_url("user:pass@example.com").is_err());
    }

    #[test]
    fn rpid_try_from_url_rejects_empty() {
        assert!(RpId::try_from_url("").is_err());
        assert!(RpId::try_from_url("   ").is_err());
    }

    // ── PasskeyCredential serde round-trip ────────────────────────────────
    // Callers persist a `PasskeyCredential` as a single JSON blob (e.g. a
    // SecretString-wrapped column on a `passkeys` row). The two tests
    // below pin the wire shape so a future field addition can't silently
    // break that storage contract.

    fn fixture_credential() -> PasskeyCredential {
        PasskeyCredential {
            id: CredentialId(vec![0x01, 0x02, 0x03, 0x04]),
            public_key_cose: CosePublicKey(vec![0xAA, 0xBB, 0xCC]),
            counter: 7,
            transports: vec!["usb".into(), "nfc".into()],
            aaguid: [0xFE; 16],
            backup_eligible: Some(true),
            backup_state: Some(false),
        }
    }

    #[test]
    fn passkey_credential_json_round_trips() {
        let original = fixture_credential();
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: PasskeyCredential = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.id.0, original.id.0);
        assert_eq!(back.public_key_cose.0, original.public_key_cose.0);
        assert_eq!(back.counter, original.counter);
        assert_eq!(back.transports, original.transports);
        assert_eq!(back.aaguid, original.aaguid);
        assert_eq!(back.backup_eligible, original.backup_eligible);
        assert_eq!(back.backup_state, original.backup_state);
    }

    #[test]
    fn passkey_credential_json_without_backup_flags_loads_as_unknown() {
        let wire = r#"{"id":[1,2],"public_key_cose":[170],"counter":3,"transports":[],"aaguid":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
        let credential: PasskeyCredential = serde_json::from_str(wire).expect("deserialise");
        assert_eq!(credential.backup_eligible, None);
        assert_eq!(credential.backup_state, None);
        assert_eq!(serde_json::to_string(&credential).expect("serialise"), wire);
    }

    #[test]
    fn passkey_credential_new_leaves_optional_parts_unset() {
        let credential =
            PasskeyCredential::new(CredentialId(vec![9]), CosePublicKey(vec![0xA0]), 4);
        assert_eq!(credential.id.as_bytes(), [9]);
        assert_eq!(credential.public_key_cose.as_bytes(), [0xA0]);
        assert_eq!(credential.counter, 4);
        assert!(credential.transports.is_empty());
        assert_eq!(credential.aaguid, [0; 16]);
        assert_eq!(credential.backup_eligible, None);
        assert_eq!(credential.backup_state, None);
    }

    #[test]
    fn auth_success_json_round_trips() {
        let original = AuthSuccess {
            credential_id: CredentialId(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            new_counter: 42,
            user_verified: true,
            backup_eligible: true,
            backup_state: true,
        };
        let wire = serde_json::to_string(&original).expect("serialise");
        let back: AuthSuccess = serde_json::from_str(&wire).expect("deserialise");
        assert_eq!(back.credential_id.0, original.credential_id.0);
        assert_eq!(back.new_counter, original.new_counter);
        assert_eq!(back.user_verified, original.user_verified);
        assert_eq!(back.backup_eligible, original.backup_eligible);
        assert_eq!(back.backup_state, original.backup_state);
    }
}
