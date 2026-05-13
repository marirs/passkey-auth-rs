//! High-level register / authenticate flow. Wires the parsers + the
//! crypto layer together into the WebAuthn ceremony state machine.

use sha2::{Digest, Sha256};

use crate::attestation::ParsedAttestation;
use crate::auth_data::AuthenticatorData;
use crate::client_data::{self, TYPE_AUTHENTICATE, TYPE_REGISTER};
use crate::cose::{ALG_EDDSA, ALG_ES256, CoseKey};
use crate::crypto;
use crate::error::{Error, Result};
use crate::types::{
    AuthSuccess, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    AuthenticatorSelection, Challenge, CosePublicKey, CredentialDescriptor, CredentialId,
    PasskeyCredential, PubKeyCredParam, RegistrationChallenge, RegistrationResponse,
    RegistrationState, RpId, RpInfo, UserInfo, b64url_decode,
};

const CEREMONY_TIMEOUT_MS: u32 = 60_000;

/// The relying-party-side WebAuthn façade. Construct once at boot and
/// re-use for every ceremony. Cheap to clone; carries only `String`s
/// internally.
#[derive(Debug, Clone)]
pub struct Webauthn {
    rp_id: RpId,
    rp_name: String,
    origin: String,
    /// When `true`, finish_registration and finish_authentication
    /// fail with Error::UserNotVerified if the authenticator did not
    /// set the UV flag. This is what a production passkey deployment
    /// almost always wants - the user has to prove identity (Touch
    /// ID, biometric, PIN), not just presence (any button press).
    require_uv: bool,
}

impl Webauthn {
    /// `rp_id` is the bare domain (e.g. `"example.com"`). `origin` is
    /// the full scheme+host (e.g. `"https://example.com"`); it must
    /// match exactly what the browser puts into `clientDataJSON.origin`.
    ///
    /// Defaults to NOT requiring user verification on the server side;
    /// the JSON challenges still ask for `userVerification: "preferred"`.
    /// Call [`Self::require_user_verification`] to flip the server
    /// check to strict before using it in production.
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> Self {
        Self {
            rp_id: RpId::new(rp_id),
            rp_name: rp_name.to_owned(),
            origin: origin.to_owned(),
            require_uv: false,
        }
    }

    /// Builder method: when set to `true`, the server REJECTS any
    /// ceremony where the authenticator did not set the UV flag.
    /// Recommended for any deployment where presence-only credentials
    /// (e.g. a button press on a roaming key) should not count as
    /// authentication.
    ///
    /// Also tightens the challenge sent to the browser to ask for
    /// `userVerification: "required"`, so a compliant browser will
    /// not even attempt a UV-less assertion.
    #[must_use]
    pub fn require_user_verification(mut self, require: bool) -> Self {
        self.require_uv = require;
        self
    }

    pub fn rp_id(&self) -> &str {
        self.rp_id.as_str()
    }

    /// The `userVerification` string we put into the challenge JSON.
    /// Mirrors `require_uv`: "required" if strict, "preferred" otherwise.
    fn uv_token(&self) -> &'static str {
        if self.require_uv {
            "required"
        } else {
            "preferred"
        }
    }

    // ─── Registration ─────────────────────────────────────────────────

    /// Build the challenge to feed to `navigator.credentials.create()`.
    /// Returned `RegistrationState` is what the caller must hand back
    /// to `finish_registration` (typically stashed in a session-keyed
    /// map with a short TTL).
    pub fn start_registration(
        &self,
        user_id: &[u8],
        user_name: &str,
        user_display_name: &str,
        existing: &[CredentialId],
    ) -> (RegistrationChallenge, RegistrationState) {
        let challenge = Challenge::random();
        let exclude = existing
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.to_b64url(),
                transports: Vec::new(),
            })
            .collect();
        let chal = RegistrationChallenge {
            challenge: challenge.to_b64url(),
            rp: RpInfo {
                id: self.rp_id.as_str().to_owned(),
                name: self.rp_name.clone(),
            },
            user: UserInfo {
                id: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    user_id,
                ),
                name: user_name.to_owned(),
                display_name: user_display_name.to_owned(),
            },
            // Algorithm preference, MOST-preferred first per the
            // WebAuthn spec. ES256 leads because every passkey-class
            // authenticator (Touch ID, Windows Hello, Android, Yubikey)
            // implements it; EdDSA is a fallback for the small set of
            // authenticators that prefer Ed25519 (some Yubikey 5+).
            pub_key_cred_params: vec![
                PubKeyCredParam {
                    kind: "public-key",
                    alg: ALG_ES256,
                },
                PubKeyCredParam {
                    kind: "public-key",
                    alg: ALG_EDDSA,
                },
            ],
            exclude_credentials: exclude,
            timeout: CEREMONY_TIMEOUT_MS,
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: Some("platform"),
                resident_key: Some("preferred"),
                user_verification: self.uv_token(),
            },
            attestation: "none",
        };
        let state = RegistrationState {
            challenge,
            user_id: user_id.to_vec(),
        };
        (chal, state)
    }

    /// Verify the registration response. On success returns the
    /// `PasskeyCredential` the caller persists.
    pub fn finish_registration(
        &self,
        state: &RegistrationState,
        response: &RegistrationResponse,
    ) -> Result<PasskeyCredential> {
        // 1. Validate clientDataJSON.
        let cdj_raw = client_data::validate(
            &response.client_data_json,
            TYPE_REGISTER,
            &state.challenge,
            &self.origin,
        )?;
        let cdj_hash = sha256_32(&cdj_raw);

        // 2. Parse the attestation object.
        let att_bytes = b64url_decode(&response.attestation_object)?;
        let att = ParsedAttestation::parse(&att_bytes)?;

        // 3. rpIdHash check.
        let want_rp_hash = sha256_32(self.rp_id.as_str().as_bytes());
        if att.auth_data.rp_id_hash != want_rp_hash {
            return Err(Error::RpIdHashMismatch);
        }

        // 4. User-present is mandatory for registration. UV is gated
        // by `require_uv` - opt-in strict mode for production passkey
        // deployments where presence-only must not count.
        if !att.auth_data.user_present() {
            return Err(Error::UserNotPresent);
        }
        if self.require_uv && !att.auth_data.user_verified() {
            return Err(Error::UserNotVerified);
        }

        // 5. AT flag MUST be set on registration; we need the attested
        // credential data to extract the public key.
        let attested = att
            .auth_data
            .attested
            .as_ref()
            .ok_or(Error::AuthData("registration authData missing AT flag"))?;

        // 6. Parse the COSE public key and verify any attestation
        // statement signed by it.
        let cose = CoseKey::parse(attested.public_key_cose.as_bytes())?;
        att.verify_statement(&cose, &cdj_hash)?;

        // 7. Build the persisted credential.
        Ok(PasskeyCredential {
            id: attested.credential_id.clone(),
            public_key_cose: CosePublicKey(attested.public_key_cose.as_bytes().to_vec()),
            counter: att.auth_data.sign_count,
            transports: response.transports.clone(),
            aaguid: attested.aaguid,
        })
    }

    // ─── Authentication ───────────────────────────────────────────────

    /// Build the challenge to feed to `navigator.credentials.get()`.
    /// `allow_credentials` SHOULD be the user's registered credential
    /// IDs; can be empty for discoverable-credential ("usernameless")
    /// flows.
    ///
    /// Convenience form that omits the `transports` hint in the
    /// challenge JSON. Browsers will fall back to "try every transport"
    /// which usually works but adds a small UX delay (e.g. the browser
    /// may briefly poll for BLE devices that the credential cannot
    /// actually use). For best UX, prefer
    /// [`Self::start_authentication_with_creds`] which threads the
    /// per-credential transports captured at registration.
    pub fn start_authentication(
        &self,
        allow_credentials: &[CredentialId],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.to_b64url(),
                transports: Vec::new(),
            })
            .collect();
        self.build_auth_challenge(allow_credentials, descriptors)
    }

    /// Like [`Self::start_authentication`] but pulls the `transports`
    /// hint from each stored credential. This is the version a real
    /// deployment usually wants: the browser narrows authenticator
    /// discovery to the channels we know work for the credential
    /// (e.g. "internal" for Touch ID, "usb" + "nfc" for a Yubikey).
    pub fn start_authentication_with_creds(
        &self,
        allow_credentials: &[PasskeyCredential],
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let descriptors = allow_credentials
            .iter()
            .map(|c| CredentialDescriptor {
                kind: "public-key",
                id: c.id.to_b64url(),
                transports: c.transports.clone(),
            })
            .collect();
        let ids: Vec<CredentialId> = allow_credentials.iter().map(|c| c.id.clone()).collect();
        self.build_auth_challenge(&ids, descriptors)
    }

    /// Internal: assemble the challenge JSON + state from already-built
    /// descriptors. Shared by both `start_authentication*` entry points.
    fn build_auth_challenge(
        &self,
        ids: &[CredentialId],
        descriptors: Vec<CredentialDescriptor>,
    ) -> (AuthenticationChallenge, AuthenticationState) {
        let challenge = Challenge::random();
        let chal = AuthenticationChallenge {
            challenge: challenge.to_b64url(),
            rp_id: self.rp_id.as_str().to_owned(),
            timeout: CEREMONY_TIMEOUT_MS,
            allow_credentials: descriptors,
            user_verification: self.uv_token(),
        };
        let state = AuthenticationState {
            challenge,
            allow_credentials: ids.to_vec(),
        };
        (chal, state)
    }

    /// Verify the assertion. `stored` is the credential the caller
    /// looked up by `response.id`.
    pub fn finish_authentication(
        &self,
        state: &AuthenticationState,
        response: &AuthenticationResponse,
        stored: &PasskeyCredential,
    ) -> Result<AuthSuccess> {
        // 1. The asserted credential ID must be one of the ones we
        // told the browser was acceptable (if we gave a non-empty
        // allow list), and it must be the stored one.
        let asserted_id = CredentialId::from_b64url(&response.id)?;
        if !state.allow_credentials.is_empty()
            && !state.allow_credentials.iter().any(|c| c == &asserted_id)
        {
            return Err(Error::BadSignature);
        }
        if asserted_id != stored.id {
            return Err(Error::BadSignature);
        }

        // 2. Validate clientDataJSON.
        let cdj_raw = client_data::validate(
            &response.client_data_json,
            TYPE_AUTHENTICATE,
            &state.challenge,
            &self.origin,
        )?;
        let cdj_hash = sha256_32(&cdj_raw);

        // 3. Parse + check authenticator data.
        let ad_bytes = b64url_decode(&response.authenticator_data)?;
        let ad = AuthenticatorData::parse(&ad_bytes)?;
        let want_rp_hash = sha256_32(self.rp_id.as_str().as_bytes());
        if ad.rp_id_hash != want_rp_hash {
            return Err(Error::RpIdHashMismatch);
        }
        if !ad.user_present() {
            return Err(Error::UserNotPresent);
        }
        if self.require_uv && !ad.user_verified() {
            return Err(Error::UserNotVerified);
        }

        // 4. Verify the signature: signedMsg = authData || cdjHash.
        let key = CoseKey::parse(stored.public_key_cose.as_bytes())?;
        let sig = b64url_decode(&response.signature)?;
        let mut msg = Vec::with_capacity(ad_bytes.len() + 32);
        msg.extend_from_slice(&ad_bytes);
        msg.extend_from_slice(&cdj_hash);
        crypto::verify(&key, &msg, &sig)?;

        // 5. Counter check. Per the spec: if BOTH signCount and the
        // stored counter are 0, the credential never increments -
        // accept. Otherwise the new count MUST be strictly greater
        // than the stored value; anything else is a likely cloned
        // credential.
        let either_nonzero = ad.sign_count != 0 || stored.counter != 0;
        if either_nonzero && ad.sign_count <= stored.counter {
            return Err(Error::CounterReplay {
                stored: stored.counter,
                new: ad.sign_count,
            });
        }

        Ok(AuthSuccess {
            credential_id: asserted_id,
            new_counter: ad.sign_count,
            user_verified: ad.user_verified(),
        })
    }
}

/// SHA-256 helper that returns the 32-byte array (not a `Vec`) so
/// rpIdHash comparison is a stack-allocated `==`.
fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}
