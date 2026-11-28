//! Pure-Rust WebAuthn server library, narrowed to the passkey
//! ceremony. See `README.md` for scope and motivation.
//!
//! Credentials can use ES256, EdDSA and RS256, and with the `pqc`
//! feature ML-DSA-44, ML-DSA-65 and ML-DSA-87
//! (`Webauthn::allow_ml_dsa`). Attestation formats `none`, `packed` and
//! `fido-u2f` are verified; certificate chains are not validated against
//! a root.
//!
//! Quickstart:
//! ```no_run
//! use passkey_auth::Webauthn;
//!
//! let wa = Webauthn::new("example.com", "Example", "https://example.com");
//!
//! // Registration ------------------------------------------------------
//! let (challenge, state) = wa.start_registration(
//!     b"user-handle-bytes",
//!     "alice@example.com",
//!     "Alice",
//!     &[], // no existing credentials yet
//! );
//! // → send `challenge` to the browser as JSON
//! // ← browser POSTs a `RegistrationResponse` back
//! # let response: passkey_auth::RegistrationResponse = unimplemented!();
//! let credential = wa.finish_registration(&state, &response).expect("ok");
//! // → persist the credential: id, public_key_cose, counter, transports,
//! //   aaguid, backup_eligible, backup_state (or serialise it as JSON)
//!
//! // Authentication ----------------------------------------------------
//! let (challenge, state) = wa.start_authentication(&[credential.id.clone()]);
//! // → send `challenge` to the browser
//! # let response: passkey_auth::AuthenticationResponse = unimplemented!();
//! let outcome = wa.finish_authentication(&state, &response, &credential).expect("ok");
//! // → update the stored credential:
//! //   counter = outcome.new_counter
//! //   backup_eligible = Some(outcome.backup_eligible)
//! //   backup_state = Some(outcome.backup_state)
//! ```
//!
//! Credentials kept in another format convert with
//! [`PasskeyCredential::new`]:
//! ```
//! use passkey_auth::{CosePublicKey, CredentialId, PasskeyCredential};
//!
//! # let (id, cose_key, counter) = (vec![1u8], vec![0xa0u8], 0u32);
//! let mut credential = PasskeyCredential::new(CredentialId(id), CosePublicKey(cose_key), counter);
//! credential.transports = vec!["internal".to_owned()];
//! // Leave the backup flags `None` when they were not stored: the next
//! // assertion's values are accepted and returned in `AuthSuccess`.
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

mod attestation;
mod auth_data;
mod cbor;
mod ceremony;
mod client_data;
mod cose;
mod crypto;
pub mod error;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod internals;
mod types;
mod x509;

pub use ceremony::{Attachment, Webauthn};
pub use error::{Error, Result};
pub use types::{
    AuthSuccess, AuthenticationChallenge, AuthenticationResponse, AuthenticationState,
    AuthenticatorSelection, Challenge, CosePublicKey, CredentialDescriptor, CredentialId,
    PasskeyCredential, PubKeyCredParam, RegistrationChallenge, RegistrationResponse,
    RegistrationState, RpId, RpInfo, UserInfo,
};
