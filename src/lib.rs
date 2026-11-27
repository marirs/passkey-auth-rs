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
//! // → persist credential.id, credential.public_key_cose, credential.counter
//!
//! // Authentication ----------------------------------------------------
//! let (challenge, state) = wa.start_authentication(&[credential.id.clone()]);
//! // → send `challenge` to the browser
//! # let response: passkey_auth::AuthenticationResponse = unimplemented!();
//! let outcome = wa.finish_authentication(&state, &response, &credential).expect("ok");
//! // → update stored credential.counter = outcome.new_counter
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
#[cfg(feature = "__internals")]
#[doc(hidden)]
pub mod internals;
mod types;
mod x509;

pub use ceremony::{Attachment, Webauthn};
pub use error::{Error, Result};
pub use types::{
    AuthSuccess, AuthenticationChallenge, AuthenticationResponse, AuthenticationState, Challenge,
    CosePublicKey, CredentialId, PasskeyCredential, RegistrationChallenge, RegistrationResponse,
    RegistrationState, RpId,
};
