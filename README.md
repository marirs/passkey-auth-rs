# passkey-auth

Pure-Rust WebAuthn server library focused on the passkey ceremony.
Verifies registration + authentication responses from browsers/OS
authenticators (Touch ID, Windows Hello, Android, iCloud Keychain,
hardware keys).

## Why this exists

The reference Rust server library, `webauthn-rs`, hard-depends on
`openssl`. This crate is the alternative for projects that ship
rustcrypto end-to-end:

| Concern | This crate | webauthn-rs |
|---|---|---|
| ECDSA P-256 verify | [`p256`](https://crates.io/crates/p256) | openssl |
| Ed25519 verify | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) | openssl |
| SHA-256 | [`sha2`](https://crates.io/crates/sha2) | openssl |
| CBOR | [`ciborium`](https://crates.io/crates/ciborium) | serde_cbor (deprecated) |
| Attestation cert chain | Not implemented (none + packed-self only) | full X.509 + FIDO MDS |

## Scope

- Registration ceremony (parse `AuthenticatorAttestationResponse`, verify origin/challenge, extract public key)
- Authentication ceremony (parse `AuthenticatorAssertionResponse`, verify signature)
- Algorithms: ES256 (COSE alg -7, P-256 ECDSA) and EdDSA (-8, Ed25519)
- Attestation formats: `none` (fully) and `packed` self-attestation (no cert chain)
- Replay protection via the authenticator counter

Not in scope:
- Full attestation cert chain validation (FIDO MDS)
- Conditional UI / discoverable credentials beyond what the server needs to know
- RSA / RS256 (rare for passkeys; reject with a clear error)

## Usage

```rust
use passkey_auth::{Webauthn, RegistrationResponse, AuthenticationResponse};

let wa = Webauthn::new("example.com", "Example", "https://example.com")?;

// 1. Registration
let (challenge, state) = wa.start_registration(
    user_id,        // stable opaque user id (raw bytes)
    "alice@x.com",  // user.name (RP-facing)
    "Alice",        // user.displayName (RP-facing)
    &existing,      // credentials already registered to this user
);
// ... send challenge to browser, get the response back ...
let credential = wa.finish_registration(state, response)?;
// store credential.id, credential.public_key_cose, credential.counter

// 2. Authentication
let (challenge, state) = wa.start_authentication(&[stored_credential_id]);
// ... browser produces an assertion ...
let outcome = wa.finish_authentication(state, response, &stored_credential)?;
// update stored_credential.counter = outcome.new_counter
```

## License

MIT OR Apache-2.0
