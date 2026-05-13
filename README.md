# passkey-auth

[![CI](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/passkey-auth.svg)](https://crates.io/crates/passkey-auth)
[![docs.rs](https://img.shields.io/docsrs/passkey-auth)](https://docs.rs/passkey-auth)
[![License](https://img.shields.io/crates/l/passkey-auth.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://blog.rust-lang.org/)
[![Dependencies](https://deps.rs/repo/github/marirs/passkey-auth/status.svg)](https://deps.rs/repo/github/marirs/passkey-auth)

Pure-Rust WebAuthn server library focused on the passkey ceremony.
Verifies registration + authentication responses from browsers/OS
authenticators (Touch ID, Windows Hello, Android, iCloud Keychain,
hardware keys).

## Installation

```toml
[dependencies]
passkey-auth = "0.1"
```

MSRV: **Rust 1.85** (edition 2024).

## Why this exists

The reference Rust server library, `webauthn-rs`, hard-depends on
`openssl`. This crate is the alternative for projects that ship
rustcrypto end-to-end:

| Concern                | This crate                                                     | webauthn-rs              |
|------------------------|----------------------------------------------------------------|--------------------------|
| ECDSA P-256 verify     | [`p256`](https://crates.io/crates/p256)                        | openssl                  |
| Ed25519 verify         | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)      | openssl                  |
| SHA-256                | [`sha2`](https://crates.io/crates/sha2)                        | openssl                  |
| CBOR                   | [`ciborium`](https://crates.io/crates/ciborium)                | serde_cbor (deprecated)  |
| Attestation cert chain | Not implemented (none + packed-self only)                      | full X.509 + FIDO MDS    |

## Scope

- Registration ceremony (parse `AuthenticatorAttestationResponse`, verify origin/challenge, extract public key)
- Authentication ceremony (parse `AuthenticatorAssertionResponse`, verify signature)
- Algorithms: **ES256** (COSE alg -7, P-256 ECDSA) and **EdDSA** (-8, Ed25519)
- Attestation formats:
  - `none` (fully)
  - `packed` self-attestation (no cert chain)
  - `packed` with `x5c` cert chain (cert sig verified; chain NOT validated to a root)
  - `fido-u2f` (legacy Yubikeys; cert sig verified, chain NOT validated)
- Replay protection via the authenticator counter
- Opt-in **user-verification enforcement** for production passkey deployments
- Configurable **authenticator attachment** (platform / cross-platform / any) — see [`Attachment`](https://docs.rs/passkey-auth/latest/passkey_auth/enum.Attachment.html)
- Permissive base64 decoding: accepts url-safe / standard / padded / unpadded inputs

Not in scope:

- **Cert chain validation against a trusted root.** Without the FIDO
  Metadata Service we cannot tell whether an `x5c` cert really came
  from Yubico / Feitian / etc.; we only confirm the attestation `sig`
  was produced by whoever owns the leaf cert's private key. For "only
  these specific authenticator models" enterprise policy, you need
  full MDS — this crate is not the right pick.
- Conditional UI / discoverable credentials beyond what the server needs to know
- RSA / RS256 (rare for passkeys; reject with a clear error)
- TPM / Android-Key / Android-SafetyNet / Apple attestation formats

## Usage

```rust,ignore
use passkey_auth::{
    AuthenticationResponse, PasskeyCredential, RegistrationResponse, Webauthn,
};

// Construct once at boot. Cheap to clone.
// `require_user_verification(true)` makes the server reject any
// ceremony where the authenticator did not set the UV bit -
// what you want for production passkey deployments.
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .require_user_verification(true);

// ── 1. Registration ───────────────────────────────────────────────
let (challenge, state) = wa.start_registration(
    b"user-handle-bytes",  // stable opaque user id
    "alice@example.com",   // user.name  (RP-facing)
    "Alice",               // user.displayName
    &[],                   // credentials already registered (for excludeCredentials)
);
// → serialise `challenge` to JSON, send to the browser
// ← browser POSTs back a RegistrationResponse JSON
let response: RegistrationResponse = todo!();

let credential: PasskeyCredential = wa.finish_registration(&state, &response)?;
// Persist: credential.id, credential.public_key_cose,
//          credential.counter, credential.transports, credential.aaguid

// ── 2. Authentication ─────────────────────────────────────────────
// Pass the user's stored credentials so the browser gets the right
// transport hints (USB / NFC / BLE / internal).
let (challenge, state) = wa.start_authentication_with_creds(&[credential.clone()]);
let response: AuthenticationResponse = todo!();

let outcome = wa.finish_authentication(&state, &response, &credential)?;
// Update stored counter: credential.counter = outcome.new_counter
```

### RP ID parsing from URLs

`Webauthn::new` takes the bare domain (no scheme, no port). If the
value might be a full URL (config file, env var pasted by an operator),
validate it first:

```rust,ignore
use passkey_auth::RpId;

let rp = RpId::try_from_url("https://example.com:8443/auth")?;
assert_eq!(rp.as_str(), "example.com");
```

`RpId::new` itself stores its input verbatim — pass a bare hostname
or call `try_from_url` first.

### Client-side encoding

The browser's `AuthenticatorResponse` fields (`attestationObject`,
`authenticatorData`, `clientDataJSON`, `signature`) are
`ArrayBuffer`s; the JS layer must base64-encode them before posting.
This crate accepts **either** url-safe-base64 **or** standard-base64,
with **or** without padding — so the obvious `btoa(...)` pattern works
without a separate url-safe-conversion step.

## Working examples

Two runnable HTTP servers live under [`examples/`](examples/), one
per popular Rust web framework. Both expose the same four endpoints
(`/register/start`, `/register/finish`, `/authenticate/start`,
`/authenticate/finish`) and serve the same browser-side HTML page.

```bash
cargo run --example axum_server     # Axum 0.7
cargo run --example rocket_server   # Rocket 0.5
```

Open <http://localhost:3000> in a passkey-capable browser. Works
with Touch ID, Windows Hello, iCloud Keychain, Yubikey, and any
other passkey-class authenticator the browser surfaces.

## Testing

```bash
cargo test            # unit + integration + doc-tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI exercises Linux x86_64 + aarch64, macOS Apple Silicon, and
Windows x86_64 on every push.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](APACHE-LICENSE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>)

at your option.
