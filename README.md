# passkey-auth

[![CI](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/passkey-auth/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/passkey-auth.svg)](https://crates.io/crates/passkey-auth)
[![docs.rs](https://img.shields.io/docsrs/passkey-auth)](https://docs.rs/passkey-auth)
[![License](https://img.shields.io/crates/l/passkey-auth.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue.svg)](https://blog.rust-lang.org/)
[![Dependencies](https://deps.rs/repo/github/marirs/passkey-auth/status.svg)](https://deps.rs/repo/github/marirs/passkey-auth)

Pure-Rust WebAuthn server library focused on the passkey ceremony.
Verifies registration + authentication responses from browsers/OS
authenticators (Touch ID, Windows Hello, Android, iCloud Keychain,
hardware keys).

## Installation

```toml
[dependencies]
passkey-auth = "0.3"
```

With ML-DSA (post-quantum) credentials:

```toml
[dependencies]
passkey-auth = { version = "0.3", features = ["pqc"] }
```

MSRV: **Rust 1.89** (edition 2024).

## Why this exists

The reference Rust server library, `webauthn-rs`, hard-depends on
`openssl`. This crate is the alternative for projects that ship
rustcrypto end-to-end:

| Concern                | This crate                                                     | webauthn-rs              |
|------------------------|----------------------------------------------------------------|--------------------------|
| ECDSA P-256 verify     | [`p256`](https://crates.io/crates/p256)                        | openssl                  |
| Ed25519 verify         | [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)      | openssl                  |
| RSA PKCS#1 v1.5 verify | [`rsa`](https://crates.io/crates/rsa) (public-key operations)  | openssl                  |
| ML-DSA verify          | [`ml-dsa`](https://crates.io/crates/ml-dsa) (`pqc` feature)    | not supported            |
| SHA-256                | [`sha2`](https://crates.io/crates/sha2)                        | openssl                  |
| CBOR                   | built-in borrowing decoder                                     | serde_cbor (deprecated)  |
| Attestation chain      | x5c sig verified, root NOT validated                           | full X.509 + FIDO MDS    |

## Scope

- Registration ceremony (parse `AuthenticatorAttestationResponse`, verify origin/challenge, extract public key)
- Authentication ceremony (parse `AuthenticatorAssertionResponse`, verify signature)
- Algorithms, in the order `pubKeyCredParams` offers them:
  - **ML-DSA-44, ML-DSA-65, ML-DSA-87** (COSE alg -48, -49, -50; FIPS 204, AKP keys per RFC 9964) with the `pqc` feature and `.allow_ml_dsa(true)`
  - **ES256** (-7, P-256 ECDSA)
  - **EdDSA** (-8, Ed25519)
  - **RS256** (-257, RSASSA-PKCS1-v1_5 with SHA-256; Windows Hello and TPM keys). Moduli outside 2048-4096 bits and public exponents that are even, below 3 or above 2^32 - 1 are refused.

  The credential's alg is enforced at registration against the advertised list (WebAuthn-3 §7.1 step 19); `Webauthn::allowed_algs` returns it.
- Attestation formats:
  - `none` (fully)
  - `packed` self-attestation (no cert chain), for every algorithm above
  - `packed` with `x5c` cert chain, ES256 (P-256 cert) or RS256 (RSA cert): cert sig and the WebAuthn-3 §8.2.1 certificate requirements verified; chain NOT validated to a root
  - `fido-u2f` (legacy Yubikeys; exactly one P-256 cert; cert sig verified, chain NOT validated)
- Replay protection via the authenticator counter
- Backup flags: BS (backed up) without BE (backup eligible) is refused in both ceremonies. The credential stores BE and BS; an assertion whose BE differs from the stored BE is refused (WebAuthn-3 §7.2 step 17), and the new BS is returned for the caller to store
- Ceremonies run in a cross-origin iframe (`crossOrigin: true` or a `topOrigin`) are refused
- Opt-in **user-verification enforcement** for production passkey deployments (`.require_user_verification(true)`)
- Opt-in **user-handle enforcement** for username-first flows (`start_authentication_for_user` + `.require_user_handle(true)`) — verifies the assertion's `userHandle` matches the expected user (WebAuthn-3 §7.2 step 6)
- Discoverable (usernameless) flows require the assertion's `userHandle` (WebAuthn-3 §7.2 step 6)
- Configurable **authenticator attachment** (platform / cross-platform / any) — see [`Attachment`](https://docs.rs/passkey-auth/latest/passkey_auth/enum.Attachment.html)
- Base64 decoding: lenient by default (accepts url-safe / standard / padded / unpadded inputs); flip `.strict_base64(true)` to require spec-compliant url-safe-no-pad

Not in scope:

- **Cert chain validation against a trusted root.** Without the FIDO
  Metadata Service we cannot tell whether an `x5c` cert really came
  from Yubico / Feitian / etc.; we only confirm the attestation `sig`
  was produced by whoever owns the leaf cert's private key. For "only
  these specific authenticator models" enterprise policy, you need
  full MDS — this crate is not the right pick.
- Conditional UI / discoverable credentials beyond what the server needs to know
- TPM / Android-Key / Android-SafetyNet / Apple attestation formats
- Cross-origin iframe ceremonies and multiple origins per relying party

## Usage

```rust,ignore
use passkey_auth::{
    AuthenticationResponse, PasskeyCredential, RegistrationResponse, Webauthn,
};

// Construct once at boot. Cheap to clone. Production-tightening
// builders:
//   .require_user_verification(true)  reject UV-less assertions
//   .require_user_handle(true)        reject assertions missing the
//                                     userHandle in for_user flows
//   .strict_base64(true)              reject non-spec base64 on wire
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .require_user_verification(true);

// ── 1. Registration ───────────────────────────────────────────────
let user_id: &[u8] = b"user-handle-bytes"; // stable opaque user id
let (challenge, state) = wa.start_registration(
    user_id,
    "alice@example.com",   // user.name  (RP-facing)
    "Alice",               // user.displayName
    &[],                   // credentials already registered (for excludeCredentials)
);
// → serialise `challenge` to JSON, send to the browser
// ← browser POSTs back a RegistrationResponse JSON
let response: RegistrationResponse = todo!();

let credential: PasskeyCredential = wa.finish_registration(&state, &response)?;
// Persist: credential.id, credential.public_key_cose,
//          credential.counter, credential.transports, credential.aaguid,
//          credential.backup_eligible, credential.backup_state

// ── 2. Authentication (username-first flow) ───────────────────────
// `_for_user` records the user_handle on the state so
// finish_authentication can verify the assertion is FOR this user
// (WebAuthn-3 §7.2 step 6) — defence in depth against credential-id
// collisions in a multi-user store.
//
// Use plain `start_authentication_with_creds(&creds)` for
// discoverable / passwordless flows where the user is unknown
// until the response arrives — see examples/axum_passwordless.rs.
let (challenge, state) = wa.start_authentication_with_creds_for_user(
    user_id,
    &[credential.clone()],
);
let response: AuthenticationResponse = todo!();

let outcome = wa.finish_authentication(&state, &response, &credential)?;
// Update the stored credential:
//   credential.counter = outcome.new_counter;
//   credential.backup_eligible = Some(outcome.backup_eligible);
//   credential.backup_state = Some(outcome.backup_state);
```

### Post-quantum credentials (`pqc` feature)

The `pqc` feature adds ML-DSA (FIPS 204) verification through the
RustCrypto [`ml-dsa`](https://crates.io/crates/ml-dsa) crate. The
relying party then opts in at runtime:

```rust,ignore
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .allow_ml_dsa(true);
// pubKeyCredParams: ML-DSA-44, ML-DSA-65, ML-DSA-87, ES256, EdDSA, RS256
```

Authenticators that implement ML-DSA register an ML-DSA credential;
all others pick ES256, EdDSA or RS256 further down the list, so no
user is locked out. Signatures use the pure ML-DSA mode with an empty
context string, as RFC 9964 requires. A build with the `pqc` feature
verifies ML-DSA credentials at sign-in whether or not `allow_ml_dsa`
is set; without the feature they fail with `Error::UnsupportedAlg`.

Without the feature the crate verifies ES256, EdDSA and RS256 only and
does not compile `ml-dsa`.

### Stored credentials

`PasskeyCredential` JSON stored by 0.1.x and 0.2.0 deserialises and
verifies unchanged, and serialises back to the same bytes
(`tests/compat_0_1_3.rs` checks this against credentials produced by
the published 0.1.3 crate).

Those credentials have no backup flags: `backup_eligible` and
`backup_state` are `None` (unknown). The first assertion is accepted
with either BE value, and `AuthSuccess::backup_eligible` and
`AuthSuccess::backup_state` carry the values to store. From then on an
assertion with a different BE fails with
`Error::BackupEligibilityChanged`. BS may change at any sign-in.

`PasskeyCredential` and `AuthSuccess` are `#[non_exhaustive]`. To turn
a credential kept in your own format into a `PasskeyCredential`, use
the constructor and set the other public fields:

```rust,ignore
use passkey_auth::{CosePublicKey, CredentialId, PasskeyCredential};

let mut credential = PasskeyCredential::new(
    CredentialId(row.id),
    CosePublicKey(row.cose_key), // COSE_Key bytes, as the authenticator sent them
    row.counter,
);
credential.transports = row.transports;
credential.backup_eligible = row.backup_eligible; // Option<bool>, None if never stored
credential.backup_state = row.backup_state;
```

`Error` is `#[non_exhaustive]` too, so a `match` on it needs a `_` arm.

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

By default this crate is **lenient**: it accepts url-safe-base64
**or** standard-base64, **with or without** padding — so the obvious
`btoa(...)` pattern works without a separate url-safe-conversion
step. Convenient for getting started.

Production deployments that control their own client JS should flip
the strict toggle:

```rust,ignore
let wa = Webauthn::new("example.com", "Example", "https://example.com")
    .strict_base64(true);
```

Strict mode accepts only the spec-compliant url-safe-no-pad
encoding (WebAuthn §6.1). Any other variant returns
`Error::Base64`, surfacing client-side encoding bugs instead of
papering over them.

## Working examples

Five runnable HTTP-server examples live under [`examples/`](examples/),
covering the most common passkey-app patterns. All bind to
<http://localhost:3000> — run **one at a time** in a passkey-capable
browser (Touch ID, Windows Hello, iCloud Keychain, Yubikey, etc.).

| Example | Framework | What it shows |
|---|---|---|
| [`axum_server`](examples/axum_server.rs) | Axum 0.8 | Minimal single-user register + authenticate; with `--features pqc` it offers ML-DSA-44/65/87 ahead of ES256, EdDSA and RS256 |
| [`rocket_server`](examples/rocket_server.rs) | Rocket 0.5 | Same as above, Rocket variant |
| [`axum_passwordless`](examples/axum_passwordless.rs) | Axum 0.8 | **Multi-user** with **usernameless** sign-in (Gmail-style "tap to sign in", discoverable credentials, browser shows account picker) |
| [`rocket_credential_manager`](examples/rocket_credential_manager.rs) | Rocket 0.5 | **Multiple devices per user**: register additional passkeys while signed in, list them, remove individual ones (refuses to remove the last) |
| [`axum_sqlite`](examples/axum_sqlite.rs) | Axum 0.8 + rusqlite | **Persistent storage**: same as `axum_server` but credentials survive process restart in `passkeys.db` |

```bash
cargo run --example axum_server                # start here
cargo run --example axum_server --features pqc # the same, offering ML-DSA first
cargo run --example axum_passwordless          # then try the Gmail flow
cargo run --example rocket_credential_manager  # then try multi-device
cargo run --example axum_sqlite                # then try persistence
```

All five are explicitly **not for production** (in-memory sessions
where applicable, single hard-coded user in the manager variant, no
CSRF protection on the start endpoints) — read them as references for
wiring the crate into your own server, not as copy-paste starters.

## Testing

```bash
cargo test                      # unit, integration and doc tests
cargo test --all-features       # the same with ML-DSA
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The integration tests cover every algorithm and backup-flag combination
(`tests/conformance.rs`), responses recorded from real authenticators
(`tests/interop.rs`, from the py_webauthn test suite), and credentials
stored by 0.1.3 (`tests/compat_0_1_3.rs`). The RS256 and ML-DSA verify
calls also run the C2SP Wycheproof RSASSA-PKCS1-v1_5 vectors and the
NIST ACVP ML-DSA sigVer vectors.

### Benchmarks

```bash
cargo bench --bench verify --features pqc               # finish_registration / finish_authentication per algorithm
RUSTFLAGS="--cfg fuzzing" cargo bench --bench parsers  # CBOR, authenticator data, COSE_Key, clientDataJSON
cargo test --all-features --test alloc_count -- --nocapture   # heap allocations per verify path
```

The parsers are reachable from the benchmarks and the fuzz targets only
under `--cfg fuzzing`, which cargo-fuzz sets. No Cargo feature exposes
them, and they are not part of the public API.

### Fuzzing

`fuzz/` holds [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
targets for every parser that reads client input: `attestation_object`
(CBOR envelope, authenticator data, COSE_Key and the attestation
statement with its certificates), `cose_key`, `authenticator_data`,
`client_data_json` and `attestation_cert`. `fuzz/seeds/` holds the seed
corpora: real authenticator output and synthetic output for every
algorithm and attestation format. Fuzzing needs a nightly toolchain:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run attestation_object fuzz/corpus/attestation_object fuzz/seeds/attestation_object -- -max_total_time=600
```

Every parser returns an error, never panics, on any input.

CI exercises Linux x86_64 + aarch64, macOS Apple Silicon, and
Windows x86_64 on every push.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](APACHE-LICENSE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>)
