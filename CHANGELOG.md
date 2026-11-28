# Changelog

## 0.3.0 - 2026-11-28

### Upgrading from 0.2

- Change the dependency to `passkey-auth = "0.3"`.
- Stored credentials keep working. `PasskeyCredential` JSON written by
  0.1.x and 0.2.0 deserialises and verifies unchanged, with both backup
  flags unknown, and serialises back to the same bytes.
- After each sign-in, store `AuthSuccess::backup_eligible` and
  `AuthSuccess::backup_state` with the credential, as
  `Some(..)`, next to `new_counter`. `AuthSuccess` JSON carries the two
  flags and needs them to deserialise.
- `PasskeyCredential` can no longer be built with a struct literal; use
  `PasskeyCredential::new(id, public_key_cose, counter)` and set the
  other public fields.
- A `match` on `Error` needs a `_` arm.
- The `__internals` feature is gone. Fuzzing with cargo-fuzz works as
  before; the parser benchmark runs with
  `RUSTFLAGS="--cfg fuzzing" cargo bench --bench parsers`.

### Added

- `PasskeyCredential::backup_eligible` and
  `PasskeyCredential::backup_state` (`Option<bool>`) hold the BE and BS
  flags. `finish_registration` sets them from the attestation's
  authenticator data; `None` means unknown, which is what credentials
  stored by 0.1.x and 0.2.0 load as.
- `AuthSuccess::backup_eligible` and `AuthSuccess::backup_state` report
  the assertion's BE and BS flags.
- `Error::BackupEligibilityChanged { stored, new }`: an assertion whose
  BE differs from the stored BE is refused (WebAuthn-3 §7.2 step 17). A
  credential with unknown BE accepts either value and adopts the one
  `AuthSuccess` returns. BS may change between assertions.
- `PasskeyCredential::new(id, public_key_cose, counter)` builds a
  credential from stored parts, with no transports, an all-zero AAGUID
  and unknown backup flags.
- The crate root re-exports `AuthenticatorSelection`,
  `CredentialDescriptor`, `PubKeyCredParam`, `RpInfo` and `UserInfo`,
  the types of public fields of `RegistrationChallenge` and
  `AuthenticationChallenge` that could not be named before.

### Changed

- `Error`, `PasskeyCredential`, `AuthSuccess`, `RegistrationChallenge`,
  `AuthenticationChallenge` and `AuthenticatorSelection` are
  `#[non_exhaustive]`.
- The parser entry points used by the fuzz targets and the parser
  benchmark compile only under `cfg(fuzzing)`, which cargo-fuzz sets,
  instead of behind the public `__internals` feature.

## 0.2.0 - 2026-11-27

### Upgrading from 0.1

- Change the dependency to `passkey-auth = "0.2"`. No code changes are
  needed: the public API only gained items.
- Stored credentials keep working. `PasskeyCredential` JSON written by
  0.1.3 deserialises and verifies unchanged, and serialises back to the
  same bytes. `RegistrationState` and `AuthenticationState` from 0.1.3
  deserialise too.
- The minimum Rust version is 1.89 (was 1.85).
- `pubKeyCredParams` now offers ES256, EdDSA and RS256 (was ES256 and
  EdDSA), so Windows Hello and TPM-backed keys can register.
- Some responses that 0.1.3 accepted are now refused, because WebAuthn
  Level 3 requires it. See "Fixed" below. Authenticators and browsers
  that follow the specification are not affected.

### Added

- RS256 (COSE -257, RSASSA-PKCS1-v1_5 with SHA-256) for credentials and
  for `packed` attestation with RSA certificates. Moduli outside
  2048-4096 bits and public exponents that are even, below 3 or above
  2^32 - 1 are refused. Verification uses only the public-key operations
  of the `rsa` crate; RUSTSEC-2023-0071 concerns private-key operations.
- The `pqc` feature (off by default): ML-DSA-44, ML-DSA-65 and ML-DSA-87
  credentials (COSE -48, -49, -50, AKP keys per RFC 9964) through the
  `ml-dsa` crate. `Webauthn::allow_ml_dsa(true)` offers them ahead of
  ES256, EdDSA and RS256, which stay as fallbacks.
- `Webauthn::allowed_algs` returns the algorithms registration offers
  and accepts.
- cargo-fuzz targets in `fuzz/` for the attestationObject, COSE_Key,
  authenticator data, clientDataJSON and attestation certificate
  parsers, with seed corpora from real and synthetic authenticators.
- Criterion benchmarks in `benches/` and an allocation count test.
- Conformance tests for every algorithm and backup-flag combination,
  replays of responses recorded from real authenticators (py_webauthn
  test suite), C2SP Wycheproof RSA vectors and NIST ACVP ML-DSA vectors.

### Changed

- Dependencies moved to their latest stable releases: p256 0.13 -> 0.14,
  ed25519-dalek 2 -> 3, sha2 0.10 -> 0.11, rand 0.8 -> 0.10,
  base64 0.22 -> 0.23, x509-cert 0.2 -> 0.3, const-oid 0.9 -> 0.10;
  dev-dependencies axum 0.7 -> 0.8, tower-http 0.6 -> 0.7,
  rusqlite 0.32 -> 0.43. New: rsa 0.10, ml-dsa 0.1.2 (optional).
- CBOR is read by a built-in borrowing decoder instead of ciborium,
  which is now a dev-dependency only. Parsed structures borrow from the
  input, and a hostile length prefix no longer drives an allocation.
- Signatures are verified over the message parts, without building the
  concatenated message. Heap allocations per call: ES256 registration
  26 -> 5 and authentication 13 -> 1; EdDSA 22 -> 5 and 11 -> 1.
  Parsing an attestationObject takes 0.44 us (was 1.53 us).
- COSE keys are checked when they are parsed: a P-256 point off the
  curve or an invalid Ed25519 key is refused at registration instead of
  at each sign-in.

### Fixed

Defects found in a review against WebAuthn Level 3:

- BS (backed up) without BE (backup eligible) is refused in both
  ceremonies (§7.1 step 17, §7.2 step 16).
- `crossOrigin: true` or a `topOrigin` in clientDataJSON is refused
  (§7.1 step 10, §7.2 step 14).
- A discoverable flow (empty allow list, no expected user) requires the
  assertion's `userHandle` (§7.2 step 6).
- Authenticator data must end where its last field ends: trailing bytes
  without the ED flag, the ED flag without an extensions map, or bytes
  after that map are refused (§6.1).
- A COSE key that repeats a label it uses is refused (RFC 9052 §3), as
  are repeated `fmt`, `attStmt`, `authData`, `alg`, `sig` and `x5c`
  keys. CBOR integers outside the i64 range no longer truncate (an
  unsigned 2^64 - 7 read as alg -7).
- `packed` with `x5c` checks the §8.2.1 certificate requirements
  (version 3, subject C, O and CN, OU "Authenticator Attestation", a
  Basic Constraints extension with CA false, non-critical AAGUID
  extension) and that `alg` matches the certificate key.
- An attestationObject must carry `attStmt`, and the `none` format's
  statement must be an empty map (§6.5, §8.7).
- `fido-u2f` requires exactly one certificate in `x5c` (§8.6).
- A leading UTF-8 byte order mark in clientDataJSON is stripped before
  parsing (§7.1 step 6).
- CBOR byte and text strings of indefinite length are refused; CTAP2
  canonical CBOR never produces them.
- An indefinite-length CBOR map with a key and no value is refused.
