//! Parser cost without signature verification: attestationObject (CBOR
//! envelope, authenticator data, COSE key), authenticator data alone,
//! COSE_Key and clientDataJSON.
//!
//! ```text
//! RUSTFLAGS="--cfg fuzzing" cargo bench --bench parsers
//! ```
//!
//! The parsers are reachable only with `--cfg fuzzing`; without it this
//! benchmark prints the command above and exits.

#[cfg(fuzzing)]
#[path = "../tests/support/mod.rs"]
mod support;

#[cfg(fuzzing)]
mod parsers {
    use std::hint::black_box;

    use crate::support::{self, Alg, Authenticator, ORIGIN};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use criterion::{Criterion, criterion_group};
    use passkey_auth::internals;

    fn parsers(c: &mut Criterion) {
        let authenticator = Authenticator::new(Alg::Es256, 7);
        let auth_data = authenticator.registration_auth_data();
        let attestation = Authenticator::none_attestation(auth_data.clone());
        let cose_key = authenticator.cose_public_key();
        let challenge = B64URL.encode(internals::CLIENT_DATA_CHALLENGE);
        let client_data = support::client_data_json("webauthn.get", &challenge, ORIGIN);

        c.bench_function("parse/attestation_object", |b| {
            b.iter(|| internals::attestation_object(black_box(&attestation)).unwrap())
        });
        c.bench_function("parse/authenticator_data", |b| {
            b.iter(|| internals::authenticator_data(black_box(&auth_data)).unwrap())
        });
        c.bench_function("parse/cose_key", |b| {
            b.iter(|| internals::cose_key(black_box(&cose_key)).unwrap())
        });
        c.bench_function("parse/client_data_json", |b| {
            b.iter(|| internals::client_data_json(black_box(&client_data)).unwrap())
        });
    }

    criterion_group!(benches, parsers);
}

#[cfg(fuzzing)]
criterion::criterion_main!(parsers::benches);

#[cfg(not(fuzzing))]
fn main() {
    eprintln!(
        "the parser benchmarks need --cfg fuzzing: RUSTFLAGS=\"--cfg fuzzing\" cargo bench --bench parsers"
    );
}
