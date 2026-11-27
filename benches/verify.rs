//! Registration and authentication verify time per signature algorithm,
//! through the public `Webauthn` API.
//!
//! ```text
//! cargo bench --bench verify --features pqc
//! ```

#[path = "../tests/support/mod.rs"]
mod support;

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use passkey_auth::Webauthn;
use support::{Alg, Authenticator, ORIGIN, RP_ID};

fn verify(c: &mut Criterion) {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    #[cfg(feature = "pqc")]
    let wa = wa.allow_ml_dsa(true);
    for alg in Alg::all() {
        let mut authenticator = Authenticator::new(alg, 7);

        // States are created per benchmark so none outlives the 5 minute
        // ceremony ceiling during a long run.
        let (challenge, state) = wa.start_registration(b"user-1", "alice", "Alice", &[]);
        let response = authenticator.register(&challenge);
        c.bench_function(&format!("finish_registration/{}", alg.name()), |b| {
            b.iter(|| {
                wa.finish_registration(black_box(&state), black_box(&response))
                    .unwrap()
            })
        });

        let credential = wa.finish_registration(&state, &response).unwrap();
        let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
        let response = authenticator.assert(&challenge);
        c.bench_function(&format!("finish_authentication/{}", alg.name()), |b| {
            b.iter(|| {
                wa.finish_authentication(black_box(&state), black_box(&response), &credential)
                    .unwrap()
            })
        });
    }
}

criterion_group!(benches, verify);
criterion_main!(benches);
