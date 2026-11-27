//! Counts heap allocations on the verify paths.
//!
//! A counting global allocator records every allocation made by the
//! current thread while `finish_registration` or `finish_authentication`
//! runs. Inputs are built before counting starts, so the numbers cover
//! the crate's own work only. Run with `--nocapture` to print them.
//!
//! For ES256 and EdDSA every allocation is the crate's own, and the test
//! pins them: registration allocates the decoded attestationObject and the
//! returned credential (ID, COSE key, transports), and authentication
//! only the credential ID in the returned `AuthSuccess`. RS256 and ML-DSA
//! add the allocations of the `rsa` and `ml-dsa` crates, which are printed
//! but not pinned.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use passkey_auth::Webauthn;
use support::{Alg, Authenticator, ORIGIN, RP_ID};

struct Counting;

thread_local! {
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System`; the counter is a
// const-initialised thread-local, so touching it never allocates.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNT.with(|c| c.set(c.get() + 1));
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with this `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNT.with(|c| c.set(c.get() + 1));
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn counted<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = COUNT.with(Cell::get);
    let out = f();
    (out, COUNT.with(Cell::get) - before)
}

#[test]
fn allocations_per_verify_path() {
    let wa = Webauthn::new(RP_ID, "Example", ORIGIN);
    #[cfg(feature = "pqc")]
    let wa = wa.allow_ml_dsa(true);
    for alg in Alg::all() {
        let mut authenticator = Authenticator::new(alg, 7);
        let (challenge, state) = wa.start_registration(b"user-1", "alice", "Alice", &[]);
        let response = authenticator.register(&challenge);
        let (credential, registration) = counted(|| wa.finish_registration(&state, &response));
        let credential = credential.expect("registration");

        let (challenge, state) = wa.start_authentication(std::slice::from_ref(&credential.id));
        let response = authenticator.assert(&challenge);
        let (outcome, authentication) =
            counted(|| wa.finish_authentication(&state, &response, &credential));
        outcome.expect("authentication");

        println!(
            "allocations {}: finish_registration {registration}, finish_authentication {authentication}",
            alg.name()
        );
        if matches!(alg, Alg::Es256 | Alg::EdDsa) {
            assert!(
                registration <= 5,
                "{} registration: {registration}",
                alg.name()
            );
            assert!(
                authentication <= 1,
                "{} authentication: {authentication}",
                alg.name()
            );
        }
    }
}
