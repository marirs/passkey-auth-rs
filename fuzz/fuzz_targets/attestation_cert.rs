//! X.509 attestation certificate parser used by packed and fido-u2f.
//! Errors are the expected outcome for most inputs and are discarded; a
//! panic, abort or hang is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = passkey_auth::internals::attestation_cert(data);
});
