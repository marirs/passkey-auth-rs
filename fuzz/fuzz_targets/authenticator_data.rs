//! Binary authenticator data: flags, sign counter, attested credential data and extensions.
//! Errors are the expected outcome for most inputs and are discarded; a
//! panic, abort or hang is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = passkey_auth::internals::authenticator_data(data);
});
