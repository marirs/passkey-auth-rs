//! clientDataJSON checks on decoded bytes.
//! Errors are the expected outcome for most inputs and are discarded; a
//! panic, abort or hang is a finding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = passkey_auth::internals::client_data_json(data);
});
