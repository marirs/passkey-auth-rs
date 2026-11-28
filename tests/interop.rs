//! Registration and authentication responses recorded from real
//! authenticators and browsers, taken from the py_webauthn test suite
//! (`fixtures/py_webauthn-vectors.json`, BSD-3-Clause, Duo Security):
//! ML-DSA-44/65/87 credentials from webauthn.io, a YubiKey's packed and
//! fido-u2f attestation, the FIDO conformance tool, and ES256, EdDSA and
//! RS256 (Windows Hello) assertions.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use serde_json::Value;

use passkey_auth::{
    AuthenticationResponse, AuthenticationState, Challenge, CosePublicKey, CredentialId, Error,
    PasskeyCredential, RegistrationResponse, RegistrationState, Webauthn,
};

const FIXTURE: &str = include_str!("fixtures/py_webauthn-vectors.json");

fn cases(kind: &str) -> Vec<Value> {
    let root: Value = serde_json::from_str(FIXTURE).expect("fixture JSON");
    root[kind].as_array().expect("cases").clone()
}

fn text<'a>(case: &'a Value, name: &str) -> &'a str {
    case[name]
        .as_str()
        .unwrap_or_else(|| panic!("{}: missing {name}", case["source"]))
}

fn test_name(case: &Value) -> &str {
    text(case, "source").rsplit("::").next().unwrap()
}

fn webauthn(case: &Value) -> Webauthn {
    let wa = Webauthn::new(text(case, "rp_id"), "Example", text(case, "origin"));
    #[cfg(feature = "pqc")]
    let wa = wa.allow_ml_dsa(true);
    wa
}

fn challenge(case: &Value) -> Challenge {
    Challenge(B64URL.decode(text(case, "challenge")).expect("challenge"))
}

/// Outcome each recorded registration must have in this build.
fn expected_registration(case: &Value) -> Result<(), &'static str> {
    let source = text(case, "source");
    if source.contains("ml_dsa") && !cfg!(feature = "pqc") {
        return Err("ML-DSA needs the pqc feature");
    }
    if source.contains("_tpm.py") {
        return Err("tpm attestation is not supported");
    }
    Ok(())
}

#[test]
fn recorded_registrations() {
    for case in cases("registration") {
        let state = RegistrationState {
            challenge: challenge(&case),
            user_id: Vec::new(),
            created_at: 0,
        };
        let response = RegistrationResponse {
            id: text(&case, "id").to_owned(),
            transports: Vec::new(),
            attestation_object: text(&case, "attestationObject").to_owned(),
            client_data_json: text(&case, "clientDataJSON").to_owned(),
        };
        let result = webauthn(&case).finish_registration(&state, &response);
        match expected_registration(&case) {
            Ok(()) => {
                let credential = result.unwrap_or_else(|e| panic!("{}: {e}", test_name(&case)));
                assert_eq!(
                    credential.id.to_b64url(),
                    text(&case, "id"),
                    "{}",
                    test_name(&case)
                );
            }
            Err(why) => {
                let err = result.expect_err(why);
                assert!(
                    matches!(err, Error::UnsupportedAlg(_) | Error::Cbor(_)),
                    "{}: {err:?}",
                    test_name(&case)
                );
            }
        }
    }
}

#[test]
fn recorded_authentications() {
    for case in cases("authentication") {
        let is_ml_dsa = text(&case, "source").contains("ml_dsa");
        let id = CredentialId::from_b64url(text(&case, "id")).unwrap();
        let stored = PasskeyCredential::new(
            id.clone(),
            CosePublicKey(B64URL.decode(text(&case, "credential_public_key")).unwrap()),
            case["sign_count"].as_u64().unwrap() as u32,
        );
        let state = AuthenticationState {
            challenge: challenge(&case),
            allow_credentials: vec![id],
            created_at: 0,
            user_handle: None,
        };
        let response = AuthenticationResponse {
            id: text(&case, "id").to_owned(),
            authenticator_data: text(&case, "authenticatorData").to_owned(),
            signature: text(&case, "signature").to_owned(),
            client_data_json: text(&case, "clientDataJSON").to_owned(),
            user_handle: case["userHandle"].as_str().map(str::to_owned),
        };
        let result = webauthn(&case).finish_authentication(&state, &response, &stored);
        if is_ml_dsa && !cfg!(feature = "pqc") {
            assert!(
                matches!(result, Err(Error::UnsupportedAlg(_))),
                "{}",
                test_name(&case)
            );
            continue;
        }
        let outcome = result.unwrap_or_else(|e| panic!("{}: {e}", test_name(&case)));
        assert!(
            outcome.new_counter > stored.counter || outcome.new_counter == 0,
            "{}",
            test_name(&case)
        );
    }
}
